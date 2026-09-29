//go:build !race

package lure

import (
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
)

// Замер памяти — только в обычной сборке, как в образе сенсора. Детектор
// гонок меняет выделение памяти (по документации Go — в разы), и замер
// под -race проверял бы не сенсор, а инструментирование. make test-go
// запускает этот тест отдельно, без -race.

// TestEditReserves: резерв правки (editReserve) не меньше памяти, которую
// правка занимает, — для тел разной длины и формы, с известной длиной
// и без неё. Замер — все выделения за время Modify: это верхняя оценка
// того, что правка держит в памяти одновременно.
//
// Без t.Parallel: параллельные тесты этого пакета ждут, пока идут
// последовательные, и не добавляют свои выделения в замер.
func TestEditReserves(t *testing.T) {
	type shape struct {
		name, path, ctype string
		policy            string
		limit, perByte    int64
		body              func(n int) string
	}
	shapes := []shape{
		{"мелкие теги", "/", "text/html", htmlPolicy, maxHTMLHead, htmlPerByte,
			func(n int) string { return strings.Repeat("<p>", n/3) + "<body>" }},
		{"теги с атрибутами", "/", "text/html", htmlPolicy, maxHTMLHead, htmlPerByte,
			func(n int) string { return strings.Repeat(`<a b="c" d='e'>`, n/15) + "<body>" }},
		{"один script", "/", "text/html", htmlPolicy, maxHTMLHead, htmlPerByte,
			func(n int) string { return "<script>" + strings.Repeat("a", n) + "</script><body>" }},
		{"одно значение атрибута", "/", "text/html", htmlPolicy, maxHTMLHead, htmlPerByte,
			func(n int) string { return `<div a="` + strings.Repeat("a", n) + `"><body>` }},
		{"без <body>", "/", "text/html", htmlPolicy, maxHTMLHead, htmlPerByte,
			func(n int) string { return strings.Repeat("a", n) }},
		{"robots.txt", "/robots.txt", "text/plain", testPolicy, maxRobotsBytes + 1, robotsPerByte,
			func(n int) string { return strings.Repeat("a", n) }},
	}
	for _, sh := range shapes {
		for _, n := range []int{0, 30, 3000, 9000, 30000, maxHTMLHead, 200 << 10, maxRobotsBytes, maxRobotsBytes + 10} {
			for _, unknown := range []bool{false, true} {
				body := sh.body(n)
				h := newHarness(t, sh.policy)
				resp := &http.Response{
					StatusCode: 200, Header: http.Header{"Content-Type": {sh.ctype}},
					Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)),
					Request: httptest.NewRequest(http.MethodGet, sh.path, nil),
				}
				if unknown {
					resp.ContentLength = -1
				}
				reserve := editReserve(resp.ContentLength, sh.limit, sh.perByte)
				var before, after runtime.MemStats
				runtime.GC()
				runtime.ReadMemStats(&before)
				_ = h.inj.Modify(resp)
				runtime.ReadMemStats(&after)

				if alloc := int64(after.TotalAlloc - before.TotalAlloc); alloc > reserve {
					t.Errorf("%s, %d байт (длина известна: %v): правка заняла %d байт при резерве %d",
						sh.name, len(body), !unknown, alloc, reserve)
				}
				// До отправки за ответом числится только то, что ждёт
				// клиента, — меньше резерва на разбор.
				if held := h.inj.EditMemory(); held > uint64(reserve/2) {
					t.Errorf("%s, %d байт: за ответом числится %d байт", sh.name, len(body), held)
				}
				_ = resp.Body.Close()
				if memUsed(h) != 0 {
					t.Errorf("%s, %d байт: память не возвращена", sh.name, len(body))
				}
			}
		}
	}
}
