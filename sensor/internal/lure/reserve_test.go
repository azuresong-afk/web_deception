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

// TestEditReserves: резерв правки не меньше памяти, которую она занимает
// на худших страницах и robots.txt. Замер — все выделения за время
// Modify: это верхняя оценка того, что правка держит в памяти одновременно.
//
// Без t.Parallel: параллельные тесты этого пакета ждут, пока идут
// последовательные, и не добавляют свои выделения в замер.
func TestEditReserves(t *testing.T) {
	type tc struct {
		name, path, ctype, body string
		unknownLength           bool
		reserve                 int64
	}
	var tests []tc
	for name, body := range map[string]string{
		"весь предел — один script": "<script>" + strings.Repeat("a", maxHTMLHead) + "</script><body>",
		"весь предел — атрибут":     `<div a="` + strings.Repeat("a", maxHTMLHead) + `"><body>`,
		"мелкие теги":               strings.Repeat("<p>", maxHTMLHead/3) + "<body>",
		"<body> у предела":          strings.Repeat("a", maxHTMLHead-16) + "<body>",
		"без <body>":                strings.Repeat("a", 2*maxHTMLHead),
	} {
		for _, unknown := range []bool{false, true} {
			tests = append(tests, tc{name, "/", "text/html", body, unknown, htmlReserve})
		}
	}
	for name, body := range map[string]string{
		"robots.txt у предела":   strings.Repeat("a", maxRobotsBytes-1),
		"robots.txt за пределом": strings.Repeat("a", maxRobotsBytes+10),
	} {
		for _, unknown := range []bool{false, true} {
			tests = append(tests, tc{name, "/robots.txt", "text/plain", body, unknown, robotsReserve})
		}
	}

	for _, tt := range tests {
		h := newHarness(t, htmlPolicy)
		if tt.path == "/robots.txt" {
			h = newHarness(t, testPolicy)
		}
		resp := &http.Response{
			StatusCode: 200, Header: http.Header{"Content-Type": {tt.ctype}},
			Body: io.NopCloser(strings.NewReader(tt.body)), ContentLength: int64(len(tt.body)),
			Request: httptest.NewRequest(http.MethodGet, tt.path, nil),
		}
		if tt.unknownLength {
			resp.ContentLength = -1
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_ = h.inj.Modify(resp)
		runtime.ReadMemStats(&after)

		if alloc := int64(after.TotalAlloc - before.TotalAlloc); alloc > tt.reserve {
			t.Errorf("%s (длина известна: %v): правка заняла %d байт при резерве %d",
				tt.name, !tt.unknownLength, alloc, tt.reserve)
		}
		// До отправки за ответом числится только то, что ждёт клиента.
		if held := h.inj.mem.used.Load(); held <= 0 || held > tt.reserve/2 {
			t.Errorf("%s: за ответом числится %d байт", tt.name, held)
		}
		_ = resp.Body.Close()
		if h.inj.mem.used.Load() != 0 {
			t.Errorf("%s: память не возвращена", tt.name)
		}
	}
}
