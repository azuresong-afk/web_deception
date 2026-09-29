package lure

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/azuresong-afk/web_deception/sensor/internal/policy"
)

// benchPage — страница размером со стартовую страницу Juice Shop (9,4 КБ):
// <head> со стилями и скриптами, затем <body>.
var benchPage = "<!doctype html><html><head><title>shop</title>" +
	strings.Repeat(`<link rel="stylesheet" href="/styles.css"><script src="/main.js" defer></script>`, 90) +
	`</head><body class="app"><app-root></app-root></body></html>`

func benchInjector(b *testing.B) *Injector {
	b.Helper()
	c, err := policy.Parse([]byte(htmlPolicy))
	if err != nil {
		b.Fatal(err)
	}
	return New(Config{
		Policy:   func() *policy.Compiled { return c },
		Degraded: func() bool { return false },
		OnPanic:  func(*http.Request, any, string) {},
	})
}

// BenchmarkModify — правка ответа приложения целиком: как её видит
// клиент, с чтением тела (ADR-0030). Страница с наживкой — поиск <body>,
// вставка, заголовки; JSON — проверка, что ответ не правится.
func BenchmarkModify(b *testing.B) {
	inj := benchInjector(b)
	for _, tc := range []struct{ name, ctype, body string }{
		{"страница с наживкой", "text/html; charset=utf-8", benchPage},
		{"JSON без правки", "application/json", `{"id":42,"name":"Apple Juice"}`},
	} {
		b.Run(tc.name, func(b *testing.B) {
			req := withClient(httptest.NewRequest(http.MethodGet, "/", nil), netip.MustParseAddr("192.0.2.1"))
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.body)))
			for b.Loop() {
				resp := &http.Response{
					StatusCode: 200, Header: http.Header{"Content-Type": {tc.ctype}},
					Body: io.NopCloser(strings.NewReader(tc.body)), ContentLength: int64(len(tc.body)), Request: req,
				}
				_ = inj.Modify(resp)
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		})
	}
}

// BenchmarkBudget — бюджет памяти под конкуренцией: занять, сжать,
// вернуть — как на каждой правке тела.
func BenchmarkBudget(b *testing.B) {
	var m memBudget
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		client := netip.MustParseAddr("192.0.2.1")
		for pb.Next() {
			if l := m.lease(client, editReserve(9<<10, maxHTMLHead, htmlPerByte)); l != nil {
				l.shrink(16 << 10)
				l.release()
			}
		}
	})
}

// BenchmarkGzipPage — сколько стоило бы сжимать страницу с наживкой
// самим сенсором (решение в ADR-0030). Новый gzip.Writer на каждую
// страницу выделяет сотни килобайт; из пула — переиспользует.
func BenchmarkGzipPage(b *testing.B) {
	page := []byte(benchPage)
	for _, level := range []int{gzip.BestSpeed, gzip.DefaultCompression} {
		pool := sync.Pool{New: func() any {
			w, _ := gzip.NewWriterLevel(io.Discard, level)
			return w
		}}
		b.Run("новый writer, уровень "+strconv.Itoa(level), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(page)))
			var out bytes.Buffer
			for b.Loop() {
				out.Reset()
				w, _ := gzip.NewWriterLevel(&out, level)
				_, _ = w.Write(page)
				_ = w.Close()
			}
		})
		b.Run("writer из пула, уровень "+strconv.Itoa(level), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(page)))
			var out bytes.Buffer
			for b.Loop() {
				out.Reset()
				w, _ := pool.Get().(*gzip.Writer)
				w.Reset(&out)
				_, _ = w.Write(page)
				_ = w.Close()
				pool.Put(w)
			}
		})
	}
}
