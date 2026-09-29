package event

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// discardSink — запись в никуда: замеряется путь запроса, а не диск.
type discardSink struct{}

func (discardSink) Write([]byte) error { return nil }
func (discardSink) Flush() error       { return nil }
func (discardSink) Close() error       { return nil }

// BenchmarkEmit — событие в буфер из многих горутин (ADR-0030). Запрос
// не ждёт записи (ADR-0023); здесь видно, сколько стоит сама передача.
func BenchmarkEmit(b *testing.B) {
	r := NewRecorder(discardSink{}, QueueSize, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer func() { _ = r.Close(context.Background()) }()
	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	ev := New(TypeDecoyTouch, SeverityLow)
	ev.Request = RequestFrom(req)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r.Emit(ev)
		}
	})
}

// BenchmarkRequestFrom — метаданные запроса для события: очистка строк,
// маскирование пути, Sec-Fetch-*.
func BenchmarkRequestFrom(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "/reset/9f8a7c6e5d4b3a2f/user@example.com?x=1", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	b.ReportAllocs()
	for b.Loop() {
		RequestFrom(req)
	}
}
