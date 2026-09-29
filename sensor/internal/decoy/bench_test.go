package decoy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/azuresong-afk/web_deception/sensor/internal/event"
	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
	"github.com/azuresong-afk/web_deception/sensor/internal/policy"
)

// nopEvents — события в никуда: замеряется обнаружение, а не запись.
type nopEvents struct{}

func (nopEvents) Emit(event.Event) {}

// BenchmarkInspect — обнаружение на одном запросе с учебной политикой
// (ADR-0030): обычный запрос приложения, переход по странице (cookie-наживка)
// и касание ловушки.
func BenchmarkInspect(b *testing.B) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "policy", "demo.json"))
	if err != nil {
		b.Fatal(err)
	}
	c, err := policy.Parse(data)
	if err != nil {
		b.Fatal(err)
	}
	d := New(nopEvents{}, forwarded.NewResolver(nil))
	d.Swap(c)

	for _, tc := range []struct {
		name    string
		path    string
		headers map[string]string
	}{
		{"запрос API", "/api/Products/42", map[string]string{"Accept": "application/json", "Cookie": "token=abc"}},
		{"переход по странице", "/", map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}},
		{"касание ловушки", "/.env", nil},
	} {
		b.Run(tc.name, func(b *testing.B) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			b.ReportAllocs()
			for b.Loop() {
				d.Inspect(httptest.NewRecorder(), r)
			}
		})
	}
}
