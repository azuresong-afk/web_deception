package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHandlerFormat(t *testing.T) {
	t.Parallel()

	var dropped atomic.Uint64
	dropped.Store(7)
	h := Handler([]Metric{
		{Name: "sensor_events_dropped_total", Help: "Отброшенные события.", Kind: Counter,
			Label: `reason="queue_full"`, Value: dropped.Load},
		{Name: "sensor_events_dropped_total", Help: "Отброшенные события.", Kind: Counter,
			Label: `reason="write_error"`, Value: func() uint64 { return 0 }},
		{Name: "sensor_events_queue_length", Help: "Событий в буфере.", Kind: Gauge,
			Value: func() uint64 { return 3 }},
	})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	want := `# HELP sensor_events_dropped_total Отброшенные события.
# TYPE sensor_events_dropped_total counter
sensor_events_dropped_total{reason="queue_full"} 7
sensor_events_dropped_total{reason="write_error"} 0
# HELP sensor_events_queue_length Событий в буфере.
# TYPE sensor_events_queue_length gauge
sensor_events_queue_length 3
`
	if rec.Code != http.StatusOK || rec.Body.String() != want {
		t.Errorf("код %d, вывод:\n%s\nожидалось:\n%s", rec.Code, rec.Body.String(), want)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type %q", ct)
	}
}

// TestHandlerRejectsBadDefinitions: ошибка в описании метрик — паника при
// запуске, а не строка, которую Prometheus не разберёт.
func TestHandlerRejectsBadDefinitions(t *testing.T) {
	t.Parallel()

	zero := func() uint64 { return 0 }
	tests := map[string][]Metric{
		"заглавные в имени":       {{Name: "Sensor", Help: "x", Kind: Counter, Value: zero}},
		"пробел в имени":          {{Name: "a b", Help: "x", Kind: Counter, Value: zero}},
		"неизвестный тип":         {{Name: "a", Help: "x", Kind: "histogram", Value: zero}},
		"пустое описание":         {{Name: "a", Kind: Counter, Value: zero}},
		"перевод строки":          {{Name: "a", Help: "x\ny", Kind: Counter, Value: zero}},
		"метка без кавычек":       {{Name: "a", Help: "x", Kind: Counter, Label: "reason=x", Value: zero}},
		"кавычка в метке":         {{Name: "a", Help: "x", Kind: Counter, Label: `reason="x"} 1` + "\n" + `b{c="d"`, Value: zero}},
		"нет значения":            {{Name: "a", Help: "x", Kind: Counter}},
		"имя не подряд":           {{Name: "a", Help: "x", Kind: Counter, Value: zero}, {Name: "b", Help: "x", Kind: Counter, Value: zero}, {Name: "a", Help: "x", Kind: Counter, Value: zero}},
		"разный тип одного имени": {{Name: "a", Help: "x", Kind: Counter, Label: `r="1"`, Value: zero}, {Name: "a", Help: "x", Kind: Gauge, Label: `r="2"`, Value: zero}},
	}
	for name, ms := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Error("ожидалась паника на неверном описании")
				}
			}()
			Handler(ms)
		})
	}
}
