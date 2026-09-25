package lure

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMemoryBudget: память правки числится за ответом, пока прокси
// не закроет тело; бюджета нет — ответ уходит как есть.
func TestMemoryBudget(t *testing.T) {
	t.Parallel()

	const body = `<html><head><title>x</title></head><body>y`
	h := newHarness(t, htmlPolicy)
	resp := &http.Response{
		StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)),
		Request: httptest.NewRequest(http.MethodGet, "/", nil),
	}
	_ = h.inj.Modify(resp)
	// Числится только прочитанное — не резерв на разбор.
	if held := h.inj.EditMemory(); held < uint64(len(body)) || held >= htmlReserve {
		t.Errorf("до отправки числится %d байт", held)
	}
	_ = resp.Body.Close()
	_ = resp.Body.Close()
	if held := h.inj.mem.used.Load(); held != 0 {
		t.Errorf("после двух Close числится %d байт", held)
	}

	// Бюджет занят другими ответами: страница и robots.txt — как есть.
	h = newHarness(t, testPolicy)
	h.inj.mem.used.Store(editMemory - robotsReserve + 1)
	if r := run(t, h, app(http.MethodGet, "/robots.txt", 200, http.Header{"Content-Type": {"text/plain"}}, "a\n")); r.body != "a\n" {
		t.Errorf("robots.txt изменён без бюджета: %q", r.body)
	}
	h2 := newHarness(t, htmlPolicy)
	h2.inj.mem.used.Store(editMemory - htmlReserve + 1)
	if r := run(t, h2, page(body)); r.body != body || r.length != int64(len(body)) {
		t.Errorf("страница изменена без бюджета: %q", r.body)
	}
	if h.inj.Stats.Skipped[SkipMemory].Load() != 1 || h2.inj.Stats.Skipped[SkipMemory].Load() != 1 ||
		h.inj.Stats.Robots.Load() != 0 || h2.inj.Stats.HTML.Load() != 0 {
		t.Error("пропуск по памяти не учтён")
	}

	// Ровно на пределе — бюджет ещё выдаётся.
	h3 := newHarness(t, htmlPolicy)
	h3.inj.mem.used.Store(editMemory - htmlReserve)
	if r := run(t, h3, page(body)); !strings.Contains(r.body, fragment) {
		t.Error("на пределе бюджета наживка не поставлена")
	}
}
