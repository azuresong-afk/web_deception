package lure

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// memUsed — занятая память как есть. Метрика (EditMemory) показывает
// отрицательное значение как 0, а тестам нужно видеть и его: минус —
// память возвращена дважды.
func memUsed(h *harness) int64 {
	h.inj.mem.mu.Lock()
	defer h.inj.mem.mu.Unlock()
	return h.inj.mem.used
}

// occupy занимает n байт бюджета «другими ответами» — без доли клиента.
func occupy(h *harness, n int64) {
	h.inj.mem.mu.Lock()
	h.inj.mem.used = n
	h.inj.mem.mu.Unlock()
}

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
	if held := h.inj.EditMemory(); held < uint64(len(body)) || held >= uint64(editReserve(int64(len(body)), maxHTMLHead, htmlPerByte)) {
		t.Errorf("до отправки числится %d байт", held)
	}
	_ = resp.Body.Close()
	_ = resp.Body.Close()
	if held := memUsed(h); held != 0 {
		t.Errorf("после двух Close числится %d байт", held)
	}

	// Бюджет занят другими ответами: страница и robots.txt — как есть.
	h = newHarness(t, testPolicy)
	occupy(h, editMemory-editReserve(2, maxRobotsBytes+1, robotsPerByte)+1)
	if r := run(t, h, app(http.MethodGet, "/robots.txt", 200, http.Header{"Content-Type": {"text/plain"}}, "a\n")); r.body != "a\n" {
		t.Errorf("robots.txt изменён без бюджета: %q", r.body)
	}
	h2 := newHarness(t, htmlPolicy)
	occupy(h2, editMemory-editReserve(int64(len(body)), maxHTMLHead, htmlPerByte)+1)
	if r := run(t, h2, page(body)); r.body != body || r.length != int64(len(body)) {
		t.Errorf("страница изменена без бюджета: %q", r.body)
	}
	if h.inj.Stats.Skipped[SkipMemory].Load() != 1 || h2.inj.Stats.Skipped[SkipMemory].Load() != 1 ||
		h.inj.Stats.Robots.Load() != 0 || h2.inj.Stats.HTML.Load() != 0 {
		t.Error("пропуск по памяти не учтён")
	}

	// Ровно на пределе — бюджет ещё выдаётся.
	h3 := newHarness(t, htmlPolicy)
	occupy(h3, editMemory-editReserve(int64(len(body)), maxHTMLHead, htmlPerByte))
	if r := run(t, h3, page(body)); !strings.Contains(r.body, fragment) {
		t.Error("на пределе бюджета наживка не поставлена")
	}
}

// TestClientShare: один клиент не займёт больше своей доли, другие
// клиенты при этом получают наживки.
func TestClientShare(t *testing.T) {
	t.Parallel()

	var b memBudget
	a := budgetKey(netip.MustParseAddr("192.0.2.1"))
	c := budgetKey(netip.MustParseAddr("192.0.2.2"))
	full := b.lease(a, clientMemory)
	if full == nil || b.lease(a, 1) != nil {
		t.Fatal("доля клиента не ограничена")
	}
	other := b.lease(c, clientMemory)
	if other == nil {
		t.Fatal("чужая доля помешала другому клиенту")
	}
	full.shrink(clientMemory - 10)
	if b.lease(a, 11) != nil || b.lease(a, 10) == nil {
		t.Error("после shrink доля считается неверно")
	}
	full.release()
	other.release()
	if b.used != 10 || len(b.perClient) != 1 {
		t.Errorf("после release: всего %d, клиентов %d", b.used, len(b.perClient))
	}

	// Через Modify: доля клиента занята — его страница как есть,
	// страница другого клиента — с наживкой.
	h := newHarness(t, htmlPolicy)
	busy := netip.MustParseAddr("2001:db8::1")
	hold := h.inj.mem.lease(budgetKey(busy), clientMemory-editReserve(int64(len(`<body>x`)), maxHTMLHead, htmlPerByte)+1)
	defer hold.release()
	resp := page(`<body>x`)
	resp.client = busy
	if r := run(t, h, resp); r.body != `<body>x` {
		t.Errorf("клиент сверх доли получил правку: %q", r.body)
	}
	resp.client = netip.MustParseAddr("2001:db8:0:1::1")
	if r := run(t, h, resp); !strings.Contains(r.body, fragment) {
		t.Error("соседний клиент остался без наживки")
	}
	if h.inj.Stats.Skipped[SkipMemory].Load() != 1 {
		t.Error("пропуск по доле клиента не учтён")
	}

	// То же для robots.txt.
	hr := newHarness(t, testPolicy)
	holdRobots := hr.inj.mem.lease(budgetKey(busy), clientMemory-editReserve(2, maxRobotsBytes+1, robotsPerByte)+1)
	defer holdRobots.release()
	robots := app(http.MethodGet, "/robots.txt", 200, http.Header{"Content-Type": {"text/plain"}}, "a\n")
	robots.client = busy
	if r := run(t, hr, robots); r.body != "a\n" {
		t.Errorf("robots.txt сверх доли клиента изменён: %q", r.body)
	}
	robots.client = netip.MustParseAddr("192.0.2.9")
	if r := run(t, hr, robots); !strings.Contains(r.body, "Disallow") {
		t.Error("robots.txt другого клиента не дополнен")
	}
}

// TestBudgetKey: IPv6 считается по сети /64, IPv4 в записи IPv6 — как IPv4.
func TestBudgetKey(t *testing.T) {
	t.Parallel()

	for a, want := range map[string]string{
		"192.0.2.1":            "192.0.2.1",
		"::ffff:192.0.2.1":     "192.0.2.1",
		"2001:db8::1":          "2001:db8::",
		"2001:db8::ffff:1:2:3": "2001:db8::",
		"2001:db8:0:1:ffff::1": "2001:db8:0:1::",
		"fe80::1%eth0":         "fe80::",
	} {
		if got := budgetKey(netip.MustParseAddr(a)); got != netip.MustParseAddr(want) {
			t.Errorf("%s → %s, ожидалось %s", a, got, want)
		}
	}
	if budgetKey(netip.Addr{}).IsValid() {
		t.Error("неизвестный клиент получил адрес")
	}
	if clientOf(&http.Response{}).IsValid() {
		t.Error("ответ без запроса получил клиента")
	}
}

// TestWorstReserveFitsClientShare: худший резерв правки — тело без длины —
// помещается в долю клиента. Иначе страницы и robots.txt без
// Content-Length (chunked) не правились бы никогда, и тихо.
func TestWorstReserveFitsClientShare(t *testing.T) {
	t.Parallel()

	for name, r := range map[string]int64{
		"HTML":       editReserve(-1, maxHTMLHead, htmlPerByte),
		"robots.txt": editReserve(-1, maxRobotsBytes+1, robotsPerByte),
	} {
		if r > clientMemory {
			t.Errorf("%s: худший резерв %d больше доли клиента %d", name, r, clientMemory)
		}
	}
}
