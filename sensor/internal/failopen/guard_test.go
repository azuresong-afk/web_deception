package failopen

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/web_deception/sensor/internal/event"
	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
)

// fakeClock — часы, которые идут только по команде теста.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type memEvents struct {
	mu     sync.Mutex
	events []event.Event
}

func (m *memEvents) Emit(ev event.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
}

func (m *memEvents) ofType(t event.Type) []event.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []event.Event
	for _, ev := range m.events {
		if ev.Type == t {
			out = append(out, ev)
		}
	}
	return out
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// detectorFunc превращает функцию в Detector.
type detectorFunc func(http.ResponseWriter, *http.Request) bool

func (f detectorFunc) Inspect(w http.ResponseWriter, r *http.Request) bool { return f(w, r) }

type harness struct {
	guard  *Guard
	clock  *fakeClock
	events *memEvents
	logs   *syncBuffer
	app    http.Handler
	calls  int
	bodies []string
}

func newHarness(t *testing.T, d Detector) *harness {
	t.Helper()
	h := &harness{clock: &fakeClock{now: t0}, events: &memEvents{}, logs: &syncBuffer{}}
	h.guard = NewGuard(Config{
		Detector: d,
		Events:   h.events,
		Trust:    forwarded.NewResolver(nil),
		Logger:   slog.New(slog.NewJSONHandler(h.logs, nil)),
		Now:      h.clock.Now,
	})
	h.app = h.guard.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.calls++
		b, _ := io.ReadAll(r.Body)
		h.bodies = append(h.bodies, string(b))
		_, _ = io.WriteString(w, "app")
	}))
	return h
}

// serve выполняет запрос и возвращает ответ и значение паники, если
// обработчик оборвал соединение.
func (h *harness) serve(r *http.Request) (rec *httptest.ResponseRecorder, aborted bool) {
	rec = httptest.NewRecorder()
	defer func() {
		if p := recover(); p != nil {
			if err, ok := p.(error); !ok || !errors.Is(err, http.ErrAbortHandler) {
				panic(p)
			}
			aborted = true
		}
	}()
	h.app.ServeHTTP(rec, r)
	return rec, false
}

func TestDetectorPassesAndHandles(t *testing.T) {
	t.Parallel()

	h := newHarness(t, detectorFunc(func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path == "/.env" {
			_, _ = io.WriteString(w, "trap")
			return true
		}
		return false
	}))
	if rec, _ := h.serve(httptest.NewRequest(http.MethodGet, "/", nil)); rec.Body.String() != "app" {
		t.Errorf("обычный запрос: %q, ожидался ответ приложения", rec.Body.String())
	}
	if rec, _ := h.serve(httptest.NewRequest(http.MethodGet, "/.env", nil)); rec.Body.String() != "trap" || h.calls != 1 {
		t.Errorf("ловушка: %q, приложение вызвано %d раз", rec.Body.String(), h.calls)
	}
}

// TestPanicPassesRequestThrough — главное свойство fail-open: паника
// в обнаружении не ломает запрос клиента, он уходит в приложение, а паника
// записана событием с адресом клиента. Режим при этом не меняется.
func TestPanicPassesRequestThrough(t *testing.T) {
	t.Parallel()

	h := newHarness(t, detectorFunc(func(http.ResponseWriter, *http.Request) bool {
		panic(errors.New("сбой обнаружения"))
	}))

	for range 100 {
		r := httptest.NewRequest(http.MethodPost, "/reset/9f8a7c6e5d4b3a2f1e0d", strings.NewReader("body"))
		r.RemoteAddr = "203.0.113.7:5555"
		rec, aborted := h.serve(r)
		if aborted || rec.Body.String() != "app" {
			t.Fatalf("после паники: оборвано %v, ответ не от приложения", aborted)
		}
	}
	if h.calls != 100 || h.bodies[0] != "body" {
		t.Errorf("приложение вызвано %d раз, тело %q", h.calls, h.bodies[0])
	}

	panics := h.events.ofType(event.TypeDetectionPanic)
	if len(panics) != 100 || panics[0].Severity != event.SeverityHigh {
		t.Fatalf("событий о панике %d, ожидалось 100 уровня high", len(panics))
	}
	ev := panics[0]
	if ev.Client.IP != "203.0.113.7" || ev.Request.Path != "/reset/{hex}" || ev.Data["panic_type"] == "" {
		t.Errorf("событие о панике: клиент %+v, запрос %+v, данные %v", ev.Client, ev.Request, ev.Data)
	}

	// Паники не включают частичный режим — иначе атакующий выключал бы
	// обнаружение для всех, повторяя вызывающий панику запрос.
	if h.guard.Degraded() || len(h.events.ofType(event.TypeFailOpen)) != 0 {
		t.Error("паники переключили общий режим")
	}
	if h.guard.Stats.Panics.Load() != 100 {
		t.Errorf("счётчик паник %d", h.guard.Stats.Panics.Load())
	}

	// Стек в лог — один раз за минуту, а не на каждую панику.
	if n := strings.Count(h.logs.String(), "паника в обнаружении"); n != 1 {
		t.Errorf("сообщений о панике в логе: %d, ожидалось 1", n)
	}
}

// TestPanicAfterResponseStartedAborts: Detector начал ответ и упал —
// пропустить запрос в приложение нельзя (клиент получил бы два ответа
// в одном), соединение обрывается.
func TestPanicAfterResponseStartedAborts(t *testing.T) {
	t.Parallel()

	h := newHarness(t, detectorFunc(func(w http.ResponseWriter, _ *http.Request) bool {
		w.WriteHeader(http.StatusOK)
		panic("сбой посреди ответа")
	}))
	if _, aborted := h.serve(httptest.NewRequest(http.MethodGet, "/", nil)); !aborted {
		t.Error("соединение не оборвано")
	}
	if h.calls != 0 || h.guard.Stats.Aborted.Load() != 1 {
		t.Errorf("приложение вызвано %d раз, оборвано %d", h.calls, h.guard.Stats.Aborted.Load())
	}
}

// TestPanicAfterBodyReadAborts: Detector прочитал часть тела и упал —
// приложение получило бы тело без начала, поэтому соединение обрывается.
func TestPanicAfterBodyReadAborts(t *testing.T) {
	t.Parallel()

	h := newHarness(t, detectorFunc(func(_ http.ResponseWriter, r *http.Request) bool {
		buf := make([]byte, 2)
		_, _ = r.Body.Read(buf)
		panic("сбой после чтения тела")
	}))
	r := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("user=a&password=b"))
	if _, aborted := h.serve(r); !aborted {
		t.Error("соединение не оборвано")
	}
	if h.calls != 0 {
		t.Errorf("приложение получило испорченный запрос: %v", h.bodies)
	}
}

// TestAbortHandlerPropagates: намеренный обрыв соединения Detector'ом —
// не сбой, и Guard его не глотает.
func TestAbortHandlerPropagates(t *testing.T) {
	t.Parallel()

	h := newHarness(t, detectorFunc(func(http.ResponseWriter, *http.Request) bool {
		panic(http.ErrAbortHandler)
	}))
	if _, aborted := h.serve(httptest.NewRequest(http.MethodGet, "/", nil)); !aborted {
		t.Error("намеренный обрыв проглочен")
	}
	if h.guard.Stats.Panics.Load() != 0 || len(h.events.ofType(event.TypeDetectionPanic)) != 0 {
		t.Error("намеренный обрыв посчитан как паника")
	}
}

// TestBodyRestored: после проверки приложение получает исходное тело,
// а запрос без тела остаётся без тела — иначе прокси отправил бы GET
// с пустым телом по частям.
func TestBodyRestored(t *testing.T) {
	t.Parallel()

	var seen []io.ReadCloser
	h := newHarness(t, NoDetector{})
	app := h.guard.Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Body)
	}))

	get := httptest.NewRequest(http.MethodGet, "/", nil)
	get.Body = http.NoBody
	app.ServeHTTP(httptest.NewRecorder(), get)
	post := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("x"))
	orig := post.Body
	app.ServeHTTP(httptest.NewRecorder(), post)

	if seen[0] != http.NoBody || seen[1] != orig {
		t.Errorf("тело после проверки подменено: %T, %T", seen[0], seen[1])
	}
}

// TestOverloadDegradesAndRecovers — перегрузка: проверки стали медленными,
// сенсор перешёл в частичное обнаружение (событие critical, строка ERROR),
// проверяет каждый десятый запрос, а когда проверки снова быстрые — вернулся
// (событие о восстановлении).
func TestOverloadDegradesAndRecovers(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	delay := 10 * time.Millisecond
	var h *harness
	h = newHarness(t, detectorFunc(func(http.ResponseWriter, *http.Request) bool {
		mu.Lock()
		d := delay
		mu.Unlock()
		h.clock.Advance(d)
		return false
	}))

	for range enterMinInspected {
		h.serve(httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if !h.guard.Degraded() {
		t.Fatal("медленные проверки не включили частичный режим")
	}
	fo := h.events.ofType(event.TypeFailOpen)
	if len(fo) != 1 || fo[0].Severity != event.SeverityCritical || fo[0].Data["reason"] != "detection_slow" {
		t.Fatalf("событие о переходе: %+v", fo)
	}
	if !strings.Contains(h.logs.String(), `"level":"ERROR"`) || !strings.Contains(h.logs.String(), "fail-open") {
		t.Errorf("перехода нет в логе уровня ERROR: %s", h.logs.String())
	}

	// В частичном режиме приложение получает каждый запрос, а проверяется
	// каждый десятый.
	inspectedBefore := h.guard.Stats.Inspected.Load()
	callsBefore := h.calls
	for range 100 {
		h.serve(httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if got := h.guard.Stats.Inspected.Load() - inspectedBefore; got != 100/SampleEvery {
		t.Errorf("в частичном режиме проверено %d из 100", got)
	}
	if h.calls-callsBefore != 100 {
		t.Errorf("приложение получило %d запросов из 100", h.calls-callsBefore)
	}

	// Проверки снова быстрые; время идёт — режим снят с событием.
	mu.Lock()
	delay = 0
	mu.Unlock()
	for i := 0; i < 400 && h.guard.Degraded(); i++ {
		h.clock.Advance(100 * time.Millisecond)
		h.serve(httptest.NewRequest(http.MethodGet, "/", nil))
	}
	if h.guard.Degraded() {
		t.Fatal("режим не снят после 40 секунд быстрых проверок")
	}
	rec := h.events.ofType(event.TypeFailOpenRecovered)
	if len(rec) != 1 || rec[0].Data["degraded_for"] == "" {
		t.Errorf("событие о восстановлении: %+v", rec)
	}
	if h.guard.Stats.Transitions.Load() != 1 {
		t.Errorf("переходов %d, ожидался 1", h.guard.Stats.Transitions.Load())
	}
}

func TestNewGuardRequiresAllFields(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("Guard без получателя событий создан без ошибки")
		}
	}()
	NewGuard(Config{Detector: NoDetector{}, Trust: forwarded.NewResolver(nil), Logger: slog.Default()})
}
