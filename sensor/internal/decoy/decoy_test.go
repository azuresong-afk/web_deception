package decoy

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/azuresong-afk/web_deception/sensor/internal/event"
	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
	"github.com/azuresong-afk/web_deception/sensor/internal/policy"
)

func policyJSON(version string, traps ...string) string {
	return `{"schema_version":1,"version":"` + version + `","traps":[` + strings.Join(traps, ",") + `]}`
}

func trapJSON(id, path, mode, confidence, body string) string {
	return `{"id":"` + id + `","path":"` + path + `","mode":"` + mode + `","confidence":"` + confidence +
		`","response":{"status":200,"content_type":"text/plain","body":"` + body + `"}}`
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

func mustCompile(t *testing.T, s string) *policy.Compiled {
	t.Helper()
	c, err := policy.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEnforceRespondsAndRecords(t *testing.T) {
	t.Parallel()

	events := &memEvents{}
	d := New(events, forwarded.NewResolver(nil))
	d.Swap(mustCompile(t, policyJSON("v1", trapJSON("env-file", "/.env", "enforce", "low", "DB_HOST=db"))))

	r := httptest.NewRequest(http.MethodGet, "//.env?x=1", nil)
	r.RemoteAddr = "203.0.113.7:5555"
	r.Header.Set("User-Agent", "scanner/1.0")
	rec := httptest.NewRecorder()
	if !d.Inspect(rec, r) {
		t.Fatal("ловушка не ответила")
	}
	if rec.Code != 200 || rec.Body.String() != "DB_HOST=db" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("ответ ловушки: %d %q, заголовки %v", rec.Code, rec.Body.String(), rec.Header())
	}

	touches := events.ofType(event.TypeDecoyTouch)
	if len(touches) != 1 {
		t.Fatalf("событий касания %d", len(touches))
	}
	ev := touches[0]
	if ev.Severity != event.SeverityLow || ev.Client.IP != "203.0.113.7" || ev.Request.UserAgent != "scanner/1.0" {
		t.Errorf("событие: %+v, клиент %+v, запрос %+v", ev, ev.Client, ev.Request)
	}
	want := map[string]string{"decoy_id": "env-file", "mode": "enforce", "confidence": "low", "policy_version": "v1"}
	for k, v := range want {
		if ev.Data[k] != v {
			t.Errorf("data[%s] = %q, ожидалось %q", k, ev.Data[k], v)
		}
	}
	if d.Stats.Enforced.Load() != 1 {
		t.Errorf("счётчик касаний %d", d.Stats.Enforced.Load())
	}
}

// TestObserveRecordsOnly: в режиме наблюдения касание записано, а запрос
// идёт в приложение — ловушка ничего не отвечает.
func TestObserveRecordsOnly(t *testing.T) {
	t.Parallel()

	events := &memEvents{}
	d := New(events, forwarded.NewResolver(nil))
	d.Swap(mustCompile(t, policyJSON("v1", trapJSON("new-rule", "/admin/backup", "observe", "high", "x"))))

	rec := httptest.NewRecorder()
	if d.Inspect(rec, httptest.NewRequest(http.MethodGet, "/admin/backup", nil)) {
		t.Fatal("ловушка в режиме наблюдения ответила сама")
	}
	if rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "" {
		t.Errorf("в режиме наблюдения что-то записано в ответ: %v", rec.Header())
	}
	touches := events.ofType(event.TypeDecoyTouch)
	if len(touches) != 1 || touches[0].Data["mode"] != "observe" || touches[0].Severity != event.SeverityHigh {
		t.Errorf("событие касания: %+v", touches)
	}
	if d.Stats.Observed.Load() != 1 || d.Stats.Enforced.Load() != 0 {
		t.Error("счётчики режимов перепутаны")
	}
}

func TestNoMatchPassesThrough(t *testing.T) {
	t.Parallel()

	events := &memEvents{}
	d := New(events, forwarded.NewResolver(nil))
	d.Swap(mustCompile(t, policyJSON("v1", trapJSON("env-file", "/.env", "enforce", "low", "x"))))

	for _, p := range []string{"/", "/products", "/.env.example"} {
		if d.Inspect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, p, nil)) {
			t.Errorf("путь %s перехвачен", p)
		}
	}
	if len(events.ofType(event.TypeDecoyTouch)) != 0 {
		t.Error("событие касания без касания")
	}
}

// TestSeverityNeverCritical: critical — только для событий о состоянии
// сенсора; касание, даже очень уверенное, — не выше high.
func TestSeverityNeverCritical(t *testing.T) {
	t.Parallel()

	for c, want := range map[policy.Confidence]event.Severity{
		policy.Low: event.SeverityLow, policy.Medium: event.SeverityMedium,
		policy.High: event.SeverityHigh, policy.VeryHigh: event.SeverityHigh,
	} {
		if got := severity(c); got != want {
			t.Errorf("%s → %s, ожидалось %s", c, got, want)
		}
	}
}

// --- загрузка ---------------------------------------------------------------

type loaderHarness struct {
	dir, file, cache string
	detector         *Detector
	events           *memEvents
	logs             *bytes.Buffer
	loader           *Loader
}

func newLoader(t *testing.T) *loaderHarness {
	t.Helper()
	h := &loaderHarness{dir: t.TempDir(), events: &memEvents{}, logs: &bytes.Buffer{}}
	h.file = filepath.Join(h.dir, "policy.json")
	h.cache = filepath.Join(h.dir, "policy.last-valid.json")
	h.detector = New(h.events, forwarded.NewResolver(nil))
	h.loader = NewLoader(h.file, h.cache, h.detector, h.events, slog.New(slog.NewJSONHandler(h.logs, nil)))
	return h
}

func (h *loaderHarness) write(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(h.file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoaderStartupAndReload(t *testing.T) {
	t.Parallel()

	h := newLoader(t)
	h.write(t, policyJSON("v1", trapJSON("env-file", "/.env", "enforce", "low", "x")))
	h.loader.Startup()
	if h.detector.Current().Version != "v1" {
		t.Fatalf("при запуске применена %q", h.detector.Current().Version)
	}
	if cached, _ := os.ReadFile(h.cache); !strings.Contains(string(cached), `"v1"`) {
		t.Error("копия последней валидной не сохранена")
	}

	// Администратор ошибся при правке — перезагрузка не применяет её,
	// сенсор остаётся на v1, событие о отказе с текстом ошибки.
	h.write(t, policyJSON("v2", trapJSON("root", "/", "enforce", "low", "x")))
	h.loader.Reload()
	if v := h.detector.Current().Version; v != "v1" {
		t.Errorf("после неверной политики применена %q, ожидалась прежняя v1", v)
	}
	rej := h.events.ofType(event.TypePolicyRejected)
	if len(rej) != 1 || rej[0].Data["kept_version"] != "v1" || !strings.Contains(rej[0].Data["error"], "traps[0].path") {
		t.Errorf("событие об отказе: %+v", rej)
	}
	if cached, _ := os.ReadFile(h.cache); !strings.Contains(string(cached), `"v1"`) {
		t.Error("неверная политика попала в копию последней валидной")
	}

	// Исправил — применяется.
	h.write(t, policyJSON("v3", trapJSON("git", "/.git/config", "enforce", "low", "x")))
	h.loader.Reload()
	if v := h.detector.Current().Version; v != "v3" {
		t.Errorf("исправленная политика не применена: %q", v)
	}
	loaded := h.events.ofType(event.TypePolicyLoaded)
	if len(loaded) != 2 || loaded[1].Data["version"] != "v3" || loaded[1].Data["source"] != "file" {
		t.Errorf("события о применении: %+v", loaded)
	}
	if h.loader.Stats.Loaded.Load() != 2 || h.loader.Stats.Rejected.Load() != 1 {
		t.Errorf("счётчики: применено %d, отказано %d", h.loader.Stats.Loaded.Load(), h.loader.Stats.Rejected.Load())
	}
}

// TestStartupFallsBackToLastValid: сенсор перезапустился, а файл
// администратора сломан — ловушки не пропадают, работает копия.
func TestStartupFallsBackToLastValid(t *testing.T) {
	t.Parallel()

	h := newLoader(t)
	h.write(t, policyJSON("v1", trapJSON("env-file", "/.env", "enforce", "low", "x")))
	h.loader.Startup()

	h.write(t, `{"schema_version":1,`) // обрыв при правке
	restarted := newLoader(t)
	restarted.file, restarted.cache = h.file, h.cache
	restarted.loader = NewLoader(h.file, h.cache, restarted.detector, restarted.events,
		slog.New(slog.NewJSONHandler(restarted.logs, nil)))
	restarted.loader.Startup()

	if v := restarted.detector.Current().Version; v != "v1" {
		t.Errorf("после перезапуска со сломанным файлом применена %q, ожидалась копия v1", v)
	}
	loaded := restarted.events.ofType(event.TypePolicyLoaded)
	if len(loaded) != 1 || loaded[0].Data["source"] != "last_valid" {
		t.Errorf("события о применении: %+v", loaded)
	}
}

// TestStartupWithoutAnything: нет ни файла, ни копии — сенсор работает
// без ловушек, но не падает: сайт клиента важнее.
func TestStartupWithoutAnything(t *testing.T) {
	t.Parallel()

	h := newLoader(t)
	h.loader.Startup()
	if h.detector.Current().Len() != 0 {
		t.Error("ловушки появились из ниоткуда")
	}
	if !strings.Contains(h.logs.String(), "без ловушек") {
		t.Errorf("в логе нет предупреждения: %s", h.logs.String())
	}
}

// TestCorruptedCacheRejected: испорченная копия проверяется так же строго,
// как файл администратора, и не применяется.
func TestCorruptedCacheRejected(t *testing.T) {
	t.Parallel()

	h := newLoader(t)
	if err := os.WriteFile(h.cache, []byte(policyJSON("evil", trapJSON("root", "/", "enforce", "low", "x"))), 0o600); err != nil {
		t.Fatal(err)
	}
	h.loader.Startup()
	if h.detector.Current().Len() != 0 {
		t.Error("применена неверная копия политики")
	}
	if !strings.Contains(h.logs.String(), "копия последней валидной политики тоже неверна") {
		t.Errorf("в логе нет сообщения: %s", h.logs.String())
	}
}
