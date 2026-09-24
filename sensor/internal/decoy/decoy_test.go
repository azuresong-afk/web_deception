package decoy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	d.Swap(mustCompile(t, policyJSON("v1", trapJSON("new-rule", "/admin/backup", "observe", "medium", "x"))))

	rec := httptest.NewRecorder()
	if d.Inspect(rec, httptest.NewRequest(http.MethodGet, "/admin/backup", nil)) {
		t.Fatal("ловушка в режиме наблюдения ответила сама")
	}
	if rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "" {
		t.Errorf("в режиме наблюдения что-то записано в ответ: %v", rec.Header())
	}
	touches := events.ofType(event.TypeDecoyTouch)
	if len(touches) != 1 || touches[0].Data["mode"] != "observe" || touches[0].Severity != event.SeverityMedium {
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

// crossSitePolicy — ловушка, которую нельзя вызвать с чужого сайта,
// и cookie-ловушка.
const crossSitePolicy = `{"schema_version":1,"version":"v9","traps":[` +
	`{"id":"api-export","path":"/api/internal/export","mode":"enforce","confidence":"high",` +
	`"methods":["POST"],"preflight_only":true,` +
	`"response":{"status":200,"content_type":"application/json","body":"{\"job\":1}"}},` +
	`{"id":"env-file","path":"/.env","mode":"enforce","confidence":"low",` +
	`"response":{"status":200,"content_type":"text/plain","body":"x"}}],` +
	`"cookie_traps":[{"id":"role-cookie","name":"user_role","value":"customer","confidence":"high"}]}`

func newCrossSite(t *testing.T, trusted ...string) (*Detector, *memEvents) {
	t.Helper()
	var prefixes []netip.Prefix
	for _, p := range trusted {
		prefixes = append(prefixes, netip.MustParsePrefix(p))
	}
	events := &memEvents{}
	d := New(events, forwarded.NewResolver(prefixes))
	d.Swap(mustCompile(t, crossSitePolicy))
	return d, events
}

// TestPreflightOnlyTrap: ловушка с preflight_only срабатывает только
// на запрос, который браузер с чужого сайта без preflight не отправил бы.
// То, что может отправить чужая страница, — не касание (T2).
func TestPreflightOnlyTrap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		method, ct  string
		wantHandled bool
		wantTouch   bool
	}{
		{"GET — не тот метод", http.MethodGet, "", false, false},
		{"POST формы — может отправить чужая страница", http.MethodPost, "application/x-www-form-urlencoded", false, false},
		{"POST text/plain — тоже", http.MethodPost, "text/plain", false, false},
		{"POST JSON — только со своей страницы или не из браузера", http.MethodPost, "application/json", true, true},
		{"DELETE — не в списке методов", http.MethodDelete, "application/json", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, events := newCrossSite(t)
			r := httptest.NewRequest(tt.method, "/api/internal/export", strings.NewReader(`{}`))
			if tt.ct != "" {
				r.Header.Set("Content-Type", tt.ct)
			}
			rec := httptest.NewRecorder()
			if got := d.Inspect(rec, r); got != tt.wantHandled {
				t.Errorf("handled = %v, ожидалось %v", got, tt.wantHandled)
			}
			touches := events.ofType(event.TypeDecoyTouch)
			if (len(touches) == 1) != tt.wantTouch || len(touches) > 1 {
				t.Fatalf("касаний %d, ожидалось касание: %v", len(touches), tt.wantTouch)
			}
			if tt.wantTouch {
				ev := touches[0]
				if ev.Severity != event.SeverityHigh || ev.Data["decoy_kind"] != "path" || ev.Data["decoy_id"] != "api-export" {
					t.Errorf("событие: %+v", ev)
				}
				if rec.Body.String() != `{"job":1}` || rec.Header().Get("Content-Type") != "application/json" {
					t.Errorf("ответ ловушки: %q %v", rec.Body.String(), rec.Header())
				}
			}
		})
	}
}

// TestPreflightRefused: на preflight к ловушке с preflight_only сенсор
// отвечает сам и не одобряет CORS — даже если приложение одобрило бы
// любой сайт. Сам preflight — не касание.
func TestPreflightRefused(t *testing.T) {
	t.Parallel()

	d, events := newCrossSite(t)
	r := httptest.NewRequest(http.MethodOptions, "/api/internal/export", nil)
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "content-type")
	rec := httptest.NewRecorder()
	if !d.Inspect(rec, r) {
		t.Fatal("preflight ушёл в приложение")
	}
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("ответ на preflight: %d %v", rec.Code, rec.Header())
	}
	if n := len(events.ofType(event.TypeDecoyTouch)); n != 0 {
		t.Errorf("preflight записан как касание: %d", n)
	}
	if d.Stats.PreflightsRefused.Load() != 1 {
		t.Error("счётчик отказов preflight")
	}

	// OPTIONS без Access-Control-Request-Method — не preflight: идёт
	// в приложение, как любой другой запрос.
	plain := httptest.NewRequest(http.MethodOptions, "/api/internal/export", nil)
	if d.Inspect(httptest.NewRecorder(), plain) {
		t.Error("обычный OPTIONS перехвачен")
	}
	// Preflight к ловушке без preflight_only — дело приложения.
	env := httptest.NewRequest(http.MethodOptions, "/.env", nil)
	env.Header.Set("Access-Control-Request-Method", "GET")
	rec = httptest.NewRecorder()
	d.Inspect(rec, env)
	if rec.Code == http.StatusNoContent {
		t.Error("preflight к ловушке без preflight_only перехвачен")
	}
}

// TestPreflightObserveMode: в режиме наблюдения сенсор не меняет ответы
// приложения, в том числе на preflight.
func TestPreflightObserveMode(t *testing.T) {
	t.Parallel()

	events := &memEvents{}
	d := New(events, forwarded.NewResolver(nil))
	d.Swap(mustCompile(t, strings.Replace(crossSitePolicy, `"mode":"enforce","confidence":"high"`,
		`"mode":"observe","confidence":"high"`, 1)))
	r := httptest.NewRequest(http.MethodOptions, "/api/internal/export", nil)
	r.Header.Set("Access-Control-Request-Method", "POST")
	if d.Inspect(httptest.NewRecorder(), r) {
		t.Error("в режиме наблюдения сенсор ответил на preflight сам")
	}
}

func navigation(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	return r
}

// TestCookieBait: наживка выдаётся к ответу на переход по странице, если
// у браузера её ещё нет, и только к нему.
func TestCookieBait(t *testing.T) {
	t.Parallel()

	const plain = "user_role=customer; Path=/; HttpOnly; SameSite=Strict"
	withHeaders := func(r *http.Request, kv ...string) *http.Request {
		for i := 0; i < len(kv); i += 2 {
			r.Header.Set(kv[i], kv[i+1])
		}
		return r
	}
	tests := []struct {
		name string
		r    *http.Request
		want string
	}{
		{"переход без cookie", navigation("/"), plain},
		{"старый браузер: Accept с text/html", withHeaders(httptest.NewRequest(http.MethodGet, "/", nil),
			"Accept", "text/html,application/xhtml+xml"), plain},
		{"cookie уже есть", withHeaders(navigation("/"), "Cookie", "user_role=customer"), ""},
		{"картинка", withHeaders(httptest.NewRequest(http.MethodGet, "/logo.png", nil),
			"Sec-Fetch-Mode", "no-cors", "Accept", "text/html"), ""},
		{"fetch из скрипта", withHeaders(httptest.NewRequest(http.MethodGet, "/api/x", nil),
			"Sec-Fetch-Mode", "cors"), ""},
		{"отправка формы", withHeaders(httptest.NewRequest(http.MethodPost, "/login", nil),
			"Sec-Fetch-Mode", "navigate"), ""},
		{"curl без Accept", httptest.NewRequest(http.MethodGet, "/", nil), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			d, events := newCrossSite(t)
			rec := httptest.NewRecorder()
			if d.Inspect(rec, tt.r) {
				t.Fatal("запрос перехвачен")
			}
			got := strings.Join(rec.Header().Values("Set-Cookie"), "|")
			if got != tt.want {
				t.Errorf("Set-Cookie = %q, ожидалось %q", got, tt.want)
			}
			if len(events.ofType(event.TypeDecoyTouch)) != 0 {
				t.Error("касание без изменённой cookie")
			}
		})
	}
}

// TestCookieBaitSecure: по HTTPS — с атрибутом Secure; о HTTPS говорит
// только доверенный прокси, а не клиент.
func TestCookieBaitSecure(t *testing.T) {
	t.Parallel()

	d, _ := newCrossSite(t, "10.0.0.0/8")
	fromProxy := navigation("/")
	fromProxy.RemoteAddr = "10.0.0.5:4000"
	fromProxy.Header.Set("X-Forwarded-For", "203.0.113.7")
	fromProxy.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	d.Inspect(rec, fromProxy)
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "; Secure") {
		t.Errorf("по HTTPS от доверенного прокси: %q", rec.Header().Get("Set-Cookie"))
	}

	fromClient := navigation("/")
	fromClient.RemoteAddr = "203.0.113.7:5555"
	fromClient.Header.Set("X-Forwarded-Proto", "https")
	rec = httptest.NewRecorder()
	d.Inspect(rec, fromClient)
	if strings.Contains(rec.Header().Get("Set-Cookie"), "Secure") {
		t.Errorf("клиент выдал HTTP за HTTPS: %q", rec.Header().Get("Set-Cookie"))
	}
}

// TestCookieTouch: изменённое значение — касание; само значение
// не записывается никуда; наживка заново не выдаётся.
func TestCookieTouch(t *testing.T) {
	t.Parallel()

	d, events := newCrossSite(t)
	r := navigation("/account")
	r.RemoteAddr = "203.0.113.7:5555"
	// Две копии изменённой cookie и чужая cookie рядом.
	r.Header.Set("Cookie", "session=SECRET-SESSION; user_role=admin-SECRET; user_role=root")
	rec := httptest.NewRecorder()
	if d.Inspect(rec, r) {
		t.Fatal("запрос с изменённой cookie перехвачен: ответ должен дать приложение")
	}
	if v := rec.Header().Values("Set-Cookie"); len(v) != 0 {
		t.Errorf("наживка выдана поверх изменённой: %v", v)
	}

	touches := events.ofType(event.TypeDecoyTouch)
	if len(touches) != 1 {
		t.Fatalf("касаний %d, ожидалось одно на ловушку", len(touches))
	}
	ev := touches[0]
	if ev.Severity != event.SeverityHigh || ev.Data["decoy_kind"] != "cookie" || ev.Data["decoy_id"] != "role-cookie" ||
		ev.Data["policy_version"] != "v9" || ev.Client.IP != "203.0.113.7" {
		t.Errorf("событие: %+v", ev)
	}
	if _, ok := ev.Data["mode"]; ok {
		t.Error("у cookie-ловушки нет режима: она никогда не отвечает сама")
	}
	line, _ := json.Marshal(ev)
	for _, secret := range []string{"SECRET", "admin", "root", "session"} {
		if bytes.Contains(line, []byte(secret)) {
			t.Errorf("в событие попало значение cookie %q: %s", secret, line)
		}
	}
	if d.Stats.CookieTouches.Load() != 1 || d.Stats.CookieBaits.Load() != 0 {
		t.Errorf("счётчики: касаний %d, наживок %d", d.Stats.CookieTouches.Load(), d.Stats.CookieBaits.Load())
	}
}

// TestCookieUnchanged: верное значение и отсутствие cookie — не касание;
// недопустимое значение библиотека отбрасывает — тоже не касание.
func TestCookieUnchanged(t *testing.T) {
	t.Parallel()

	for _, cookie := range []string{"user_role=customer", `user_role="customer"`, "other=1", "user_role=a\x7fb"} {
		d, events := newCrossSite(t)
		r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
		r.Header.Set("Cookie", cookie)
		d.Inspect(httptest.NewRecorder(), r)
		if n := len(events.ofType(event.TypeDecoyTouch)); n != 0 {
			t.Errorf("Cookie: %q — касаний %d", cookie, n)
		}
	}
}

// TestTrapResponseHasNoBait: ответ ловушки — от сенсора, наживка
// в него не добавляется.
func TestTrapResponseHasNoBait(t *testing.T) {
	t.Parallel()

	d, _ := newCrossSite(t)
	rec := httptest.NewRecorder()
	if !d.Inspect(rec, navigation("/.env")) {
		t.Fatal("ловушка не ответила")
	}
	if v := rec.Header().Values("Set-Cookie"); len(v) != 0 {
		t.Errorf("в ответе ловушки наживка: %v", v)
	}
}

// TestTouchRecordsLure: касание ловушки, к которой ведёт наживка, говорит,
// какая именно: так видно, что прочитал атакующий.
func TestTouchRecordsLure(t *testing.T) {
	t.Parallel()

	events := &memEvents{}
	d := New(events, forwarded.NewResolver(nil))
	d.Swap(mustCompile(t, `{"schema_version":1,"version":"v1","traps":[`+
		trapJSON("old-admin", "/backup-admin", "enforce", "medium", "x")+`,`+
		trapJSON("env-file", "/.env", "enforce", "low", "x")+`],`+
		`"lures":[{"id":"robots-admin","kind":"robots_txt","trap":"old-admin"}]}`))

	d.Inspect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/backup-admin", nil))
	d.Inspect(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/.env", nil))
	touches := events.ofType(event.TypeDecoyTouch)
	if len(touches) != 2 {
		t.Fatalf("касаний %d", len(touches))
	}
	if touches[0].Data["lure_id"] != "robots-admin" {
		t.Errorf("касание ловушки с наживкой: %v", touches[0].Data)
	}
	if _, ok := touches[1].Data["lure_id"]; ok {
		t.Errorf("у ловушки без наживки есть lure_id: %v", touches[1].Data)
	}
}

// TestTrapResponseCarriesLureHeaders: ответ ловушки несёт те же
// заголовки-наживки, что и ответы приложения, — иначе ловушку выдало бы
// сравнение заголовков (T5).
func TestTrapResponseCarriesLureHeaders(t *testing.T) {
	t.Parallel()

	d := New(&memEvents{}, forwarded.NewResolver(nil))
	d.Swap(mustCompile(t, `{"schema_version":1,"version":"v1","traps":[`+
		trapJSON("debug-trace", "/internal/debug/trace", "enforce", "medium", "x")+`,`+
		trapJSON("env-file", "/.env", "enforce", "low", "x")+`,`+
		`{"id":"api","path":"/api/x","mode":"enforce","confidence":"high","methods":["POST"],"preflight_only":true,`+
		`"response":{"status":200,"content_type":"text/plain","body":"x"}}],`+
		`"lures":[{"id":"debug-header","kind":"header","header":"X-Debug-Trace","trap":"debug-trace"}]}`))

	rec := httptest.NewRecorder()
	d.Inspect(rec, httptest.NewRequest(http.MethodGet, "/.env", nil))
	if rec.Header().Get("X-Debug-Trace") != "/internal/debug/trace" {
		t.Errorf("ответ ловушки без заголовка-наживки: %v", rec.Header())
	}

	pre := httptest.NewRequest(http.MethodOptions, "/api/x", nil)
	pre.Header.Set("Access-Control-Request-Method", "POST")
	rec = httptest.NewRecorder()
	d.Inspect(rec, pre)
	if rec.Code != http.StatusNoContent || rec.Header().Get("X-Debug-Trace") != "/internal/debug/trace" {
		t.Errorf("отказ в preflight без заголовка-наживки: %d %v", rec.Code, rec.Header())
	}
}
