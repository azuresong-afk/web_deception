package lure

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/azuresong-afk/web_deception/sensor/internal/policy"
)

const testPolicy = `{"schema_version":1,"version":"v1","traps":[
 {"id":"debug-trace","path":"/internal/debug/trace","mode":"enforce","confidence":"medium",
  "response":{"status":403,"content_type":"text/plain","body":"x"}},
 {"id":"old-admin","path":"/backup-admin","mode":"enforce","confidence":"medium",
  "response":{"status":401,"content_type":"text/plain","body":"x"}},
 {"id":"old-api","path":"/api/v0","mode":"enforce","confidence":"medium",
  "response":{"status":404,"content_type":"text/plain","body":"x"}}],
 "lures":[
 {"id":"debug-header","kind":"header","header":"X-Debug-Trace","trap":"debug-trace"},
 {"id":"robots-admin","kind":"robots_txt","trap":"old-admin"},
 {"id":"robots-api","kind":"robots_txt","trap":"old-api"}]}`

// harness — Injector с подменяемой политикой и режимом.
type harness struct {
	inj      *Injector
	degraded atomic.Bool
	panics   []string
}

func newHarness(t *testing.T, policyJSON string) *harness {
	t.Helper()
	c := policy.Empty()
	if policyJSON != "" {
		var err error
		if c, err = policy.Parse([]byte(policyJSON)); err != nil {
			t.Fatal(err)
		}
	}
	h := &harness{}
	h.inj = New(Config{
		Policy:   func() *policy.Compiled { return c },
		Degraded: h.degraded.Load,
		OnPanic:  func(_ *http.Request, _ any, stage string) { h.panics = append(h.panics, stage) },
	})
	return h
}

// appResponse — ответ приложения, который тест отдаёт Injector.
// Описание, а не готовый *http.Response: ответ собирает и закрывает run,
// в одном месте.
type appResponse struct {
	method, path string
	status       int
	header       http.Header
	body         string
	// bodyReader — тело с особым поведением вместо body.
	bodyReader io.ReadCloser
	chunked    bool
	// nilHeader — заголовки — nil-карта: так тест вызывает панику.
	nilHeader bool
	// unknownLength — длина тела неизвестна (ContentLength = -1).
	unknownLength bool
}

// app — ответ приложения на запрос method path.
func app(method, path string, status int, header http.Header, body string) appResponse {
	return appResponse{method: method, path: path, status: status, header: header, body: body}
}

// result — что получит клиент после правки ответа.
type result struct {
	status int
	header http.Header
	body   string
	// length и chunked — длина и способ передачи, которые увидит прокси.
	length  int64
	chunked bool
	err     error
}

// run отдаёт ответ приложения Injector и читает то, что уйдёт клиенту.
// Тело читается и закрывается здесь, в одном месте. Ошибка чтения
// возвращается, а не выводится: она получена из тела ответа (T4).
func run(t *testing.T, h *harness, a appResponse) result {
	t.Helper()
	header := a.header
	if header == nil && !a.nilHeader {
		header = http.Header{}
	}
	rc := a.bodyReader
	if rc == nil {
		rc = io.NopCloser(strings.NewReader(a.body))
	}
	resp := &http.Response{
		StatusCode:    a.status,
		Status:        http.StatusText(a.status),
		Header:        header,
		Body:          rc,
		ContentLength: int64(len(a.body)),
		Request:       httptest.NewRequest(a.method, a.path, nil),
	}
	if a.chunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	if a.unknownLength {
		resp.ContentLength = -1
	}
	if err := h.inj.Modify(resp); err != nil {
		t.Fatal("Modify вернул ошибку: прокси ответил бы 502")
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return result{
		status: resp.StatusCode, header: resp.Header, body: string(body),
		length: resp.ContentLength, chunked: resp.TransferEncoding != nil, err: err,
	}
}

func TestHeaderLure(t *testing.T) {
	t.Parallel()

	h := newHarness(t, testPolicy)
	r := run(t, h, app(http.MethodGet, "/", 200, http.Header{"Content-Type": {"text/html"}}, "<html>"))
	if got := r.header.Get("X-Debug-Trace"); got != "/internal/debug/trace" {
		t.Errorf("X-Debug-Trace = %q", got)
	}
	if r.body != "<html>" {
		t.Error("тело ответа изменилось")
	}

	// Заголовок приложения с тем же именем не трогается.
	own := run(t, h, app(http.MethodGet, "/", 200, http.Header{"X-Debug-Trace": {"app-value"}}, ""))
	if got := own.header.Values("X-Debug-Trace"); len(got) != 1 || got[0] != "app-value" {
		t.Errorf("заголовок приложения изменён: %v", got)
	}
	if h.inj.Stats.Headers.Load() != 1 || h.inj.Stats.Skipped[SkipHeaderExists].Load() != 1 {
		t.Errorf("счётчики: добавлено %d, пропущено %d",
			h.inj.Stats.Headers.Load(), h.inj.Stats.Skipped[SkipHeaderExists].Load())
	}
}

func TestNoLuresNoChanges(t *testing.T) {
	t.Parallel()

	h := newHarness(t, "")
	r := run(t, h, app(http.MethodGet, "/robots.txt", 404, http.Header{"Content-Type": {"text/html"}}, "not found"))
	if r.status != 404 || len(r.header) != 1 || r.body != "not found" {
		t.Errorf("ответ изменён без наживок в политике: %d %v", r.status, r.header)
	}
}

// TestRobotsAppend: к robots.txt приложения — своя группа в конце;
// строки приложения не меняются.
func TestRobotsAppend(t *testing.T) {
	t.Parallel()

	h := newHarness(t, testPolicy)
	resp := app(http.MethodGet, "/robots.txt", 200, http.Header{
		"Content-Type": {"text/plain; charset=utf-8"}, "Etag": {`"abc"`}, "Last-Modified": {"x"},
	}, "User-agent: *\nDisallow: /ftp")
	resp.chunked = true
	r := run(t, h, resp)

	want := "User-agent: *\nDisallow: /ftp\n\nUser-agent: *\nDisallow: /backup-admin\nDisallow: /api/v0\n"
	if r.body != want {
		t.Errorf("robots.txt:\n%q\nожидалось:\n%q", r.body, want)
	}
	if r.length != int64(len(want)) || r.header.Get("Content-Length") != strconv.Itoa(len(want)) || r.chunked {
		t.Errorf("длина: %d, заголовок %q, chunked %v", r.length, r.header.Get("Content-Length"), r.chunked)
	}
	if r.header.Get("Etag") != "" || r.header.Get("Last-Modified") != "x" {
		t.Errorf("валидаторы: %v", r.header)
	}
	if h.inj.Stats.Robots.Load() != 1 {
		t.Error("счётчик robots.txt")
	}
}

// TestRobotsCreatedOn404: robots.txt нет — сенсор отвечает своим,
// заголовки приложения, не описывающие тело, остаются.
func TestRobotsCreatedOn404(t *testing.T) {
	t.Parallel()

	h := newHarness(t, testPolicy)
	r := run(t, h, app(http.MethodGet, "/robots.txt", 404, http.Header{
		"Content-Type": {"text/html; charset=utf-8"}, "Server": {"Werkzeug/2.0.1"}, "Etag": {`"x"`},
	}, "<h1>Not Found</h1>"))

	want := "User-agent: *\nDisallow: /backup-admin\nDisallow: /api/v0\n"
	if r.status != 200 || r.body != want {
		t.Errorf("ответ: %d", r.status)
	}
	if r.header.Get("Content-Type") != "text/plain; charset=utf-8" || r.header.Get("Server") != "Werkzeug/2.0.1" ||
		r.header.Get("Etag") != "" {
		t.Errorf("заголовки: %v", r.header)
	}
}

// TestRobotsLeftAsIs: всё, что сенсор не может или не должен дополнять,
// уходит клиенту без изменений — вплоть до байта.
func TestRobotsLeftAsIs(t *testing.T) {
	t.Parallel()

	big := strings.Repeat("Disallow: /x\n", maxRobotsBytes/13+1)
	tests := []struct {
		name   string
		status int
		header http.Header
		body   string
		reason SkipReason
	}{
		{"5xx — «не заходить никуда»", 503, nil, "down", SkipRobotsStatus},
		{"перенаправление", 301, nil, "", SkipRobotsStatus},
		{"не текст", 200, http.Header{"Content-Type": {"text/html"}}, "<p>", SkipRobotsNotText},
		{"сжат", 200, http.Header{"Content-Type": {"text/plain"}, "Content-Encoding": {"br"}}, "\x0b\x02", SkipRobotsEncoded},
		{"больше предела", 200, http.Header{"Content-Type": {"text/plain"}}, big, SkipRobotsTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, testPolicy)
			r := run(t, h, app(http.MethodGet, "/robots.txt", tt.status, tt.header, tt.body))
			if r.status != tt.status || r.body != tt.body || r.err != nil {
				t.Error("ответ изменён")
			}
			if h.inj.Stats.Skipped[tt.reason].Load() != 1 || h.inj.Stats.Robots.Load() != 0 {
				t.Errorf("причина %s не учтена", tt.reason)
			}
		})
	}

	// Другие пути и методы robots.txt не трогаются вовсе.
	for _, req := range []struct{ method, path string }{
		{http.MethodHead, "/robots.txt"}, {http.MethodGet, "/ROBOTS.TXT"}, {http.MethodGet, "/static/robots.txt"},
	} {
		h := newHarness(t, testPolicy)
		if r := run(t, h, app(req.method, req.path, 404, nil, "nf")); r.status != 404 {
			t.Errorf("%s %s: ответ изменён", req.method, req.path)
		}
	}
}

// failingBody — тело, которое обрывается после части данных. Ошибку
// отдаёт один раз, дальше — чистый конец данных: так ведут себя не все
// тела, но если бы сенсор полагался на повтор ошибки, такое тело дало бы
// клиенту обрезанный robots.txt, похожий на целый.
type failingBody struct {
	io.Reader
	err      error
	reported bool
}

func (f *failingBody) Read(p []byte) (int, error) {
	n, err := f.Reader.Read(p)
	if err == io.EOF && !f.reported {
		f.reported = true
		return n, f.err
	}
	return n, err
}

func (f *failingBody) Close() error { return nil }

// TestRobotsReadError: обрыв тела у приложения доходит до клиента так же,
// как без сенсора: прочитанное и та же ошибка.
func TestRobotsReadError(t *testing.T) {
	t.Parallel()

	h := newHarness(t, testPolicy)
	broken := errors.New("upstream reset")
	resp := app(http.MethodGet, "/robots.txt", 200, http.Header{"Content-Type": {"text/plain"}}, "")
	resp.bodyReader = &failingBody{Reader: strings.NewReader("User-agent: *\n"), err: broken}
	r := run(t, h, resp)
	if r.body != "User-agent: *\n" || !errors.Is(r.err, broken) {
		t.Errorf("клиент получил %q и ошибку того же вида: %v", r.body, errors.Is(r.err, broken))
	}
}

// panicBody — тело, у которого первый Close паникует: так проверяется,
// что паника после чтения тела не теряет ответ. Второй Close — от run,
// когда клиент дочитал ответ.
type panicBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *panicBody) Close() error {
	if !b.closed.Swap(true) {
		panic("close")
	}
	return nil
}

// TestPanicLeavesResponse: паника при правке — ответ уходит как есть,
// паника записана, ошибки для прокси нет.
func TestPanicLeavesResponse(t *testing.T) {
	t.Parallel()

	// Паника до чтения тела: заголовки ответа — nil-карта.
	h := newHarness(t, testPolicy)
	resp := app(http.MethodGet, "/", 200, nil, "page")
	resp.nilHeader = true
	if r := run(t, h, resp); r.body != "page" || len(h.panics) != 1 || h.panics[0] != "lure" {
		t.Errorf("паника до чтения: %v", h.panics)
	}

	// Паника после чтения тела robots.txt: тело собирается обратно.
	h = newHarness(t, testPolicy)
	resp = app(http.MethodGet, "/robots.txt", 200, http.Header{"Content-Type": {"text/plain"}}, "")
	resp.bodyReader = &panicBody{Reader: strings.NewReader("User-agent: *\nDisallow: /ftp\n")}
	if r := run(t, h, resp); r.body != "User-agent: *\nDisallow: /ftp\n" || r.err != nil {
		t.Errorf("после паники клиент получил %q", r.body)
	}
	if h.inj.Stats.Skipped[SkipPanic].Load() != 1 {
		t.Error("паника не учтена")
	}
}

// TestDegraded: при перегрузке обнаружения наживки не ставятся.
func TestDegraded(t *testing.T) {
	t.Parallel()

	h := newHarness(t, testPolicy)
	h.degraded.Store(true)
	if r := run(t, h, app(http.MethodGet, "/robots.txt", 404, nil, "nf")); r.status != 404 || r.header.Get("X-Debug-Trace") != "" {
		t.Error("наживка поставлена в частичном режиме")
	}
	if h.inj.Stats.Skipped[SkipDegraded].Load() != 1 {
		t.Error("пропуск не учтён")
	}
}

// TestPrepare: за robots.txt сенсор просит ответ без сжатия и без условий,
// остальные запросы не трогает.
func TestPrepare(t *testing.T) {
	t.Parallel()

	conditional := func(path string) (*http.Request, *http.Request) {
		in := httptest.NewRequest(http.MethodGet, path, nil)
		out := in.Clone(in.Context())
		for k, v := range map[string]string{
			"Accept-Encoding": "gzip, br", "If-None-Match": `"a"`, "If-Modified-Since": "x", "Range": "bytes=0-1",
		} {
			out.Header.Set(k, v)
		}
		return in, out
	}

	h := newHarness(t, testPolicy)
	in, out := conditional("/robots.txt")
	h.inj.Prepare(in, out)
	if out.Header.Get("Accept-Encoding") != "identity" || out.Header.Get("If-None-Match") != "" ||
		out.Header.Get("If-Modified-Since") != "" || out.Header.Get("Range") != "" {
		t.Errorf("запрос за robots.txt: %v", out.Header)
	}

	in, out = conditional("/")
	h.inj.Prepare(in, out)
	if out.Header.Get("Accept-Encoding") != "gzip, br" || out.Header.Get("If-None-Match") == "" {
		t.Errorf("обычный запрос изменён: %v", out.Header)
	}

	h = newHarness(t, "")
	in, out = conditional("/robots.txt")
	h.inj.Prepare(in, out)
	if out.Header.Get("Accept-Encoding") != "gzip, br" {
		t.Error("запрос изменён без наживок в robots.txt")
	}
}

// FuzzRobotsAppend: при любом robots.txt приложения его содержимое
// остаётся началом ответа, а наша группа — концом.
func FuzzRobotsAppend(f *testing.F) {
	for _, s := range []string{"", "User-agent: *\nDisallow: /ftp", "\n\n", "\xff\xfe", "Sitemap: /s.xml\r\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, original string) {
		h := newHarness(t, testPolicy)
		r := run(t, h, app(http.MethodGet, "/robots.txt", 200, http.Header{"Content-Type": {"text/plain"}}, original))
		if len(original) > maxRobotsBytes {
			return
		}
		if !strings.HasPrefix(r.body, original) || !strings.HasSuffix(r.body, "User-agent: *\nDisallow: /backup-admin\nDisallow: /api/v0\n") {
			t.Errorf("robots.txt %q стал %q", original, r.body)
		}
		if r.length != int64(len(r.body)) {
			t.Errorf("длина %d, тело %d", r.length, len(r.body))
		}
	})
}

// TestNewRequiresConfig: пропущенная зависимость — ошибка при запуске,
// а не на первом ответе.
func TestNewRequiresConfig(t *testing.T) {
	t.Parallel()

	defer func() {
		if recover() == nil {
			t.Error("New без зависимостей не упал")
		}
	}()
	New(Config{})
}

// TestSkipReasonNames: у каждой причины своё имя для метки метрики.
func TestSkipReasonNames(t *testing.T) {
	t.Parallel()

	seen := map[string]bool{}
	for _, r := range SkipReasons() {
		if r.String() == "" || seen[r.String()] {
			t.Errorf("имя причины %d: %q", r, r.String())
		}
		seen[r.String()] = true
	}
}
