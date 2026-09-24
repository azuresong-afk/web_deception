package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/azuresong-afk/web_deception/sensor/internal/event"
	"github.com/azuresong-afk/web_deception/sensor/internal/failopen"
	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
)

// --- вспомогательное ---------------------------------------------------------

// syncBuffer — буфер для лога, в который безопасно пишут несколько горутин.
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

// seenRequest — что приложение увидело в запросе.
type seenRequest struct {
	Method     string
	RequestURI string
	Host       string
	Header     http.Header
	Body       string
	BodyErr    error
	CL         int64
	TE         []string
}

// fakeApp — приложение для тестов: запоминает последний запрос и отвечает
// заданным обработчиком.
type fakeApp struct {
	*httptest.Server
	mu    sync.Mutex
	last  *seenRequest
	calls atomic.Int32
}

func newFakeApp(t *testing.T, reply http.HandlerFunc) *fakeApp {
	t.Helper()
	app := &fakeApp{}
	app.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, bodyErr := io.ReadAll(r.Body)
		app.mu.Lock()
		app.last = &seenRequest{
			Method: r.Method, RequestURI: r.RequestURI, Host: r.Host,
			Header: r.Header.Clone(), Body: string(body), BodyErr: bodyErr,
			CL: r.ContentLength, TE: r.TransferEncoding,
		}
		app.mu.Unlock()
		app.calls.Add(1)
		if reply != nil {
			reply(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(app.Close)
	return app
}

func (a *fakeApp) lastRequest(t *testing.T) *seenRequest {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.last == nil {
		t.Fatal("запрос до приложения не дошёл")
	}
	return a.last
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// startProxy поднимает клиентский слушатель сенсора так же, как main:
// через NewServer, а не через httptest.Server — иначе тесты не проверили бы
// наши таймауты и пределы.
func startProxy(t *testing.T, h http.Handler, logOut io.Writer) string {
	t.Helper()
	if logOut == nil {
		logOut = io.Discard
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := NewServer(h, slog.New(slog.NewJSONHandler(logOut, nil)))
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// rawRequest отправляет запрос байт в байт, как его написал бы атакующий.
// Обычный клиент Go такие запросы собрать не даст: он сам их «исправит».
func rawRequest(t *testing.T, addr, raw string) (int, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("чтение ответа: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func discardLogger() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

// noTrust — сенсор без доверенных прокси, как по умолчанию.
var noTrust = forwarded.NewResolver(nil)

// memEvents — получатель событий для тестов: складывает их в память.
type memEvents struct {
	mu     sync.Mutex
	events []event.Event
}

func (m *memEvents) Emit(ev event.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
}

func (m *memEvents) all() []event.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]event.Event(nil), m.events...)
}

func testOptions(trust *forwarded.Resolver, logger *slog.Logger) Options {
	events := &memEvents{}
	guard := failopen.NewGuard(failopen.Config{
		Detector: failopen.NoDetector{}, Events: events, Trust: trust, Logger: logger,
	})
	return Options{Trust: trust, Events: events, Guard: guard, Stats: &Stats{}, Logger: logger}
}

// --- прозрачность --------------------------------------------------------------

// TestForwardsTransparently: метод, путь, параметры, тело, заголовки и Host
// доходят до приложения как есть; ответ приложения — до клиента как есть.
func TestForwardsTransparently(t *testing.T) {
	t.Parallel()

	app := newFakeApp(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "app-server")
		w.Header().Add("Set-Cookie", "session=abc; HttpOnly")
		w.Header().Set("X-App", "1")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "создано")
	})
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger())), nil)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"http://"+addr+"/api/orders?id=5&sort=desc", strings.NewReader(`{"qty":2}`))
	req.Host = "shop.example"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom", "значение")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("запрос: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)

	got := app.lastRequest(t)
	if got.Method != http.MethodPost || got.RequestURI != "/api/orders?id=5&sort=desc" {
		t.Errorf("приложение получило %s %s", got.Method, got.RequestURI)
	}
	if got.Body != `{"qty":2}` {
		t.Errorf("тело %q", got.Body)
	}
	// Host — исходный: по нему приложение строит ссылки.
	if got.Host != "shop.example" {
		t.Errorf("Host %q, ожидался исходный shop.example", got.Host)
	}
	if got.Header.Get("X-Custom") != "значение" || got.Header.Get("Content-Type") != "application/json" {
		t.Errorf("заголовки не дошли: %v", got.Header)
	}

	if resp.StatusCode != http.StatusCreated || string(body) != "создано" {
		t.Errorf("клиент получил %d %q", resp.StatusCode, body)
	}
	// Заголовки ответа приложения — включая Server — проходят как есть:
	// сенсор не добавляет своих и не выдаёт себя (угроза T5).
	if resp.Header.Get("Server") != "app-server" || resp.Header.Get("X-App") != "1" ||
		resp.Header.Get("Set-Cookie") != "session=abc; HttpOnly" {
		t.Errorf("заголовки ответа изменены: %v", resp.Header)
	}
	if v := resp.Header.Get("Via"); v != "" {
		t.Errorf("сенсор добавил заголовок Via %q и выдал себя", v)
	}
}

// TestPathIsNotNormalized: сенсор не «чистит» путь. Разбор пути —
// дело приложения; сенсор, меняющий путь, меняет и поведение приложения.
func TestPathIsNotNormalized(t *testing.T) {
	t.Parallel()

	app := newFakeApp(t, nil)
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger())), nil)

	for _, path := range []string{"/a/../b/%2e%2e/c", "//double/slash", "/%2F/encoded"} {
		code, _ := rawRequest(t, addr, "GET "+path+" HTTP/1.1\r\nHost: x\r\n\r\n")
		if code != http.StatusOK {
			t.Fatalf("%s: код %d", path, code)
		}
		if got := app.lastRequest(t).RequestURI; got != path {
			t.Errorf("путь %q дошёл до приложения как %q", path, got)
		}
	}
}

// TestUnparsableQueryParamsDropped закрепляет поведение ReverseProxy:
// параметры, которые Go не может разобрать (с точкой с запятой), до
// приложения не доходят. Иначе сенсор и приложение видели бы в одном
// запросе разные параметры, и приманку можно было бы обойти, спрятав
// параметр от сенсора (ADR-0021).
func TestUnparsableQueryParamsDropped(t *testing.T) {
	t.Parallel()

	app := newFakeApp(t, nil)
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger())), nil)

	code, _ := rawRequest(t, addr, "GET /q?x=1;y=2&z=3 HTTP/1.1\r\nHost: x\r\n\r\n")
	if code != http.StatusOK {
		t.Fatalf("код %d", code)
	}
	if got := app.lastRequest(t).RequestURI; got != "/q?z=3" {
		t.Errorf("приложение получило %q, ожидалось /q?z=3", got)
	}
}

// --- открытый прокси и SSRF (угроза T17) --------------------------------------

// TestUpstreamOnlyFromConfig: ни Host, ни абсолютный адрес в строке запроса
// не заставят сенсор соединиться с кем-то, кроме приложения из конфигурации.
func TestUpstreamOnlyFromConfig(t *testing.T) {
	t.Parallel()

	app := newFakeApp(t, nil)
	// «Внутренний сервис», до которого атакующий хотел бы дотянуться.
	internal := newFakeApp(t, nil)
	internalHost := mustURL(t, internal.URL).Host

	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger())), nil)

	requests := []string{
		"GET /x HTTP/1.1\r\nHost: " + internalHost + "\r\n\r\n",
		"GET http://" + internalHost + "/x HTTP/1.1\r\nHost: " + internalHost + "\r\n\r\n",
		"GET http://" + internalHost + "/x HTTP/1.1\r\nHost: shop.example\r\n\r\n",
	}
	for _, raw := range requests {
		if code, _ := rawRequest(t, addr, raw); code != http.StatusOK {
			t.Errorf("%q: код %d", strings.SplitN(raw, "\r\n", 2)[0], code)
		}
	}

	if n := internal.calls.Load(); n != 0 {
		t.Fatalf("внутренний сервис получил %d запросов через сенсор: сенсор — открытый прокси", n)
	}
	if n := app.calls.Load(); n != int32(len(requests)) {
		t.Errorf("приложение получило %d запросов из %d", n, len(requests))
	}
}

// TestConnectRejected: CONNECT — просьба открыть туннель куда угодно.
func TestConnectRejected(t *testing.T) {
	t.Parallel()

	app := newFakeApp(t, nil)
	internal := newFakeApp(t, nil)
	internalHost := mustURL(t, internal.URL).Host
	opts := testOptions(noTrust, discardLogger())
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), opts), nil)

	code, _ := rawRequest(t, addr, "CONNECT "+internalHost+" HTTP/1.1\r\nHost: "+internalHost+"\r\n"+
		"User-Agent: proxy-checker/1.0\r\n\r\n")
	if code != http.StatusMethodNotAllowed {
		t.Errorf("CONNECT получил %d, ожидался 405", code)
	}
	if app.calls.Load() != 0 || internal.calls.Load() != 0 {
		t.Error("CONNECT дошёл до приложения или внутреннего сервиса")
	}

	// Попытка записана событием: кто, куда просил туннель, чем.
	events := opts.Events.(*memEvents).all()
	if len(events) != 1 {
		t.Fatalf("событий %d, ожидалось 1", len(events))
	}
	ev := events[0]
	if ev.Type != event.TypeConnectRejected || ev.Severity != event.SeverityLow {
		t.Errorf("тип %q, важность %q", ev.Type, ev.Severity)
	}
	if ev.Client == nil || ev.Client.IP != "127.0.0.1" {
		t.Errorf("клиент события: %+v", ev.Client)
	}
	if ev.Request == nil || ev.Request.Method != "CONNECT" || ev.Request.UserAgent != "proxy-checker/1.0" {
		t.Errorf("запрос события: %+v", ev.Request)
	}
	if ev.Data["target"] != internalHost {
		t.Errorf("цель туннеля %q, ожидалась %q", ev.Data["target"], internalHost)
	}
	if opts.Stats.ConnectRejected.Load() != 1 {
		t.Errorf("счётчик CONNECT = %d", opts.Stats.ConnectRejected.Load())
	}
}

// --- заголовки с адресом клиента (угроза T1) ----------------------------------

// TestClientIPHeadersReplaced: заголовки, которыми клиент мог бы выдать себя
// за другой IP или рассказать о «своём» исходном запросе, до приложения
// не доходят; X-Forwarded-For содержит только адрес TCP-соединения.
//
// X-Forwarded-Port, -Prefix, -Ssl и вариант с подчёркиванием добавлены
// на шаге 5: ReverseProxy их не удаляет, и до шага 5 они проходили.
func TestClientIPHeadersReplaced(t *testing.T) {
	t.Parallel()

	app := newFakeApp(t, nil)
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger())), nil)

	spoofed := map[string]string{
		"X-Forwarded-For":     "1.2.3.4",
		"X-Forwarded-Host":    "evil.example",
		"X-Forwarded-Proto":   "https",
		"Forwarded":           "for=1.2.3.4",
		"X-Real-IP":           "1.2.3.4",
		"True-Client-IP":      "1.2.3.4",
		"CF-Connecting-IP":    "1.2.3.4",
		"X-Client-IP":         "1.2.3.4",
		"X-Cluster-Client-IP": "1.2.3.4",
		"X-Forwarded-Port":    "1.2.3.4",
		"X-Forwarded-Prefix":  "/1.2.3.4",
		"X-Forwarded-Ssl":     "1.2.3.4",
		"X_Forwarded_For":     "1.2.3.4",
	}
	var raw strings.Builder
	raw.WriteString("GET / HTTP/1.1\r\nHost: shop.example\r\n")
	for k, v := range spoofed {
		fmt.Fprintf(&raw, "%s: %s\r\n", k, v)
	}
	raw.WriteString("\r\n")

	if code, _ := rawRequest(t, addr, raw.String()); code != http.StatusOK {
		t.Fatalf("код %d", code)
	}
	got := app.lastRequest(t).Header

	for k := range spoofed {
		for _, v := range got.Values(k) {
			if strings.Contains(v, "1.2.3.4") || strings.Contains(v, "evil.example") {
				t.Errorf("подставленное клиентом значение дошло до приложения: %s: %s", k, v)
			}
		}
	}
	if xff := got.Values("X-Forwarded-For"); len(xff) != 1 || xff[0] != "127.0.0.1" {
		t.Errorf("X-Forwarded-For = %v, ожидался только адрес соединения 127.0.0.1", xff)
	}
	if got.Get("X-Forwarded-Host") != "shop.example" || got.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("X-Forwarded-Host/Proto = %q/%q", got.Get("X-Forwarded-Host"), got.Get("X-Forwarded-Proto"))
	}
}

// TestTrustedProxyChain: запрос пришёл от доверенного прокси — его
// утверждения о клиенте проходят, а X-Forwarded-For пересобран: без того,
// что атакующий дописал слева, и с адресом прокси справа.
func TestTrustedProxyChain(t *testing.T) {
	t.Parallel()

	// Тест подключается к сенсору с 127.0.0.1 — он и есть «балансировщик».
	trust := forwarded.NewResolver([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	app := newFakeApp(t, nil)
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(trust, discardLogger())), nil)

	code, _ := rawRequest(t, addr, "GET / HTTP/1.1\r\nHost: app.internal\r\n"+
		"X-Forwarded-For: 1.2.3.4, 203.0.113.7\r\n"+
		"X-Forwarded-Proto: https\r\n"+
		"X-Forwarded-Host: shop.example\r\n"+
		"X-Forwarded-Port: 443\r\n"+
		"X_Forwarded_Proto: http\r\n\r\n")
	if code != http.StatusOK {
		t.Fatalf("код %d", code)
	}
	got := app.lastRequest(t).Header

	want := map[string]string{
		"X-Forwarded-For":   "203.0.113.7, 127.0.0.1",
		"X-Forwarded-Proto": "https",
		"X-Forwarded-Host":  "shop.example",
		"X-Forwarded-Port":  "443",
	}
	for k, v := range want {
		if vals := got.Values(k); len(vals) != 1 || vals[0] != v {
			t.Errorf("%s = %q, ожидалось %q", k, vals, v)
		}
	}
	if vals := got.Values("X_Forwarded_Proto"); len(vals) != 0 {
		t.Errorf("вариант с подчёркиванием дошёл до приложения: %q", vals)
	}
}

// panicDetector падает на каждом запросе.
type panicDetector struct{}

func (panicDetector) Inspect(http.ResponseWriter, *http.Request) bool {
	panic("сбой обнаружения")
}

// TestFailOpenKeepsProtections: обнаружение падает на каждом запросе,
// а сайт работает — запросы доходят до приложения. Защита при этом
// не отключается: CONNECT по-прежнему 405, заголовки клиента по-прежнему
// вычищены. Fail-open отключает обнаружение, но не защиту.
func TestFailOpenKeepsProtections(t *testing.T) {
	t.Parallel()

	opts := testOptions(noTrust, discardLogger())
	opts.Guard = failopen.NewGuard(failopen.Config{
		Detector: panicDetector{}, Events: opts.Events, Trust: noTrust, Logger: discardLogger(),
	})
	app := newFakeApp(t, nil)
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), opts), nil)

	code, body := rawRequest(t, addr, "GET /page HTTP/1.1\r\nHost: x\r\nX-Real-IP: 1.2.3.4\r\n\r\n")
	if code != http.StatusOK || app.calls.Load() != 1 {
		t.Fatalf("при падающем обнаружении: код %d %q, приложение вызвано %d раз", code, body, app.calls.Load())
	}
	if v := app.lastRequest(t).Header.Get("X-Real-Ip"); v != "" {
		t.Errorf("заголовок клиента дошёл до приложения при fail-open: %q", v)
	}
	if code, _ := rawRequest(t, addr, "CONNECT 10.0.0.1:22 HTTP/1.1\r\nHost: 10.0.0.1:22\r\n\r\n"); code != http.StatusMethodNotAllowed {
		t.Errorf("CONNECT при fail-open получил %d, ожидался 405", code)
	}
	if n := opts.Guard.Stats.Panics.Load(); n != 1 {
		t.Errorf("паник %d, ожидалась 1: CONNECT не должен доходить до обнаружения", n)
	}
}

// TestChainBrokenCounted: доверенный прокси прислал X-Forwarded-For,
// который нельзя разобрать, — это ошибка настройки прокси, и она видна
// в счётчике.
func TestChainBrokenCounted(t *testing.T) {
	t.Parallel()

	trust := forwarded.NewResolver([]netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")})
	opts := testOptions(trust, discardLogger())
	app := newFakeApp(t, nil)
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), opts), nil)

	if code, _ := rawRequest(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: unknown\r\n\r\n"); code != http.StatusOK {
		t.Fatalf("код %d", code)
	}
	if n := opts.Stats.ChainBroken.Load(); n != 1 {
		t.Errorf("счётчик оборванных цепочек = %d, ожидалось 1", n)
	}
}

// TestHopByHopHeadersRemoved: заголовки соединения клиент—сенсор не уходят
// в соединение сенсор—приложение. Proxy-Authorization среди них: учётные
// данные для прокси не должны достаться приложению.
func TestHopByHopHeadersRemoved(t *testing.T) {
	t.Parallel()

	app := newFakeApp(t, nil)
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger())), nil)

	code, _ := rawRequest(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n"+
		"Connection: keep-alive, X-Secret-Hop\r\n"+
		"X-Secret-Hop: 1\r\n"+
		"Proxy-Authorization: Basic c2VjcmV0\r\n"+
		"Keep-Alive: timeout=5\r\n\r\n")
	if code != http.StatusOK {
		t.Fatalf("код %d", code)
	}
	got := app.lastRequest(t).Header
	for _, h := range []string{"X-Secret-Hop", "Proxy-Authorization", "Keep-Alive"} {
		if v := got.Get(h); v != "" {
			t.Errorf("hop-by-hop заголовок %s дошёл до приложения: %q", h, v)
		}
	}
}

// --- разбор запроса и request smuggling (угроза T18) -------------------------

// TestAmbiguousFramingIsNormalized: запрос с Content-Length и Transfer-Encoding
// одновременно — классика request smuggling. Сенсор разбирает его сам и
// отправляет приложению заново собранный запрос с одним способом указать
// длину тела. Приложение не может «увидеть» границу запроса иначе, чем сенсор.
func TestAmbiguousFramingIsNormalized(t *testing.T) {
	t.Parallel()

	app := newFakeApp(t, nil)
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger())), nil)

	code, _ := rawRequest(t, addr, "POST /a HTTP/1.1\r\nHost: x\r\n"+
		"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"+
		"3\r\nabc\r\n0\r\n\r\n")
	if code != http.StatusOK {
		t.Fatalf("код %d", code)
	}
	got := app.lastRequest(t)
	if got.Body != "abc" {
		t.Errorf("тело %q, ожидалось abc", got.Body)
	}
	if got.Header.Get("Content-Length") != "" {
		t.Errorf("до приложения дошли оба способа указать длину: Content-Length=%q, TE=%v",
			got.Header.Get("Content-Length"), got.TE)
	}
}

// TestMalformedRequestsRejected: запросы, которые разные серверы понимают
// по-разному, отвергаются самим сервером Go и до приложения не доходят.
func TestMalformedRequestsRejected(t *testing.T) {
	t.Parallel()

	app := newFakeApp(t, nil)
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger())), nil)

	tests := []struct {
		name string
		raw  string
		want int
	}{
		{"два разных Content-Length", "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd", 400},
		{"неизвестный Transfer-Encoding", "POST /a HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, identity\r\n\r\n3\r\nabc\r\n0\r\n\r\n", 501},
		{"пробел в пути", "GET /sp ace HTTP/1.1\r\nHost: x\r\n\r\n", 400},
		{"пробел в имени заголовка", "GET / HTTP/1.1\r\nHost: x\r\nX Bad: 1\r\n\r\n", 400},
		{"нет Host в HTTP/1.1", "GET / HTTP/1.1\r\n\r\n", 400},
		// Первый рубеж против управляющих последовательностей в событиях
		// (T19): ESC в заголовке или пути не доходит даже до сенсора.
		// Второй — экранирование JSON в пакете event.
		{"ESC в заголовке", "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: a\x1b[31mb\r\n\r\n", 400},
		{"ESC в пути", "GET /a\x1b[31m HTTP/1.1\r\nHost: x\r\n\r\n", 400},
	}
	for _, tt := range tests {
		if code, _ := rawRequest(t, addr, tt.raw); code != tt.want {
			t.Errorf("%s: код %d, ожидался %d", tt.name, code, tt.want)
		}
	}
	if n := app.calls.Load(); n != 0 {
		t.Errorf("до приложения дошло %d испорченных запросов", n)
	}
}

// TestOversizedHeadersRejected: заголовки больше MaxHeaderBytes — 431
// от сервера, без обращения к приложению.
func TestOversizedHeadersRejected(t *testing.T) {
	t.Parallel()

	app := newFakeApp(t, nil)
	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger())), nil)

	// Сервер Go добавляет к MaxHeaderBytes запас 4 КиБ на буфер чтения,
	// поэтому превышение должно быть больше: +1 КиБ ещё проходит.
	huge := strings.Repeat("a", MaxHeaderBytes+16<<10)
	code, _ := rawRequest(t, addr, "GET / HTTP/1.1\r\nHost: x\r\nX-Big: "+huge+"\r\n\r\n")
	if code != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("код %d, ожидался 431", code)
	}
	if app.calls.Load() != 0 {
		t.Error("запрос с огромными заголовками дошёл до приложения")
	}
}

// --- ошибки приложения ---------------------------------------------------------

// TestUpstreamDownIsNeutral502: приложение недоступно — клиент получает
// нейтральный 502 без подробностей; в лог не попадают ни адрес запроса,
// ни параметры с возможными токенами.
func TestUpstreamDownIsNeutral502(t *testing.T) {
	t.Parallel()

	// Адрес, на котором гарантированно никто не слушает: открыли и закрыли.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	var logBuf syncBuffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts := testOptions(noTrust, logger)
	addr := startProxy(t, NewHandler(mustURL(t, "http://"+deadAddr), opts), nil)

	code, body := rawRequest(t, addr, "GET /reset/confirm?token=SECRET-TOKEN-123 HTTP/1.1\r\nHost: x\r\n\r\n")
	if code != http.StatusBadGateway || body != "Bad Gateway\n" {
		t.Errorf("получено %d %q, ожидался нейтральный 502", code, body)
	}
	// Отказ посчитан по своему классу — это видно в /metrics.
	if n := opts.Stats.UpstreamErrors[ErrUpstreamUnreachable].Load(); n != 1 {
		t.Errorf("счётчик «приложение недоступно» = %d, ожидалось 1", n)
	}
	if strings.Contains(body, deadAddr) {
		t.Error("ответ клиенту раскрывает адрес приложения")
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "не удалось соединиться с приложением") {
		t.Errorf("в логе нет причины сбоя: %s", logs)
	}
	for _, leak := range []string{"SECRET-TOKEN-123", "/reset/confirm"} {
		if strings.Contains(logs, leak) {
			t.Errorf("в лог попало %q: %s", leak, logs)
		}
	}
}

// TestUpstreamTimeoutIs504: приложение не прислало заголовки ответа вовремя.
func TestUpstreamTimeoutIs504(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	app := newFakeApp(t, func(_ http.ResponseWriter, _ *http.Request) { <-release })
	// Регистрируется после newFakeApp, значит выполнится раньше app.Close
	// (очистка идёт в обратном порядке): иначе Close ждал бы обработчик,
	// который ждёт release, — и тест завис бы.
	t.Cleanup(func() { close(release) })

	tr := newTransport()
	tr.ResponseHeaderTimeout = 100 * time.Millisecond
	addr := startProxy(t, newHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger()), tr, IOIdleTimeout), nil)

	code, body := rawRequest(t, addr, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if code != http.StatusGatewayTimeout || body != "Gateway Timeout\n" {
		t.Errorf("получено %d %q, ожидался 504", code, body)
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		err       error
		wantClass ErrorClass
		want      int
	}{
		{"клиент ушёл", context.Canceled, ErrClientCanceled, http.StatusBadGateway},
		{"срок истёк", context.DeadlineExceeded, ErrUpstreamTimeout, http.StatusGatewayTimeout},
		{"сетевой таймаут", os.ErrDeadlineExceeded, ErrUpstreamTimeout, http.StatusGatewayTimeout},
		{"нет соединения", &net.OpError{Op: "dial", Err: errors.New("refused")}, ErrUpstreamUnreachable, http.StatusBadGateway},
		{"прочее", errors.New("malformed response"), ErrUpstreamOther, http.StatusBadGateway},
	}
	for _, tt := range tests {
		if class, got, _ := classify(tt.err); got != tt.want || class != tt.wantClass {
			t.Errorf("%s: %s %d, ожидался %s %d", tt.name, class, got, tt.wantClass, tt.want)
		}
	}

	// Имена классов — метки метрик: у каждого класса своё непустое имя.
	seen := map[string]bool{}
	for _, c := range ErrorClasses() {
		if c.String() == "" || seen[c.String()] {
			t.Errorf("класс %d: имя %q пустое или повторяется", c, c.String())
		}
		seen[c.String()] = true
	}
}

// --- транспорт -----------------------------------------------------------------

// TestTransportIgnoresEnvironmentProxy: трафик клиента не уходит через
// прокси из HTTP_PROXY, даже если переменная задана в окружении.
func TestTransportIgnoresEnvironmentProxy(t *testing.T) {
	t.Parallel()

	tr := newTransport()
	if tr.Proxy != nil {
		t.Error("у транспорта задан Proxy: трафик может уйти через прокси из окружения")
	}
	if !tr.DisableCompression {
		t.Error("транспорт сам распаковывает ответы — прокси не прозрачен")
	}
	if tr.MaxIdleConnsPerHost < 100 {
		t.Errorf("MaxIdleConnsPerHost = %d: под нагрузкой соединения будут открываться заново", tr.MaxIdleConnsPerHost)
	}
}

// --- WebSocket и потоковые ответы -----------------------------------------------

// TestUpgradePassesThrough: WebSocket и другие Upgrade работают через сенсор.
// Проверяет, что обёртка ResponseWriter не мешает захвату соединения.
func TestUpgradePassesThrough(t *testing.T) {
	t.Parallel()

	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "echo" {
			http.Error(w, "no upgrade", http.StatusBadRequest)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
		_ = brw.Flush()
		line, _ := brw.ReadString('\n')
		_, _ = brw.WriteString("echo: " + line)
		_ = brw.Flush()
	}))
	t.Cleanup(app.Close)

	addr := startProxy(t, NewHandler(mustURL(t, app.URL), testOptions(noTrust, discardLogger())), nil)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")

	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ответ на Upgrade: %v", err)
	}
	// У ответа 101 тела нет, дальнейший обмен идёт через br, а не через Body.
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("код %d, ожидался 101", resp.StatusCode)
	}
	_, _ = io.WriteString(c, "привет\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "echo: привет\n" {
		t.Errorf("эхо через туннель: %q, %v", line, err)
	}
}

// --- буферы --------------------------------------------------------------------

func TestBufferPool(t *testing.T) {
	t.Parallel()

	p := newBufferPool()
	buf := p.Get()
	if len(buf) != copyBufferSize {
		t.Fatalf("размер буфера %d, ожидался %d", len(buf), copyBufferSize)
	}
	p.Put(buf)
	// Чужой буфер другого размера в пул не попадает.
	p.Put(make([]byte, 10))
	if got := len(p.Get()); got != copyBufferSize {
		t.Errorf("из пула выдан буфер размером %d", got)
	}
}
