package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/azuresong-afk/web_deception/sensor/internal/config"
)

// silentLogger отправляет логи в никуда: вывод тестов должен содержать
// результаты тестов, а не журнал сенсора.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// httpGet выполняет запрос с жёстким таймаутом. Без таймаута упавший тест
// не падает, а висит — и CI умирает по общему лимиту времени, не сказав,
// что именно сломалось.
func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("запрос %s не удался: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// Это ошибка чтения (ввода-вывода), содержимого тела в ней нет. Общего
		// исключения для ошибок в правиле нет намеренно: ошибки разбора включают
		// входные данные — см. тест правила go-no-sensitive-http-logging.
		// nosemgrep: go-no-sensitive-http-logging
		t.Fatalf("не удалось прочитать тело ответа %s: %v", url, err)
	}
	return resp.StatusCode, string(body)
}

// testConfig — конфигурация для тестов: оба слушателя на порту 0.
//
// Порт 0 означает «любой свободный». Фиксированный порт в тесте сделал бы
// его нестабильным: порт может быть занят на машине разработчика или другим
// тестом в CI.
func testConfig(t *testing.T, upstream string) *config.Config {
	t.Helper()

	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatalf("адрес приложения для теста: %v", err)
	}
	return &config.Config{
		ListenAddr:      "127.0.0.1:0",
		Upstream:        u,
		MaxConns:        64,
		AdminAddr:       "127.0.0.1:0",
		ShutdownTimeout: 5 * time.Second,
		LogLevel:        slog.LevelError,
		// Свой файл событий у каждого теста: тесты идут параллельно
		// и не должны писать в один файл.
		EventsFile: filepath.Join(t.TempDir(), "events.jsonl"),
	}
}

// startSensor запускает сенсор в горутине и возвращает адреса слушателей
// и канал с результатом run.
func startSensor(ctx context.Context, t *testing.T, cfg *config.Config) (listenAddrs, <-chan error) {
	t.Helper()

	addrCh := make(chan listenAddrs, 1)
	runErr := make(chan error, 1)
	go func() {
		runErr <- run(ctx, cfg, silentLogger(), func(a listenAddrs) { addrCh <- a })
	}()

	select {
	case a := <-addrCh:
		return a, runErr
	case err := <-runErr:
		t.Fatalf("сенсор завершился, не начав слушать: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("сенсор не открыл слушатели за 10 секунд")
	}
	return listenAddrs{}, nil
}

// TestRunServesAndShutsDownGracefully — единственный тест, который поднимает
// сенсор целиком: настоящие слушатели, настоящие сетевые запросы через
// сенсор в приложение, настоящая остановка по отмене контекста.
func TestRunServesAndShutsDownGracefully(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ответ приложения на "+r.URL.Path)
	}))
	defer app.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrs, runErr := startSensor(ctx, t, testConfig(t, app.URL))
	base := "http://" + addrs.Admin.String()

	// Запрос через клиентский слушатель доходит до приложения, и его ответ
	// возвращается клиенту без изменений.
	if code, body := httpGet(t, "http://"+addrs.Proxy.String()+"/catalog"); code != http.StatusOK || body != "ответ приложения на /catalog" {
		t.Errorf("запрос через сенсор вернул %d %q, ожидался ответ приложения", code, body)
	}

	if code, body := httpGet(t, base+"/healthz"); code != http.StatusOK || body != "ok\n" {
		t.Errorf("/healthz на живом сенсоре вернул %d %q, ожидалось 200 \"ok\\n\"", code, body)
	}

	// Готовность выставляется до того, как сенсор сообщает адрес,
	// поэтому здесь она уже должна быть true.
	if code, body := httpGet(t, base+"/readyz"); code != http.StatusOK || body != "ready\n" {
		t.Errorf("/readyz на запущенном сенсоре вернул %d %q, ожидалось 200 \"ready\\n\"", code, body)
	}

	// Отмена контекста имитирует SIGTERM от docker stop или Kubernetes.
	cancel()

	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("штатная остановка вернула ошибку: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("сенсор не завершился за 15 секунд после сигнала остановки")
	}

	// После остановки оба слушателя должны быть закрыты. Если сенсор
	// продолжает отвечать, значит Shutdown не отработал, и при обновлении
	// в проде останутся висеть два процесса на одном порту.
	client := &http.Client{Timeout: 2 * time.Second}
	for _, u := range []string{base + "/healthz", "http://" + addrs.Proxy.String() + "/"} {
		if resp, err := client.Get(u); err == nil {
			_ = resp.Body.Close()
			t.Errorf("сенсор отвечает на %s после остановки: слушатель не закрыт", u)
		}
	}
}

// TestRunRecordsEventsAndMetrics — путь события целиком: запуск записан,
// попытка CONNECT записана и посчитана в /metrics, остановка записана,
// и всё это лежит в файле после остановки.
func TestRunRecordsEventsAndMetrics(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer app.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := testConfig(t, app.URL)
	addrs, runErr := startSensor(ctx, t, cfg)

	conn, err := net.DialTimeout("tcp", addrs.Proxy.String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, "CONNECT 10.0.0.1:22 HTTP/1.1\r\nHost: 10.0.0.1:22\r\n\r\n")
	reply := make([]byte, 64)
	n, _ := conn.Read(reply)
	_ = conn.Close()
	if !strings.Contains(string(reply[:n]), "405") {
		t.Errorf("CONNECT получил %q, ожидался 405", reply[:n])
	}

	code, body := httpGet(t, "http://"+addrs.Admin.String()+"/metrics")
	for _, want := range []string{
		"sensor_connect_rejected_total 1\n",
		"sensor_events_queue_capacity 4096\n",
		"sensor_fail_open 0\n",
		// Запрос CONNECT до обнаружения не доходит: защита стоит раньше.
		"sensor_detection_inspected_total 0\n",
		`sensor_upstream_errors_total{class="upstream_unreachable"} 0` + "\n",
	} {
		if code != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("/metrics (%d) не содержит %q:\n%s", code, want, body)
		}
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("штатная остановка вернула ошибку: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("сенсор не завершился за 15 секунд")
	}

	data, err := os.ReadFile(cfg.EventsFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var types []string
	for _, line := range lines {
		var ev struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("строка файла событий не разбирается как JSON: %q", line)
		}
		types = append(types, ev.Type)
	}
	want := []string{"sensor.started", "request.connect_rejected", "sensor.stopping"}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Errorf("события в файле: %v, ожидались %v", types, want)
	}
}

// TestRunServesTrapsAndReloadsOnHUP — ловушки целиком: сенсор с политикой
// отвечает на /.env вместо приложения и записывает касание; по SIGHUP
// перечитывает политику; неверную не применяет и продолжает работать.
func TestRunServesTrapsAndReloadsOnHUP(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ответ приложения")
	}))
	defer app.Close()

	cfg := testConfig(t, app.URL)
	dir := t.TempDir()
	cfg.PolicyFile = filepath.Join(dir, "policy.json")
	cfg.PolicyCacheFile = filepath.Join(dir, "policy.last-valid.json")
	writePolicy := func(version, body string) {
		t.Helper()
		p := `{"schema_version":1,"version":"` + version + `","traps":[{"id":"env-file","path":"/.env",` +
			`"mode":"enforce","confidence":"low","response":{"status":200,"content_type":"text/plain","body":"` + body + `"}}]}`
		if err := os.WriteFile(cfg.PolicyFile, []byte(p), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writePolicy("v1", "DB_HOST=first")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs, runErr := startSensor(ctx, t, cfg)
	base := "http://" + addrs.Proxy.String()

	if code, body := httpGet(t, base+"/.env"); code != http.StatusOK || body != "DB_HOST=first" {
		t.Errorf("ловушка: %d %q", code, body)
	}
	if _, body := httpGet(t, base+"/catalog"); body != "ответ приложения" {
		t.Errorf("обычный запрос не дошёл до приложения: %q", body)
	}

	// Новая политика — по сигналу, как `docker compose kill -s HUP`.
	reload := func(want string) {
		t.Helper()
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, body := httpGet(t, base+"/.env"); body == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("после SIGHUP ловушка не отвечает %q", want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	writePolicy("v2", "DB_HOST=second")
	reload("DB_HOST=second")

	// Сломанная политика: остаётся v2, сенсор жив. Тело ловушки при этом
	// не меняется, поэтому ждём не его, а отказ в /metrics — иначе тест
	// проверял бы раньше, чем сенсор обработал сигнал.
	if err := os.WriteFile(cfg.PolicyFile, []byte(`{"schema_version":1,`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	var metricsBody string
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(metricsBody, `sensor_policy_loads_total{result="rejected"} 1`) {
		if time.Now().After(deadline) {
			t.Fatalf("отказ сломанной политики не виден в /metrics:\n%s", metricsBody)
		}
		time.Sleep(20 * time.Millisecond)
		_, metricsBody = httpGet(t, "http://"+addrs.Admin.String()+"/metrics")
	}
	if _, body := httpGet(t, base+"/.env"); body != "DB_HOST=second" {
		t.Errorf("после сломанной политики ловушка отвечает %q, ожидалась прежняя v2", body)
	}
	for _, want := range []string{`sensor_decoy_touches_total{mode="enforce"}`, "sensor_policy_traps 1\n"} {
		if !strings.Contains(metricsBody, want) {
			t.Errorf("в /metrics нет %q", want)
		}
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("остановка: %v", err)
	}

	data, err := os.ReadFile(cfg.EventsFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"type":"decoy.touch"`, `"decoy_id":"env-file"`, `"type":"sensor.policy_rejected"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("в файле событий нет %s", want)
		}
	}
}

// TestRunCrossSiteTraps — ловушки, устойчивые к межсайтовым срабатываниям,
// через настоящий прокси. Приложение одобряет CORS для любого сайта
// и ставит свою cookie, как Juice Shop: сенсор должен не дать одобрить
// preflight к ловушке и не потерять ни свою наживку, ни cookie приложения.
func TestRunCrossSiteTraps(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "content-type")
		w.Header().Add("Set-Cookie", "session=app-session; Path=/")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = io.WriteString(w, "ответ приложения")
	}))
	defer app.Close()

	cfg := testConfig(t, app.URL)
	dir := t.TempDir()
	cfg.PolicyFile = filepath.Join(dir, "policy.json")
	cfg.PolicyCacheFile = filepath.Join(dir, "policy.last-valid.json")
	policy := `{"schema_version":1,"version":"v1","traps":[{"id":"api-export","path":"/api/internal/export",` +
		`"mode":"enforce","confidence":"high","methods":["POST"],"preflight_only":true,` +
		`"response":{"status":200,"content_type":"application/json","body":"{\"job\":1}"}}],` +
		`"cookie_traps":[{"id":"role-cookie","name":"user_role","value":"customer","confidence":"high"}]}`
	if err := os.WriteFile(cfg.PolicyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs, runErr := startSensor(ctx, t, cfg)
	base := "http://" + addrs.Proxy.String()

	// reply — то, что получил клиент.
	type reply struct {
		code   int
		header http.Header
		body   string
	}
	do := func(method, path string, headers ...string) reply {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, method, base+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		// Текст ошибки не выводим: он получен из тела ответа, а данные
		// тела в выводе запрещены (правило Semgrep, угроза T4).
		if readErr != nil || closeErr != nil {
			t.Fatalf("%s %s: ответ не прочитан", method, path)
		}
		return reply{resp.StatusCode, resp.Header, string(body)}
	}

	// Переход по странице: наживка и cookie приложения — обе.
	cookies := strings.Join(do(http.MethodGet, "/", "Sec-Fetch-Mode", "navigate").header.Values("Set-Cookie"), "|")
	if !strings.Contains(cookies, "user_role=customer; Path=/; HttpOnly; SameSite=Strict") ||
		!strings.Contains(cookies, "session=app-session") {
		t.Errorf("Set-Cookie после прокси: %q", cookies)
	}

	// Preflight с чужого сайта: приложение одобрило бы, сенсор — нет.
	pre := do(http.MethodOptions, "/api/internal/export",
		"Origin", "https://evil.example", "Access-Control-Request-Method", "POST")
	if pre.code != http.StatusNoContent || pre.header.Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("preflight к ловушке одобрен: %d %v", pre.code, pre.header)
	}

	// Форму может отправить чужая страница — не касание, ответ приложения.
	if r := do(http.MethodPost, "/api/internal/export", "Content-Type", "application/x-www-form-urlencoded"); r.body != "ответ приложения" {
		t.Errorf("POST формы: %q", r.body)
	}
	// JSON — только со своей страницы или не из браузера: ловушка.
	if r := do(http.MethodPost, "/api/internal/export", "Content-Type", "application/json"); r.body != `{"job":1}` {
		t.Errorf("POST JSON: %q", r.body)
	}
	// Изменённая cookie: ответ приложения, касание в событиях.
	if r := do(http.MethodGet, "/account", "Cookie", "user_role=TAMPERED-admin"); r.body != "ответ приложения" {
		t.Errorf("запрос с изменённой cookie: %q", r.body)
	}

	_, metricsBody := httpGet(t, "http://"+addrs.Admin.String()+"/metrics")
	for _, want := range []string{
		"sensor_cookie_touches_total 1\n", "sensor_cookie_baits_total 1\n",
		"sensor_preflights_refused_total 1\n", `sensor_decoy_touches_total{mode="enforce"} 1` + "\n",
		"sensor_policy_traps 2\n",
	} {
		if !strings.Contains(metricsBody, want) {
			t.Errorf("в /metrics нет %q", want)
		}
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("остановка: %v", err)
	}
	data, err := os.ReadFile(cfg.EventsFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"decoy_id":"api-export"`, `"decoy_id":"role-cookie"`, `"decoy_kind":"cookie"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("в файле событий нет %s", want)
		}
	}
	if strings.Contains(string(data), "TAMPERED") {
		t.Error("значение cookie попало в файл событий")
	}
}

// TestRunLures — наживки через настоящий прокси. Приложение сжимает
// robots.txt, если ему разрешено: сенсор должен попросить его без сжатия,
// дописать строку-наживку и привести к ловушке с записью цепочки.
func TestRunLures(t *testing.T) {
	var robotsEncoding atomic.Value
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/robots.txt" {
			_, _ = io.WriteString(w, "ответ приложения")
			return
		}
		robotsEncoding.Store(r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = io.WriteString(w, "\x1f\x8b сжатое")
			return
		}
		_, _ = io.WriteString(w, "User-agent: *\nDisallow: /ftp")
	}))
	defer app.Close()

	cfg := testConfig(t, app.URL)
	dir := t.TempDir()
	cfg.PolicyFile = filepath.Join(dir, "policy.json")
	cfg.PolicyCacheFile = filepath.Join(dir, "policy.last-valid.json")
	policy := `{"schema_version":1,"version":"v1","traps":[` +
		`{"id":"old-admin","path":"/backup-admin","mode":"enforce","confidence":"medium",` +
		`"response":{"status":401,"content_type":"text/plain","body":"auth required"}},` +
		`{"id":"debug-trace","path":"/internal/debug/trace","mode":"enforce","confidence":"medium",` +
		`"response":{"status":403,"content_type":"text/plain","body":"forbidden"}}],` +
		`"lures":[{"id":"robots-admin","kind":"robots_txt","trap":"old-admin"},` +
		`{"id":"debug-header","kind":"header","header":"X-Debug-Trace","trap":"debug-trace"}]}`
	if err := os.WriteFile(cfg.PolicyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs, runErr := startSensor(ctx, t, cfg)
	base := "http://" + addrs.Proxy.String()

	get := func(path string, headers ...string) (int, http.Header, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		// Транспорт без собственной распаковки: проверяем то, что пришло.
		resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("GET %s: ответ не прочитан", path)
		}
		return resp.StatusCode, resp.Header, string(body)
	}

	// Заголовок-наживка — на ответе приложения.
	if _, h, body := get("/"); h.Get("X-Debug-Trace") != "/internal/debug/trace" || body != "ответ приложения" {
		t.Errorf("заголовок-наживка: %q, тело %q", h.Get("X-Debug-Trace"), body)
	}

	// robots.txt: клиент разрешил gzip, но приложение получило запрос
	// без сжатия, и строка-наживка дописана.
	code, h, body := get("/robots.txt", "Accept-Encoding", "gzip, br")
	if code != http.StatusOK || body != "User-agent: *\nDisallow: /ftp\n\nUser-agent: *\nDisallow: /backup-admin\n" ||
		h.Get("Content-Encoding") != "" {
		t.Errorf("robots.txt: %d %q %v", code, body, h)
	}
	if got, _ := robotsEncoding.Load().(string); got != "identity" {
		t.Errorf("приложение получило Accept-Encoding %q", got)
	}

	// Атакующий идёт по наживке — касание с цепочкой.
	if code, _, _ := get("/backup-admin"); code != http.StatusUnauthorized {
		t.Errorf("ловушка из robots.txt: %d", code)
	}

	// Заголовок — на двух ответах приложения: странице и robots.txt.
	// Ответ ловушки даёт сенсор, а не приложение, — он наживку не несёт.
	_, metricsBody := httpGet(t, "http://"+addrs.Admin.String()+"/metrics")
	for _, want := range []string{`sensor_lures_total{kind="robots_txt"} 1` + "\n", `sensor_lures_total{kind="header"} 2` + "\n"} {
		if !strings.Contains(metricsBody, want) {
			t.Errorf("в /metrics нет %q", want)
		}
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("остановка: %v", err)
	}
	data, err := os.ReadFile(cfg.EventsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"decoy_id":"old-admin"`) || !strings.Contains(string(data), `"lure_id":"robots-admin"`) {
		t.Error("в событиях нет касания с цепочкой robots-admin → old-admin")
	}
}

// TestRunHTMLLures — наживки в HTML через настоящий прокси. Приложение
// сжимает страницу, если ему разрешено: переход по странице должен получить
// страницу с наживками без сжатия, а запрос из скрипта — ответ приложения
// как есть.
func TestRunHTMLLures(t *testing.T) {
	const page = `<!doctype html><html><head><script>var s = "<body>";</script></head>` +
		`<body class="app"><main>магазин</main></body></html>`
	var lastEncoding atomic.Value
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastEncoding.Store(r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("ETag", `"v1"`)
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = io.WriteString(w, "\x1f\x8b сжатое")
			return
		}
		_, _ = io.WriteString(w, page)
	}))
	defer app.Close()

	cfg := testConfig(t, app.URL)
	dir := t.TempDir()
	cfg.PolicyFile = filepath.Join(dir, "policy.json")
	cfg.PolicyCacheFile = filepath.Join(dir, "policy.last-valid.json")
	policy := `{"schema_version":1,"version":"v1","traps":[` +
		`{"id":"legacy-login","path":"/account/legacy-login","mode":"enforce","confidence":"medium",` +
		`"response":{"status":401,"content_type":"text/plain","body":"x"}},` +
		`{"id":"api-docs","path":"/internal/api/v2/docs","mode":"enforce","confidence":"medium",` +
		`"response":{"status":200,"content_type":"text/plain","body":"x"}}],` +
		`"lures":[{"id":"docs-comment","kind":"html_comment","text":"API v2 documentation moved to {path}","trap":"api-docs"},` +
		`{"id":"legacy-link","kind":"html_link","trap":"legacy-login"}]}`
	if err := os.WriteFile(cfg.PolicyFile, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs, runErr := startSensor(ctx, t, cfg)
	base := "http://" + addrs.Proxy.String()

	get := func(path string, headers ...string) (http.Header, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(headers); i += 2 {
			req.Header.Set(headers[i], headers[i+1])
		}
		resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("GET %s: ответ не прочитан", path)
		}
		return resp.Header, string(body)
	}

	// Браузер открывает страницу: разрешает сжатие, но получает страницу
	// без сжатия и с наживками сразу после <body>.
	h, body := get("/", "Sec-Fetch-Dest", "document", "Accept-Encoding", "gzip, br")
	want := `<!doctype html><html><head><script>var s = "<body>";</script></head><body class="app">` +
		`<!-- API v2 documentation moved to /internal/api/v2/docs -->` +
		`<a href="/account/legacy-login" hidden aria-hidden="true" tabindex="-1" rel="nofollow"></a>` +
		`<main>магазин</main></body></html>`
	if body != want || h.Get("Content-Encoding") != "" || h.Get("Content-Length") != strconv.Itoa(len(want)) ||
		h.Get("Etag") != `W/"v1"` {
		t.Errorf("страница: %q\nзаголовки %v", body, h)
	}
	if got, _ := lastEncoding.Load().(string); got != "identity" {
		t.Errorf("приложение получило Accept-Encoding %q", got)
	}

	// Запрос из скрипта — как есть: сенсор не отключает ему сжатие.
	if h, body := get("/", "Sec-Fetch-Dest", "empty", "Accept-Encoding", "gzip"); h.Get("Content-Encoding") != "gzip" ||
		!strings.Contains(body, "сжатое") {
		t.Errorf("запрос из скрипта изменён: %v", h)
	}

	// Паук идёт по скрытой ссылке — касание с цепочкой.
	get("/account/legacy-login")

	_, metricsBody := httpGet(t, "http://"+addrs.Admin.String()+"/metrics")
	for _, want := range []string{`sensor_lures_total{kind="html"} 1` + "\n", `sensor_lures_skipped_total{reason="html_encoded"} 1` + "\n"} {
		if !strings.Contains(metricsBody, want) {
			t.Errorf("в /metrics нет %q", want)
		}
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("остановка: %v", err)
	}
	data, err := os.ReadFile(cfg.EventsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"lure_id":"legacy-link"`) {
		t.Error("в событиях нет касания по скрытой ссылке")
	}
}

// TestRunFailsWhenEventsFileUnavailable: файл событий открыть нельзя —
// сенсор не стартует и не открывает слушатели.
func TestRunFailsWhenEventsFileUnavailable(t *testing.T) {
	cfg := testConfig(t, "http://127.0.0.1:1")
	cfg.EventsFile = filepath.Join(t.TempDir(), "нет-каталога", "events.jsonl")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	listened := false
	err := run(ctx, cfg, silentLogger(), func(listenAddrs) { listened = true })
	if err == nil || !strings.Contains(err.Error(), "файл событий") {
		t.Errorf("ожидалась ошибка о файле событий, получено %v", err)
	}
	if listened {
		t.Error("сенсор открыл слушатели, не открыв файл событий")
	}
}

// TestRunFailsWhenAddressIsBusy закрепляет поведение «падать сразу и громко».
//
// Противоположный вариант — записать ошибку в лог и продолжить работу —
// даёт процесс, который выглядит живым, но не слушает ничего. Для сенсора
// в чужой инфраструктуре это худший исход: мониторинг зелёный, защиты нет.
func TestRunFailsWhenAddressIsBusy(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("не удалось занять порт для теста: %v", err)
	}
	defer func() { _ = busy.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Занятым может оказаться любой из двух портов — сенсор должен упасть
	// в обоих случаях, а не работать наполовину.
	adminBusy := testConfig(t, "http://127.0.0.1:1")
	adminBusy.AdminAddr = busy.Addr().String()
	if err := run(ctx, adminBusy, silentLogger(), nil); err == nil {
		t.Error("ожидалась ошибка при занятом служебном порте, получен nil")
	}

	proxyBusy := testConfig(t, "http://127.0.0.1:1")
	proxyBusy.ListenAddr = busy.Addr().String()
	if err := run(ctx, proxyBusy, silentLogger(), nil); err == nil {
		t.Error("ожидалась ошибка при занятом клиентском порте, получен nil")
	}
}

// TestHealthcheckCommand проверяет подкоманду так, как её вызывает Docker:
// по адресу из переменной окружения, с кодом выхода 0 или 1.
func TestHealthcheckCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrs, runErr := startSensor(ctx, t, testConfig(t, "http://127.0.0.1:1"))
	addr := addrs.Admin.String()

	env := func(k string) string {
		switch k {
		case "SENSOR_ADMIN_ADDR":
			return addr
		case "SENSOR_UPSTREAM_URL":
			// Контейнер получает те же переменные окружения, что и сам
			// сенсор, поэтому адрес приложения в них есть всегда.
			return "http://app:3000"
		}
		return ""
	}

	if code := runHealthcheck(env, io.Discard); code != 0 {
		t.Errorf("проверка работающего сенсора вернула %d, ожидался 0", code)
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("остановка вернула ошибку: %v", err)
	}

	if code := runHealthcheck(env, io.Discard); code != 1 {
		t.Errorf("проверка остановленного сенсора вернула %d, ожидалась 1", code)
	}
}

// TestHealthcheckNeverReturnsTwo закрепляет требование Docker: код 2
// в проверке здоровья зарезервирован, даже при ошибке конфигурации.
func TestHealthcheckNeverReturnsTwo(t *testing.T) {
	env := func(k string) string {
		if k == "SENSOR_SHUTDOWN_TIMEOUT" {
			return "не-длительность"
		}
		return ""
	}

	if code := runHealthcheck(env, io.Discard); code != 1 {
		t.Errorf("при ошибке конфигурации получен код %d, ожидалась 1", code)
	}
}
