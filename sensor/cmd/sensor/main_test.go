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
	"strings"
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
