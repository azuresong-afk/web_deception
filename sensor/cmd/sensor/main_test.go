package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
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
		t.Fatalf("не удалось прочитать тело ответа %s: %v", url, err)
	}
	return resp.StatusCode, string(body)
}

// TestRunServesAndShutsDownGracefully — единственный тест, который поднимает
// сенсор целиком: настоящий слушатель, настоящие сетевые запросы, настоящая
// остановка по отмене контекста.
func TestRunServesAndShutsDownGracefully(t *testing.T) {
	cfg := &config.Config{
		// Порт 0 означает «любой свободный». Фиксированный порт в тесте
		// сделал бы его нестабильным: порт может быть занят на машине
		// разработчика или другим тестом в CI.
		AdminAddr:       "127.0.0.1:0",
		ShutdownTimeout: 5 * time.Second,
		LogLevel:        slog.LevelError,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addrCh := make(chan net.Addr, 1)
	runErr := make(chan error, 1)

	go func() {
		runErr <- run(ctx, cfg, silentLogger(), func(a net.Addr) { addrCh <- a })
	}()

	var addr net.Addr
	select {
	case addr = <-addrCh:
	case err := <-runErr:
		t.Fatalf("сенсор завершился, не начав слушать: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("сенсор не открыл слушатель за 10 секунд")
	}

	base := "http://" + addr.String()

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

	// После остановки слушатель должен быть закрыт. Если сенсор продолжает
	// отвечать, значит Shutdown не отработал, и при обновлении в проде
	// останутся висеть два процесса на одном порту.
	client := &http.Client{Timeout: 2 * time.Second}
	if resp, err := client.Get(base + "/healthz"); err == nil {
		_ = resp.Body.Close()
		t.Error("сенсор отвечает после остановки: слушатель не закрыт")
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

	cfg := &config.Config{
		AdminAddr:       busy.Addr().String(),
		ShutdownTimeout: time.Second,
		LogLevel:        slog.LevelError,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := run(ctx, cfg, silentLogger(), nil); err == nil {
		t.Fatal("ожидалась ошибка при занятом порте, получен nil")
	}
}
