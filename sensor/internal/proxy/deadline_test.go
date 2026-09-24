package proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"
)

// deadlineRecorder — ResponseWriter, который запоминает выставленные сроки.
// http.ResponseController находит методы SetReadDeadline и SetWriteDeadline
// у самого ResponseWriter, поэтому настоящее соединение для проверки
// логики не нужно.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	mu    sync.Mutex
	read  []time.Time
	write []time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.read = append(d.read, t)
	return nil
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.write = append(d.write, t)
	return nil
}

// TestIdleDeadlinesMoveAndReset: перед каждым чтением тела и каждой записью
// ответа срок сдвигается вперёд, а после обработки снимается.
func TestIdleDeadlinesMoveAndReset(t *testing.T) {
	t.Parallel()

	const idle = 30 * time.Second
	h := withIOIdleDeadlines(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 2)
		_, _ = r.Body.Read(buf) // первое чтение
		_, _ = r.Body.Read(buf) // второе чтение
		_, _ = w.Write([]byte("a"))
		_, _ = w.Write([]byte("b"))
	}), idle)

	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("abcd"))
	before := time.Now()
	h.ServeHTTP(rec, req)

	// Два чтения + сброс в конце; две записи + сброс в конце.
	if len(rec.read) != 3 || len(rec.write) != 3 {
		t.Fatalf("сроков чтения %d, записи %d; ожидалось по 3", len(rec.read), len(rec.write))
	}
	for i := range 2 {
		for name, d := range map[string]time.Time{"чтения": rec.read[i], "записи": rec.write[i]} {
			if d.Before(before.Add(idle)) || d.After(time.Now().Add(idle)) {
				t.Errorf("срок %s №%d = %v, ожидалось около now+%s", name, i+1, d, idle)
			}
		}
	}
	if !rec.read[2].IsZero() || !rec.write[2].IsZero() {
		t.Error("после обработки сроки не сняты: они сработают посреди следующего запроса в keep-alive соединении")
	}
}

// TestNoBodyNoReadDeadline: у запроса без тела срок чтения не трогаем —
// только сброс в конце.
func TestNoBodyNoReadDeadline(t *testing.T) {
	t.Parallel()

	h := withIOIdleDeadlines(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), time.Minute)
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	if len(rec.read) != 1 || !rec.read[0].IsZero() {
		t.Errorf("сроки чтения %v, ожидался только сброс", rec.read)
	}
}

// TestKeepAliveSurvivesIdle: пауза между запросами в keep-alive соединении
// дольше idle не обрывает следующий запрос. Сроки простоя относятся
// к передаче тела, а не к паузе между запросами — за неё отвечает
// IdleTimeout сервера.
//
// Второй ответ — без тела (204): его сервер отправляет уже после
// обработчика, не через idleWriter.Write, и оставшийся срок записи
// сработал бы именно на нём. Сейчас такой срок снимает и наш код,
// и сам сервер Go, поэтому тест проверяет поведение целиком,
// а не одну из этих мер.
func TestKeepAliveSurvivesIdle(t *testing.T) {
	t.Parallel()

	const idle = 150 * time.Millisecond
	app := newFakeApp(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = io.WriteString(w, "ok")
	})
	addr := startProxy(t, newHandler(mustURL(t, app.URL), noTrust, discardLogger(), newTransport(), idle), nil)

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1},
	}
	defer client.CloseIdleConnections()

	do := func(method string, body io.Reader) (reused bool) {
		t.Helper()
		trace := &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }}
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace),
			method, "http://"+addr+"/", body)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("%s: код %d", method, resp.StatusCode)
		}
		return reused
	}

	do(http.MethodPost, strings.NewReader("тело"))
	time.Sleep(3 * idle) // больше idle, но меньше IdleTimeout сервера
	if !do(http.MethodGet, nil) {
		t.Fatal("второй запрос пошёл по новому соединению: тест не проверил keep-alive")
	}
}

// TestSlowBodyIsCutOff: клиент прислал начало тела и замолчал. Сенсор
// не ждёт вечно: через idle запрос обрывается с 408, а приложение не
// получает полного тела.
func TestSlowBodyIsCutOff(t *testing.T) {
	t.Parallel()

	const idle = 200 * time.Millisecond
	app := newFakeApp(t, nil)
	addr := startProxy(t, newHandler(mustURL(t, app.URL), noTrust, discardLogger(), newTransport(), idle), nil)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	// Обещаем 10 байт, присылаем 3 и молчим.
	_, _ = io.WriteString(c, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nabc")

	start := time.Now()
	resp, err := readResponse(c)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ответ не получен: %v", err)
	}
	if resp != http.StatusRequestTimeout {
		t.Errorf("код %d, ожидался 408", resp)
	}
	if elapsed > 2*time.Second {
		t.Errorf("обрыв через %s, ожидалось около %s", elapsed, idle)
	}
	// Обработчик приложения вызывается сразу после заголовков, а тело
	// читается потоком. Поэтому приложение могло начать запрос — но полного
	// тела получить не должно: чтение обязано завершиться ошибкой.
	if app.calls.Load() > 0 {
		got := app.lastRequest(t)
		if got.BodyErr == nil || len(got.Body) >= 10 {
			t.Errorf("приложение получило тело %q без ошибки чтения", got.Body)
		}
	}
}

func readResponse(c net.Conn) (int, error) {
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return 0, err
	}
	line, _, _ := bytes.Cut(buf[:n], []byte("\r\n"))
	var code int
	_, err = fmtSscanf(string(line), &code)
	return code, err
}

// fmtSscanf разбирает код из строки статуса "HTTP/1.1 408 Request Timeout".
func fmtSscanf(statusLine string, code *int) (int, error) {
	return fmt.Sscanf(statusLine, "HTTP/1.1 %d", code)
}
