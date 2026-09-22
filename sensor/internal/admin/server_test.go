package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// response — всё, что тестам нужно знать об ответе.
type response struct {
	StatusCode int
	Header     http.Header
}

// call выполняет запрос к обработчику без поднятия настоящего сервера.
//
// Возвращает код, заголовки и прочитанное тело, но не сам *http.Response:
// тело закрывается здесь же, и открытый ответ не выходит за пределы функции.
// Так закрытие видно и читателю, и линтеру bodyclose, а не держится
// на t.Cleanup, который линтер проследить не может.
func call(t *testing.T, ready bool, method, path string) (response, string) {
	t.Helper()

	var flag atomic.Bool
	flag.Store(ready)

	rec := httptest.NewRecorder()
	NewHandler(&flag).ServeHTTP(rec, httptest.NewRequest(method, path, nil))

	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		// Это ошибка чтения (ввода-вывода), содержимого тела в ней нет. Общего
		// исключения для ошибок в правиле нет намеренно: ошибки разбора включают
		// входные данные — см. тест правила go-no-sensitive-http-logging.
		// nosemgrep: go-no-sensitive-http-logging
		t.Fatalf("не удалось прочитать тело ответа: %v", err)
	}
	return response{StatusCode: resp.StatusCode, Header: resp.Header}, string(body)
}

func TestHealthzAnswersEvenWhenNotReady(t *testing.T) {
	t.Parallel()

	// Ключевая проверка различия живости и готовности: сенсор в процессе
	// остановки ещё жив, и перезапускать его не нужно.
	resp, body := call(t, false, http.MethodGet, "/healthz")

	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz вернул %d, ожидался 200 независимо от готовности", resp.StatusCode)
	}
	if body != "ok\n" {
		t.Errorf("тело /healthz = %q, ожидалось \"ok\\n\"", body)
	}
}

func TestReadyzReflectsReadiness(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ready    bool
		wantCode int
		wantBody string
	}{
		{"готов", true, http.StatusOK, "ready\n"},
		{"не готов", false, http.StatusServiceUnavailable, "not ready\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			resp, body := call(t, tt.ready, http.MethodGet, "/readyz")
			if resp.StatusCode != tt.wantCode {
				t.Errorf("/readyz вернул %d, ожидался %d", resp.StatusCode, tt.wantCode)
			}
			if body != tt.wantBody {
				t.Errorf("тело /readyz = %q, ожидалось %q", body, tt.wantBody)
			}
		})
	}
}

func TestOnlyGetIsAllowed(t *testing.T) {
	t.Parallel()

	// Служебные эндпоинты ничего не меняют, поэтому любой метод кроме
	// GET и HEAD — это либо ошибка, либо разведка.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			resp, _ := call(t, true, method, "/healthz")
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("%s /healthz вернул %d, ожидался 405", method, resp.StatusCode)
			}
		})
	}
}

func TestUnknownPathsReturn404(t *testing.T) {
	t.Parallel()

	// Служебный слушатель не должен обслуживать ничего сверх объявленного.
	//
	// Случай "/healthz/../etc/passwd" здесь не для красоты: именно он поймал
	// редирект 301 от стандартного маршрутизатора Go и привёл к появлению
	// обёртки onlyKnownPaths. Тест остаётся как защита от возврата
	// этого поведения.
	for _, path := range []string{"/", "/metrics", "/admin", "/healthz/../etc/passwd", "/HEALTHZ", "/healthz/"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			resp, _ := call(t, true, http.MethodGet, path)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s вернул %d, ожидался 404", path, resp.StatusCode)
			}
		})
	}
}

func TestResponsesDoNotRevealProduct(t *testing.T) {
	t.Parallel()

	// Прямая проверка меры против угрозы T5: служебный ответ, случайно
	// оказавшийся доступным снаружи, не должен позволять опознать продукт.
	forbidden := []string{"deception", "sensor", "honeypot", "приманк"}

	for _, path := range []string{"/healthz", "/readyz"} {
		resp, body := call(t, true, http.MethodGet, path)

		if got := resp.Header.Get("Server"); got != "" {
			t.Errorf("%s отдаёт заголовок Server: %q — это признак для атакующего", path, got)
		}

		haystack := strings.ToLower(body)
		for k, vs := range resp.Header {
			haystack += " " + strings.ToLower(k) + " " + strings.ToLower(strings.Join(vs, " "))
		}
		for _, word := range forbidden {
			if strings.Contains(haystack, word) {
				t.Errorf("ответ %s содержит %q, по которому продукт можно опознать", path, word)
			}
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()

	resp, _ := call(t, true, http.MethodGet, "/healthz")

	if got := resp.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q, ожидался text/plain; charset=utf-8", got)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, ожидался nosniff", got)
	}
}

func TestNewServerSetsTimeouts(t *testing.T) {
	t.Parallel()

	// Таймаут, равный нулю, означает «ждать вечно». Именно так выглядит
	// http.Server, созданный без явной настройки, и именно этим
	// пользуется Slowloris. Тест закрепляет, что ни один из них не забыт.
	srv := NewServer(http.NewServeMux(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout, ReadHeaderTimeout},
		{"ReadTimeout", srv.ReadTimeout, ReadTimeout},
		{"WriteTimeout", srv.WriteTimeout, WriteTimeout},
		{"IdleTimeout", srv.IdleTimeout, IdleTimeout},
		{"MaxHeaderBytes", srv.MaxHeaderBytes, MaxHeaderBytes},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, ожидалось %v", c.name, c.got, c.want)
		}
	}

	if srv.ErrorLog == nil {
		t.Error("ErrorLog не настроен: ошибки HTTP-сервера уйдут мимо нашего лога")
	}
}
