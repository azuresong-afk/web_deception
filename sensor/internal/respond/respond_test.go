package respond

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPlain(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	Plain(rec, http.StatusBadGateway, "bad gateway")

	if rec.Code != http.StatusBadGateway {
		t.Errorf("код %d, ожидался 502", rec.Code)
	}
	// Тело сравниваем как байты и в сообщение не выводим: правило Semgrep
	// go-no-sensitive-http-logging считает стоком любой вызов .String()
	// на теле (так оно ловит slog.String), и исключение ради теста
	// ослабило бы правило. Неточность правила записана в roadmap.
	if !bytes.Equal(rec.Body.Bytes(), []byte("bad gateway\n")) {
		t.Error("тело ответа не совпадает с ожидаемым \"bad gateway\\n\"")
	}
	if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options %q, ожидалось nosniff", got)
	}
	// Ответ сенсора не должен выдавать продукт (угроза T5).
	if got := rec.Header().Get("Server"); got != "" {
		t.Errorf("заголовок Server %q, ожидалось отсутствие", got)
	}
}
