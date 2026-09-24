package respond

import (
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
	// Тело в сообщение об ошибке не выводим: правило Semgrep
	// go-no-sensitive-http-logging запрещает печатать тела, в том числе
	// в тестах. Само сравнение через .String() правило не трогает — эта
	// строка заодно проверяет, что правило не вернулось к ложному
	// срабатыванию на любой .String() у тела.
	if rec.Body.String() != "bad gateway\n" {
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
