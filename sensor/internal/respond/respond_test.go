package respond

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestTrap(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	Trap(rec, http.StatusOK, "text/plain", "DB_HOST=db\n")
	if rec.Code != http.StatusOK || rec.Body.String() != "DB_HOST=db\n" {
		t.Errorf("ответ %d %q", rec.Code, rec.Body.String())
	}
	want := map[string]string{
		"Content-Type":           "text/plain; charset=utf-8",
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "no-store",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, ожидалось %q", k, got, v)
		}
	}

	// Тип вне списка — ни при каких условиях не text/html.
	rec = httptest.NewRecorder()
	Trap(rec, http.StatusOK, "text/html", "<script>")
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("неизвестный тип отдан как %q", got)
	}
}

// TestRefusePreflight: ни одного заголовка, который одобрил бы CORS.
func TestRefusePreflight(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	RefusePreflight(rec)
	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Errorf("код %d, тело %d байт", rec.Code, rec.Body.Len())
	}
	for name := range rec.Header() {
		if strings.HasPrefix(name, "Access-Control-") {
			t.Errorf("в ответе заголовок CORS %s", name)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("нет Cache-Control: no-store")
	}
}
