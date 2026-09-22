// Тестовые примеры для правила go-no-sensitive-http-logging.
// Строка "ruleid" — правило обязано сработать на следующей строке,
// "ok" — обязано промолчать. Проверяется командой semgrep --test.
package examples

import (
	"log"
	"log/slog"
	"net/http"
	"strconv"
)

func handler(w http.ResponseWriter, r *http.Request, logger *slog.Logger) {
	// ruleid: go-no-sensitive-http-logging
	logger.Info("запрос", slog.Any("headers", r.Header))

	// ruleid: go-no-sensitive-http-logging
	logger.Warn("вход", "auth", r.Header.Get("Authorization"))

	// ruleid: go-no-sensitive-http-logging
	slog.Info("cookie", "c", r.Header.Get("cookie"))

	// ruleid: go-no-sensitive-http-logging
	log.Printf("тело: %v", r.Body)

	// ruleid: go-no-sensitive-http-logging
	logger.Debug("параметры", "q", r.URL.RawQuery)

	// ruleid: go-no-sensitive-http-logging
	logger.Info("адрес", "url", r.URL.String())

	// ruleid: go-no-sensitive-http-logging
	logger.Info("cookies", "all", r.Cookies())

	// Путь через переменную тоже ловится: для этого правило в режиме taint.
	headers := r.Header
	// ruleid: go-no-sensitive-http-logging
	logger.Error("сбой", "h", headers)

	// Атрибут, собранный заранее, — та же утечка: правило отмечает
	// и создание атрибута, и его запись в лог.
	// ruleid: go-no-sensitive-http-logging
	attr := slog.Any("form", r.PostForm)
	// ruleid: go-no-sensitive-http-logging
	logger.Info("форма", attr)

	// Ошибка разбора содержит входную строку целиком: strconv.Atoi вернёт
	// `parsing "Bearer eyJ...": invalid syntax`. Поэтому у правила нет
	// общего исключения для ошибок — отдельные безопасные случаи
	// помечаются в коде явно, с объяснением.
	_, err := strconv.Atoi(r.Header.Get("Authorization"))
	// ruleid: go-no-sensitive-http-logging
	logger.Error("не число", "err", err)

	// Метаданные логировать можно и нужно.
	// ok: go-no-sensitive-http-logging
	logger.Info("запрос", "method", r.Method, "path", r.URL.Path)

	// ok: go-no-sensitive-http-logging
	logger.Info("клиент", "ua", r.Header.Get("User-Agent"))

	// ok: go-no-sensitive-http-logging
	logger.Info("тип", "ct", r.Header.Get("Content-Type"))
}
