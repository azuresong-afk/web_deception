package proxy

import (
	"log/slog"
	"net/http"
	"time"
)

// Таймауты и пределы клиентских соединений.
const (
	// ReadHeaderTimeout — сколько ждём заголовки запроса. Главная защита
	// от Slowloris: атакующий открывает тысячи соединений и шлёт заголовки
	// по байту раз в несколько секунд.
	ReadHeaderTimeout = 10 * time.Second

	// IdleTimeout — сколько держим keep-alive соединение между запросами.
	IdleTimeout = 120 * time.Second

	// MaxHeaderBytes — предел суммарного размера заголовков запроса.
	// Браузеры с большими cookie присылают до 10–20 КиБ; 64 КиБ оставляет
	// запас легитимным клиентам и в 16 раз меньше значения Go по умолчанию.
	// Запрос с заголовками больше предела получает 431 от самого сервера Go.
	MaxHeaderBytes = 64 << 10
)

// NewServer оборачивает обработчик в http.Server для клиентского трафика.
//
// ReadTimeout и WriteTimeout намеренно не заданы: они ограничивают
// длительность запроса целиком и рвали бы легитимные длинные загрузки.
// Их роль выполняют ReadHeaderTimeout, IdleTimeout, сроки простоя из
// withIOIdleDeadlines и предел соединений из LimitListener.
func NewServer(h http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,

		// Ошибки самого HTTP-сервера: битые запросы, сбои разбора протокола,
		// паники в обработчиках. Без этой строки они ушли бы в глобальный
		// log мимо структурированного лога.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}
