// Package proxy — клиентский слушатель сенсора: принимает запросы из сети
// и передаёт их защищаемому приложению, возвращая его ответы.
//
// Главное требование к этому коду — прозрачность. Приложение и его
// пользователи не должны замечать сенсор: те же пути, параметры, заголовки,
// тела, коды ответа. Всё, что сенсор меняет, перечислено в ADR-0021,
// и у каждого такого изменения есть причина из модели угроз.
//
// Граница доверия проходит прямо здесь. Всё, что приходит в запросе —
// путь, заголовки, тело, скорость отправки, — прислал атакующий.
// Ответ приложения доверенный лишь частично: приложение наше, но в ответе
// может оказаться то, что атакующий в нём сохранил.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
	"github.com/azuresong-afk/web_deception/sensor/internal/respond"
)

// Таймауты и пределы соединений сенсора с приложением. Константы, а не
// настройки, по той же причине, что у служебного слушателя: это защита
// от класса сбоев, и возможность выставить её в ноль — возможность
// её отключить.
const (
	// dialTimeout — сколько ждём установки TCP-соединения с приложением.
	// Приложение обычно в той же сети; если за 5 секунд соединения нет,
	// его нет вообще, и клиенту лучше быстро получить 502.
	dialTimeout = 5 * time.Second

	tlsHandshakeTimeout = 5 * time.Second

	// responseHeaderTimeout — сколько ждём заголовков ответа после того,
	// как запрос отправлен. Это не предел длительности ответа: длинная
	// загрузка файла идёт сколько угодно, если приложение начало отвечать.
	// 60 секунд — как proxy_read_timeout в nginx по умолчанию: сенсор
	// не должен рвать запросы, которые приложение считает нормальными.
	responseHeaderTimeout = 60 * time.Second

	// Сколько держать неиспользуемое соединение с приложением открытым.
	upstreamIdleConnTimeout = 90 * time.Second

	// Сколько неиспользуемых соединений с приложением держать в запасе.
	// Значение Go по умолчанию — 2 на хост; для прокси, который весь
	// трафик шлёт в один хост, это означает новое TCP-соединение почти
	// на каждый запрос под нагрузкой — лишние миллисекунды к p99.
	maxIdleConnsPerHost = 256

	// Предел размера заголовков ответа приложения. Приложение доверенное
	// лишь частично, и ответ на 10 МБ заголовков — это 10 МБ памяти сенсора.
	maxResponseHeaderBytes = 1 << 20 // 1 МиБ

	// Размер буфера копирования тела. 32 КиБ — значение, которое
	// ReverseProxy выбирает сам; мы лишь переиспользуем буферы.
	copyBufferSize = 32 << 10
)

// NewHandler собирает обработчик, передающий запросы в upstream.
//
// upstream приходит только из конфигурации (слой запуска, ADR-0018),
// а не из запроса. Это главная защита от превращения сенсора в открытый
// прокси: какой бы Host или адрес в строке запроса ни прислал атакующий,
// соединение откроется только с приложением (угроза T17).
//
// trust решает, от каких соединений верить заголовкам о клиенте (ADR-0022).
func NewHandler(upstream *url.URL, trust *forwarded.Resolver, logger *slog.Logger) http.Handler {
	return newHandler(upstream, trust, logger, newTransport(), IOIdleTimeout)
}

// newHandler — то же, что NewHandler, но с транспортом и сроком простоя
// из параметров: тестам нужны короткие таймауты, а ждать минуту в каждом
// тесте нельзя.
func newHandler(upstream *url.URL, trust *forwarded.Resolver, logger *slog.Logger, transport http.RoundTripper, idle time.Duration) http.Handler {
	rp := &httputil.ReverseProxy{
		// Rewrite, а не устаревший Director. До вызова Rewrite ReverseProxy
		// сам удаляет из исходящего запроса служебные заголовки соединения
		// (hop-by-hop), а также X-Forwarded-For, X-Forwarded-Host,
		// X-Forwarded-Proto и Forwarded, присланные клиентом. Остальные
		// X-Forwarded-* он оставляет — их чистит пакет forwarded ниже.
		//
		// Поправка к шагу 3: тогда здесь было написано, что ReverseProxy
		// удаляет «все X-Forwarded-*». Это неверно, и X-Forwarded-Port,
		// -Prefix, -Ssl доходили до приложения от клиента (ADR-0022).
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Схема и адрес — строго из конфигурации.
			pr.SetURL(upstream)

			// SetURL подменяет Host на адрес приложения. Мы возвращаем
			// исходный: приложение строит по нему ссылки и перенаправления,
			// и без него сайт за сенсором вёл бы себя иначе, чем без сенсора.
			// На то, куда открывается соединение, Host не влияет.
			pr.Out.Host = pr.In.Host

			// Заголовки о клиенте и исходном запросе: X-Forwarded-*,
			// X-Real-IP и подобные. Приложению их сообщает либо доверенный
			// прокси, либо сенсор по своему соединению, но не клиент
			// (угроза T1). Вся логика — в пакете forwarded: это единственное
			// место, где такие заголовки разрешено читать.
			forwarded.SetOutbound(pr.Out.Header, pr.In, trust.Resolve(pr.In))
		},
		Transport:    transport,
		BufferPool:   newBufferPool(),
		ErrorHandler: errorHandler(logger),
		// Сюда ReverseProxy пишет редкие внутренние ошибки, например обрыв
		// копирования тела ответа. Данных запроса в этих сообщениях нет.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	return rejectConnect(withIOIdleDeadlines(rp, idle))
}

// newTransport — клиент HTTP, которым сенсор ходит в приложение.
func newTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}
	return &http.Transport{
		// Никаких прокси из переменных окружения. Транспорт Go по умолчанию
		// читает HTTP_PROXY, и тогда весь трафик клиента — с паролями
		// и cookie — ушёл бы через машину, указанную в окружении.
		Proxy: nil,

		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: tlsHandshakeTimeout,

		ResponseHeaderTimeout:  responseHeaderTimeout,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,

		IdleConnTimeout:     upstreamIdleConnTimeout,
		MaxIdleConns:        maxIdleConnsPerHost,
		MaxIdleConnsPerHost: maxIdleConnsPerHost,

		// Без этого транспорт сам добавляет Accept-Encoding: gzip, если его
		// не прислал клиент, и сам распаковывает ответ. Клиент получил бы
		// не то, что отправило приложение, — прокси перестал бы быть
		// прозрачным.
		DisableCompression: true,

		// С приложением говорим по HTTP/1.1. HTTP/2 внутри доверенной сети
		// не даёт выигрыша, но добавляет сложный код в путь каждого запроса.
		ForceAttemptHTTP2: false,
	}
}

// rejectConnect отвергает метод CONNECT.
//
// CONNECT просит прокси открыть туннель к произвольному адресу — ровно
// то, что делает сенсор открытым прокси. Приложению за сенсором CONNECT
// не нужен никогда: браузер отправляет его только прокси, а не сайту.
func rejectConnect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			respond.Plain(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// errorHandler отвечает клиенту, когда приложение не ответило.
//
// Ответ нейтральный: только код и его стандартное название. Ни адреса
// приложения, ни текста ошибки — это внутреннее устройство, которое
// атакующему знать незачем.
//
// В лог тоже не пишется текст ошибки целиком: в некоторых ошибках
// транспорта есть фрагменты ответа приложения, а в ошибках клиента HTTP —
// полный адрес запроса с параметрами, где бывают токены (CLAUDE.md,
// раздел «Запрещено»). Пишем только класс ошибки и её тип.
func errorHandler(logger *slog.Logger) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		status, reason := classify(err)
		if clientBodyTimedOut(r) {
			// Виноват клиент, а не приложение: 408, а не 504.
			status, reason = http.StatusRequestTimeout, "клиент не прислал тело запроса вовремя"
		}

		attrs := []any{
			slog.String("reason", reason),
			slog.String("error_type", fmt.Sprintf("%T", err)),
			slog.Int("status", status),
		}
		if errors.Is(err, context.Canceled) {
			// Клиент ушёл сам — это его решение, а не сбой. На уровне warn
			// такие сообщения позволили бы любому раздувать лог обрывом
			// соединений.
			logger.Debug("клиент закрыл соединение до ответа приложения", attrs...)
		} else {
			logger.Warn("запрос к приложению не удался", attrs...)
		}

		respond.Plain(w, status, http.StatusText(status))
	}
}

// classify сопоставляет ошибку транспорта с кодом ответа и причиной для лога.
func classify(err error) (status int, reason string) {
	if errors.Is(err, context.Canceled) {
		return http.StatusBadGateway, "клиент закрыл соединение"
	}

	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return http.StatusGatewayTimeout, "приложение не ответило вовремя"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return http.StatusBadGateway, "не удалось соединиться с приложением"
	}

	return http.StatusBadGateway, "ошибка обмена с приложением"
}

// bufferPool переиспользует буферы копирования тел между запросами.
//
// Без пула каждый запрос выделяет новые 32 КиБ, и под нагрузкой сборщик
// мусора Go работает чаще — это паузы, которые видны именно в хвосте
// распределения задержек, то есть в p99.
type bufferPool struct {
	pool sync.Pool
}

func newBufferPool() *bufferPool {
	return &bufferPool{pool: sync.Pool{New: func() any {
		buf := make([]byte, copyBufferSize)
		return &buf
	}}}
}

func (p *bufferPool) Get() []byte {
	buf, ok := p.pool.Get().(*[]byte)
	if !ok {
		return make([]byte, copyBufferSize)
	}
	return *buf
}

func (p *bufferPool) Put(buf []byte) {
	// Буфер другого размера в пул не возвращаем: иначе однажды
	// выданный маленький буфер замедлил бы все последующие копирования.
	if cap(buf) != copyBufferSize {
		return
	}
	buf = buf[:copyBufferSize]
	p.pool.Put(&buf)
}
