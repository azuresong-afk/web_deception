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
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/web_deception/sensor/internal/event"
	"github.com/azuresong-afk/web_deception/sensor/internal/failopen"
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

// Options — всё, что нужно обработчику, кроме адреса приложения.
// Все поля обязательны.
type Options struct {
	// Trust решает, от каких соединений верить заголовкам о клиенте
	// (ADR-0022).
	Trust *forwarded.Resolver
	// Events получает события; не ждёт (ADR-0023).
	Events event.Emitter
	// Guard запускает обнаружение под защитой fail-open (ADR-0024).
	// Обнаружение — внутри Guard, защита (запрет CONNECT, заголовки
	// о клиенте, адрес приложения) — снаружи: fail-open её не отключает.
	Guard *failopen.Guard
	// Stats — счётчики для /metrics.
	Stats  *Stats
	Logger *slog.Logger
	// Lures — наживки в ответах приложения (ADR-0027). Необязательно:
	// nil — ответы приложения уходят клиенту без изменений.
	Lures Lures
}

// Lures правит запрос к приложению и его ответ, чтобы поставить наживки.
// Реализация — пакет lure. Modify не должен возвращать ошибку из-за
// сбоя наживки: ошибка из ModifyResponse — это 502 для клиента.
type Lures interface {
	// Prepare правит исходящий запрос: in — запрос клиента, out — копия,
	// которая уйдёт приложению.
	Prepare(in, out *http.Request)
	// Modify правит ответ приложения до того, как он уйдёт клиенту.
	Modify(resp *http.Response) error
}

// Stats — счётчики прокси. Атомарные: их увеличивают обработчики запросов,
// а читает обработчик /metrics.
type Stats struct {
	// ConnectRejected — отвергнутые запросы CONNECT.
	ConnectRejected atomic.Uint64
	// ChainBroken — запросы от доверенного прокси с неразобранным
	// X-Forwarded-For. Рост означает ошибку настройки прокси (ADR-0022).
	ChainBroken atomic.Uint64
	// Saturated — сколько раз новое соединение ждало из-за предела
	// соединений.
	Saturated atomic.Uint64
	// UpstreamErrors — запросы, на которые не ответило приложение,
	// по классам из ErrorClasses.
	UpstreamErrors [numErrorClasses]atomic.Uint64
}

// ErrorClass — почему запрос не получил ответа приложения.
type ErrorClass int

const (
	// ErrClientCanceled — клиент закрыл соединение сам.
	ErrClientCanceled ErrorClass = iota
	// ErrClientBodyTimeout — клиент замолчал посреди тела запроса (408).
	ErrClientBodyTimeout
	// ErrUpstreamTimeout — приложение не ответило вовремя (504).
	ErrUpstreamTimeout
	// ErrUpstreamUnreachable — не удалось соединиться с приложением (502).
	ErrUpstreamUnreachable
	// ErrUpstreamOther — прочие сбои обмена с приложением (502).
	ErrUpstreamOther
	numErrorClasses
)

// errorClassNames — значения метки class в /metrics. Константы из кода:
// метка никогда не берётся из запроса или текста ошибки.
var errorClassNames = [numErrorClasses]string{
	ErrClientCanceled:      "client_canceled",
	ErrClientBodyTimeout:   "client_body_timeout",
	ErrUpstreamTimeout:     "upstream_timeout",
	ErrUpstreamUnreachable: "upstream_unreachable",
	ErrUpstreamOther:       "upstream_other",
}

// ErrorClasses — все классы по порядку, для построения /metrics.
func ErrorClasses() []ErrorClass {
	out := make([]ErrorClass, numErrorClasses)
	for i := range out {
		out[i] = ErrorClass(i)
	}
	return out
}

// String — имя класса для метки метрики.
func (c ErrorClass) String() string { return errorClassNames[c] }

// NewHandler собирает обработчик, передающий запросы в upstream.
//
// upstream приходит только из конфигурации (слой запуска, ADR-0018),
// а не из запроса. Это главная защита от превращения сенсора в открытый
// прокси: какой бы Host или адрес в строке запроса ни прислал атакующий,
// соединение откроется только с приложением (угроза T17).
func NewHandler(upstream *url.URL, o Options) http.Handler {
	return newHandler(upstream, o, newTransport(), IOIdleTimeout)
}

// newHandler — то же, что NewHandler, но с транспортом и сроком простоя
// из параметров: тестам нужны короткие таймауты, а ждать минуту в каждом
// тесте нельзя.
func newHandler(upstream *url.URL, o Options, transport http.RoundTripper, idle time.Duration) http.Handler {
	// Пропущенное поле — ошибка программиста. Падаем при запуске, а не
	// на первом запросе клиента.
	if o.Trust == nil || o.Events == nil || o.Guard == nil || o.Stats == nil || o.Logger == nil {
		panic("proxy: в Options не заданы все поля")
	}
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
			client := o.Trust.Resolve(pr.In)
			if client.ChainBroken {
				o.Stats.ChainBroken.Add(1)
			}
			forwarded.SetOutbound(pr.Out.Header, pr.In, client)
			if o.Lures != nil {
				o.Lures.Prepare(pr.In, pr.Out)
			}
		},
		Transport:    transport,
		BufferPool:   newBufferPool(),
		ErrorHandler: errorHandler(o.Logger, o.Stats),
		// Сюда ReverseProxy пишет редкие внутренние ошибки, например обрыв
		// копирования тела ответа. Данных запроса в этих сообщениях нет.
		ErrorLog: slog.NewLogLogger(o.Logger.Handler(), slog.LevelWarn),
	}

	if o.Lures != nil {
		rp.ModifyResponse = o.Lures.Modify
	}

	// Порядок обёрток — снаружи внутрь:
	//   rejectConnect — защита, работает всегда, до всего остального;
	//   сроки простоя — и для обнаружения, если оно читает тело, и для прокси;
	//   Guard — обнаружение; упало или перегружено — запрос идёт дальше;
	//   ReverseProxy — приложение.
	return rejectConnect(o, withIOIdleDeadlines(o.Guard.Handler(rp), idle))
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

// rejectConnect отвергает метод CONNECT и записывает событие.
//
// CONNECT просит прокси открыть туннель к произвольному адресу — ровно
// то, что делает сенсор открытым прокси. Приложению за сенсором CONNECT
// не нужен никогда: браузер отправляет его только прокси, а не сайту.
// Значит, CONNECT — это проверка «не открытый ли здесь прокси», и о ней
// стоит знать (угроза T17). Обычно так делают сканеры интернета, поэтому
// важность низкая: это шум, а не целевая атака.
func rejectConnect(o Options, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			o.Stats.ConnectRejected.Add(1)

			ev := event.New(event.TypeConnectRejected, event.SeverityLow)
			ev.Client = event.ClientFrom(o.Trust.Resolve(r))
			ev.Request = event.RequestFrom(r)
			// Куда клиент просил туннель — например, во внутреннюю сеть
			// или на порт SSH. Обрезано и приведено к UTF-8.
			ev.Data = map[string]string{"target": event.ConnectTarget(r)}
			// Emit не ждёт: если буфер полон, событие потеряется
			// и попадёт в счётчик, а клиент получит ответ без задержки.
			o.Events.Emit(ev)

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
func errorHandler(logger *slog.Logger, stats *Stats) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		class, status, reason := classify(err)
		if clientBodyTimedOut(r) {
			// Виноват клиент, а не приложение: 408, а не 504.
			class, status, reason = ErrClientBodyTimeout, http.StatusRequestTimeout, "клиент не прислал тело запроса вовремя"
		}
		stats.UpstreamErrors[class].Add(1)

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

// classify сопоставляет ошибку транспорта с классом, кодом ответа
// и причиной для лога.
func classify(err error) (class ErrorClass, status int, reason string) {
	if errors.Is(err, context.Canceled) {
		return ErrClientCanceled, http.StatusBadGateway, "клиент закрыл соединение"
	}

	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return ErrUpstreamTimeout, http.StatusGatewayTimeout, "приложение не ответило вовремя"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return ErrUpstreamUnreachable, http.StatusBadGateway, "не удалось соединиться с приложением"
	}

	return ErrUpstreamOther, http.StatusBadGateway, "ошибка обмена с приложением"
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
