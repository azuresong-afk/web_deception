package proxy

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// IOIdleTimeout — сколько клиент может молчать посреди передачи тела
// запроса или не забирать очередную порцию ответа.
//
// Почему не обычные ReadTimeout и WriteTimeout сервера. Они ограничивают
// всю длительность запроса целиком, и для прокси это ломает легитимное:
// загрузку большого файла на медленном канале, скачивание отчёта, потоковые
// ответы. Нам нужно другое — не «запрос длится не дольше N», а «клиент
// не может замолчать дольше N». Это защита от медленного тела запроса
// и медленного чтения ответа — родственников Slowloris (угроза T3).
// Так же устроены client_body_timeout и send_timeout в nginx.
const IOIdleTimeout = 60 * time.Second

// withIOIdleDeadlines ставит на соединение срок перед каждым чтением тела
// запроса и перед каждой записью ответа. Пока данные идут, срок каждый раз
// сдвигается вперёд; если клиент замолчал дольше idle, операция завершается
// ошибкой, и запрос обрывается.
func withIOIdleDeadlines(next http.Handler, idle time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)

		// Сроки живут на соединении, а не на запросе: срок, оставшийся от
		// этого ответа, мог бы сработать посреди следующего запроса в том же
		// keep-alive соединении. Сервер Go 1.27 сам снимает срок записи после
		// ответа и выставляет срок чтения заново перед следующим запросом,
		// но это деталь реализации, не описанная в документации. Снимаем
		// оба срока явно, чтобы не зависеть от неё.
		// Ошибку игнорируем: после захвата соединения (WebSocket) сроки
		// управляются уже не сервером, и это штатная ситуация.
		defer func() {
			_ = rc.SetReadDeadline(time.Time{})
			_ = rc.SetWriteDeadline(time.Time{})
		}()

		if r.Body != nil && r.Body != http.NoBody {
			r.Body = &idleReader{body: r.Body, rc: rc, idle: idle}
		}
		next.ServeHTTP(&idleWriter{ResponseWriter: w, rc: rc, idle: idle}, r)
	})
}

// idleReader сдвигает срок чтения перед каждым чтением тела запроса.
type idleReader struct {
	body io.ReadCloser
	rc   *http.ResponseController
	idle time.Duration

	// timedOut — клиент замолчал посреди тела. Нужен обработчику ошибок:
	// без него такой сбой выглядел бы как таймаут приложения, и в лог
	// и в ответ попала бы неверная причина. Атомарный, потому что тело
	// читает транспорт в своей горутине, а флаг проверяет обработчик.
	timedOut atomic.Bool
}

func (r *idleReader) Read(p []byte) (int, error) {
	// Ошибка означает, что соединение не поддерживает сроки (например,
	// в тестах с поддельным ResponseWriter). Тогда работаем без срока:
	// таймаут — защита, а не условие работы.
	_ = r.rc.SetReadDeadline(time.Now().Add(r.idle))
	n, err := r.body.Read(p)
	var netErr net.Error
	if err != nil && errors.As(err, &netErr) && netErr.Timeout() {
		r.timedOut.Store(true)
	}
	return n, err
}

// clientBodyTimedOut сообщает, оборвался ли запрос из-за того, что клиент
// замолчал посреди тела.
func clientBodyTimedOut(r *http.Request) bool {
	b, ok := r.Body.(*idleReader)
	return ok && b.timedOut.Load()
}

func (r *idleReader) Close() error { return r.body.Close() }

// idleWriter сдвигает срок записи перед каждой записью ответа.
type idleWriter struct {
	http.ResponseWriter
	rc   *http.ResponseController
	idle time.Duration
}

func (w *idleWriter) Write(p []byte) (int, error) {
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.idle))
	return w.ResponseWriter.Write(p)
}

// Unwrap открывает исходный ResponseWriter для http.ResponseController.
// Без него ReverseProxy не смог бы через нашу обёртку ни сбросить буфер
// (Flush — нужен для потоковых ответов), ни захватить соединение
// (Hijack — нужен для WebSocket).
func (w *idleWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
