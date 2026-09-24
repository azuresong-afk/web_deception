// Package failopen защищает трафик клиента от сбоев обнаружения.
//
// Сенсор стоит в пути трафика. Если обнаружение (приманки, правила)
// упало или стало медленным, сайт клиента не должен из-за этого
// сломаться или замедлиться: запросы идут в приложение без проверки.
// Это и есть fail-open (CLAUDE.md), и каждый такой переход — событие
// с алертом. Решение и альтернативы — ADR-0024.
//
// Отключается только обнаружение. Защита — запрет CONNECT, чистка
// заголовков о клиенте, адрес приложения только из конфигурации —
// работает всегда: она стоит вне Guard.
//
// Два случая:
//   - паника в обнаружении — этот запрос идёт в приложение без проверки,
//     а паника записывается событием detection.panic с адресом клиента.
//     Общий режим не меняется: иначе атакующий, нашедший вызывающий
//     панику запрос, выключал бы обнаружение для всех;
//   - перегрузка — проверки стали медленными. Сенсор переходит в режим
//     частичного обнаружения (проверяется каждый SampleEvery-й запрос)
//     и возвращается с гистерезисом (mode.go).
package failopen

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/web_deception/sensor/internal/event"
	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
)

// panicLogInterval — стек паники в лог не чаще раза в минуту: паника
// на каждом запросе не должна превращаться в заполненный диск.
const panicLogInterval = time.Minute

// Detector — обнаружение: смотрит на запрос и, если это касание ловушки,
// отвечает сам.
//
// Договор для реализаций (шаг 8 и дальше):
//   - сначала решить, потом писать ответ: паника после начала ответа
//     уже не даёт пропустить запрос к приложению, и соединение
//     обрывается;
//   - не читать тело запроса без необходимости: прочитанное тело
//     приложение не получит, и после паники такой запрос тоже
//     обрывается, а не уходит в приложение испорченным.
type Detector interface {
	// Inspect возвращает true, если ответил сам и запрос дальше не идёт.
	Inspect(w http.ResponseWriter, r *http.Request) (handled bool)
}

// NoDetector — обнаружения нет: все запросы идут в приложение.
// Используется до появления приманок (шаг 8).
type NoDetector struct{}

// Inspect ничего не делает.
func (NoDetector) Inspect(http.ResponseWriter, *http.Request) bool { return false }

// Stats — счётчики для /metrics.
type Stats struct {
	// Inspected — запросы, прошедшие обнаружение.
	Inspected atomic.Uint64
	// Bypassed — запросы, пропущенные без обнаружения в частичном режиме.
	Bypassed atomic.Uint64
	// Slow — проверки дольше SlowThreshold.
	Slow atomic.Uint64
	// Panics — паники в обнаружении.
	Panics atomic.Uint64
	// Aborted — запросы, оборванные после паники: ответ уже начат или тело
	// прочитано, и пропустить их в приложение нельзя.
	Aborted atomic.Uint64
	// Transitions — входы в частичный режим.
	Transitions atomic.Uint64
}

// Config — зависимости Guard. Все поля, кроме Now, обязательны.
type Config struct {
	Detector Detector
	Events   event.Emitter
	Trust    *forwarded.Resolver
	Logger   *slog.Logger
	// Now — часы; в тестах подменяются, чтобы «медленную» проверку
	// не приходилось ждать по-настоящему.
	Now func() time.Time
}

// Guard запускает обнаружение под защитой fail-open.
type Guard struct {
	cfg  Config
	mode *controller

	lastPanicLog atomic.Int64

	Stats Stats
}

// NewGuard создаёт Guard в обычном режиме.
func NewGuard(cfg Config) *Guard {
	if cfg.Detector == nil || cfg.Events == nil || cfg.Trust == nil || cfg.Logger == nil {
		panic("failopen: в Config не заданы все поля")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Guard{cfg: cfg, mode: newController(cfg.Now())}
}

// Degraded — включён ли режим частичного обнаружения.
func (g *Guard) Degraded() bool { return g.mode.degraded.Load() }

// Handler оборачивает next: сначала обнаружение под защитой, потом next.
func (g *Guard) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inspect, tr := g.mode.shouldInspect(g.cfg.Now())
		g.transition(tr)
		if !inspect {
			g.Stats.Bypassed.Add(1)
			next.ServeHTTP(w, r)
			return
		}

		tw := &trackedWriter{ResponseWriter: w}
		origBody := r.Body
		var tb *trackedBody
		if r.Body != nil && r.Body != http.NoBody {
			tb = &trackedBody{ReadCloser: r.Body}
			r.Body = tb
		}

		handled, panicked := g.inspect(tw, r)
		// Исходное тело — обратно: обёртка нужна только на время проверки,
		// а приложению и обработчику ошибок прокси важен исходный тип тела.
		r.Body = origBody

		if handled {
			return
		}
		if panicked && (tw.wrote.Load() || (tb != nil && tb.read.Load())) {
			// Ответ уже начат или часть тела прочитана: пропустить запрос
			// в приложение нельзя — оно получило бы испорченный запрос,
			// а клиент — два ответа в одном. Обрываем соединение: сервер Go
			// обрабатывает http.ErrAbortHandler молча, без стека в логе.
			g.Stats.Aborted.Add(1)
			panic(http.ErrAbortHandler)
		}
		next.ServeHTTP(w, r)
	})
}

// inspect вызывает Detector, перехватывает панику и замеряет время.
func (g *Guard) inspect(w http.ResponseWriter, r *http.Request) (handled, panicked bool) {
	start := g.cfg.Now()
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		// Намеренный обрыв соединения — не сбой, передаём дальше.
		if err, ok := p.(error); ok && errors.Is(err, http.ErrAbortHandler) {
			panic(p)
		}
		handled, panicked = false, true
		g.onPanic(r, p)
	}()

	handled = g.cfg.Detector.Inspect(w, r)

	g.Stats.Inspected.Add(1)
	now := g.cfg.Now()
	slow := now.Sub(start) >= SlowThreshold
	if slow {
		g.Stats.Slow.Add(1)
	}
	g.transition(g.mode.record(now, slow))
	return handled, false
}

// onPanic записывает панику: счётчик, событие с адресом клиента и —
// не чаще раза в минуту — стек в лог.
func (g *Guard) onPanic(r *http.Request, p any) {
	g.Stats.Panics.Add(1)

	// Паника на чужом вводе — повод посмотреть, кто его прислал: это может
	// быть поиск уязвимости в самом сенсоре. Поэтому событие с адресом
	// клиента и метаданными запроса. Значение паники не записывается —
	// в нём могут оказаться данные запроса; только тип.
	ev := event.New(event.TypeDetectionPanic, event.SeverityHigh)
	ev.Client = event.ClientFrom(g.cfg.Trust.Resolve(r))
	ev.Request = event.RequestFrom(r)
	ev.Data = map[string]string{"panic_type": fmt.Sprintf("%T", p)}
	g.cfg.Events.Emit(ev)

	now := g.cfg.Now().Unix()
	last := g.lastPanicLog.Load()
	if now-last < int64(panicLogInterval/time.Second) || !g.lastPanicLog.CompareAndSwap(last, now) {
		return
	}
	// Стек — имена функций и строки кода, без данных запроса. Нужен, чтобы
	// найти ошибку; значение паники не пишем по той же причине, что и выше.
	g.cfg.Logger.Error("паника в обнаружении: запрос пропущен в приложение без проверки",
		slog.String("panic_type", fmt.Sprintf("%T", p)),
		slog.String("stack", string(debug.Stack())))
}

// transition записывает смену режима: событие, строку в лог, счётчик.
func (g *Guard) transition(tr *Transition) {
	if tr == nil {
		return
	}
	data := map[string]string{
		"inspected": strconv.FormatUint(tr.Inspected, 10),
		"slow":      strconv.FormatUint(tr.Slow, 10),
	}
	if tr.Degraded {
		g.Stats.Transitions.Add(1)
		data["reason"] = "detection_slow"
		data["sample"] = "1/" + strconv.Itoa(SampleEvery)
		ev := event.New(event.TypeFailOpen, event.SeverityCritical)
		ev.Data = data
		g.cfg.Events.Emit(ev)
		// ERROR — по правилу этапа 2: до этапа 6 алерт человеку не
		// доставляется, и строка в логе — один из трёх следов перехода
		// вместе с событием и метрикой.
		g.cfg.Logger.Error("fail-open: обнаружение перегружено, проверяется каждый "+
			strconv.Itoa(SampleEvery)+"-й запрос",
			slog.Uint64("inspected", tr.Inspected), slog.Uint64("slow", tr.Slow))
		return
	}
	data["degraded_for"] = tr.Duration.Round(time.Second).String()
	ev := event.New(event.TypeFailOpenRecovered, event.SeverityInfo)
	ev.Data = data
	g.cfg.Events.Emit(ev)
	g.cfg.Logger.Info("fail-open снят: обнаружение снова проверяет каждый запрос",
		slog.String("degraded_for", data["degraded_for"]))
}

// trackedWriter запоминает, начал ли Detector ответ.
type trackedWriter struct {
	http.ResponseWriter
	wrote atomic.Bool
}

func (w *trackedWriter) WriteHeader(code int) {
	w.wrote.Store(true)
	w.ResponseWriter.WriteHeader(code)
}

func (w *trackedWriter) Write(p []byte) (int, error) {
	w.wrote.Store(true)
	return w.ResponseWriter.Write(p)
}

// Unwrap открывает исходный ResponseWriter для http.ResponseController.
func (w *trackedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// trackedBody запоминает, читал ли Detector тело запроса.
type trackedBody struct {
	io.ReadCloser
	read atomic.Bool
}

func (b *trackedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.read.Store(true)
	}
	return n, err
}
