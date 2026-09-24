package event

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// QueueSize — ёмкость буфера событий.
//
// Буфер нужен на время, пока запись отстаёт: диск занят, идёт ротация.
// Сканер, перебирающий приманки, даёт сотни событий в секунду, запись
// в файл — десятки тысяч, так что в обычной работе буфер почти пуст.
// 4096 событий — несколько секунд задержки диска при таком потоке;
// в памяти это порядка мегабайта.
const QueueSize = 4096

// PriorityQueueSize — ёмкость отдельного буфера для событий о состоянии
// сенсора (типы sensor.*): запуск, остановка, переход в fail-open. Таких
// событий единицы в час, 64 места — с большим запасом.
const PriorityQueueSize = 64

// dropLogInterval — не чаще одного сообщения о потерях в минуту: иначе
// атака, переполняющая буфер, заодно заполнила бы лог.
const dropLogInterval = time.Minute

// Emitter — то, чем пользуются остальные пакеты: отдать событие и не ждать.
type Emitter interface {
	Emit(Event)
}

// Sink — куда Recorder пишет готовые строки. Сейчас это файл (FileSink),
// на этапе 3 добавится очередь NATS.
type Sink interface {
	Write(line []byte) error
	Flush() error
	Close() error
}

// Stats — счётчики Recorder. Читаются из обработчика /metrics
// одновременно с записью, поэтому атомарные.
type Stats struct {
	// Emitted — события, принятые в буфер.
	Emitted atomic.Uint64
	// Written — события, переданные в Sink.
	Written atomic.Uint64
	// DroppedQueueFull — потеряны из-за полного буфера: вытеснены новыми
	// или не поместились сами.
	DroppedQueueFull atomic.Uint64
	// DroppedWriteError — отброшены: Sink вернул ошибку.
	DroppedWriteError atomic.Uint64
	// DroppedStopped — отброшены: сенсор уже останавливается.
	DroppedStopped atomic.Uint64
	// SinkErrors — неудачные записи и сбросы буфера в Sink.
	SinkErrors atomic.Uint64
}

// Recorder принимает события от обработчиков запросов и пишет их в Sink
// в отдельной горутине.
//
// Главное свойство: Emit никогда не ждёт запись. Обработчик запроса кладёт
// событие в буфер и сразу идёт дальше; если буфер полон — самое старое
// событие вытесняется новым и учитывается в счётчике потерь. Медленный
// диск или зависшая запись не должны задерживать трафик клиента
// (CLAUDE.md: «Сенсор никогда не ждёт очередь событий»). Цена — возможная
// потеря событий, принятый риск R2.
//
// Учёт точный: после Close каждое событие, переданное в Emit, либо
// записано, либо попало ровно в один счётчик потерь.
type Recorder struct {
	queue chan Event
	// prio — отдельный буфер для событий о состоянии сенсора (ADR-0024).
	// Поток касаний приманок заполняет queue и вытесняет из неё старые
	// события; если бы событие о переходе в fail-open лежало там же, его
	// вытеснил бы этот поток — а это как раз момент, когда оно важнее всего.
	prio chan Event
	sink Sink

	// mu защищает stopped. Emit держит его на чтение на время нескольких
	// неблокирующих операций, Close — на запись один раз при остановке.
	// Без него событие, отданное в Emit в момент остановки, могло бы
	// остаться в буфере после того, как горутина записи его уже
	// дочитала: не записанным и не учтённым.
	//
	// Канал queue не закрываем никогда: запись в закрытый канал — паника,
	// а Emit вызывается из обработчиков, которые могут не успеть
	// завершиться к остановке.
	mu       sync.RWMutex
	stopped  bool
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
	closeErr error

	logger *slog.Logger
	// Поля ниже меняет только горутина записи.
	lastDropLog      time.Time
	reportedDrops    uint64
	lastSinkErrorLog time.Time

	Stats Stats
}

// NewRecorder создаёт Recorder и запускает горутину записи.
func NewRecorder(sink Sink, queueSize int, logger *slog.Logger) *Recorder {
	r := &Recorder{
		queue:  make(chan Event, queueSize),
		prio:   make(chan Event, PriorityQueueSize),
		sink:   sink,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		logger: logger,
	}
	go r.run()
	return r
}

// Emit кладёт событие в буфер, не ожидая записи. Безопасен для вызова
// из многих горутин и после Close.
func (r *Recorder) Emit(ev Event) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.stopped {
		r.Stats.DroppedStopped.Add(1)
		return
	}

	q := r.queue
	if isPriority(ev.Type) {
		q = r.prio
	}

	// select с default — неблокирующая запись: если места в канале нет,
	// выполняется default, а не ожидание.
	select {
	case q <- ev:
		r.Stats.Emitted.Add(1)
		return
	default:
	}

	// Буфер полон. Вытесняем самое старое событие, а не отбрасываем новое
	// (ADR-0004, ADR-0023). Атакующий может сам заполнить буфер, касаясь
	// приманок; если бы терялись новые события, его следующие действия
	// не записались бы вовсе. Так в буфере всегда самые свежие.
	select {
	case <-q:
		r.Stats.DroppedQueueFull.Add(1)
	default:
		// Горутина записи успела забрать событие — место уже есть.
	}
	// Вторая попытка — последняя. Освободившееся место мог занять другой
	// обработчик; тогда теряется это событие, но ожидания и цикла нет.
	select {
	case q <- ev:
		r.Stats.Emitted.Add(1)
	default:
		r.Stats.DroppedQueueFull.Add(1)
	}
}

// isPriority — событие о состоянии сенсора. Решает тип, а не важность:
// тип — константа из кода, и события, которые может вызвать атакующий
// (request.*, detection.*, касания приманок), в приоритетный буфер
// не попадут никогда, сколько бы их ни было.
func isPriority(t Type) bool {
	return strings.HasPrefix(string(t), "sensor.")
}

// QueueLen — сколько событий ждут записи. uint64 — тип значений метрик.
func (r *Recorder) QueueLen() uint64 { return toUint64(len(r.queue)) }

// QueueCap — ёмкость буфера.
func (r *Recorder) QueueCap() uint64 { return toUint64(cap(r.queue)) }

// toUint64 переводит длину в uint64. Отрицательной длина не бывает, но
// перевод отрицательного int дал бы огромное число, и проверка здесь
// делает безопасность перевода видимой — и читателю, и линтеру gosec.
func toUint64(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

// Close перестаёт принимать события, дописывает накопленные и закрывает
// Sink. Ждёт не дольше, чем позволяет ctx: зависший диск не должен
// превращать остановку сенсора в зависание.
func (r *Recorder) Close(ctx context.Context) error {
	r.stopOnce.Do(func() {
		// После этой блокировки ни один Emit не положит событие в буфер:
		// всё, что там есть, горутина записи дочитает до выхода.
		r.mu.Lock()
		r.stopped = true
		r.mu.Unlock()
		close(r.stop)
	})
	select {
	case <-r.done:
		return r.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run — горутина записи.
func (r *Recorder) run() {
	defer close(r.done)
	for {
		// Сначала — события о состоянии сенсора, если они есть. select
		// с несколькими готовыми ветками выбирает случайную, поэтому
		// приоритет — отдельной неблокирующей проверкой перед общим select.
		select {
		case ev := <-r.prio:
			r.write(ev)
			r.flushIfIdle()
			continue
		default:
		}

		select {
		case ev := <-r.prio:
			r.write(ev)
		case ev := <-r.queue:
			r.write(ev)
		case <-r.stop:
			// Дописываем то, что уже в буферах, — сначала приоритетный —
			// и выходим. Новые события Emit уже не принимает.
			r.drain(r.prio)
			r.drain(r.queue)
			r.flush()
			r.closeErr = r.sink.Close()
			return
		}
		r.flushIfIdle()
	}
}

// flushIfIdle сбрасывает буфер файла, когда обе очереди опустели: при редких
// событиях каждое сразу видно в файле, при потоке — пишутся пачками,
// а буфер файла сбрасывается сам по заполнении.
func (r *Recorder) flushIfIdle() {
	if len(r.prio) == 0 && len(r.queue) == 0 {
		r.flush()
	}
}

func (r *Recorder) drain(q chan Event) {
	for {
		select {
		case ev := <-q:
			r.write(ev)
		default:
			return
		}
	}
}

// write кодирует и записывает одно событие.
//
// Паника здесь — ошибка в нашем коде записи — не должна уронить процесс:
// горутина записи не обработчик запроса, и сервер Go её панику
// не перехватит. Упавший сенсор — это упавший сайт клиента. Поэтому
// паника перехватывается, событие считается потерянным, запись
// продолжается со следующего.
func (r *Recorder) write(ev Event) {
	defer func() {
		if p := recover(); p != nil {
			r.Stats.DroppedWriteError.Add(1)
			r.sinkError(fmt.Errorf("паника при записи события: %T", p))
		}
	}()

	// json.Marshal экранирует в строках переводы строк, управляющие символы
	// и <, >, & и заменяет недопустимый UTF-8. Поэтому строка события
	// никогда не содержит перевода строки внутри: одна строка — одно
	// событие, как бы ни был устроен путь или User-Agent атакующего.
	line, err := json.Marshal(ev)
	if err != nil {
		// Событие собирается из строк, чисел и времени, ошибке кодирования
		// взяться неоткуда. Если всё же случилась — считаем как ошибку записи.
		r.Stats.DroppedWriteError.Add(1)
		r.sinkError(err)
		return
	}
	line = append(line, '\n')
	if err := r.sink.Write(line); err != nil {
		r.Stats.DroppedWriteError.Add(1)
		r.sinkError(err)
		return
	}
	r.Stats.Written.Add(1)
}

func (r *Recorder) flush() {
	if err := r.sink.Flush(); err != nil {
		r.sinkError(err)
	}
	r.reportDrops()
}

// sinkError учитывает ошибку записи и пишет её в лог не чаще раза в минуту.
// Текст ошибки — от файловой системы (путь, «нет места»), данных запросов
// в нём нет.
func (r *Recorder) sinkError(err error) {
	r.Stats.SinkErrors.Add(1)
	now := time.Now()
	if now.Sub(r.lastSinkErrorLog) < dropLogInterval {
		return
	}
	r.lastSinkErrorLog = now
	r.logger.Error("не удалось записать события", slog.String("error", err.Error()))
}

// reportDrops пишет в лог, сколько событий потеряно из-за полного буфера,
// не чаще раза в минуту. Считать в Emit нельзя: там лог писали бы
// обработчики запросов, по строке на каждое потерянное событие.
func (r *Recorder) reportDrops() {
	total := r.Stats.DroppedQueueFull.Load()
	if total == r.reportedDrops {
		return
	}
	now := time.Now()
	if now.Sub(r.lastDropLog) < dropLogInterval {
		return
	}
	r.logger.Warn("буфер событий переполнялся: старые события вытеснены новыми",
		slog.Uint64("dropped", total-r.reportedDrops),
		slog.Uint64("dropped_total", total))
	r.reportedDrops = total
	r.lastDropLog = now
}
