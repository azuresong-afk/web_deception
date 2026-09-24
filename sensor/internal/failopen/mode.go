package failopen

import (
	"sync"
	"sync/atomic"
	"time"
)

// Пороги режима частичного обнаружения. Константы, а не настройки:
// это защита, и возможность выставить её в ноль — возможность её
// отключить.
const (
	// SlowThreshold — проверка дольше этого считается медленной. Весь бюджет
	// сенсора — +5 мс к p99 времени ответа (docs/roadmap.md, шаг 11);
	// проверка, которая одна съедает весь бюджет, — признак перегрузки,
	// а не нормы. Время — по часам, а не по процессору: при нехватке
	// процессора горутина ждёт своей очереди, и это ожидание — ровно то,
	// что мы хотим заметить.
	SlowThreshold = 5 * time.Millisecond

	// SampleEvery — в режиме частичного обнаружения проверяется каждый
	// SampleEvery-й запрос. Не ноль: сканер, перебирающий приманки,
	// сделает десятки касаний, и какие-то из них попадут в выборку.
	SampleEvery = 10

	// Вход: за последние enterWindow секунд проверено не меньше
	// enterMinInspected запросов, и медленных среди них не меньше
	// enterSlowPercent процентов. Минимум выборки — чтобы два медленных
	// запроса из трёх в тихую минуту не переключали режим.
	enterWindow       = 10
	enterMinInspected = 50
	enterSlowPercent  = 10

	// Выход: в режиме частичного обнаружения провели не меньше
	// minDegraded и за последние exitWindow секунд медленных меньше
	// exitSlowPercent процентов. Порог выхода намного строже порога входа —
	// это гистерезис: между 1% и 10% режим не меняется, и сенсор
	// не переключается туда-обратно на каждом всплеске.
	exitWindow      = 30
	minDegraded     = exitWindow * time.Second
	exitSlowPercent = 1
)

// windowSeconds — сколько секунд помнит окно: самое длинное из окон.
const windowSeconds = exitWindow

// bucket — счётчики за одну секунду.
type bucket struct {
	sec       int64
	inspected uint64
	slow      uint64
}

// window — скользящее окно по секундам: кольцо из windowSeconds корзин.
// Память постоянная, сколько бы запросов ни было.
type window struct {
	b [windowSeconds]bucket
}

func (w *window) add(now time.Time, slow bool) {
	sec := now.Unix()
	i := sec % windowSeconds
	if w.b[i].sec != sec {
		// Корзина осталась от прошлого оборота кольца — обнуляем.
		w.b[i] = bucket{sec: sec}
	}
	w.b[i].inspected++
	if slow {
		w.b[i].slow++
	}
}

// sum — сколько проверок и медленных за последние span секунд, включая
// текущую.
func (w *window) sum(now time.Time, span int64) (inspected, slow uint64) {
	sec := now.Unix()
	for _, b := range w.b {
		if b.sec > sec-span && b.sec <= sec {
			inspected += b.inspected
			slow += b.slow
		}
	}
	return inspected, slow
}

// Transition — смена режима. Возвращается тому, кто её вызвал, чтобы
// записать событие и строку в лог уже вне блокировки.
type Transition struct {
	// Degraded — новый режим: true — частичное обнаружение.
	Degraded bool
	// Inspected и Slow — счётчики окна, по которым принято решение.
	Inspected, Slow uint64
	// Duration — сколько длился режим, из которого вышли.
	Duration time.Duration
}

// controller решает, проверять ли запрос, и переключает режим.
//
// Блокировка берётся на каждую проверку: запись в окно и решение о смене
// режима должны быть согласованы. Для сотен и тысяч запросов в секунду
// это десятки наносекунд; замер под нагрузкой — на шаге 11.
type controller struct {
	// degraded читается без блокировки на каждом запросе: в обычном
	// режиме решение «проверять» не должно ждать чужую блокировку.
	degraded atomic.Bool
	sample   atomic.Uint64

	mu    sync.Mutex
	since time.Time
	win   window
}

func newController(now time.Time) *controller {
	return &controller{since: now}
}

// shouldInspect — проверять ли этот запрос. В частичном режиме заодно
// проверяет, не пора ли выйти: при слабом трафике запросов с результатом
// проверки мало, и выход по одному record ждал бы слишком долго.
func (c *controller) shouldInspect(now time.Time) (bool, *Transition) {
	if !c.degraded.Load() {
		return true, nil
	}
	c.mu.Lock()
	tr := c.maybeRecover(now)
	c.mu.Unlock()
	if tr != nil {
		return true, tr
	}
	return c.sample.Add(1)%SampleEvery == 0, nil
}

// record учитывает результат проверки и, если пора, меняет режим.
func (c *controller) record(now time.Time, slow bool) *Transition {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.win.add(now, slow)

	if c.degraded.Load() {
		return c.maybeRecover(now)
	}
	inspected, slowN := c.win.sum(now, enterWindow)
	if inspected >= enterMinInspected && slowN*100 >= inspected*enterSlowPercent {
		c.degraded.Store(true)
		tr := &Transition{Degraded: true, Inspected: inspected, Slow: slowN, Duration: now.Sub(c.since)}
		c.since = now
		return tr
	}
	return nil
}

// maybeRecover выходит из частичного режима, если условия выхода
// выполнены. Вызывается под блокировкой.
func (c *controller) maybeRecover(now time.Time) *Transition {
	if !c.degraded.Load() || now.Sub(c.since) < minDegraded {
		return nil
	}
	inspected, slow := c.win.sum(now, exitWindow)
	// Нет проверок за 30 секунд — нет и нагрузки: трафик ушёл, держать
	// частичный режим незачем.
	if inspected > 0 && slow*100 >= inspected*exitSlowPercent {
		return nil
	}
	c.degraded.Store(false)
	tr := &Transition{Degraded: false, Inspected: inspected, Slow: slow, Duration: now.Sub(c.since)}
	c.since = now
	return tr
}
