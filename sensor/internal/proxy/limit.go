package proxy

import (
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// LimitListener ограничивает число одновременно открытых соединений.
//
// Когда предел достигнут, новые соединения не отвергаются, а ждут
// в очереди ядра, пока освободится место. Это мягче отказа: при кратком
// всплеске клиент получит ответ чуть позже, а не ошибку. При атаке на
// исчерпание соединений сенсор перестаёт принимать новые, но не падает
// по памяти — а падение сенсора, стоящего в пути трафика, уронило бы сайт
// клиента целиком (угроза T3).
//
// Своя реализация вместо golang.org/x/net/netutil: это около сорока строк,
// и ради них не стоит тянуть в сенсор отдельный модуль с зависимостями
// (CLAUDE.md: каждая зависимость обосновывается).
//
// onSaturated вызывается каждый раз, когда соединению приходится ждать
// освобождения места. Вызов должен быть быстрым: он в пути Accept.
func LimitListener(l net.Listener, limit int, onSaturated func()) net.Listener {
	return &limitListener{
		Listener:    l,
		slots:       make(chan struct{}, limit),
		done:        make(chan struct{}),
		onSaturated: onSaturated,
	}
}

type limitListener struct {
	net.Listener

	// slots — семафор: канал ёмкостью limit. Занять место — положить
	// значение в канал, освободить — забрать. Когда канал полон,
	// положить нельзя, и Accept ждёт.
	slots       chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
	onSaturated func()
}

// acquire занимает место под соединение. Возвращает false, если слушатель
// закрыли, пока мы ждали, — иначе остановка сервера зависла бы на Accept.
func (l *limitListener) acquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
	}

	if l.onSaturated != nil {
		l.onSaturated()
	}

	select {
	case l.slots <- struct{}{}:
		return true
	case <-l.done:
		return false
	}
}

func (l *limitListener) release() { <-l.slots }

func (l *limitListener) Accept() (net.Conn, error) {
	if !l.acquire() {
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		l.release()
		return nil, err
	}
	return &limitConn{Conn: c, release: l.release}, nil
}

func (l *limitListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

// limitConn освобождает место при закрытии соединения — ровно один раз,
// сколько бы раз ни вызвали Close: иначе двойное закрытие освободило бы
// чужое место, и предел перестал бы соблюдаться.
type limitConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(c.release)
	return err
}

// saturationLogInterval — не чаще одного сообщения о насыщении в минуту.
const saturationLogInterval = time.Minute

// SaturationLogger возвращает функцию для onSaturated, которая пишет
// предупреждение в лог не чаще раза в минуту.
//
// Без ограничения частоты атака на исчерпание соединений превращалась бы
// ещё и в атаку на лог: сообщение на каждое ждущее соединение — это
// тысячи строк в секунду и заполненный диск.
func SaturationLogger(logger *slog.Logger, limit int) func() {
	var last atomic.Int64 // время последнего сообщения, секунды Unix
	return func() {
		now := time.Now().Unix()
		prev := last.Load()
		if now-prev < int64(saturationLogInterval/time.Second) {
			return
		}
		// CompareAndSwap: из множества одновременно ждущих соединений
		// сообщение напишет ровно одно.
		if !last.CompareAndSwap(prev, now) {
			return
		}
		logger.Warn("достигнут предел одновременных соединений: новые соединения ждут в очереди",
			slog.Int("max_conns", limit))
	}
}
