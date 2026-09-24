package proxy

import (
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// acceptLoop принимает соединения в канал, пока слушатель не закроют.
func acceptLoop(ln net.Listener) <-chan net.Conn {
	out := make(chan net.Conn, 16)
	go func() {
		defer close(out)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			out <- c
		}
	}()
	return out
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func expectAccepted(t *testing.T, accepted <-chan net.Conn, what string) net.Conn {
	t.Helper()
	select {
	case c := <-accepted:
		return c
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: соединение не принято", what)
	}
	return nil
}

func expectNotAccepted(t *testing.T, accepted <-chan net.Conn, what string) {
	t.Helper()
	select {
	case c := <-accepted:
		_ = c.Close()
		t.Fatalf("%s: соединение принято сверх предела", what)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestLimitListenerWaitsAtLimit: сверх предела соединение ждёт, а как только
// место освобождается — принимается.
func TestLimitListenerWaitsAtLimit(t *testing.T) {
	t.Parallel()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var saturated atomic.Int32
	ln := LimitListener(base, 1, func() { saturated.Add(1) })
	t.Cleanup(func() { _ = ln.Close() })
	accepted := acceptLoop(ln)

	dial(t, base.Addr().String())
	first := expectAccepted(t, accepted, "первое")

	dial(t, base.Addr().String())
	expectNotAccepted(t, accepted, "второе при занятом месте")
	if saturated.Load() == 0 {
		t.Error("onSaturated не вызван, хотя соединение ждёт")
	}

	_ = first.Close()
	expectAccepted(t, accepted, "второе после освобождения места")
}

// TestLimitListenerCloseUnblocksAccept: закрытие слушателя будит Accept,
// ждущий свободного места. Иначе остановка сенсора под нагрузкой зависла бы.
func TestLimitListenerCloseUnblocksAccept(t *testing.T) {
	t.Parallel()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := LimitListener(base, 1, nil)

	dial(t, base.Addr().String())
	first, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()

	errCh := make(chan error, 1)
	go func() {
		_, err := ln.Accept() // место занято — ждёт
		errCh <- err
	}()
	time.Sleep(100 * time.Millisecond)
	_ = ln.Close()

	select {
	case err := <-errCh:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept после закрытия вернул %v, ожидался net.ErrClosed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Accept не проснулся после закрытия слушателя")
	}
}

// TestLimitConnDoubleCloseReleasesOnce: повторное закрытие соединения
// не освобождает чужое место — иначе предел перестал бы соблюдаться.
func TestLimitConnDoubleCloseReleasesOnce(t *testing.T) {
	t.Parallel()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := LimitListener(base, 1, nil)
	t.Cleanup(func() { _ = ln.Close() })
	accepted := acceptLoop(ln)

	dial(t, base.Addr().String())
	first := expectAccepted(t, accepted, "первое")
	_ = first.Close()
	_ = first.Close() // второе закрытие не должно освободить ещё одно место

	dial(t, base.Addr().String())
	expectAccepted(t, accepted, "второе")

	dial(t, base.Addr().String())
	expectNotAccepted(t, accepted, "третье при пределе 1")
}

// lineCounter считает строки лога.
type lineCounter struct {
	mu    sync.Mutex
	lines []string
}

func (l *lineCounter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, string(p))
	return len(p), nil
}

// TestSaturationLoggerThrottles: тысяча ждущих соединений — одна строка
// в логе, а не тысяча.
func TestSaturationLoggerThrottles(t *testing.T) {
	t.Parallel()

	var out lineCounter
	notify := SaturationLogger(slog.New(slog.NewJSONHandler(&out, nil)), 1024)

	var wg sync.WaitGroup
	for range 1000 {
		wg.Go(notify)
	}
	wg.Wait()

	if len(out.lines) != 1 {
		t.Fatalf("строк в логе %d, ожидалась 1", len(out.lines))
	}
	if !strings.Contains(out.lines[0], `"max_conns":1024`) {
		t.Errorf("в сообщении нет предела: %s", out.lines[0])
	}
}
