package decoy

import (
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/azuresong-afk/web_deception/sensor/internal/event"
)

// fakeClock — часы, которые двигает тест.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

// TestCookieTouchDeduplicated: одна изменённая cookie уходит с каждым
// запросом страницы. В событиях — первое касание от клиента за минуту,
// в счётчике — все.
func TestCookieTouchDeduplicated(t *testing.T) {
	t.Parallel()

	d, events := newCrossSite(t)
	clock := &fakeClock{t: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)}
	d.recent.now = clock.now

	send := func(client string) {
		r := httptest.NewRequest("GET", "/main.js", nil)
		r.RemoteAddr = client + ":5555"
		r.Header.Set("Cookie", "user_role=admin")
		d.Inspect(httptest.NewRecorder(), r)
	}
	count := func() int { return len(events.ofType(event.TypeDecoyTouch)) }

	for range 30 {
		send("203.0.113.7")
	}
	if count() != 1 || d.Stats.CookieTouches.Load() != 30 {
		t.Fatalf("одна страница: событий %d, в счётчике %d; ожидалось 1 и 30", count(), d.Stats.CookieTouches.Load())
	}

	send("198.51.100.9") // другой клиент — своё событие
	if count() != 2 {
		t.Errorf("касание другого клиента не записано: событий %d", count())
	}

	clock.t = clock.t.Add(cookieTouchWindow - time.Second)
	send("203.0.113.7")
	if count() != 2 {
		t.Errorf("повтор внутри окна записан: событий %d", count())
	}
	clock.t = clock.t.Add(time.Second)
	send("203.0.113.7")
	if count() != 3 {
		t.Errorf("касание после окна не записано: событий %d", count())
	}
}

// TestRecentTouchesUnknownClient: адрес клиента неизвестен — прореживать
// не по чему, каждое касание записывается.
func TestRecentTouchesUnknownClient(t *testing.T) {
	t.Parallel()

	r := newRecentTouches()
	for i := range 2 {
		if !r.first("", "c") {
			t.Errorf("касание %d клиента без адреса прорежено", i+1)
		}
	}
}

// TestRecentTouchesBounded: таблица не растёт больше предела; переполнение
// даёт лишние события, но не пропущенные.
func TestRecentTouchesBounded(t *testing.T) {
	t.Parallel()

	clock := &fakeClock{t: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)}
	r := newRecentTouches()
	r.now = clock.now

	for i := range maxRecentTouches {
		if !r.first("ip-"+strconv.Itoa(i), "c") {
			t.Fatalf("новый клиент %d прорежен", i)
		}
	}
	if r.first("ip-0", "c") {
		t.Error("повтор до переполнения не прорежен")
	}

	// Половина записей истекла, половина свежая: при переполнении
	// вычищаются только истёкшие, свежие по-прежнему прореживают.
	clear(r.seen)
	for i := range maxRecentTouches / 2 {
		r.first("old-"+strconv.Itoa(i), "c")
	}
	clock.t = clock.t.Add(cookieTouchWindow)
	for i := range maxRecentTouches / 2 {
		r.first("fresh-"+strconv.Itoa(i), "c")
	}
	if !r.first("new-after-prune", "c") {
		t.Fatal("новый клиент прорежен")
	}
	if r.first("fresh-0", "c") {
		t.Error("свежая запись потеряна при очистке истёкших")
	}
	if len(r.seen) != maxRecentTouches/2+1 {
		t.Errorf("после очистки истёкших записей %d, ожидалось %d", len(r.seen), maxRecentTouches/2+1)
	}
	r.first("fresh", "c")

	// Все записи свежие, места нет — таблица очищается целиком.
	for i := range maxRecentTouches {
		r.first("burst-"+strconv.Itoa(i), "c")
	}
	if len(r.seen) > maxRecentTouches {
		t.Errorf("таблица выросла до %d", len(r.seen))
	}
	if !r.first("fresh", "c") {
		t.Error("после полной очистки касание прорежено — ожидалось лишнее событие, а не пропуск")
	}
}
