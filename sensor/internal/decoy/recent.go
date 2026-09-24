package decoy

import (
	"sync"
	"time"
)

// Касание cookie-ловушки — состояние браузера, а не действие: изменённая
// cookie уходит с каждым запросом, и одна открытая страница — это десятки
// касаний (скрипты, стили, запросы к API). Найдено при проверке в браузере:
// одна правка cookie в Juice Shop дала 30 событий high на одну страницу.
//
// Поэтому в событиях — первое касание от клиента за cookieTouchWindow,
// а все касания — в счётчике sensor_cookie_touches_total. Касания ловушек
// на путях не прореживаются: каждое из них — отдельный запрос атакующего.
const (
	cookieTouchWindow = time.Minute

	// maxRecentTouches — предел памяти на запоминание. Ключи — адреса
	// клиентов, и атакующий с множеством адресов может заполнить таблицу.
	// Тогда она очищается, и события снова пишутся на каждое касание:
	// переполнение даёт лишние события, но никогда — пропущенные.
	maxRecentTouches = 4096
)

type touchKey struct {
	client, decoyID string
}

// recentTouches помнит, когда записано последнее касание для пары
// «клиент, ловушка».
type recentTouches struct {
	mu   sync.Mutex
	seen map[touchKey]time.Time
	now  func() time.Time
}

func newRecentTouches() *recentTouches {
	return &recentTouches{seen: map[touchKey]time.Time{}, now: time.Now}
}

// first — нужно ли записать касание событием: для этой пары его не было
// дольше cookieTouchWindow. Клиент с неизвестным адресом (цепочка прокси
// оборвана) не прореживается: без адреса не понять, тот же ли это клиент.
func (r *recentTouches) first(client, decoyID string) bool {
	if client == "" {
		return true
	}
	key := touchKey{client, decoyID}
	now := r.now()

	r.mu.Lock()
	defer r.mu.Unlock()
	if last, ok := r.seen[key]; ok && now.Sub(last) < cookieTouchWindow {
		return false
	}
	if len(r.seen) >= maxRecentTouches {
		for k, t := range r.seen {
			if now.Sub(t) >= cookieTouchWindow {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= maxRecentTouches {
			clear(r.seen)
		}
	}
	r.seen[key] = now
	return true
}
