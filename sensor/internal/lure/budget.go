package lure

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"sync"
)

// Бюджет памяти правки тел (T3, ADR-0028, ADR-0029).
//
// Чтобы вставить наживку в страницу или robots.txt, сенсор читает начало
// ответа приложения в память и держит прочитанное, пока клиент его
// не заберёт. Медленный клиент держит его долго, а соединений у сенсора —
// до SENSOR_MAX_CONNS. Без общего предела тысяча медленных клиентов
// на странице без <body> (например, большой HTML-файл, загруженный
// в приложение самим атакующим) заняла бы сотни мегабайт, и сенсор упал бы
// по памяти. Падение процесса fail-open не покрывает (R1): сайт встал бы.
//
// Поэтому у всех правок тел вместе — один бюджет:
//   - до чтения правка занимает память на худший случай (замер —
//     TestEditReserves);
//   - после правки оставляет за собой ровно то, что ждёт отправки клиенту,
//     и возвращает это, когда прокси закрывает тело ответа;
//   - бюджета нет — ответ уходит как есть, без наживки. Страдает только
//     наживка, а не сайт; пропуск виден в метрике (reason="memory").
//
// Доля одного клиента — не больше clientMemory. Иначе один атакующий
// с сотней медленных соединений занял бы весь бюджет, и наживки пропали бы
// у всех (ADR-0029). Клиент — адрес после разбора доверенных прокси
// (ADR-0022), а у IPv6 — сеть /64: её целиком получает один абонент,
// и адресов в ней хватило бы на любое число «клиентов».

const (
	// editMemory — сколько памяти могут занимать все правки тел вместе:
	// четверть предела памяти контейнера сенсора в стенде (128 МиБ).
	// Остальное — буферы соединений, события, политика.
	editMemory = 32 << 20
	// clientMemory — доля одного клиента: чтобы занять весь бюджет,
	// нужно не меньше восьми адресов. Не меньше robotsReserve — иначе
	// robots.txt не дополнялся бы никогда.
	clientMemory = editMemory / 8
)

// memBudget — занятая память: всего и по клиентам. Под одной блокировкой:
// общий предел и доля клиента проверяются и меняются вместе. Блокировка
// короткая — несколько сложений на правку, а не на каждый запрос.
type memBudget struct {
	mu        sync.Mutex
	used      int64
	perClient map[netip.Addr]int64
}

// EditMemory — сколько байт сейчас держат правки тел: для метрики.
// Когда ответы отправлены, здесь 0; рост без возврата — утечка.
func (inj *Injector) EditMemory() uint64 {
	inj.mem.mu.Lock()
	defer inj.mem.mu.Unlock()
	return uint64(max(inj.mem.used, 0))
}

// lease занимает n байт для клиента. nil — не хватает общего бюджета
// или доли клиента; ничего не занято.
func (b *memBudget) lease(client netip.Addr, n int64) *lease {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > editMemory || b.perClient[client]+n > clientMemory {
		return nil
	}
	if b.perClient == nil {
		b.perClient = make(map[netip.Addr]int64)
	}
	b.used += n
	b.perClient[client] += n
	return &lease{budget: b, client: client, n: n}
}

// lease — память, занятая одной правкой.
type lease struct {
	budget *memBudget
	client netip.Addr
	n      int64
}

// shrink оставляет за правкой keep байт, остальное возвращает.
func (l *lease) shrink(keep int64) {
	l.set(keep)
}

// release возвращает всё. Повторный вызов ничего не делает: тело могут
// закрыть дважды, а при панике память возвращает ещё и Modify.
func (l *lease) release() {
	l.set(0)
}

// set меняет занятое правкой на n и поправляет обе суммы. Клиент,
// за которым ничего не числится, удаляется из карты: её размер не больше
// числа ответов, которые сейчас в пути.
func (l *lease) set(n int64) {
	b := l.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	d := n - l.n
	l.n = n
	b.used += d
	if b.perClient[l.client] += d; b.perClient[l.client] == 0 {
		delete(b.perClient, l.client)
	}
}

// heldBody — тело ответа, за которым числится память из бюджета.
// Прокси закрывает тело, когда ответ отправлен или клиент ушёл, —
// тогда память возвращается.
type heldBody struct {
	io.Reader
	io.Closer
	mem *lease
}

func (b heldBody) Close() error {
	b.mem.release()
	return b.Closer.Close()
}

// clientKey — ключ контекста исходящего запроса: чей это ответ.
type clientKey struct{}

// withClient запоминает клиента в исходящем запросе: ответ приложения
// ссылается на этот запрос (resp.Request), и правка ответа узнаёт, из чьей
// доли брать память.
func withClient(out *http.Request, client netip.Addr) *http.Request {
	return out.WithContext(context.WithValue(out.Context(), clientKey{}, budgetKey(client)))
}

// clientOf — клиент ответа. Неизвестный клиент (оборванная цепочка
// прокси, ответ без запроса) — нулевой адрес: все такие делят одну долю.
func clientOf(resp *http.Response) netip.Addr {
	if resp.Request == nil {
		return netip.Addr{}
	}
	a, _ := resp.Request.Context().Value(clientKey{}).(netip.Addr)
	return a
}

// budgetKey — адрес, по которому считается доля: IPv4 как есть, IPv6 —
// сеть /64. IPv4, записанный как IPv6 (::ffff:1.2.3.4), — как IPv4.
func budgetKey(a netip.Addr) netip.Addr {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.Addr()
	}
	return a
}
