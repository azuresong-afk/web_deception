// Package forwarded решает, кто клиент, и какие заголовки о клиенте
// передать приложению.
//
// Это единственное место в сенсоре, где разрешено читать X-Forwarded-For
// и подобные заголовки: их может прислать кто угодно, и верить им можно
// только тогда, когда их выставил один из доверенных прокси администратора
// (CLAUDE.md, раздел «Запрещено»; угроза T1). Правило Semgrep
// go-untrusted-forwarded-headers запрещает читать их где-либо ещё;
// этот пакет исключён из правила явно. Решение и альтернативы — ADR-0022.
//
// Граница доверия проходит здесь. Адрес TCP-соединения подделать нельзя:
// его сообщает ядро. Всё в заголовках прислал клиент или записал прокси
// по пути, и отличить одно от другого можно только по тому, кто стоит
// справа в цепочке.
package forwarded

import (
	"net/http"
	"net/netip"
	"strings"
)

const (
	// headerXFF — единственный заголовок, по которому сенсор определяет
	// адрес клиента. Его выставляют все распространённые балансировщики,
	// CDN и nginx; Forwarded (RFC 7239) и заголовки отдельных CDN
	// не поддерживаются намеренно — ADR-0022.
	headerXFF = "X-Forwarded-For"

	// maxFields — сколько элементов X-Forwarded-For разбираем справа
	// налево, считая пустые. Настоящие цепочки — 1–4 прокси. Длинная
	// цепочка из одних доверенных адресов — это петля между прокси или
	// ошибка настройки, а не клиент; предел не даёт тратить на неё время.
	maxFields = 32

	// maxHopLen — самая длинная запись, которую пытаемся разобрать.
	// IPv6 в полной форме с портом в квадратных скобках — около 50 символов.
	maxHopLen = 64
)

// Resolver знает, каким прокси администратор доверяет.
type Resolver struct {
	trusted []netip.Prefix
}

// NewResolver создаёт Resolver. Список приходит из конфигурации запуска
// (SENSOR_TRUSTED_PROXIES) и проверен там же; пустой список означает
// «не доверять никому» — адрес клиента всегда адрес соединения.
func NewResolver(trusted []netip.Prefix) *Resolver {
	return &Resolver{trusted: trusted}
}

// Client — что сенсор знает об отправителе запроса.
type Client struct {
	// Addr — адрес клиента: самый правый адрес, которому нельзя доверять
	// как прокси. Если соединение пришло не от доверенного прокси, это
	// адрес соединения.
	//
	// Нулевой (Addr.IsValid() == false), если клиента установить нельзя:
	// не разобран адрес соединения или цепочка оборвалась (ChainBroken).
	// Нулевой, а не «последний известный адрес», намеренно: последний
	// известный — это адрес нашего же прокси, и реакция по нему на этапе 4
	// заблокировала бы всех пользователей сразу.
	Addr netip.Addr

	// Peer — адрес TCP-соединения, из которого пришёл запрос.
	Peer netip.Addr

	// ViaTrustedProxy — соединение пришло от доверенного прокси,
	// и X-Forwarded-For разбирался.
	ViaTrustedProxy bool

	// ChainBroken — в X-Forwarded-For от доверенного прокси встретилась
	// запись, которую нельзя разобрать, или цепочка длиннее maxFields.
	// Доверенные прокси такого не пишут: это признак ошибки настройки,
	// и в событиях (шаг 6 этапа 2) он будет виден.
	ChainBroken bool

	// chain — проверенная часть X-Forwarded-For слева направо, без Peer:
	// адрес клиента (если найден) и доверенные прокси после него. Её,
	// с добавленным Peer, сенсор передаёт приложению.
	chain []netip.Addr
}

// Resolve определяет адрес клиента.
//
// Алгоритм — «самый правый недоверенный адрес». Каждый прокси дописывает
// в X-Forwarded-For справа адрес того, кто к нему подключился. Значит,
// запись справа от доверенного прокси написал он сам, и ей можно верить;
// всё левее первой недоверенной записи мог написать кто угодно, в том
// числе атакующий в собственном запросе. Поэтому идём справа налево
// и останавливаемся на первом адресе, который не принадлежит нашим прокси.
//
// Самый левый адрес, который берут наивные реализации, — ровно тот, что
// подставляет атакующий.
func (r *Resolver) Resolve(req *http.Request) Client {
	peer, ok := parsePeer(req.RemoteAddr)
	if !ok {
		return Client{}
	}
	c := Client{Addr: peer, Peer: peer}
	if !r.trusts(peer) {
		// Запрос пришёл не от нашего прокси: X-Forwarded-For написал
		// сам клиент, и читать его незачем.
		return c
	}
	c.ViaTrustedProxy = true

	// Values, а не Get: прокси может добавить свою запись отдельной
	// строкой заголовка, а не дописать в существующую. Строки идут
	// в порядке получения, поэтому разбираем их тоже с конца.
	values := req.Header.Values(headerXFF)

	// Проверенные адреса справа налево. Разворачиваем в конце.
	var verified []netip.Addr
	fields := 0
	for i := len(values) - 1; i >= 0; i-- {
		rest := values[i]
		for rest != "" {
			var field string
			rest, field = cutLast(rest)

			// Предел считаем до разбора и с пустыми элементами:
			// число итераций ограничено при любом содержимом.
			fields++
			if fields > maxFields {
				return c.broken(verified)
			}

			// Пробелы и табуляция вокруг элемента разрешены синтаксисом
			// списков HTTP. Другие пробельные символы — нет: такую запись
			// ParseAddr не разберёт, и цепочка оборвётся.
			field = strings.Trim(field, " \t")
			if field == "" {
				// Пустые элементы списка HTTP разрешает и велит пропускать.
				continue
			}

			addr, ok := parseHop(field)
			if !ok {
				return c.broken(verified)
			}
			verified = append(verified, addr)
			if !r.trusts(addr) {
				c.Addr = addr
				c.chain = reversed(verified)
				return c
			}
		}
	}

	// Все адреса цепочки — наши прокси. Запрос начался внутри доверенной
	// сети (например, проверка живости с балансировщика), и клиент — самый
	// левый адрес: его записал доверенный прокси. Если цепочки нет вовсе,
	// клиент — сам прокси, и Addr уже равен Peer.
	if len(verified) > 0 {
		c.Addr = verified[len(verified)-1]
	}
	c.chain = reversed(verified)
	return c
}

// broken отмечает оборванную цепочку. Проверенную часть сохраняем:
// её сенсор всё равно передаст приложению, а адрес клиента — неизвестен.
func (c Client) broken(verified []netip.Addr) Client {
	c.Addr = netip.Addr{}
	c.ChainBroken = true
	c.chain = reversed(verified)
	return c
}

// trusts сообщает, принадлежит ли адрес одному из доверенных прокси.
//
// Перебор списка: доверенных сетей единицы или десятки, а проверок на
// запрос — не больше maxFields. Дерево префиксов быстрее на тысячах
// записей, но потребовало бы зависимости или своего кода, где легко
// ошибиться.
func (r *Resolver) trusts(addr netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parsePeer разбирает адрес соединения вида "ip:port".
func parsePeer(remoteAddr string) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	return normalize(ap.Addr()), true
}

// parseHop разбирает одну запись X-Forwarded-For.
//
// Принимаем то, что пишут настоящие прокси: IP, IP с портом и IPv6
// в квадратных скобках с портом и без. Всё прочее — "unknown",
// обфусцированные имена из RFC 7239, имена хостов — обрывает цепочку:
// адресом клиента такая запись быть не может.
func parseHop(s string) (netip.Addr, bool) {
	if len(s) > maxHopLen {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		// "203.0.113.7:5555" и "[2001:db8::1]:443". ParseAddrPort сам
		// требует скобок для IPv6 и запрещает их для IPv4.
		ap, errPort := netip.ParseAddrPort(s)
		switch {
		case errPort == nil:
			addr = ap.Addr()
		case len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']':
			// "[2001:db8::1]" без порта.
			addr, err = netip.ParseAddr(s[1 : len(s)-1])
			if err != nil || !addr.Is6() {
				return netip.Addr{}, false
			}
		default:
			return netip.Addr{}, false
		}
	}
	// Зона IPv6 ("fe80::1%eth0") имеет смысл только внутри одной машины.
	// В заголовке от другого узла это ошибка, а не адрес.
	if addr.Zone() != "" {
		return netip.Addr{}, false
	}
	return normalize(addr), true
}

// normalize приводит адрес к виду, в котором его сравнивают с сетями.
//
// IPv4, записанный как IPv6 ("::ffff:10.0.0.1"), — тот же адрес, но
// netip.Prefix 10.0.0.0/8 его не содержит. Без Unmap такой адрес
// доверенного прокси не опознался бы, а адрес клиента в этой форме
// не совпал бы с тем же адресом в IPv4-записи.
//
// Зону у адреса соединения снимаем: Prefix.Contains для адреса с зоной
// всегда возвращает false.
func normalize(a netip.Addr) netip.Addr {
	return a.Unmap().WithZone("")
}

// cutLast отрезает последний элемент списка через запятую.
//
// Идём с конца, а не делим всю строку через strings.Split: заголовок
// может быть длиной в десятки килобайт, а нужны нам обычно один-два
// правых элемента. Split выделял бы память под каждый элемент,
// включая тысячи элементов, подставленных атакующим слева.
func cutLast(s string) (rest, field string) {
	i := strings.LastIndexByte(s, ',')
	if i < 0 {
		return "", s
	}
	return s[:i], s[i+1:]
}

// reversed возвращает адреса в обратном порядке, не трогая исходный срез.
func reversed(in []netip.Addr) []netip.Addr {
	if len(in) == 0 {
		return nil
	}
	out := make([]netip.Addr, len(in))
	for i, a := range in {
		out[len(in)-1-i] = a
	}
	return out
}
