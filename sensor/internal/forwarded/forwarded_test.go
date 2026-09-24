package forwarded

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// Адреса из документационных диапазонов (RFC 5737, RFC 3849): они
// не принадлежат никому, и тест не может случайно совпасть с настоящим.
const (
	clientIP   = "203.0.113.7"   // настоящий клиент
	spoofedIP  = "198.51.100.66" // адрес, который подставляет атакующий
	proxyNear  = "10.0.0.1"      // доверенный прокси, ближайший к сенсору
	proxyFar   = "10.0.0.2"      // доверенный прокси, ближайший к клиенту
	clientIPv6 = "2001:db8::7"
)

func testResolver(t *testing.T) *Resolver {
	t.Helper()
	return NewResolver([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("fd00::/8"),
	})
}

func request(remoteAddr string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestResolve(t *testing.T) {
	t.Parallel()

	long := strings.TrimSuffix(strings.Repeat(proxyFar+", ", maxFields+1), ", ")

	tests := []struct {
		name       string
		remoteAddr string
		xff        []string
		wantAddr   string // "" — адрес клиента неизвестен
		wantVia    bool
		wantBroken bool
	}{
		// --- соединение не от доверенного прокси: заголовок не читается ---
		{
			name:       "клиент напрямую, без заголовка",
			remoteAddr: clientIP + ":5555",
			wantAddr:   clientIP,
		},
		{
			name:       "клиент напрямую подставил X-Forwarded-For",
			remoteAddr: clientIP + ":5555",
			xff:        []string{spoofedIP},
			wantAddr:   clientIP,
		},
		{
			name:       "клиент напрямую подставил адрес нашего прокси",
			remoteAddr: clientIP + ":5555",
			xff:        []string{proxyNear},
			wantAddr:   clientIP,
		},

		// --- соединение от доверенного прокси ---
		{
			name:       "прокси без заголовка: клиент — сам прокси",
			remoteAddr: proxyNear + ":40000",
			wantAddr:   proxyNear,
			wantVia:    true,
		},
		{
			name:       "один прокси",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{clientIP},
			wantAddr:   clientIP,
			wantVia:    true,
		},
		{
			name:       "атакующий дописал адрес слева — берём правый недоверенный",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{spoofedIP + ", " + clientIP},
			wantAddr:   clientIP,
			wantVia:    true,
		},
		{
			name:       "два прокси подряд",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{spoofedIP + ", " + clientIP + ", " + proxyFar},
			wantAddr:   clientIP,
			wantVia:    true,
		},
		{
			name:       "прокси добавил свою запись отдельной строкой заголовка",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{spoofedIP, clientIP + ", " + proxyFar},
			wantAddr:   clientIP,
			wantVia:    true,
		},
		{
			name:       "вся цепочка доверенная: клиент — самый левый",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{proxyFar + ", " + proxyNear},
			wantAddr:   proxyFar,
			wantVia:    true,
		},
		{
			name:       "пустые элементы и пробелы пропускаются",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{" \t" + clientIP + " ,, ,", ""},
			wantAddr:   clientIP,
			wantVia:    true,
		},

		// --- формы записи адреса ---
		{
			name:       "IPv4 с портом",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{clientIP + ":5555"},
			wantAddr:   clientIP,
			wantVia:    true,
		},
		{
			name:       "IPv6",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{clientIPv6},
			wantAddr:   clientIPv6,
			wantVia:    true,
		},
		{
			name:       "IPv6 в скобках",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{"[" + clientIPv6 + "]"},
			wantAddr:   clientIPv6,
			wantVia:    true,
		},
		{
			name:       "IPv6 в скобках с портом",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{"[" + clientIPv6 + "]:443"},
			wantAddr:   clientIPv6,
			wantVia:    true,
		},
		{
			name:       "IPv4 в записи IPv6 приводится к IPv4",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{"::ffff:" + clientIP},
			wantAddr:   clientIP,
			wantVia:    true,
		},
		{
			name:       "доверенный прокси в записи IPv6 опознаётся",
			remoteAddr: "[::ffff:" + proxyNear + "]:40000",
			xff:        []string{clientIP + ", ::ffff:" + proxyFar},
			wantAddr:   clientIP,
			wantVia:    true,
		},
		{
			name:       "доверенный прокси по IPv6",
			remoteAddr: "[fd00::1]:40000",
			xff:        []string{clientIP},
			wantAddr:   clientIP,
			wantVia:    true,
		},

		// --- мусор: левее клиента не важен, правее — обрывает цепочку ---
		{
			name:       "мусор левее адреса клиента не читается",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{"<script>, unknown, " + clientIP},
			wantAddr:   clientIP,
			wantVia:    true,
		},
		{
			name:       "unknown от доверенного прокси обрывает цепочку",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{clientIP + ", unknown"},
			wantVia:    true,
			wantBroken: true,
		},
		{
			name:       "имя хоста вместо адреса",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{"client.example"},
			wantVia:    true,
			wantBroken: true,
		},
		{
			name:       "IPv6 с зоной",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{"fe80::1%eth0"},
			wantVia:    true,
			wantBroken: true,
		},
		{
			name:       "IPv4 в квадратных скобках",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{"[" + clientIP + "]"},
			wantVia:    true,
			wantBroken: true,
		},
		{
			name:       "адрес с лишними символами",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{clientIP + "x"},
			wantVia:    true,
			wantBroken: true,
		},
		{
			name:       "неразрывный пробел не считается пробелом",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{" " + clientIP},
			wantVia:    true,
			wantBroken: true,
		},
		{
			name:       "слишком длинная запись",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{strings.Repeat("1", maxHopLen+1)},
			wantVia:    true,
			wantBroken: true,
		},
		{
			name:       "цепочка из доверенных адресов длиннее предела",
			remoteAddr: proxyNear + ":40000",
			xff:        []string{long},
			wantVia:    true,
			wantBroken: true,
		},

		// --- адрес соединения ---
		{
			name:       "адрес соединения не разобран",
			remoteAddr: "not-an-address",
			xff:        []string{clientIP},
		},
	}

	res := testResolver(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := res.Resolve(request(tt.remoteAddr, tt.xff...))

			gotAddr := ""
			if got.Addr.IsValid() {
				gotAddr = got.Addr.String()
			}
			if gotAddr != tt.wantAddr {
				t.Errorf("Addr = %q, ожидался %q", gotAddr, tt.wantAddr)
			}
			if got.ViaTrustedProxy != tt.wantVia {
				t.Errorf("ViaTrustedProxy = %v, ожидался %v", got.ViaTrustedProxy, tt.wantVia)
			}
			if got.ChainBroken != tt.wantBroken {
				t.Errorf("ChainBroken = %v, ожидался %v", got.ChainBroken, tt.wantBroken)
			}
		})
	}
}

// TestResolveNoTrustedProxies: без списка доверенных прокси заголовок
// не читается даже с localhost — «доверять никому» значит никому.
func TestResolveNoTrustedProxies(t *testing.T) {
	t.Parallel()

	got := NewResolver(nil).Resolve(request("127.0.0.1:40000", clientIP))
	if got.Addr.String() != "127.0.0.1" || got.ViaTrustedProxy {
		t.Errorf("Addr = %s, ViaTrustedProxy = %v; ожидался адрес соединения без доверия", got.Addr, got.ViaTrustedProxy)
	}
}

// TestResolveChain: приложению уходит только проверенная часть цепочки.
func TestResolveChain(t *testing.T) {
	t.Parallel()

	res := testResolver(t)
	tests := []struct {
		name string
		xff  []string
		want string
	}{
		{"подставленное слева отброшено", []string{spoofedIP + ", " + clientIP + ", " + proxyFar}, clientIP + ", " + proxyFar},
		{"оборванная цепочка: только доверенная часть", []string{clientIP + ", unknown, " + proxyFar}, proxyFar},
		{"запись приведена к каноническому виду", []string{"[2001:DB8:0::7]:443"}, clientIPv6},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := res.Resolve(request(proxyNear+":40000", tt.xff...))
			parts := make([]string, 0, len(got.chain))
			for _, a := range got.chain {
				parts = append(parts, a.String())
			}
			if s := strings.Join(parts, ", "); s != tt.want {
				t.Errorf("проверенная цепочка = %q, ожидалась %q", s, tt.want)
			}
		})
	}
}

// FuzzResolve: разбор не паникует на любом заголовке, а найденный адрес
// клиента — всегда либо адрес соединения, либо адрес, который реально
// есть в проверенной цепочке.
func FuzzResolve(f *testing.F) {
	for _, seed := range []string{
		clientIP,
		spoofedIP + ", " + clientIP + ", " + proxyFar,
		"[2001:db8::7]:443, ::ffff:10.0.0.2",
		"unknown,,, ,\t",
		"fe80::1%eth0",
		strings.Repeat(",", 100),
	} {
		f.Add(proxyNear+":40000", seed)
	}

	res := NewResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
	f.Fuzz(func(t *testing.T, remoteAddr, xff string) {
		c := res.Resolve(request(remoteAddr, xff))

		if !c.Addr.IsValid() {
			return
		}
		if c.Addr == c.Peer {
			return
		}
		if !c.ViaTrustedProxy || len(c.chain) == 0 || c.chain[0] != c.Addr {
			t.Fatalf("адрес клиента %s не взят ни из соединения, ни из проверенной цепочки %v", c.Addr, c.chain)
		}
	})
}
