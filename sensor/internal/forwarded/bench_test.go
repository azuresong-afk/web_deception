package forwarded

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

// BenchmarkResolve — адрес клиента на каждом запросе (ADR-0030): прямое
// соединение и цепочка X-Forwarded-For от доверенного балансировщика.
func BenchmarkResolve(b *testing.B) {
	r := NewResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.RemoteAddr = "203.0.113.7:51234"
	chain := httptest.NewRequest(http.MethodGet, "/", nil)
	chain.RemoteAddr = "10.0.0.5:40000"
	chain.Header.Set("X-Forwarded-For", "198.51.100.9, 203.0.113.7, 10.0.0.4")

	for name, req := range map[string]*http.Request{"прямое соединение": direct, "через балансировщик": chain} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				r.Resolve(req)
			}
		})
	}
}
