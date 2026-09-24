package forwarded

import (
	"crypto/tls"
	"net/http"
	"slices"
	"testing"
)

// outbound повторяет то, что делает сенсор: исходящий запрос получает
// копию заголовков входящего, и SetOutbound правит эту копию.
func outbound(t *testing.T, in *http.Request) http.Header {
	t.Helper()
	out := in.Header.Clone()
	SetOutbound(out, in, testResolver(t).Resolve(in))
	return out
}

// spoofable — заголовки, которыми клиент мог бы рассказать приложению
// о «себе» и об исходном запросе. Ключи — как их запишет сервер Go.
var spoofable = map[string]string{
	"X-Forwarded-Port":    "443",
	"X-Forwarded-Prefix":  "/evil",
	"X-Forwarded-Ssl":     "on",
	"X-Forwarded-Server":  "evil.example",
	"X-Real-Ip":           spoofedIP,
	"True-Client-Ip":      spoofedIP,
	"Cf-Connecting-Ip":    spoofedIP,
	"X-Client-Ip":         spoofedIP,
	"X-Cluster-Client-Ip": spoofedIP,
	"Forwarded":           "for=" + spoofedIP,
	// Не о клиенте, а об исходном пути: приложение, которое им верит,
	// обработало бы другой путь, чем видят прокси и сенсор (ADR-0026).
	"X-Original-Url": "/admin",
	"X-Rewrite-Url":  "/admin",
}

// underscored — варианты с подчёркиванием. Сервер Go приводит имя к виду
// «X_forwarded_for»: для него это другой заголовок, а для CGI — тот же.
var underscored = map[string]string{
	"X_forwarded_for":   spoofedIP,
	"X_forwarded_proto": "https",
	"X_real_ip":         spoofedIP,
	"X_original_url":    "/admin",
}

func TestSetOutboundUntrustedPeer(t *testing.T) {
	t.Parallel()

	in := request(clientIP+":5555", spoofedIP)
	in.Host = "shop.example"
	in.Header.Set("X-Forwarded-Host", "evil.example")
	in.Header.Set("X-Forwarded-Proto", "https")
	for k, v := range spoofable {
		in.Header[k] = []string{v}
	}
	for k, v := range underscored {
		in.Header[k] = []string{v}
	}

	out := outbound(t, in)

	for k := range spoofable {
		if v, ok := out[k]; ok {
			t.Errorf("заголовок клиента дошёл до приложения: %s: %v", k, v)
		}
	}
	for k := range underscored {
		if v, ok := out[k]; ok {
			t.Errorf("вариант с подчёркиванием дошёл до приложения: %s: %v", k, v)
		}
	}
	assertHeader(t, out, "X-Forwarded-For", clientIP)
	assertHeader(t, out, "X-Forwarded-Host", "shop.example")
	assertHeader(t, out, "X-Forwarded-Proto", "http")
}

// TestSetOutboundUntrustedPeerTLS: схему сенсор берёт из своего
// соединения, а не из заголовка клиента.
func TestSetOutboundUntrustedPeerTLS(t *testing.T) {
	t.Parallel()

	in := request(clientIP + ":5555")
	in.TLS = &tls.ConnectionState{}
	out := outbound(t, in)
	assertHeader(t, out, "X-Forwarded-Proto", "https")
}

func TestSetOutboundTrustedPeer(t *testing.T) {
	t.Parallel()

	in := request(proxyNear+":40000", spoofedIP+", "+clientIP+", "+proxyFar)
	in.Host = "app.internal:8080"
	in.Header.Set("X-Forwarded-Host", "shop.example")
	in.Header.Set("X-Forwarded-Proto", "https")
	for k, v := range spoofable {
		in.Header[k] = []string{v}
	}
	for k, v := range underscored {
		in.Header[k] = []string{v}
	}

	out := outbound(t, in)

	// Утверждения доверенного прокси проходят как есть — кроме Forwarded.
	for k, v := range spoofable {
		if k == "Forwarded" {
			if _, ok := out[k]; ok {
				t.Errorf("Forwarded дошёл до приложения: сенсор его не поддерживает")
			}
			continue
		}
		assertHeader(t, out, k, v)
	}
	for k := range underscored {
		if v, ok := out[k]; ok {
			t.Errorf("вариант с подчёркиванием дошёл до приложения даже от доверенного прокси: %s: %v", k, v)
		}
	}

	// Цепочка без подставленного слева, плюс адрес прокси.
	assertHeader(t, out, "X-Forwarded-For", clientIP+", "+proxyFar+", "+proxyNear)
	assertHeader(t, out, "X-Forwarded-Host", "shop.example")
	assertHeader(t, out, "X-Forwarded-Proto", "https")
}

// TestSetOutboundTrustedPeerDefaults: доверенный прокси не прислал
// Host и Proto — сенсор ставит свои, как для обычного клиента.
func TestSetOutboundTrustedPeerDefaults(t *testing.T) {
	t.Parallel()

	in := request(proxyNear+":40000", clientIP)
	in.Host = "shop.example"
	out := outbound(t, in)

	assertHeader(t, out, "X-Forwarded-For", clientIP+", "+proxyNear)
	assertHeader(t, out, "X-Forwarded-Host", "shop.example")
	assertHeader(t, out, "X-Forwarded-Proto", "http")
}

// TestSetOutboundCopiesValues: исходящий запрос не делит память с входящим.
func TestSetOutboundCopiesValues(t *testing.T) {
	t.Parallel()

	in := request(proxyNear+":40000", clientIP)
	in.Header.Set("X-Forwarded-Proto", "https")
	out := outbound(t, in)

	out["X-Forwarded-Proto"][0] = "changed"
	if got := in.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Errorf("правка исходящего запроса изменила входящий: %q", got)
	}
}

// TestSetOutboundUnknownPeer: адрес соединения не разобран — лучше
// без X-Forwarded-For, чем с выдуманным.
func TestSetOutboundUnknownPeer(t *testing.T) {
	t.Parallel()

	in := request("not-an-address", spoofedIP)
	out := outbound(t, in)
	if v, ok := out["X-Forwarded-For"]; ok {
		t.Errorf("X-Forwarded-For = %v, ожидалось отсутствие", v)
	}
}

func assertHeader(t *testing.T, h http.Header, name, want string) {
	t.Helper()
	if got := h.Values(name); !slices.Equal(got, []string{want}) {
		t.Errorf("%s = %q, ожидалось [%q]", name, got, want)
	}
}

// TestHTTPS: о схеме судим по своему соединению или по заголовку
// доверенного прокси, но не по заголовку клиента.
func TestHTTPS(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		peer  string
		tls   bool
		proto []string
		want  bool
	}{
		{"клиент по HTTP", clientIP + ":5555", false, nil, false},
		{"клиент по HTTP выдаёт себя за HTTPS", clientIP + ":5555", false, []string{"https"}, false},
		{"TLS снял сенсор", clientIP + ":5555", true, nil, true},
		{"доверенный прокси: https", proxyNear + ":40000", false, []string{"https"}, true},
		{"доверенный прокси: HTTPS в другом регистре", proxyNear + ":40000", false, []string{" HTTPS "}, true},
		{"доверенный прокси: http", proxyNear + ":40000", false, []string{"http"}, false},
		{"доверенный прокси: цепочка, первым http", proxyNear + ":40000", false, []string{"http, https"}, false},
		{"доверенный прокси: цепочка, первым https", proxyNear + ":40000", false, []string{"https, http"}, true},
		{"доверенный прокси без заголовка", proxyNear + ":40000", false, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := request(tc.peer)
			if tc.tls {
				in.TLS = &tls.ConnectionState{}
			}
			if tc.proto != nil {
				in.Header["X-Forwarded-Proto"] = tc.proto
			}
			if got := HTTPS(in, testResolver(t).Resolve(in)); got != tc.want {
				t.Errorf("HTTPS = %v, ожидалось %v", got, tc.want)
			}
		})
	}
}
