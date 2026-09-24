package forwarded

import (
	"net/http"
	"slices"
	"strings"
)

const (
	headerXFH = "X-Forwarded-Host"
	headerXFP = "X-Forwarded-Proto"
)

// clientIPHeaders — заголовки с «настоящим IP клиента» от отдельных
// прокси и CDN. Сенсор их не читает, но передаёт приложению только от
// доверенного прокси: приложение, настроенное верить, например, X-Real-IP,
// иначе поверило бы значению, которое подставил атакующий (угроза T1).
// Имена — в нормализованном виде, см. normalizeName.
var clientIPHeaders = map[string]bool{
	"x-real-ip":           true,
	"true-client-ip":      true,
	"cf-connecting-ip":    true,
	"x-client-ip":         true,
	"x-cluster-client-ip": true,
}

// SetOutbound выставляет заголовки о клиенте в запросе, который сенсор
// отправляет приложению. out — заголовки исходящего запроса, in — входящий
// запрос, c — результат Resolve для него.
//
// Правило одно: о клиенте и исходном запросе приложению сообщает либо
// доверенный прокси, либо сам сенсор, но никогда не клиент.
//
//   - Соединение не от доверенного прокси. Удаляются все X-Forwarded-*
//     (не только For, Host и Proto, которые удаляет ReverseProxy, но и Port,
//     Prefix, Ssl и любые другие), Forwarded и заголовки из clientIPHeaders.
//     X-Forwarded-For, -Host и -Proto сенсор выставляет сам по соединению.
//   - Соединение от доверенного прокси. Его заголовки проходят как есть:
//     это утверждения нашего прокси, а сенсор должен быть прозрачным
//     (без X-Forwarded-Proto от балансировщика, снявшего TLS, приложение
//     решило бы, что запрос пришёл по HTTP, и зациклилось бы на
//     перенаправлении на HTTPS). X-Forwarded-For пересобирается:
//     проверенная часть цепочки и адрес прокси — без того, что левее
//     адреса клиента, то есть без подставленного атакующим.
//
// Независимо от доверия всегда удаляются:
//   - варианты этих заголовков с подчёркиванием (X_Forwarded_For): Go
//     считает их другим заголовком, а часть серверов приложений (CGI,
//     PHP-FPM, некоторые WSGI-серверы) — тем же самым, потому что
//     переводит «-» в «_». Настоящие прокси подчёркиваний не пишут;
//   - Forwarded (RFC 7239): сенсор его не разбирает и не дописывает,
//     и пропускать его от прокси значило бы передать приложению цепочку
//     без проверки и без сенсора в ней (ADR-0022).
func SetOutbound(out http.Header, in *http.Request, c Client) {
	for name := range out {
		norm := normalizeName(name)
		if !isForwardingHeader(norm) {
			continue
		}
		switch {
		case !c.ViaTrustedProxy,
			// Имя не в канонической записи: в запросе, разобранном
			// сервером Go, так выглядят только имена с подчёркиванием.
			name != http.CanonicalHeaderKey(norm),
			norm == "forwarded",
			// Эти три сенсор выставляет ниже сам.
			norm == "x-forwarded-for", norm == "x-forwarded-host", norm == "x-forwarded-proto":
			delete(out, name)
		}
	}

	// Адрес соединения не разобран — значит, сказать о клиенте нечего.
	// Лучше без X-Forwarded-For, чем с выдуманным значением.
	if c.Peer.IsValid() {
		var b strings.Builder
		for _, a := range c.chain {
			b.WriteString(a.String())
			b.WriteString(", ")
		}
		b.WriteString(c.Peer.String())
		out.Set(headerXFF, b.String())
	}

	// Host и Proto от доверенного прокси — его значения; иначе — наши.
	// Заголовки клиента читаем, только если соединение от доверенного прокси.
	if v := trustedValues(in, c, headerXFH); v != nil {
		out[headerXFH] = v
	} else if in.Host != "" {
		out.Set(headerXFH, in.Host)
	}

	if v := trustedValues(in, c, headerXFP); v != nil {
		out[headerXFP] = v
	} else if in.TLS != nil {
		out.Set(headerXFP, "https")
	} else {
		out.Set(headerXFP, "http")
	}
}

// trustedValues возвращает копию значений заголовка входящего запроса,
// если соединение пришло от доверенного прокси и заголовок есть.
//
// Копия, а не исходный срез: иначе исходящий и входящий запросы делили бы
// одну память, и правка одного незаметно меняла бы другой.
func trustedValues(in *http.Request, c Client, name string) []string {
	if !c.ViaTrustedProxy {
		return nil
	}
	v := in.Header.Values(name)
	if len(v) == 0 {
		return nil
	}
	return slices.Clone(v)
}

// normalizeName приводит имя заголовка к виду, в котором сравниваем:
// нижний регистр, «_» заменено на «-».
func normalizeName(name string) string {
	return strings.ToLower(strings.ReplaceAll(name, "_", "-"))
}

// isForwardingHeader — заголовок сообщает о клиенте или исходном запросе.
// norm — имя после normalizeName.
func isForwardingHeader(norm string) bool {
	return norm == "forwarded" ||
		strings.HasPrefix(norm, "x-forwarded-") ||
		clientIPHeaders[norm]
}
