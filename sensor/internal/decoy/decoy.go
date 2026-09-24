// Package decoy — обнаружение по политике: ловушки на путях
// и cookie-ловушки.
//
// Detector встаёт внутрь failopen.Guard (ADR-0024): упал или перегружен —
// запрос идёт в приложение. Loader читает политику из файла и заменяет её
// в Detector целиком; неверная политика не применяется, сенсор остаётся
// на последней валидной (ADR-0025).
//
// Граница доверия: путь, метод, Content-Type и cookie запроса — от
// атакующего. Они только сравниваются с политикой; в ответ ловушки и в
// Set-Cookie из запроса не попадает ничего — всё берётся из политики.
// Значение cookie не записывается никуда, даже изменённое: в событии только
// факт касания (CLAUDE.md, раздел «Запрещено»).
//
// Межсайтовые срабатывания (угроза T2) — ADR-0026.
package decoy

import (
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/azuresong-afk/web_deception/sensor/internal/event"
	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
	"github.com/azuresong-afk/web_deception/sensor/internal/policy"
	"github.com/azuresong-afk/web_deception/sensor/internal/respond"
)

// Stats — счётчики касаний для /metrics.
type Stats struct {
	// Enforced — касания, на которые ответила ловушка.
	Enforced atomic.Uint64
	// Observed — касания в режиме наблюдения: запрос ушёл в приложение.
	Observed atomic.Uint64
	// CookieTouches — запросы с изменённой cookie-наживкой. Все, а не только
	// записанные событием: события прорежены (recent.go).
	CookieTouches atomic.Uint64
	// CookieBaits — сколько раз сенсор выдал cookie-наживку.
	CookieBaits atomic.Uint64
	// PreflightsRefused — предварительные запросы CORS к ловушкам
	// с preflight_only, на которые сенсор ответил отказом.
	PreflightsRefused atomic.Uint64
}

// Detector сравнивает путь запроса с ловушками текущей политики.
type Detector struct {
	// current — текущая политика. Заменяется целиком одной атомарной
	// операцией: запрос видит либо старую политику, либо новую, но никогда
	// половину той и другой.
	current atomic.Pointer[policy.Compiled]
	events  event.Emitter
	trust   *forwarded.Resolver
	// recent прореживает события о касаниях cookie-ловушек (recent.go).
	recent *recentTouches

	Stats Stats
}

// New создаёт Detector без ловушек.
func New(events event.Emitter, trust *forwarded.Resolver) *Detector {
	d := &Detector{events: events, trust: trust, recent: newRecentTouches()}
	d.current.Store(policy.Empty())
	return d
}

// Swap заменяет политику.
func (d *Detector) Swap(c *policy.Compiled) { d.current.Store(c) }

// Current — текущая политика.
func (d *Detector) Current() *policy.Compiled { return d.current.Load() }

// Inspect проверяет запрос по договору failopen.Detector: сначала решает
// и записывает событие, потом пишет ответ; тело запроса не читает.
//
// Порядок:
//  1. cookie-ловушки — касание, если значение cookie изменено;
//  2. ловушка на пути — касание, если выполнены её условия; в режиме
//     enforce сенсор отвечает сам, и запрос дальше не идёт;
//  3. cookie-наживка — Set-Cookie к ответу приложения на переход
//     по странице, если у браузера этой cookie ещё нет.
func (d *Detector) Inspect(w http.ResponseWriter, r *http.Request) bool {
	p := d.current.Load()
	present := d.checkCookies(p, r)

	if trap, ok := p.Match(r.URL.Path); ok {
		if trap.PreflightOnly && trap.Mode == policy.Enforce && policy.IsCORSPreflight(r) {
			// Одобрения CORS не будет: без него браузер не отправит
			// «непростой» запрос с чужого сайта. Сам preflight — не касание:
			// его браузер отправляет автоматически (ADR-0026).
			d.Stats.PreflightsRefused.Add(1)
			respond.RefusePreflight(w)
			return true
		}
		if trap.Accepts(r) {
			d.touch(r, p, trap.ID, severity(trap.Confidence), map[string]string{
				"decoy_kind": "path",
				"mode":       string(trap.Mode),
				"confidence": string(trap.Confidence),
			})
			if trap.Mode == policy.Enforce {
				d.Stats.Enforced.Add(1)
				respond.Trap(w, trap.Response.Status, trap.Response.ContentType, trap.Response.Body)
				return true
			}
			d.Stats.Observed.Add(1)
		}
	}

	d.setBaits(w, r, p, present)
	return false
}

// touch записывает касание ловушки. Ключи data — константы из кода.
func (d *Detector) touch(r *http.Request, p *policy.Compiled, id string, sev event.Severity, data map[string]string) {
	d.emitTouch(r, event.ClientFrom(d.trust.Resolve(r)), p, id, sev, data)
}

func (d *Detector) emitTouch(r *http.Request, client *event.Client, p *policy.Compiled, id string,
	sev event.Severity, data map[string]string) {
	ev := event.New(event.TypeDecoyTouch, sev)
	ev.Client = client
	ev.Request = event.RequestFrom(r)
	data["decoy_id"] = id
	data["policy_version"] = p.Version
	ev.Data = data
	d.events.Emit(ev)
}

// checkCookies ищет в запросе cookie-ловушки. Изменённое значение —
// касание, одно на ловушку, сколько бы копий cookie ни пришло. Возвращает,
// какие из cookie-ловушек у браузера уже есть (с любым значением).
func (d *Detector) checkCookies(p *policy.Compiled, r *http.Request) map[string]bool {
	if len(p.Cookies()) == 0 || r.Header.Get("Cookie") == "" {
		return nil
	}
	present := make(map[string]bool, len(p.Cookies()))
	var touched map[string]bool
	// Разбирает стандартная библиотека: заголовок Cookie ограничен
	// MaxHeaderBytes сервера, число cookie — пределом самой библиотеки.
	// Cookie с недопустимым значением она отбрасывает; для нас это
	// «не изменена», то есть пропуск касания, а не ложное касание.
	for _, c := range r.Cookies() {
		trap, ok := p.CookieByName(c.Name)
		if !ok {
			continue
		}
		present[trap.Name] = true
		// Значение не секрет — сравнение за постоянное время не нужно.
		if c.Value != trap.Value && !touched[trap.Name] {
			if touched == nil {
				touched = map[string]bool{}
			}
			touched[trap.Name] = true
			d.Stats.CookieTouches.Add(1)
			client := event.ClientFrom(d.trust.Resolve(r))
			if !d.recent.first(client.IP, trap.ID) {
				continue
			}
			// Изменённое значение не записывается: это cookie, а значит,
			// в ней может оказаться что угодно, вплоть до чужого токена.
			d.emitTouch(r, client, p, trap.ID, severity(trap.Confidence), map[string]string{
				"decoy_kind": "cookie",
				"confidence": string(trap.Confidence),
			})
		}
	}
	return present
}

// setBaits выдаёт cookie-наживки, которых у браузера ещё нет.
//
// Только к ответу на переход по странице (GET документа): cookie попадёт
// в браузер пользователя при первом же открытии сайта, а ответы на запросы
// картинок, скриптов и API сенсор не трогает — в том числе потому, что
// CDN может не кэшировать ответ с Set-Cookie.
//
// Заголовок добавляется в ответ до того, как ReverseProxy скопирует в него
// заголовки приложения: они добавляются к нашим, а не заменяют их.
func (d *Detector) setBaits(w http.ResponseWriter, r *http.Request, p *policy.Compiled, present map[string]bool) {
	if len(p.Cookies()) == 0 || !isNavigation(r) {
		return
	}
	var secure, resolved bool
	for _, trap := range p.Cookies() {
		if present[trap.Name] {
			continue
		}
		if !resolved {
			secure = forwarded.HTTPS(r, d.trust.Resolve(r))
			resolved = true
		}
		w.Header().Add("Set-Cookie", trap.SetCookie(secure))
		d.Stats.CookieBaits.Add(1)
	}
}

// isNavigation — запрос открывает страницу: GET, и браузер сообщил режим
// navigate, а если Sec-Fetch-Mode нет (старый браузер или инструмент) —
// в Accept есть text/html.
func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// severity переводит уверенность приманки в важность события. critical
// не бывает никогда: он оставлен для событий о состоянии сенсора, и поток
// касаний не должен смешиваться с ними (ADR-0024).
func severity(c policy.Confidence) event.Severity {
	switch c {
	case policy.Medium:
		return event.SeverityMedium
	case policy.High, policy.VeryHigh:
		return event.SeverityHigh
	default:
		return event.SeverityLow
	}
}
