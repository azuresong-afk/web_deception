// Package decoy — обнаружение по политике: ловушки на путях.
//
// Detector встаёт внутрь failopen.Guard (ADR-0024): упал или перегружен —
// запрос идёт в приложение. Loader читает политику из файла и заменяет её
// в Detector целиком; неверная политика не применяется, сенсор остаётся
// на последней валидной (ADR-0025).
//
// Граница доверия: путь запроса — от атакующего. Он только сравнивается
// с путями ловушек после нормализации; в ответ ловушки из запроса
// не попадает ничего — ответ целиком из политики.
package decoy

import (
	"net/http"
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
}

// Detector сравнивает путь запроса с ловушками текущей политики.
type Detector struct {
	// current — текущая политика. Заменяется целиком одной атомарной
	// операцией: запрос видит либо старую политику, либо новую, но никогда
	// половину той и другой.
	current atomic.Pointer[policy.Compiled]
	events  event.Emitter
	trust   *forwarded.Resolver

	Stats Stats
}

// New создаёт Detector без ловушек.
func New(events event.Emitter, trust *forwarded.Resolver) *Detector {
	d := &Detector{events: events, trust: trust}
	d.current.Store(policy.Empty())
	return d
}

// Swap заменяет политику.
func (d *Detector) Swap(c *policy.Compiled) { d.current.Store(c) }

// Current — текущая политика.
func (d *Detector) Current() *policy.Compiled { return d.current.Load() }

// Inspect проверяет запрос по договору failopen.Detector: сначала решает
// и записывает событие, потом пишет ответ; тело запроса не читает.
func (d *Detector) Inspect(w http.ResponseWriter, r *http.Request) bool {
	p := d.current.Load()
	trap, ok := p.Match(r.URL.Path)
	if !ok {
		return false
	}

	// Касание записывается при любом методе и в любом режиме: легитимным
	// пользователям на путях ловушек делать нечего (ADR-0011).
	ev := event.New(event.TypeDecoyTouch, severity(trap.Confidence))
	ev.Client = event.ClientFrom(d.trust.Resolve(r))
	ev.Request = event.RequestFrom(r)
	ev.Data = map[string]string{
		"decoy_id":       trap.ID,
		"mode":           string(trap.Mode),
		"confidence":     string(trap.Confidence),
		"policy_version": p.Version,
	}
	d.events.Emit(ev)

	if trap.Mode == policy.Observe {
		d.Stats.Observed.Add(1)
		return false
	}
	d.Stats.Enforced.Add(1)
	respond.Trap(w, trap.Response.Status, trap.Response.ContentType, trap.Response.Body)
	return true
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
