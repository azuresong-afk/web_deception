package policy

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Наживка (lure) — то, что видит атакующий: строка в ответах приложения,
// которая ведёт к ловушке. Разные наживки ведут к разным ловушкам,
// поэтому по касанию видно, что именно прочитал атакующий: это цепочка
// «наживка → ловушка» (ADR-0027).
//
// Текст наживки не пишет администратор: он выбирает вид наживки и ловушку,
// а строку собирает сенсор по шаблону. В ответ сайту клиента из политики
// попадают только путь ловушки (уже проверенный) и имя заголовка из
// безопасного набора символов.

// LureKind — вид наживки.
type LureKind string

const (
	// LureHeader — заголовок ответа со ссылкой на ловушку:
	// «X-Debug-Trace: /internal/debug/trace».
	LureHeader LureKind = "header"
	// LureRobots — строка «Disallow: /путь» в robots.txt: честные роботы
	// путь обходят, а сканеры и атакующие читают robots.txt как карту.
	LureRobots LureKind = "robots_txt"
)

const (
	maxLures         = 16
	maxLureHeaderLen = 40
)

// Lure — наживка, как она записана в политике.
type Lure struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Kind        LureKind `json:"kind"`
	// Trap — id ловушки на пути, к которой ведёт наживка.
	Trap string `json:"trap"`
	// Header — имя заголовка; только для kind «header».
	Header string `json:"header"`

	// path — путь ловушки; подставляется при разборе политики.
	path string
}

// Path — путь ловушки, к которой ведёт наживка.
func (l *Lure) Path() string { return l.path }

var (
	// Имя заголовка-наживки: «X-» и слова из латиницы и цифр через дефис.
	lureHeaderRe = regexp.MustCompile(`^X-[A-Za-z0-9]+(-[A-Za-z0-9]+)*$`)

	// trapRefRe — ссылка на ловушку в теле ответа другой ловушки:
	// «{{trap:api-export}}» заменяется на путь ловушки api-export.
	// Так фейковая документация ведёт к фейковому методу, и путь в тексте
	// не разойдётся с путём ловушки после правки политики.
	trapRefRe = regexp.MustCompile(`\{\{trap:([a-z0-9][a-z0-9-]*)\}\}`)
)

const trapRefPrefix = "{{trap:"

// deniedLureHeaders — начала имён заголовков, которые нельзя сделать
// наживкой: их понимают браузеры, прокси перед сенсором или само
// приложение. Например, «X-Accel-Redirect» от сенсора заставил бы nginx
// перед ним отдать внутренний файл, «X-Robots-Tag» — убрать сайт из
// поиска, а «X-Frame-Options» и «X-Content-Type-Options» — ослабить или
// сломать защиту страниц. Сравнение — без учёта регистра.
var deniedLureHeaders = []string{
	"x-forwarded-", "x-real-", "x-original-", "x-rewrite-", "x-client-", "x-cluster-",
	"x-accel-", "x-sendfile", "x-lighttpd-", "x-litespeed-",
	"x-frame-", "x-content-", "x-xss-", "x-permitted-", "x-dns-", "x-download-",
	"x-robots-", "x-ua-", "x-powered-by",
	"x-http-method", "x-method-", "x-csrf", "x-xsrf", "x-requested-with",
	"x-cache", "x-amz-", "x-goog-", "x-ms-", "x-envoy-",
}

// validateLures проверяет наживки и ссылки между ловушками. ids — уже
// занятые идентификаторы ловушек всех видов.
func validateLures(p *Policy, ids map[string]bool, add func(string, ...any)) {
	if len(p.Lures) > maxLures {
		add("lures: не больше %d наживок, получено %d", maxLures, len(p.Lures))
	}
	traps := map[string]*Trap{}
	for i := range p.Traps {
		traps[p.Traps[i].ID] = &p.Traps[i]
	}
	// referrer — кто ведёт к ловушке: наживка или тело другой ловушки.
	// Не больше одного: иначе по касанию не понять, откуда атакующий
	// узнал путь. Одна страница может упомянуть ловушку дважды.
	referrer := map[string]string{}
	refer := func(at, from, to string) {
		if prev, ok := referrer[to]; ok && prev != from {
			add("%s: к ловушке %q уже ведёт %q — по касанию было бы не понять, откуда атакующий узнал путь",
				at, to, prev)
			return
		}
		referrer[to] = from
	}

	headers := map[string]bool{}
	for i := range p.Lures {
		if i >= maxLures {
			break
		}
		l := &p.Lures[i]
		at := "lures[" + strconv.Itoa(i) + "]"

		if len(l.ID) > maxIDLen || !idRe.MatchString(l.ID) {
			add("%s.id: обязателен, до %d символов из a-z 0-9 -, начинается с буквы или цифры", at, maxIDLen)
		} else if ids[l.ID] {
			add("%s.id: %q уже есть", at, l.ID)
		}
		ids[l.ID] = true

		if len(l.Description) > maxDescriptionLen {
			add("%s.description: не длиннее %d байт", at, maxDescriptionLen)
		}

		switch l.Kind {
		case LureHeader:
			validateLureHeader(at, l.Header, headers, add)
		case LureRobots:
			if l.Header != "" {
				add("%s.header: только для kind «header»", at)
			}
		default:
			add("%s.kind: обязателен, header или robots_txt", at)
		}

		t, ok := traps[l.Trap]
		switch {
		case !ok:
			add("%s.trap: нет ловушки на пути с id %q", at, l.Trap)
			continue
		case t.PreflightOnly || (t.Methods != nil && !slices.Contains(t.Methods, "GET")):
			// Робот или человек, прочитавший наживку, откроет путь обычным
			// GET. Ловушка, которая на него не срабатывает, делает наживку
			// бесполезной, а политику — обманчивой.
			add("%s.trap: ловушка %q не срабатывает на обычный GET — наживка к ней бесполезна", at, l.Trap)
		case l.Kind == LureRobots && strings.ContainsAny(t.Path, "*$"):
			// В robots.txt «*» и «$» — шаблоны, и строка значила бы
			// не тот путь, что у ловушки.
			add("%s.trap: путь %q с «*» или «$» в robots.txt означал бы шаблон", at, t.Path)
		}
		refer(at+".trap", l.ID, l.Trap)
	}

	// Ссылки в телах ответов ловушек.
	for i := range p.Traps {
		t := &p.Traps[i]
		at := "traps[" + strconv.Itoa(i) + "].response.body"
		body := t.Response.Body
		matches := trapRefRe.FindAllStringSubmatch(body, -1)
		if strings.Count(body, trapRefPrefix) != len(matches) {
			add("%s: ссылка на ловушку записывается как {{trap:id}}, id из a-z 0-9 -", at)
		}
		size := len(body)
		for _, m := range matches {
			target, ok := traps[m[1]]
			switch {
			case !ok:
				add("%s: нет ловушки на пути с id %q", at, m[1])
				continue
			case target.ID == t.ID:
				add("%s: ловушка ссылается сама на себя", at)
				continue
			}
			size += len(target.Path) - len(m[0])
			refer(at, t.ID, target.ID)
		}
		// Предел тела — после подстановки путей: иначе тело из тысяч
		// коротких ссылок выросло бы в десятки раз (T15).
		if size > maxBodyBytes {
			add("%s: после подстановки путей больше %d байт", at, maxBodyBytes)
		}
	}
}

// validateLureHeader проверяет имя заголовка-наживки.
func validateLureHeader(at, name string, seen map[string]bool, add func(string, ...any)) {
	lower := strings.ToLower(name)
	switch {
	case name == "":
		add("%s.header: обязателен для kind «header»", at)
		return
	case len(name) > maxLureHeaderLen || !lureHeaderRe.MatchString(name):
		add("%s.header: до %d символов, «X-» и слова из A-Z a-z 0-9 через дефис", at, maxLureHeaderLen)
		return
	case seen[lower]:
		add("%s.header: заголовок %q уже занят другой наживкой", at, name)
		return
	}
	seen[lower] = true
	for _, denied := range deniedLureHeaders {
		if strings.HasPrefix(lower, denied) {
			add("%s.header: %q понимают браузеры, прокси или приложения — не годится для наживки", at, name)
			return
		}
	}
}

// compileLures подставляет пути ловушек в наживки и тела ответов
// и запоминает, кто к какой ловушке ведёт. Вызывается после validate:
// все ссылки уже проверены.
func compileLures(p *Policy, c *Compiled) {
	byID := make(map[string]*Trap, len(c.traps))
	for _, t := range c.traps {
		byID[t.ID] = t
	}
	for _, t := range c.traps {
		t.Response.Body = trapRefRe.ReplaceAllStringFunc(t.Response.Body, func(ref string) string {
			target := byID[trapRefRe.FindStringSubmatch(ref)[1]]
			target.lureID = t.ID
			return target.Path
		})
	}
	for i := range p.Lures {
		l := p.Lures[i]
		target := byID[l.Trap]
		l.path = target.Path
		target.lureID = l.ID
		c.lures = append(c.lures, &l)
		switch l.Kind {
		case LureHeader:
			c.headerLures = append(c.headerLures, &l)
		case LureRobots:
			c.robotsPaths = append(c.robotsPaths, target.Path)
		}
	}
}

// Lures — все наживки в порядке политики.
func (c *Compiled) Lures() []*Lure { return c.lures }

// HeaderLures — наживки-заголовки.
func (c *Compiled) HeaderLures() []*Lure { return c.headerLures }

// RobotsDisallow — пути для строк «Disallow» в robots.txt.
func (c *Compiled) RobotsDisallow() []string { return c.robotsPaths }
