// Package policy — политика обнаружения: формат, строгая проверка,
// нормализация пути для сравнения с ловушками, загрузка из файла.
//
// Политика — данные, а не код (ADR-0018): сенсор понимает фиксированный
// набор конструкций, и администратор меняет их параметры. На шаге 8
// конструкция одна — ловушка на пути: запрос к этому пути — касание,
// а сенсор отвечает вместо приложения заданным ответом или только
// записывает касание (режим наблюдения).
//
// Граница доверия: политику пишет администратор, а с этапа 3 — control
// plane, который может быть взломан (угроза T15). Поэтому сенсор проверяет
// политику сам и строго: всё, что проверка пропустила, попадёт в ответы
// сайту клиента. Формат и решения — ADR-0025.
package policy

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/azuresong-afk/web_deception/sensor/internal/respond"
)

// SchemaVersion — версия формата, которую понимает этот сенсор. Политику
// другой версии сенсор не принимает: поле, которого он не знает, могло бы
// менять смысл правила.
const SchemaVersion = 1

// Пределы. Константы: политика приходит извне, и каждый предел — защита
// памяти и времени сенсора от ошибочной или вредоносной политики (T15).
const (
	MaxPolicyBytes    = 1 << 20 // 1 МиБ
	maxTraps          = 256
	maxIDLen          = 64
	maxVersionLen     = 64
	maxDescriptionLen = 256
	maxPathLen        = 256
	maxBodyBytes      = 64 << 10 // 64 КиБ
	// Сколько ошибок проверки перечислять. Остальные не нужны, чтобы
	// понять, что политика неверна, и раздули бы сообщение.
	maxReportedErrors = 20
)

// Mode — что делать при касании ловушки.
type Mode string

const (
	// Observe — только записать касание; запрос идёт в приложение. Так
	// новое правило проверяют на настоящем трафике, прежде чем оно начнёт
	// отвечать вместо приложения (ADR-0018).
	Observe Mode = "observe"
	// Enforce — записать и ответить вместо приложения.
	Enforce Mode = "enforce"
)

// Confidence — уверенность, что касание — атака, а не случайность.
type Confidence string

const (
	Low      Confidence = "low"
	Medium   Confidence = "medium"
	High     Confidence = "high"
	VeryHigh Confidence = "very_high"
)

// Policy — документ политики, как он записан в файле.
type Policy struct {
	SchemaVersion int `json:"schema_version"`
	// Version — метка версии от администратора; попадает в события,
	// чтобы по касанию было видно, какая политика сработала.
	Version string `json:"version"`
	Traps   []Trap `json:"traps"`
}

// Trap — ловушка на пути.
type Trap struct {
	// ID — имя ловушки в событиях: по нему видно, что именно трогали.
	ID          string     `json:"id"`
	Description string     `json:"description"`
	Path        string     `json:"path"`
	Mode        Mode       `json:"mode"`
	Confidence  Confidence `json:"confidence"`
	Response    Response   `json:"response"`
}

// Response — ответ ловушки в режиме enforce.
type Response struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
	// Символы пути ловушки: буквы, цифры и то, что допустимо в сегменте
	// пути по RFC 3986, кроме «;» (параметры сегмента) и «%» (путь записан
	// уже раскодированным).
	pathRe = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,=:@/-]*$`)
)

// Коды ответа ловушки. Без перенаправлений: 3xx с адресом из политики —
// это готовый открытый редирект на сайте клиента.
var allowedStatus = map[int]bool{200: true, 401: true, 403: true, 404: true, 500: true}

// Compiled — проверенная политика, готовая к сравнению путей.
// Не меняется после создания: сенсор заменяет её целиком.
type Compiled struct {
	Version string
	traps   map[string]*Trap
}

// Empty — политика без ловушек: обнаружения нет.
func Empty() *Compiled {
	return &Compiled{traps: map[string]*Trap{}}
}

// Len — число ловушек.
func (c *Compiled) Len() int { return len(c.traps) }

// Match ищет ловушку для пути запроса. requestPath — r.URL.Path,
// уже раскодированный из процентной записи.
func (c *Compiled) Match(requestPath string) (*Trap, bool) {
	t, ok := c.traps[NormalizePath(requestPath)]
	return t, ok
}

// Parse разбирает и проверяет политику. Любая ошибка — политика целиком
// не принимается: половина политики хуже, чем прежняя целиком.
func Parse(data []byte) (*Compiled, error) {
	if len(data) > MaxPolicyBytes {
		return nil, fmt.Errorf("политика больше %d байт", MaxPolicyBytes)
	}
	var p Policy
	// encoding/json/v2 строже прежнего encoding/json, и здесь это нужно:
	// повторяющийся ключ («mode» дважды), имя в другом регистре («Path»),
	// неизвестное поле, недопустимый UTF-8 и данные после документа — ошибка,
	// а не молча принятое значение.
	if err := json.Unmarshal(data, &p, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("политика не разбирается как JSON: %w", err)
	}
	if err := validate(&p); err != nil {
		return nil, err
	}
	c := &Compiled{Version: p.Version, traps: make(map[string]*Trap, len(p.Traps))}
	for i := range p.Traps {
		t := p.Traps[i]
		c.traps[t.Path] = &t
	}
	return c, nil
}

// validate проверяет политику целиком и возвращает все найденные ошибки
// (не больше maxReportedErrors): администратору удобнее исправить всё сразу.
func validate(p *Policy) error {
	var errs []error
	add := func(format string, args ...any) {
		if len(errs) < maxReportedErrors {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}

	if p.SchemaVersion != SchemaVersion {
		add("schema_version: этот сенсор понимает версию %d, получено %d", SchemaVersion, p.SchemaVersion)
	}
	if p.Version == "" || len(p.Version) > maxVersionLen || !versionRe.MatchString(p.Version) {
		add("version: обязательна, до %d символов из A-Z a-z 0-9 . _ : -", maxVersionLen)
	}
	if len(p.Traps) > maxTraps {
		add("traps: не больше %d ловушек, получено %d", maxTraps, len(p.Traps))
	}

	ids := map[string]bool{}
	paths := map[string]bool{}
	for i := range p.Traps {
		if i >= maxTraps {
			break
		}
		t := &p.Traps[i]
		at := "traps[" + strconv.Itoa(i) + "]"

		if len(t.ID) > maxIDLen || !idRe.MatchString(t.ID) {
			add("%s.id: обязателен, до %d символов из a-z 0-9 -, начинается с буквы или цифры", at, maxIDLen)
		} else if ids[t.ID] {
			add("%s.id: %q уже есть", at, t.ID)
		}
		ids[t.ID] = true

		if len(t.Description) > maxDescriptionLen {
			add("%s.description: не длиннее %d байт", at, maxDescriptionLen)
		}

		if err := validatePath(t.Path); err != nil {
			add("%s.path: %v", at, err)
		} else if paths[t.Path] {
			add("%s.path: %q уже занят другой ловушкой", at, t.Path)
		}
		paths[t.Path] = true

		if t.Mode != Observe && t.Mode != Enforce {
			add("%s.mode: обязателен, observe или enforce", at)
		}
		switch t.Confidence {
		case Low, Medium, High, VeryHigh:
		default:
			add("%s.confidence: обязательна, low, medium, high или very_high", at)
		}

		r := &t.Response
		if !allowedStatus[r.Status] {
			add("%s.response.status: допустимы 200, 401, 403, 404, 500", at)
		}
		if _, ok := respond.TrapContentTypes[r.ContentType]; !ok {
			add("%s.response.content_type: допустимы text/plain, application/json, application/octet-stream", at)
		}
		if len(r.Body) > maxBodyBytes {
			add("%s.response.body: не больше %d байт", at, maxBodyBytes)
		}
		if !utf8.ValidString(r.Body) {
			add("%s.response.body: недопустимый UTF-8", at)
		}
		if r.ContentType == "application/json" && !jsontext.Value(r.Body).IsValid() {
			add("%s.response.body: объявлен application/json, но это не JSON", at)
		}
	}
	return errors.Join(errs...)
}

// validatePath проверяет путь ловушки.
func validatePath(p string) error {
	switch {
	case len(p) > maxPathLen:
		return fmt.Errorf("не длиннее %d байт", maxPathLen)
	case !pathRe.MatchString(p):
		return errors.New("начинается с «/», только буквы, цифры и . _ ~ ! $ & ' ( ) * + , = : @ / -")
	case p == "/":
		// Ловушка на корне перехватила бы главную страницу сайта клиента.
		return errors.New("ловушка на «/» перехватила бы главную страницу")
	case NormalizePath(p) != p:
		// Путь сравнивается после нормализации; ненормализованная запись
		// («/a/../b», «/b/») никогда бы не совпала и выглядела бы как
		// работающая ловушка.
		return fmt.Errorf("запишите в нормализованном виде: %q", NormalizePath(p))
	}
	return nil
}

// NormalizePath приводит путь запроса к виду, в котором он сравнивается
// с ловушками.
//
// Атакующий или сканер может записать один и тот же путь по-разному:
// «//.env», «/./.env», «/a/../.env», «/.env/», «/.env;jsessionid=1»,
// «\.env». Приложение (и тем более сервер перед ним) часто понимает их
// все как «/.env», и если бы ловушка сравнивала строку как есть, её было бы
// легко обойти. Процентная запись («/%2eenv») уже раскодирована сервером
// Go в r.URL.Path.
//
// Нормализация — только для сравнения. В приложение уходит исходный путь:
// сенсор прозрачен (ADR-0021).
func NormalizePath(p string) string {
	// Нулевой байт: часть серверов и языков обрезает строку на нём.
	if i := strings.IndexByte(p, 0); i >= 0 {
		p = p[:i]
	}
	// Обратная косая черта — разделитель пути для IIS и Windows.
	p = strings.ReplaceAll(p, `\`, "/")
	// Параметры сегмента «;…» — так Tomcat передаёт идентификатор сессии;
	// для приложения «/.env;x» — тот же «/.env».
	if strings.IndexByte(p, ';') >= 0 {
		segs := strings.Split(p, "/")
		for i, s := range segs {
			if j := strings.IndexByte(s, ';'); j >= 0 {
				segs[i] = s[:j]
			}
		}
		p = strings.Join(segs, "/")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// path.Clean убирает «//», «/./», разрешает «/../» и завершающий «/».
	return path.Clean(p)
}
