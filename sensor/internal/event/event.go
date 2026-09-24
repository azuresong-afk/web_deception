// Package event — события сенсора: что записывается, в каком виде и как
// оно доходит до файла, не задерживая трафик.
//
// Событие — метаданные, а не запись трафика (ADR-0007): тела, заголовки
// авторизации, cookie и значения параметров запроса в событие не попадают
// никогда. Путь запроса записывается с замаскированными идентификаторами
// и токенами (mask.go), строки от клиента ограничены по длине
// и приводятся к корректному UTF-8.
//
// Граница доверия: в событие попадают данные атакующего — путь, User-Agent,
// адрес из CONNECT. Они записываются только как значения JSON, и кодировщик
// экранирует в них переводы строк и управляющие символы. Поэтому одна строка
// файла — ровно одно событие, и подделать соседнее событие или отправить
// управляющую последовательность в терминал того, кто читает файл,
// нельзя (угроза T19). Формат и его решения — ADR-0023.
package event

import (
	"crypto/rand"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
)

// Version — версия формата. 0 означает «формат ещё меняется»: до этапа 3,
// где события начнёт читать control plane, поля могут переименовываться.
// Версия 1 — первый формат с обязательством совместимости.
const Version = 0

// Пределы длины строк от клиента, в байтах. Строка длиннее обрезается,
// и событие это отмечает.
const (
	maxPathBytes      = 1024
	maxUserAgentBytes = 256
	maxMethodBytes    = 32
	// Адрес из CONNECT — host:port; имя хоста не длиннее 253 символов.
	maxTargetBytes = 261
)

// Type — тип события. Имена — «область.что_случилось».
type Type string

const (
	// TypeSensorStarted — сенсор запущен и принимает трафик.
	TypeSensorStarted Type = "sensor.started"
	// TypeSensorStopping — сенсор начал остановку.
	TypeSensorStopping Type = "sensor.stopping"
	// TypeConnectRejected — клиент прислал CONNECT: проверял, не открытый
	// ли перед ним прокси (угроза T17). Сенсор ответил 405.
	TypeConnectRejected Type = "request.connect_rejected"
	// TypeFailOpen — обнаружение перегружено, сенсор проверяет только часть
	// запросов (ADR-0024). Всегда critical.
	TypeFailOpen Type = "sensor.fail_open"
	// TypeFailOpenRecovered — обнаружение снова проверяет каждый запрос.
	TypeFailOpenRecovered Type = "sensor.fail_open_recovered"
	// TypeDetectionPanic — паника в обнаружении на этом запросе; запрос
	// ушёл в приложение без проверки.
	TypeDetectionPanic Type = "detection.panic"
	// TypeDecoyTouch — касание ловушки (ADR-0025).
	TypeDecoyTouch Type = "decoy.touch"
	// TypePolicyLoaded — политика обнаружения применена.
	TypePolicyLoaded Type = "sensor.policy_loaded"
	// TypePolicyRejected — политика не прошла проверку; сенсор остался
	// на прежней.
	TypePolicyRejected Type = "sensor.policy_rejected"
)

// Severity — важность события.
//
// Для касаний приманок (шаг 8) важность будет следовать из уверенности
// приманки. Классификация «шум или целевая атака» — этап 4, не здесь.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Event — одно событие. Порядок полей — порядок в JSON.
type Event struct {
	// V — версия формата.
	V int `json:"v"`
	// ID — случайный идентификатор, 128 бит. Нужен, чтобы на этапе 3
	// одно и то же событие, отправленное дважды, не посчиталось двумя.
	ID string `json:"id"`
	// Time — время события в UTC.
	Time time.Time `json:"ts"`
	Type Type      `json:"type"`
	// Severity — важность.
	Severity Severity `json:"severity"`
	// Client — кто прислал запрос; только у событий, связанных с запросом.
	Client *Client `json:"client,omitempty"`
	// Request — метаданные запроса; только у событий, связанных с запросом.
	Request *Request `json:"request,omitempty"`
	// Data — поля, свои для каждого типа. Ключи — константы из кода,
	// значения от клиента проходят через Clean.
	Data map[string]string `json:"data,omitempty"`
}

// Client — адрес клиента по результату пакета forwarded (ADR-0022).
type Client struct {
	// IP — адрес клиента. Нет поля — адрес неизвестен (цепочка оборвана).
	IP string `json:"ip,omitempty"`
	// Peer — адрес TCP-соединения.
	Peer string `json:"peer,omitempty"`
	// ViaTrustedProxy — запрос пришёл через доверенный прокси.
	ViaTrustedProxy bool `json:"via_trusted_proxy,omitempty"`
	// ChainBroken — X-Forwarded-For от доверенного прокси не разобран.
	ChainBroken bool `json:"chain_broken,omitempty"`
}

// Request — метаданные запроса. Только то, что перечислено здесь:
// ни тела, ни cookie, ни Authorization, ни значений параметров.
type Request struct {
	Method string `json:"method"`
	// Path — путь с замаскированными идентификаторами и токенами, как его
	// прислал клиент (в процентной кодировке).
	Path string `json:"path,omitempty"`
	// PathTruncated — путь длиннее предела и обрезан.
	PathTruncated bool `json:"path_truncated,omitempty"`
	// HasQuery — в запросе были параметры. Сами параметры не записываются:
	// в них бывают токены, пароли и персональные данные (угроза T4).
	HasQuery bool `json:"has_query,omitempty"`
	// UserAgent — нужен для отпечатка клиента (ADR-0007); обрезан.
	UserAgent string `json:"user_agent,omitempty"`
	// Fetch — заголовки Sec-Fetch-*; нет поля — клиент не прислал
	// ни одного.
	Fetch *Fetch `json:"sec_fetch,omitempty"`
}

// Fetch — заголовки Fetch Metadata (Sec-Fetch-*). Их ставит сам браузер,
// и скрипт на странице изменить их не может. По ним видно, не пришёл ли
// запрос с чужого сайта — не заставила ли чужая страница браузер
// пользователя коснуться ловушки (угроза T2, ADR-0026).
//
// Инструмент атакующего может прислать любые значения. Поэтому это
// свидетельство о браузере, а не доказательство: «cross-site» от curl
// ничего не значит, а вот его отсутствие у современного браузера значит.
//
// Записываются только значения из спецификации; любое другое — «other».
// Строки от клиента в это поле не попадают.
type Fetch struct {
	// Site — откуда запрос относительно сайта: cross-site, same-site,
	// same-origin, none (адрес набран вручную или из закладки).
	Site string `json:"site,omitempty"`
	// Mode — режим запроса: navigate (переход по странице), cors, no-cors,
	// same-origin, websocket.
	Mode string `json:"mode,omitempty"`
	// Dest — для чего ресурс: document, image, script, empty (fetch)
	// и другие.
	Dest string `json:"dest,omitempty"`
	// User — переход вызван действием пользователя (клик), а не скриптом.
	User bool `json:"user,omitempty"`
}

// fetchOther — значение Sec-Fetch-*, которого нет в спецификации.
const fetchOther = "other"

// Допустимые значения Sec-Fetch-* по спецификации Fetch Metadata.
var (
	fetchSites = map[string]bool{"cross-site": true, "same-origin": true, "same-site": true, "none": true}
	fetchModes = map[string]bool{
		"cors": true, "navigate": true, "no-cors": true, "same-origin": true, "websocket": true,
	}
	fetchDests = map[string]bool{
		"audio": true, "audioworklet": true, "document": true, "embed": true, "empty": true,
		"fencedframe": true, "font": true, "frame": true, "iframe": true, "image": true,
		"json": true, "manifest": true, "object": true, "paintworklet": true, "report": true,
		"script": true, "serviceworker": true, "sharedworker": true, "style": true,
		"track": true, "video": true, "webidentity": true, "worker": true, "xslt": true,
	}
)

// New создаёт событие с версией, идентификатором и временем.
func New(t Type, s Severity) Event {
	return Event{
		V:  Version,
		ID: rand.Text(),
		// UTC — чтобы события сенсоров в разных часовых поясах сравнивались
		// без пересчёта.
		Time:     time.Now().UTC(),
		Type:     t,
		Severity: s,
	}
}

// ClientFrom переводит результат forwarded.Resolve в поля события.
func ClientFrom(c forwarded.Client) *Client {
	out := &Client{
		ViaTrustedProxy: c.ViaTrustedProxy,
		ChainBroken:     c.ChainBroken,
	}
	if c.Addr.IsValid() {
		out.IP = c.Addr.String()
	}
	if c.Peer.IsValid() {
		out.Peer = c.Peer.String()
	}
	return out
}

// RequestFrom извлекает из запроса метаданные для события.
//
// Функция читает ровно это: метод, путь, User-Agent, факт наличия
// параметров и заголовки Sec-Fetch-* (только значения из спецификации).
// Всё остальное из запроса в событие не попадает.
func RequestFrom(r *http.Request) *Request {
	method, _ := Clean(r.Method, maxMethodBytes)
	path, truncated := MaskPath(r.URL.EscapedPath())
	ua, _ := Clean(r.Header.Get("User-Agent"), maxUserAgentBytes)
	return &Request{
		Method:        method,
		Path:          path,
		PathTruncated: truncated,
		HasQuery:      r.URL.RawQuery != "" || r.URL.ForceQuery,
		UserAgent:     ua,
		Fetch:         fetchFrom(r.Header),
	}
}

// fetchFrom извлекает заголовки Sec-Fetch-*. nil — ни одного нет.
func fetchFrom(h http.Header) *Fetch {
	f := Fetch{
		Site: fetchValue(h.Get("Sec-Fetch-Site"), fetchSites),
		Mode: fetchValue(h.Get("Sec-Fetch-Mode"), fetchModes),
		Dest: fetchValue(h.Get("Sec-Fetch-Dest"), fetchDests),
		// Браузер присылает только «?1»; «?0» он не отправляет вовсе.
		User: h.Get("Sec-Fetch-User") == "?1",
	}
	if f == (Fetch{}) {
		return nil
	}
	return &f
}

// fetchValue сверяет значение со списком допустимых. Сравнение точное:
// браузер пишет значения в нижнем регистре, и «Cross-Site» — не браузер.
func fetchValue(v string, allowed map[string]bool) string {
	switch {
	case v == "":
		return ""
	case allowed[v]:
		return v
	default:
		return fetchOther
	}
}

// ConnectTarget — адрес, к которому клиент просил открыть туннель,
// подготовленный для события.
func ConnectTarget(r *http.Request) string {
	target, _ := Clean(r.Host, maxTargetBytes)
	return target
}

// Clean готовит строку от клиента к записи в событие: не длиннее max байт
// и корректный UTF-8. Возвращает true, если строку пришлось обрезать.
//
// Экранирование здесь не нужно и не делается: его делает кодировщик JSON
// при записи. Двойное экранирование испортило бы данные для того, кто
// будет их разбирать.
func Clean(s string, max int) (string, bool) {
	truncated := false
	// Сначала отрезаем лишнее, чтобы не обрабатывать строку длиной
	// в десятки килобайт целиком.
	if len(s) > max {
		s = s[:max]
		truncated = true
	}
	// Недопустимые последовательности байтов — в U+FFFD. Кодировщик JSON
	// сделал бы то же сам, но тогда длина могла бы вырасти после проверки.
	s = strings.ToValidUTF8(s, "�")
	if len(s) > max {
		// Замена могла удлинить строку: байт → 3 байта U+FFFD. Режем снова,
		// по границе символа, чтобы не оставить половину символа.
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
		truncated = true
	}
	return s, truncated
}
