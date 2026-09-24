package policy

import (
	"net/http"
	"strings"
)

// maxSafelistedContentType — длиннее этого браузер не считает Content-Type
// «простым» и отправляет preflight (спецификация Fetch, CORS-safelisted
// request-header).
const maxSafelistedContentType = 128

// Preflighted — отправил бы браузер такой запрос с чужого сайта только после
// предварительного запроса CORS (preflight).
//
// Зачем. Чужая страница может заставить браузер пользователя отправить
// на сайт клиента «простой» запрос — GET или POST формы — вместе с cookie
// пользователя. Если такой запрос касается ловушки, касание приписывается
// пользователю, хотя он ничего не делал (угроза T2). «Непростой» запрос
// браузер с чужого сайта сначала согласует preflight-запросом, и без
// одобрения сервера сам запрос не отправит. Значит, «непростой» запрос
// пришёл либо со страницы самого сайта, либо не из браузера — от инструмента
// атакующего.
//
// Проверка консервативна: ответ «да» только тогда, когда браузер точно
// потребовал бы preflight. Ошибиться в другую сторону — не заметить часть
// «непростых» запросов — безопасно: это пропуск касания, а не ложное
// касание пользователя. Поэтому здесь нет, например, проверки
// нестандартных заголовков: браузер сам добавляет к запросам заголовки,
// которых нет в списке «простых», и отличить их надёжно нельзя.
// Исключение — заголовки переопределения метода (X-HTTP-Method-Override
// и подобные): браузер их не ставит никогда (ADR-0027).
//
// Граница доверия: метод и Content-Type прислал клиент. Они только
// сравниваются; длина Content-Type ограничена сервером (MaxHeaderBytes)
// и ещё раз здесь — до разбора.
func Preflighted(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
		// «Простые» методы: решает Content-Type.
	case http.MethodOptions:
		// Сам preflight-запрос браузер отправляет с любого сайта без
		// спроса — он не может быть доказательством.
		return false
	default:
		// PUT, DELETE, PATCH и любой другой метод — только через preflight.
		return true
	}
	// Заголовок переопределения метода браузер сам не ставит, а скрипт
	// с чужого сайта может добавить его только после preflight: это
	// нестандартный заголовок.
	for _, h := range methodOverrideHeaders {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	values := r.Header.Values("Content-Type")
	if len(values) == 0 {
		return false
	}
	// Несколько строк Content-Type браузер не отправляет; fetch склеил бы
	// их через «, », и так же поступаем мы — склеенное значение
	// не разбирается как тип, и браузер потребовал бы preflight.
	return !safelistedContentType(strings.Join(values, ", "))
}

// safelistedContentType — «простой» ли Content-Type по спецификации Fetch:
// не длиннее 128 байт, без запрещённых байтов, и тип — один из трёх,
// которые умеет отправлять HTML-форма.
//
// Сравнение повторяет браузер ровно настолько, чтобы никогда не назвать
// «непростым» то, что браузер считает простым: тип берётся до «;», без
// пробелов и табуляций по краям, в нижнем регистре только для ASCII.
func safelistedContentType(v string) bool {
	if len(v) > maxSafelistedContentType {
		return false
	}
	for i := 0; i < len(v); i++ {
		if corsUnsafeByte(v[i]) {
			return false
		}
	}
	essence, _, _ := strings.Cut(v, ";")
	switch lowerASCII(strings.Trim(essence, " \t")) {
	case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
		return true
	}
	return false
}

// corsUnsafeByte — байт, с которым заголовок перестаёт быть «простым»
// (CORS-unsafe request-header byte в спецификации Fetch).
func corsUnsafeByte(b byte) bool {
	if b < 0x20 {
		return b != '\t'
	}
	switch b {
	case '"', '(', ')', ':', '<', '>', '?', '@', '[', '\\', ']', '{', '}', 0x7f:
		return true
	}
	return false
}

// lowerASCII переводит в нижний регистр только латиницу. strings.ToLower
// превратил бы, например, турецкую «İ» (U+0130) в латинскую «i»:
// «text/plaİn» стал бы у нас простым «text/plain», а браузер такой тип
// не распознал бы вовсе и отправил бы preflight.
func lowerASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// methodOverrideHeaders — заголовки, которыми клиент просит приложение
// считать POST другим методом.
var methodOverrideHeaders = []string{"X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"}

// upperASCII переводит в верхний регистр только латиницу — по той же
// причине, что lowerASCII.
func upperASCII(s string) string {
	return strings.Map(func(r rune) rune {
		if 'a' <= r && r <= 'z' {
			return r - ('a' - 'A')
		}
		return r
	}, s)
}

// IsCORSPreflight — это предварительный запрос CORS: OPTIONS с заголовком
// Access-Control-Request-Method. Его браузер отправляет сам перед
// «непростым» межсайтовым запросом.
func IsCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != ""
}
