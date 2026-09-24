package event

import "strings"

// Метки, которыми заменяются сегменты пути.
const (
	maskEmail  = "{email}"
	maskUUID   = "{uuid}"
	maskJWT    = "{jwt}"
	maskNum    = "{num}"
	maskHex    = "{hex}"
	maskToken  = "{token}"
	maskParams = "{params}"
)

// Пороги длины, начиная с которых строка считается секретом, а не словом.
const (
	// 16 шестнадцатеричных символов — 64 бита: столько у самых коротких
	// токенов и идентификаторов сессий. Короче бывают обычные слова
	// из букв a–f («facade», «decade»).
	minHexLen = 16
	// 20 символов из букв и цифр — токены сброса пароля, ключи API, ссылки
	// «волшебного входа». Обычные сегменты пути короче или без цифр.
	minTokenLen = 20
)

// MaskPath заменяет в пути сегменты, похожие на секреты и идентификаторы,
// на метки: /reset/9f8a7c6e5d4b3a2f1e0d → /reset/{hex}. Возвращает true,
// если путь пришлось обрезать.
//
// Зачем. Путь — единственная часть запроса, которую событие записывает
// почти целиком. А в пути бывают токены сброса пароля, ключи API,
// идентификаторы сессий, адреса почты и номера пользователей. Токен в файле
// событий — это действующий секрет в месте, которое читают администраторы
// и куда могут добраться чужие (угроза T4). Номер и почта — персональные
// данные, которые продукту не нужны (ADR-0007).
//
// Как. Путь режется по «/», каждый сегмент проверяется правилами
// maskSegment. Правила — эвристика: они не поймают короткий токен и
// замаскируют длинный осмысленный сегмент с цифрами. Выбрано так, чтобы
// ошибаться в сторону маскирования: лишняя метка стоит меньше, чем
// записанный секрет.
//
// p — путь в процентной кодировке (URL.EscapedPath): в нём только ASCII.
func MaskPath(p string) (string, bool) {
	truncated := false
	if len(p) > maxPathBytes {
		// Обрезанный последний сегмент выбрасываем целиком: по его началу
		// нельзя понять, был ли это секрет, а начало токена — тоже часть
		// токена.
		p = p[:maxPathBytes]
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			p = p[:i+1]
		} else {
			p = ""
		}
		truncated = true
	}

	segments := strings.Split(p, "/")
	for i, s := range segments {
		segments[i] = maskSegment(s)
	}
	out := strings.Join(segments, "/")

	// Метка бывает длиннее сегмента («1» → «{num}»), и путь из тысячи
	// «/1» вырос бы впятеро. Режем результат так же, по границе сегмента.
	if len(out) > maxPathBytes {
		out = out[:maxPathBytes]
		if i := strings.LastIndexByte(out, '/'); i >= 0 {
			out = out[:i+1]
		}
		truncated = true
	}
	return out, truncated
}

// maskSegment проверяет один сегмент пути. Порядок правил важен: более
// точное правило раньше более общего.
func maskSegment(s string) string {
	if s == "" {
		return s
	}

	// Параметры сегмента после «;» — так Tomcat и другие передают
	// идентификатор сессии: /shop;jsessionid=0123ABCD. Имя до «;» проверяем
	// как обычный сегмент, параметры не записываем вовсе.
	if i := strings.IndexByte(s, ';'); i >= 0 {
		return maskSegment(s[:i]) + ";" + maskParams
	}

	switch {
	// «@» или его процентная запись «%40»: в ней нет букв, поэтому регистр
	// не важен.
	case strings.Contains(s, "@") || strings.Contains(s, "%40"):
		return maskEmail
	case isUUID(s):
		return maskUUID
	case isJWT(s):
		return maskJWT
	case isDigits(s):
		return maskNum
	case len(s) >= minHexLen && isHex(s):
		return maskHex
	case len(s) >= minTokenLen && isToken(s):
		return maskToken
	}
	return s
}

// isUUID — 8-4-4-4-12 шестнадцатеричных символов.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexByte(s[i]) {
				return false
			}
		}
	}
	return true
}

// isJWT — «eyJ» в начале (это base64 от «{"») и хотя бы одна точка:
// заголовок.данные.подпись.
func isJWT(s string) bool {
	return strings.HasPrefix(s, "eyJ") && strings.Contains(s, ".")
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexByte(s[i]) {
			return false
		}
	}
	return true
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isToken — только символы, из которых состоят токены (буквы, цифры,
// «-_.~+=» и «%» процентной кодировки), и есть хотя бы одна буква и одна
// цифра. Требование цифры отличает токен от длинного слова вроде
// «configuration-management».
func isToken(s string) bool {
	hasDigit, hasLetter := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasLetter = true
		case strings.IndexByte("-_.~+=%", c) >= 0:
		default:
			return false
		}
	}
	return hasDigit && hasLetter
}
