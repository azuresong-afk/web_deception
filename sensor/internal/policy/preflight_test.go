package policy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPreflighted: «непростой» запрос — только тот, который браузер
// с чужого сайта точно не отправил бы без preflight. Ошибка в сторону
// «да» — это ложное касание пользователя (T2), поэтому случаи, где
// браузер preflight не требует, проверены отдельно и подробно.
func TestPreflighted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		method      string
		contentType []string
		want        bool
	}{
		// Методы.
		{"GET без тела", http.MethodGet, nil, false},
		{"HEAD", http.MethodHead, nil, false},
		{"POST без Content-Type", http.MethodPost, nil, false},
		{"PUT", http.MethodPut, nil, true},
		{"DELETE", http.MethodDelete, nil, true},
		{"PATCH", http.MethodPatch, nil, true},
		{"свой метод", "PURGE", nil, true},
		{"сам preflight", http.MethodOptions, []string{"application/json"}, false},

		// Content-Type, который умеет отправлять форма, — простой запрос.
		{"форма", http.MethodPost, []string{"application/x-www-form-urlencoded"}, false},
		{"форма с файлом", http.MethodPost, []string{"multipart/form-data; boundary=x"}, false},
		{"текст", http.MethodPost, []string{"text/plain"}, false},
		{"текст с кодировкой", http.MethodPost, []string{"text/plain; charset=utf-8"}, false},
		{"текст в верхнем регистре", http.MethodPost, []string{"TEXT/Plain"}, false},
		{"текст с пробелами", http.MethodPost, []string{"text/plain ;charset=x"}, false},
		{"текст с табуляцией", http.MethodPost, []string{"text/plain\t"}, false},
		{"текст, а после ; — JSON", http.MethodPost, []string{"text/plain; application/json"}, false},
		{"GET с формой", http.MethodGet, []string{"text/plain"}, false},

		// Всё остальное браузер согласует preflight-запросом.
		{"JSON", http.MethodPost, []string{"application/json"}, true},
		{"JSON с кодировкой", http.MethodPost, []string{"application/json; charset=utf-8"}, true},
		{"GET с JSON", http.MethodGet, []string{"application/json"}, true},
		{"XML", http.MethodPost, []string{"application/xml"}, true},
		{"две строки Content-Type", http.MethodPost, []string{"text/plain", "text/plain"}, true},
		{"список через запятую", http.MethodPost, []string{"text/plain, application/json"}, true},
		{"кавычки", http.MethodPost, []string{`"text/plain"`}, true},
		{"запрещённый байт в параметре", http.MethodPost, []string{"text/plain; x=(y)"}, true},
		{"управляющий символ", http.MethodPost, []string{"text/plain\x01"}, true},
		{"длиннее 128 байт", http.MethodPost, []string{"text/plain; x=" + strings.Repeat("a", 120)}, true},
		// Параметр с не-ASCII именем браузер пропускает, тип остаётся простым.
		{"не-ASCII в параметре", http.MethodPost, []string{"text/plain; \u212a=1"}, false},
		// А не-ASCII в самом типе — уже не тип: браузер отправит preflight.
		// strings.ToLower превратил бы «İ» в «i» и счёл бы тип простым.
		{"не-ASCII в типе", http.MethodPost, []string{"text/pla\u0130n"}, true},
		{"пробел внутри типа", http.MethodPost, []string{"text /plain"}, true},
		{"пустой", http.MethodPost, []string{""}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(tt.method, "/x", nil)
			if tt.contentType != nil {
				r.Header["Content-Type"] = tt.contentType
			}
			if got := Preflighted(r); got != tt.want {
				t.Errorf("Preflighted(%s, %q) = %v, ожидалось %v", tt.method, tt.contentType, got, tt.want)
			}
		})
	}
}

// TestSafelistedLengthBoundary: 128 байт — ещё простой, 129 — уже нет.
func TestSafelistedLengthBoundary(t *testing.T) {
	t.Parallel()

	v := "text/plain; x="
	v += strings.Repeat("a", maxSafelistedContentType-len(v))
	if !safelistedContentType(v) {
		t.Errorf("%d байт: ожидался простой", len(v))
	}
	if safelistedContentType(v + "a") {
		t.Errorf("%d байт: ожидался не простой", len(v)+1)
	}
}

func TestAccepts(t *testing.T) {
	t.Parallel()

	req := func(method, ct string) *http.Request {
		r := httptest.NewRequest(method, "/x", nil)
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		return r
	}
	any := &Trap{}
	post := &Trap{Methods: []string{http.MethodPost}}
	pre := &Trap{Methods: []string{http.MethodPost, http.MethodDelete}, PreflightOnly: true}

	tests := []struct {
		name string
		trap *Trap
		r    *http.Request
		want bool
	}{
		{"без условий, GET", any, req(http.MethodGet, ""), true},
		{"без условий, OPTIONS", any, req(http.MethodOptions, ""), true},
		{"POST-ловушка, POST", post, req(http.MethodPost, ""), true},
		{"POST-ловушка, GET", post, req(http.MethodGet, ""), false},
		{"preflight: POST формы", pre, req(http.MethodPost, "application/x-www-form-urlencoded"), false},
		{"preflight: POST JSON", pre, req(http.MethodPost, "application/json"), true},
		{"preflight: DELETE", pre, req(http.MethodDelete, ""), true},
		{"preflight: PUT не в списке", pre, req(http.MethodPut, "application/json"), false},
	}
	for _, tt := range tests {
		if got := tt.trap.Accepts(tt.r); got != tt.want {
			t.Errorf("%s: Accepts = %v, ожидалось %v", tt.name, got, tt.want)
		}
	}
}

func TestIsCORSPreflight(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodOptions, "/x", nil)
	if IsCORSPreflight(r) {
		t.Error("OPTIONS без Access-Control-Request-Method — не preflight")
	}
	r.Header.Set("Access-Control-Request-Method", "DELETE")
	if !IsCORSPreflight(r) {
		t.Error("preflight не распознан")
	}
	g := httptest.NewRequest(http.MethodGet, "/x", nil)
	g.Header.Set("Access-Control-Request-Method", "DELETE")
	if IsCORSPreflight(g) {
		t.Error("GET с Access-Control-Request-Method — не preflight")
	}
}

// FuzzPreflighted: на любом Content-Type нет паники, и простой по нашему
// мнению тип всегда из трёх разрешённых.
func FuzzPreflighted(f *testing.F) {
	for _, s := range []string{"text/plain", "application/json", "TEXT/PLAIN;x=1", "", "\x00", "text/plain\u212a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ct string) {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		r.Header["Content-Type"] = []string{ct}
		if !Preflighted(r) {
			essence, _, _ := strings.Cut(ct, ";")
			switch strings.ToLower(strings.Trim(essence, " \t")) {
			case "application/x-www-form-urlencoded", "multipart/form-data", "text/plain":
			default:
				t.Errorf("%q признан простым", ct)
			}
		}
	})
}
