package policy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// lurePolicy — цепочки из учебного набора: заголовок и robots.txt ведут
// к своим ловушкам, фейковая документация ссылается на фейковый метод.
const lurePolicy = `{
  "schema_version": 1,
  "version": "lures-1",
  "traps": [
    {"id": "debug-trace", "path": "/internal/debug/trace", "mode": "enforce", "confidence": "medium",
     "response": {"status": 403, "content_type": "text/plain", "body": "forbidden"}},
    {"id": "old-admin", "path": "/backup-admin", "mode": "enforce", "confidence": "medium", "methods": ["GET", "HEAD"],
     "response": {"status": 401, "content_type": "text/plain", "body": "auth required"}},
    {"id": "api-docs", "path": "/internal/api/v2/docs", "mode": "enforce", "confidence": "medium",
     "response": {"status": 200, "content_type": "application/json",
                  "body": "{\"export\":\"POST {{trap:api-export}}\"}"}},
    {"id": "api-export", "path": "/api/internal/v1/users/export", "mode": "enforce", "confidence": "high",
     "methods": ["POST"], "preflight_only": true,
     "response": {"status": 200, "content_type": "application/json", "body": "{}"}}
  ],
  "lures": [
    {"id": "debug-header", "kind": "header", "header": "X-Debug-Trace", "trap": "debug-trace"},
    {"id": "robots-admin", "kind": "robots_txt", "trap": "old-admin"}
  ]
}`

func TestLuresCompile(t *testing.T) {
	t.Parallel()

	c, err := Parse([]byte(lurePolicy))
	if err != nil {
		t.Fatalf("политика с наживками отвергнута: %v", err)
	}
	if n := len(c.Lures()); n != 2 {
		t.Fatalf("наживок %d", n)
	}
	h := c.HeaderLures()
	if len(h) != 1 || h[0].Header != "X-Debug-Trace" || h[0].Path() != "/internal/debug/trace" {
		t.Errorf("заголовок-наживка: %+v", h)
	}
	if got := c.RobotsDisallow(); len(got) != 1 || got[0] != "/backup-admin" {
		t.Errorf("строки Disallow: %v", got)
	}

	// Ссылка в теле заменена на путь, а цепочка записана у ловушек.
	// Одна страница может упомянуть ловушку дважды — это не конфликт.
	twice := strings.Replace(lurePolicy, `{{trap:api-export}}`, `{{trap:api-export}} {{trap:api-export}}`, 1)
	if _, err := Parse([]byte(twice)); err != nil {
		t.Errorf("два упоминания одной ловушки в одном теле: %v", err)
	}

	docs, _ := c.Match("/internal/api/v2/docs")
	if docs.Response.Body != `{"export":"POST /api/internal/v1/users/export"}` {
		t.Errorf("тело документации: %s", docs.Response.Body)
	}
	for path, want := range map[string]string{
		"/internal/debug/trace":         "debug-header",
		"/backup-admin":                 "robots-admin",
		"/api/internal/v1/users/export": "api-docs",
		"/internal/api/v2/docs":         "",
	} {
		if trap, _ := c.Match(path); trap.LureID() != want {
			t.Errorf("к %s ведёт %q, ожидалось %q", path, trap.LureID(), want)
		}
	}
}

// TestLuresReject — что проверка наживок обязана отвергнуть.
func TestLuresReject(t *testing.T) {
	t.Parallel()

	// withLures — lurePolicy с другим списком наживок.
	withLures := func(lures string) string {
		i := strings.Index(lurePolicy, `"lures"`)
		return lurePolicy[:i] + `"lures": [` + lures + `]}`
	}
	// withDocsBody — lurePolicy с другим телом фейковой документации.
	withDocsBody := func(body string) string {
		return strings.Replace(lurePolicy, `"body": "{\"export\":\"POST {{trap:api-export}}\"}"`, `"body": "`+body+`"`, 1)
	}
	header := func(name string) string {
		return `{"id":"h","kind":"header","header":"` + name + `","trap":"debug-trace"}`
	}

	tests := []struct{ name, policy, want string }{
		{"неизвестный вид", withLures(`{"id":"x","kind":"html_script","trap":"debug-trace"}`), ".kind"},
		{"нет ловушки", withLures(`{"id":"x","kind":"robots_txt","trap":"nope"}`), "нет ловушки"},
		{"ловушка только для POST", withLures(`{"id":"x","kind":"robots_txt","trap":"api-export"}`), "не срабатывает на обычный GET"},
		{"cookie-ловушка вместо ловушки на пути", strings.Replace(withLures(`{"id":"x","kind":"robots_txt","trap":"c"}`),
			`"lures"`, `"cookie_traps":[{"id":"c","name":"role","value":"user","confidence":"high"}],"lures"`, 1), "нет ловушки"},
		{"шаблон в robots.txt", strings.Replace(withLures(`{"id":"x","kind":"robots_txt","trap":"old-admin"}`),
			`/backup-admin`, `/backup*`, 1), "шаблон"},
		{"заголовок без имени", withLures(`{"id":"x","kind":"header","trap":"debug-trace"}`), "обязателен"},
		{"имя заголовка у robots", withLures(`{"id":"x","kind":"robots_txt","header":"X-A","trap":"old-admin"}`), "только для kind"},
		{"заголовок не X-", withLures(header("Debug-Trace")), ".header"},
		{"подчёркивание в заголовке", withLures(header("X_Debug")), ".header"},
		{"перевод строки в заголовке", withLures(header(`X-A\r\nSet-Cookie: a=b`)), ".header"},
		{"длинный заголовок", withLures(header("X-" + strings.Repeat("a", maxLureHeaderLen))), ".header"},
		{"X-Accel-Redirect", withLures(header("X-Accel-Redirect")), "не годится"},
		{"x-robots-tag в нижнем регистре", withLures(header("x-robots-tag")), ".header"},
		{"X-Robots-Tag", withLures(header("X-Robots-Tag")), "не годится"},
		{"X-Forwarded-Host", withLures(header("X-Forwarded-Host")), "не годится"},
		{"X-Frame-Options", withLures(header("X-Frame-Options")), "не годится"},
		{"повтор заголовка", withLures(header("X-Debug") + `,{"id":"h2","kind":"header","header":"X-DEBUG","trap":"old-admin"}`), "уже занят"},
		{"id занят ловушкой", withLures(`{"id":"old-admin","kind":"robots_txt","trap":"old-admin"}`), "уже есть"},
		{"две наживки к одной ловушке", withLures(`{"id":"a","kind":"robots_txt","trap":"old-admin"},` +
			`{"id":"b","kind":"header","header":"X-Old","trap":"old-admin"}`), "уже ведёт"},
		{"неизвестное поле", withLures(`{"id":"x","kind":"robots_txt","trap":"old-admin","html":"<script>"}`), "html"},
		{"текст у robots", withLures(`{"id":"x","kind":"robots_txt","trap":"old-admin","text":"see {path}"}`), ".text: только"},
		{"текст у ссылки", withLures(`{"id":"x","kind":"html_link","trap":"old-admin","text":"see {path}"}`), ".text: только"},
		{"заголовок у комментария", withLures(`{"id":"x","kind":"html_comment","trap":"old-admin","text":"see {path}","header":"X-A"}`),
			".header: только"},
		{"слишком много", withLures(strings.TrimSuffix(strings.Repeat(`{},`, maxLures+1), ",")), "не больше 16"},

		// Ссылки в телах ловушек.
		{"ссылка на несуществующую", withDocsBody(`{{trap:nope}}`), "нет ловушки"},
		{"ссылка с заглавными", withDocsBody(`{{trap:API}}`), "{{trap:id}}"},
		{"незакрытая ссылка", withDocsBody(`{{trap:api-export`), "{{trap:id}}"},
		{"ссылка на себя", withDocsBody(`{{trap:api-docs}}`), "сама на себя"},
		{"тело и наживка к одной ловушке", withDocsBody(`{{trap:debug-trace}}`), "уже ведёт"},
		{"рост тела после подстановки", withDocsBody(strings.Repeat(`{{trap:api-export}}`, maxBodyBytes/len(`{{trap:api-export}}`))),
			"после подстановки"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, err := Parse([]byte(tt.policy))
			if err == nil {
				t.Fatalf("политика принята: %v", c.Lures())
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ошибка %q не содержит %q", err.Error(), tt.want)
			}
		})
	}
}

// TestMethodOverride: POST с «X-HTTP-Method-Override: DELETE» для ловушки
// только на DELETE — тоже касание, и такой запрос «непростой».
func TestMethodOverride(t *testing.T) {
	t.Parallel()

	trap := &Trap{Methods: []string{http.MethodDelete}, PreflightOnly: true}
	req := func(method, header, value string) *http.Request {
		r := httptest.NewRequest(method, "/x", nil)
		if header != "" {
			r.Header.Set(header, value)
		}
		return r
	}
	tests := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"DELETE", req(http.MethodDelete, "", ""), true},
		{"POST без переопределения", req(http.MethodPost, "", ""), false},
		{"POST + X-HTTP-Method-Override", req(http.MethodPost, "X-HTTP-Method-Override", "DELETE"), true},
		{"POST + X-HTTP-Method, нижний регистр", req(http.MethodPost, "X-HTTP-Method", " delete "), true},
		{"POST + X-Method-Override", req(http.MethodPost, "X-Method-Override", "DELETE"), true},
		{"POST + другой метод", req(http.MethodPost, "X-HTTP-Method-Override", "PUT"), false},
		{"GET + переопределение: фреймворки не принимают", req(http.MethodGet, "X-HTTP-Method-Override", "DELETE"), false},
	}
	for _, tt := range tests {
		if got := trap.Accepts(tt.r); got != tt.want {
			t.Errorf("%s: Accepts = %v, ожидалось %v", tt.name, got, tt.want)
		}
	}

	// Заголовок переопределения — нестандартный: с чужого сайта только
	// через preflight, даже у GET.
	if !Preflighted(req(http.MethodGet, "X-HTTP-Method-Override", "DELETE")) {
		t.Error("GET с X-HTTP-Method-Override не признан «непростым»")
	}
	if Preflighted(req(http.MethodOptions, "X-HTTP-Method-Override", "DELETE")) {
		t.Error("OPTIONS признан «непростым»")
	}
}

// TestHTMLLuresCompile: вставка в <body> собирается при разборе политики;
// путь в ссылке экранирован для атрибута.
func TestHTMLLuresCompile(t *testing.T) {
	t.Parallel()

	withHTML := strings.Replace(lurePolicy, `"lures": [`, `"lures": [
    {"id": "docs-comment", "kind": "html_comment", "text": "API v2 documentation moved to {path}", "trap": "api-docs"},
    {"id": "legacy-link", "kind": "html_link", "trap": "legacy-login"},`, 1)
	withHTML = strings.Replace(withHTML, `"traps": [`, `"traps": [
    {"id": "legacy-login", "path": "/account/login&legacy", "mode": "enforce", "confidence": "medium",
     "response": {"status": 401, "content_type": "text/plain", "body": "x"}},`, 1)
	c, err := Parse([]byte(withHTML))
	if err != nil {
		t.Fatalf("политика с HTML-наживками отвергнута: %v", err)
	}
	want := `<!-- API v2 documentation moved to /internal/api/v2/docs -->` +
		`<a href="/account/login&amp;legacy" hidden aria-hidden="true" tabindex="-1" rel="nofollow"></a>`
	if got := c.HTMLFragment(); got != want {
		t.Errorf("вставка:\n%s\nожидалось:\n%s", got, want)
	}
	if trap, _ := c.Match("/internal/api/v2/docs"); trap.LureID() != "docs-comment" {
		t.Errorf("к документации ведёт %q", trap.LureID())
	}
	if Empty().HTMLFragment() != "" {
		t.Error("у пустой политики есть HTML-вставка")
	}
}

// TestHTMLCommentTextRejects: текст комментария не может закрыть
// комментарий или открыть новый — ни сам, ни вместе с путём.
func TestHTMLCommentTextRejects(t *testing.T) {
	t.Parallel()

	withText := func(text string) string {
		i := strings.Index(lurePolicy, `"lures"`)
		return lurePolicy[:i] + `"lures": [{"id":"c","kind":"html_comment","trap":"old-admin","text":"` + text + `"}]}`
	}
	tests := []struct{ name, policy, want string }{
		{"без текста", withText(""), "{path} ровно один раз"},
		{"без {path}", withText("see docs"), "{path} ровно один раз"},
		{"{path} дважды", withText("{path} and {path}"), "{path} ровно один раз"},
		{"закрыть комментарий", withText("x --> <script>alert(1)</script> {path}"), ".text"},
		{"--!>", withText("x --!> {path}"), ".text"},
		{"открыть новый", withText("<!-- {path}"), ".text"},
		{"амперсанд", withText("a &amp; {path}"), ".text"},
		{"двойной дефис", withText("a -- b {path}"), "двойного дефиса"},
		{"дефис перед путём", withText("see -{path}"), "вплотную"},
		{"дефис после пути", withText("{path}- ok"), "вплотную"},
		{"кириллица", withText("документация: {path}"), ".text"},
		{"перевод строки", withText(`a\n{path}`), ".text"},
		{"длинный", withText(strings.Repeat("a", maxLureTextLen) + "{path}"), "не длиннее"},
		{"путь с --", strings.Replace(withText("see {path}"), "/backup-admin", "/backup--admin", 1), "«--»"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse([]byte(tt.policy)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ошибка %v не содержит %q", err, tt.want)
			}
		})
	}
}
