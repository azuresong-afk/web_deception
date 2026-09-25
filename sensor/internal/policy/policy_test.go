package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validPolicy = `{
  "schema_version": 1,
  "version": "test-1",
  "traps": [
    {
      "id": "env-file",
      "description": "фейковый .env",
      "path": "/.env",
      "mode": "enforce",
      "confidence": "low",
      "response": {"status": 200, "content_type": "text/plain", "body": "APP_ENV=production\n"}
    },
    {
      "id": "api-export",
      "path": "/internal/api/v2/export",
      "mode": "observe",
      "confidence": "high",
      "methods": ["POST", "DELETE"],
      "preflight_only": true,
      "response": {"status": 200, "content_type": "application/json", "body": "{\"job\":1}"}
    }
  ],
  "cookie_traps": [
    {"id": "role-cookie", "description": "роль в cookie", "name": "user_role", "value": "customer", "confidence": "high"}
  ]
}`

func TestParseValid(t *testing.T) {
	t.Parallel()

	c, err := Parse([]byte(validPolicy))
	if err != nil {
		t.Fatalf("корректная политика отвергнута: %v", err)
	}
	if c.Version != "test-1" || c.Len() != 3 {
		t.Errorf("версия %q, ловушек %d", c.Version, c.Len())
	}
	trap, ok := c.Match("/.env")
	if !ok || trap.ID != "env-file" || trap.Mode != Enforce || trap.Response.Body != "APP_ENV=production\n" {
		t.Errorf("ловушка /.env: %+v, найдена %v", trap, ok)
	}
	api, ok := c.Match("/internal/api/v2/export")
	if !ok || !api.PreflightOnly || len(api.Methods) != 2 {
		t.Errorf("ловушка с условиями: %+v, найдена %v", api, ok)
	}

	// Атрибуты cookie — от сенсора, а не из политики.
	ck, ok := c.CookieByName("user_role")
	if !ok || len(c.Cookies()) != 1 || ck.ID != "role-cookie" || ck.Value != "customer" {
		t.Fatalf("cookie-ловушка: %+v, найдена %v", ck, ok)
	}
	const want = "user_role=customer; Path=/; HttpOnly; SameSite=Strict"
	if got := ck.SetCookie(false); got != want {
		t.Errorf("Set-Cookie по HTTP = %q, ожидалось %q", got, want)
	}
	if got := ck.SetCookie(true); got != "user_role=customer; Path=/; HttpOnly; Secure; SameSite=Strict" {
		t.Errorf("Set-Cookie по HTTPS = %q", got)
	}
}

// TestParseRejects — всё, что проверка обязана отвергнуть. Каждый случай —
// способ ошибиться или навредить политикой (угроза T15).
func TestParseRejects(t *testing.T) {
	t.Parallel()

	trap := func(fields string) string {
		return `{"schema_version":1,"version":"v1","traps":[{` + fields + `}]}`
	}
	const okTrap = `"id":"a","path":"/.env","mode":"enforce","confidence":"low",` +
		`"response":{"status":200,"content_type":"text/plain","body":"x"}`
	withResponse := func(resp string) string {
		return trap(`"id":"a","path":"/.env","mode":"enforce","confidence":"low","response":` + resp)
	}
	// withCookie — политика с одной cookie-ловушкой; fields дописываются
	// после корректных полей и заменяют их (повторяющийся ключ был бы
	// ошибкой разбора, поэтому заменяемые поля убираются).
	withCookie := func(fields string) string {
		base := map[string]string{"id": `"id":"c"`, "name": `"name":"role"`, "value": `"value":"user"`}
		for k := range base {
			if strings.Contains(fields, `"`+k+`":`) {
				delete(base, k)
			}
		}
		out := fields
		for _, k := range []string{"id", "name", "value"} {
			if v, ok := base[k]; ok {
				out += "," + v
			}
		}
		return `{"schema_version":1,"version":"v1","traps":[],"cookie_traps":[{` + out + `,"confidence":"high"}]}`
	}
	withPath := func(p string) string {
		return trap(`"id":"a","path":"` + p + `","mode":"enforce","confidence":"low",` +
			`"response":{"status":200,"content_type":"text/plain","body":"x"}`)
	}

	tests := []struct {
		name, policy, want string
	}{
		// Разбор JSON.
		{"не JSON", `{`, "не разбирается"},
		{"повторяющийся ключ", trap(okTrap + `,"mode":"observe"`), "duplicate"},
		{"имя в другом регистре", trap(strings.Replace(okTrap, `"path"`, `"Path"`, 1)), "Path"},
		{"неизвестное поле", trap(okTrap + `,"regex":".*"`), "regex"},
		{"данные после документа", withPath("/.env") + ` {}`, "не разбирается"},
		{"слишком большая политика", `{"version":"` + strings.Repeat("a", MaxPolicyBytes) + `"}`, "больше"},

		// Документ.
		{"нет версии схемы", `{"version":"v1","traps":[]}`, "schema_version"},
		{"чужая версия схемы", `{"schema_version":2,"version":"v1","traps":[]}`, "schema_version"},
		{"нет метки версии", `{"schema_version":1,"traps":[]}`, "version"},
		{"пробел в метке версии", `{"schema_version":1,"version":"v 1","traps":[]}`, "version"},
		{"слишком много ловушек", `{"schema_version":1,"version":"v1","traps":[` +
			strings.TrimSuffix(strings.Repeat(`{},`, maxTraps+1), ",") + `]}`, "не больше 256"},

		// Ловушка.
		{"нет id", trap(strings.Replace(okTrap, `"id":"a"`, `"id":""`, 1)), ".id"},
		{"заглавные в id", trap(strings.Replace(okTrap, `"id":"a"`, `"id":"Env"`, 1)), ".id"},
		{"повтор id", `{"schema_version":1,"version":"v1","traps":[{` + okTrap + `},{` +
			strings.Replace(okTrap, `"/.env"`, `"/b"`, 1) + `}]}`, "уже есть"},
		{"повтор пути", `{"schema_version":1,"version":"v1","traps":[{` + okTrap + `},{` +
			strings.Replace(okTrap, `"id":"a"`, `"id":"b"`, 1) + `}]}`, "уже занят"},
		{"неизвестный режим", trap(strings.Replace(okTrap, `"enforce"`, `"block"`, 1)), ".mode"},
		{"неизвестная уверенность", trap(strings.Replace(okTrap, `"low"`, `"certain"`, 1)), ".confidence"},
		{"длинное описание", trap(okTrap + `,"description":"` + strings.Repeat("a", maxDescriptionLen+1) + `"`), ".description"},

		// Условия и межсайтовые срабатывания (T2).
		{"high без preflight_only", trap(strings.Replace(okTrap, `"low"`, `"high"`, 1)), "preflight_only"},
		{"very_high без preflight_only", trap(strings.Replace(okTrap, `"low"`, `"very_high"`, 1) +
			`,"preflight_only":false`), "preflight_only"},
		{"пустой список методов", trap(okTrap + `,"methods":[]`), "пустой список"},
		{"OPTIONS в методах", trap(okTrap + `,"methods":["OPTIONS"]`), ".methods"},
		{"неизвестный метод", trap(okTrap + `,"methods":["TRACE"]`), ".methods"},
		{"метод в нижнем регистре", trap(okTrap + `,"methods":["post"]`), ".methods"},
		{"повтор метода", trap(okTrap + `,"methods":["POST","POST"]`), "повторяется"},
		{"preflight_only не булево", trap(okTrap + `,"preflight_only":"yes"`), "не разбирается"},

		// Путь.
		{"корень", withPath("/"), "главную"},
		{"без косой черты", withPath(".env"), "начинается"},
		{"параметры в пути", withPath("/a?x=1"), "начинается"},
		{"точка с запятой", withPath("/a;x"), "начинается"},
		{"процентная запись", withPath("/%2eenv"), "начинается"},
		{"не нормализован: ..", withPath("/a/../.env"), "нормализованном"},
		{"не нормализован: /.env/", withPath("/.env/"), "нормализованном"},
		{"не нормализован: //", withPath("//.env"), "нормализованном"},
		{"слишком длинный путь", withPath("/" + strings.Repeat("a", maxPathLen)), "не длиннее"},

		// Ответ.
		{"перенаправление", withResponse(`{"status":302,"content_type":"text/plain","body":""}`), ".status"},
		{"нет кода", withResponse(`{"content_type":"text/plain","body":""}`), ".status"},
		{"HTML", withResponse(`{"status":200,"content_type":"text/html","body":"<script>"}`), ".content_type"},
		{"JSON, который не JSON", withResponse(`{"status":200,"content_type":"application/json","body":"{"}`), "не JSON"},
		{"слишком большое тело", withResponse(`{"status":200,"content_type":"text/plain","body":"` +
			strings.Repeat("a", maxBodyBytes+1) + `"}`), ".body"},

		// Cookie-ловушка.
		{"cookie: префикс __Host-", withCookie(`"name":"__Host-role"`), ".name"},
		{"cookie: пробел в имени", withCookie(`"name":"user role"`), ".name"},
		{"cookie: нет имени", withCookie(`"name":""`), ".name"},
		{"cookie: длинное имя", withCookie(`"name":"` + strings.Repeat("a", maxCookieNameLen+1) + `"`), ".name"},
		{"cookie: ; в значении", withCookie(`"name":"role","value":"a;Domain=evil.example"`), ".value"},
		{"cookie: кавычки в значении", withCookie(`"name":"role","value":"\"a\""`), ".value"},
		{"cookie: пустое значение", withCookie(`"name":"role","value":""`), ".value"},
		{"cookie: длинное значение", withCookie(`"name":"role","value":"` + strings.Repeat("a", maxCookieValueLen+1) + `"`), ".value"},
		{"cookie: нет уверенности", `{"schema_version":1,"version":"v1","traps":[],"cookie_traps":[` +
			`{"id":"c","name":"role","value":"user"}]}`, ".confidence"},
		{"cookie: неизвестное поле", withCookie(`"name":"role","domain":"evil.example"`), "domain"},
		{"cookie: id занят ловушкой на пути", `{"schema_version":1,"version":"v1","traps":[{` + okTrap + `}],` +
			`"cookie_traps":[{"id":"a","name":"role","value":"user","confidence":"high"}]}`, "уже есть"},
		{"cookie: повтор имени", `{"schema_version":1,"version":"v1","traps":[],"cookie_traps":[` +
			`{"id":"c1","name":"role","value":"user","confidence":"high"},` +
			`{"id":"c2","name":"role","value":"admin","confidence":"high"}]}`, "уже занята"},
		{"cookie: слишком много", `{"schema_version":1,"version":"v1","traps":[],"cookie_traps":[` +
			strings.TrimSuffix(strings.Repeat(`{},`, maxCookieTraps+1), ",") + `]}`, "не больше 8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			c, err := Parse([]byte(tt.policy))
			if err == nil {
				t.Fatalf("политика принята: %v", c)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("ошибка %q не содержит %q", err.Error(), tt.want)
			}
		})
	}
}

// TestParseReportsAllErrors: администратору удобнее исправить всё за раз.
func TestParseReportsAllErrors(t *testing.T) {
	t.Parallel()

	_, err := Parse([]byte(`{"schema_version":1,"version":"v1","traps":[` +
		`{"id":"a","path":"/","mode":"x","confidence":"low","response":{"status":200,"content_type":"text/plain","body":""}},` +
		`{"id":"B","path":"/b","mode":"observe","confidence":"low","response":{"status":302,"content_type":"text/plain","body":""}}]}`))
	for _, want := range []string{"traps[0].path", "traps[0].mode", "traps[1].id", "traps[1].response.status"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("в ошибке нет %q: %v", want, err)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"/.env":              "/.env",
		"//.env":             "/.env",
		"/./.env":            "/.env",
		"/a/../.env":         "/.env",
		"/../../.env":        "/.env",
		"/.env/":             "/.env",
		"/.env;jsessionid=1": "/.env",
		"/a;x/.env":          "/a/.env",
		`\.env`:              "/.env",
		"/.env\x00.png":      "/.env",
		".env":               "/.env",
		"":                   "/",
		"/.ENV":              "/.ENV", // регистр сохраняется: ловушка — точный путь
	}
	for in, want := range tests {
		if got := NormalizePath(in); got != want {
			t.Errorf("NormalizePath(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// TestMatchEvasions: разные записи одного пути ловятся одной ловушкой.
func TestMatchEvasions(t *testing.T) {
	t.Parallel()

	c, err := Parse([]byte(validPolicy))
	if err != nil {
		t.Fatal(err)
	}
	// Путь — как его отдаёт r.URL.Path: процентная запись уже раскодирована.
	for _, p := range []string{"/.env", "//.env", "/static/../.env", "/.env/", "/.env;x=1", `\.env`} {
		if _, ok := c.Match(p); !ok {
			t.Errorf("путь %q не совпал с ловушкой /.env", p)
		}
	}
	for _, p := range []string{"/", "/.env.bak", "/env", "/x/.env"} {
		if trap, ok := c.Match(p); ok {
			t.Errorf("путь %q ложно совпал с ловушкой %q", p, trap.ID)
		}
	}
}

func TestEmpty(t *testing.T) {
	t.Parallel()

	if c := Empty(); c.Len() != 0 {
		t.Errorf("пустая политика с ловушками: %d", c.Len())
	} else if _, ok := c.Match("/.env"); ok {
		t.Error("пустая политика совпала с путём")
	}
}

func TestLoadFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	good := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(good, []byte(validPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	c, raw, err := LoadFile(good)
	if err != nil || c.Len() != 3 || string(raw) != validPolicy {
		t.Errorf("LoadFile: %v, ловушек %v", err, c)
	}

	if _, _, err := LoadFile(dir); err == nil {
		t.Error("каталог принят как файл политики")
	}
	if _, _, err := LoadFile(filepath.Join(dir, "нет")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("отсутствующий файл: %v", err)
	}

	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, make([]byte, MaxPolicyBytes+10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadFile(big); err == nil || !strings.Contains(err.Error(), "больше") {
		t.Errorf("слишком большой файл: %v", err)
	}
}

func TestWriteCache(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.last-valid.json")
	for _, content := range []string{"first", "second"} {
		if err := WriteCache(path, []byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "second" {
		t.Errorf("копия: %q, %v", got, err)
	}
	st, _ := os.Stat(path)
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("права копии %v: ожидался доступ только владельцу", perm)
	}
	// Временных файлов не осталось.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("в каталоге %d файлов, ожидался 1", len(entries))
	}

	if err := WriteCache(filepath.Join(dir, "нет-каталога", "p.json"), []byte("x")); err == nil {
		t.Error("запись в несуществующий каталог прошла без ошибки")
	}
}

// FuzzNormalizePath: результат всегда начинается с «/» и повторная
// нормализация его не меняет — иначе ловушка, записанная в нормализованном
// виде, могла бы не совпасть.
func FuzzNormalizePath(f *testing.F) {
	for _, s := range []string{"/.env", "//a/../b;c", `\x\..\y`, "a\x00b", "/../.."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		n := NormalizePath(p)
		if !strings.HasPrefix(n, "/") {
			t.Fatalf("NormalizePath(%q) = %q без «/» в начале", p, n)
		}
		if again := NormalizePath(n); again != n {
			t.Fatalf("нормализация не идемпотентна: %q → %q → %q", p, n, again)
		}
	})
}

// TestDemoPolicyValid: учебная политика из репозитория проходит ту же
// проверку, что и в сенсоре. Иначе опечатка в ней обнаружилась бы только
// на стенде — как отказ политики и сенсор без ловушек.
func TestDemoPolicyValid(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "policy", "demo.json"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		t.Fatalf("учебная политика не проходит проверку: %v", err)
	}
	for _, p := range []string{
		"/.env", "/.git/config", "/backup.sql", "/admin-backup", "/internal/api/v2/docs",
		"/internal/debug/trace", "/api/internal/v1/users/export",
	} {
		if _, ok := c.Match(p); !ok {
			t.Errorf("в учебной политике нет ловушки %s", p)
		}
	}
	// Цепочки учебного набора: robots.txt → №4, заголовок → №7,
	// документация №6 → метод №8.
	for path, lure := range map[string]string{
		"/admin-backup": "robots-admin", "/internal/debug/trace": "debug-header",
		"/api/internal/v1/users/export": "api-docs",
	} {
		if trap, _ := c.Match(path); trap.LureID() != lure {
			t.Errorf("к %s ведёт %q, ожидалось %q", path, trap.LureID(), lure)
		}
	}
	if _, ok := c.CookieByName("account_role"); !ok {
		t.Error("в учебной политике нет cookie-ловушки account_role")
	}
}
