package lure

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

const htmlPolicy = `{"schema_version":1,"version":"v1","traps":[
 {"id":"api-docs","path":"/internal/api/v2/docs","mode":"enforce","confidence":"medium",
  "response":{"status":200,"content_type":"text/plain","body":"x"}},
 {"id":"legacy-login","path":"/account/legacy-login","mode":"enforce","confidence":"medium",
  "response":{"status":401,"content_type":"text/plain","body":"x"}}],
 "lures":[
 {"id":"docs-comment","kind":"html_comment","text":"API v2 documentation moved to {path}","trap":"api-docs"},
 {"id":"legacy-link","kind":"html_link","trap":"legacy-login"}]}`

// fragment — то, что сенсор вставляет по htmlPolicy.
const fragment = `<!-- API v2 documentation moved to /internal/api/v2/docs -->` +
	`<a href="/account/legacy-login" hidden aria-hidden="true" tabindex="-1" rel="nofollow"></a>`

func page(body string) appResponse {
	return app(http.MethodGet, "/", 200, http.Header{"Content-Type": {"text/html; charset=utf-8"}}, body)
}

// TestInjectHTMLPlace: вставка — сразу после настоящего <body>, даже если
// строка «<body» встречается раньше там, где она не тег.
func TestInjectHTMLPlace(t *testing.T) {
	t.Parallel()

	tests := []struct{ name, before, after string }{
		{"простая страница", `<!doctype html><html><head><title>x</title></head><body>`, `<p>hi</p></body></html>`},
		{"атрибуты тела", `<html><body class="a>b" data-x='<body>' onload=init()>`, `<main></main>`},
		{"верхний регистр", `<HTML><BODY BGCOLOR=white>`, `text`},
		{"самозакрытый", `<body/>`, `text`},
		{"в комментарии", `<!-- <body> --><body>`, `x`},
		{"комментарий до doctype", "<!--\n  ~ Copyright\n  -->\n\n<!doctype html>\n<html><body class=\"theme\">", "\n<app-root></app-root>"},
		{"в скрипте", `<head><script>var s = "<body>"; if (a<b) {}</script></head><body>`, `x`},
		{"скрипт с комментарием внутри", `<script><!--<script></script><body></script><body>`, `x`},
		{"в стилях", `<style>body > p { color: red } /* <body> */</style><body>`, `x`},
		{"в заголовке", `<title>Где <body>?</title><body>`, `x`},
		{"в noscript", `<noscript><body><p>включите JS</p></noscript><body>`, `x`},
		{"в textarea", `<textarea><body></textarea><body>`, `x`},
		{"в значении атрибута", `<meta name="x" content="<body>"><body>`, `x`},
		{"CDATA вне SVG — комментарий", `<![CDATA[<body>]]><body>`, `x`},
		{"BOM", "\ufeff<!doctype html><body>", "x"},
		{"пробелы в теге", "<body\n\tclass=x\n>", "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, htmlPolicy)
			resp := page(tt.before + tt.after)
			resp.header.Set("Etag", `"abc"`)
			resp.header.Set("Content-Digest", "sha-256=:x:")
			r := run(t, h, resp)
			if want := tt.before + fragment + tt.after; r.body != want {
				t.Fatalf("страница:\n%q\nожидалось:\n%q", r.body, want)
			}
			// Заголовок Content-Length прокси отдаст клиенту как есть:
			// старое значение обрезало бы страницу на её прежней длине.
			if r.length != int64(len(r.body)) || r.header.Get("Content-Length") != strconv.Itoa(len(r.body)) ||
				r.header.Get("Etag") != `W/"abc"` || r.header.Get("Content-Digest") != "" {
				t.Errorf("заголовки: длина %d при теле %d, %v", r.length, len(r.body), r.header)
			}
		})
	}
}

// TestInjectHTMLNoBody: тега <body> нет или он дальше предела — страница
// уходит как есть, вплоть до байта.
func TestInjectHTMLNoBody(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"нет тела":             `<!doctype html><title>x</title><p>body без тега`,
		"только в скрипте":     `<script>document.write("<body>")</script>`,
		"только в комментарии": `<!-- <body> -->`,
		"после plaintext":      `<plaintext><body>`,
		"дальше предела":       strings.Repeat("a", maxHTMLHead) + `<body>`,
		"пустая":               ``,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, htmlPolicy)
			r := run(t, h, page(body))
			if r.body != body || r.err != nil || r.length != int64(len(body)) {
				t.Errorf("страница изменена: %d байт вместо %d", len(r.body), len(body))
			}
			if h.inj.Stats.Skipped[SkipHTMLNoBody].Load() != 1 || h.inj.Stats.HTML.Load() != 0 {
				t.Error("пропуск не учтён")
			}
		})
	}
}

// TestHTMLEligible: вставка — только в страницу, которую откроет браузер.
func TestHTMLEligible(t *testing.T) {
	t.Parallel()

	const body = `<body>x`
	tests := []struct {
		name   string
		resp   appResponse
		reason SkipReason // -1 — не учитывается
	}{
		{"404", app(http.MethodGet, "/", 404, http.Header{"Content-Type": {"text/html"}}, body), -1},
		{"POST", app(http.MethodPost, "/", 200, http.Header{"Content-Type": {"text/html"}}, body), -1},
		{"HEAD", app(http.MethodHead, "/", 200, http.Header{"Content-Type": {"text/html"}}, body), -1},
		{"JSON", app(http.MethodGet, "/", 200, http.Header{"Content-Type": {"application/json"}}, body), -1},
		{"XHTML", app(http.MethodGet, "/", 200, http.Header{"Content-Type": {"application/xhtml+xml"}}, body), -1},
		{"без типа", app(http.MethodGet, "/", 200, nil, body), -1},
		{"сжата", app(http.MethodGet, "/", 200, http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {"br"}}, body),
			SkipHTMLEncoded},
		{"на скачивание", app(http.MethodGet, "/", 200, http.Header{
			"Content-Type": {"text/html"}, "Content-Disposition": {`attachment; filename="a.html"`}}, body), SkipHTMLNotPage},
		{"UTF-16", app(http.MethodGet, "/", 200, http.Header{"Content-Type": {"text/html; charset=UTF-16LE"}}, body),
			SkipHTMLNotPage},
		{"часть файла", app(http.MethodGet, "/", 200, http.Header{
			"Content-Type": {"text/html"}, "Content-Range": {"bytes 0-6/100"}}, body), SkipHTMLNotPage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, htmlPolicy)
			if r := run(t, h, tt.resp); r.body != body {
				t.Errorf("ответ изменён: %q", r.body)
			}
			for _, reason := range SkipReasons() {
				want := uint64(0)
				if reason == tt.reason {
					want = 1
				}
				if got := h.inj.Stats.Skipped[reason].Load(); got != want {
					t.Errorf("причина %s: %d, ожидалось %d", reason, got, want)
				}
			}
		})
	}

	// Identity — то же, что без сжатия; тип в другом регистре — тот же тип.
	h := newHarness(t, htmlPolicy)
	resp := app(http.MethodGet, "/", 200, http.Header{"Content-Type": {"Text/HTML"}, "Content-Encoding": {"identity"}}, body)
	if r := run(t, h, resp); r.body != `<body>`+fragment+`x` {
		t.Errorf("страница с identity: %q", r.body)
	}
}

// TestInjectHTMLChunked: длина неизвестна (chunked) — так и остаётся.
func TestInjectHTMLChunked(t *testing.T) {
	t.Parallel()

	h := newHarness(t, htmlPolicy)
	resp := page(`<body>x`)
	resp.chunked = true
	resp.unknownLength = true
	r := run(t, h, resp)
	if r.body != `<body>`+fragment+`x` || r.length != -1 || r.header.Get("Content-Length") != "" {
		t.Errorf("chunked: %q, длина %d", r.body, r.length)
	}
}

// TestInjectHTMLReadError: обрыв страницы у приложения доходит до клиента
// тем же обрывом, а прочитанное — как есть.
func TestInjectHTMLReadError(t *testing.T) {
	t.Parallel()

	h := newHarness(t, htmlPolicy)
	broken := errors.New("upstream reset")
	resp := page("")
	resp.bodyReader = &failingBody{Reader: strings.NewReader("<html><head>"), err: broken}
	r := run(t, h, resp)
	if r.body != "<html><head>" || !errors.Is(r.err, broken) {
		t.Errorf("клиент получил %q и ошибку того же вида: %v", r.body, errors.Is(r.err, broken))
	}
}

// panicOnceReader отдаёт первую часть, на следующем чтении паникует —
// один раз, — дальше отдаёт остаток. Так выглядит паника посреди чтения
// страницы, например внутри токенизатора.
type panicOnceReader struct {
	parts    []string
	panicked bool
}

func (r *panicOnceReader) Read(p []byte) (int, error) {
	if len(r.parts) == 0 {
		return 0, io.EOF
	}
	if len(r.parts) == 1 && !r.panicked {
		r.panicked = true
		panic("посреди чтения")
	}
	n := copy(p, r.parts[0])
	r.parts[0] = r.parts[0][n:]
	if r.parts[0] == "" {
		r.parts = r.parts[1:]
	}
	return n, nil
}

func (r *panicOnceReader) Close() error { return nil }

// TestInjectHTMLPanic: паника посреди чтения начала страницы — страница
// собирается обратно из прочитанного и остатка, без вставки и без потерь.
func TestInjectHTMLPanic(t *testing.T) {
	t.Parallel()

	h := newHarness(t, htmlPolicy)
	resp := page("")
	resp.bodyReader = &panicOnceReader{parts: []string{"<html><head><title>x", "</title></head><body>y"}}
	r := run(t, h, resp)
	if r.body != "<html><head><title>x</title></head><body>y" || len(h.panics) != 1 {
		t.Errorf("после паники клиент получил %q, паник %d", r.body, len(h.panics))
	}
	if h.inj.Stats.HTML.Load() != 0 || h.inj.Stats.Skipped[SkipPanic].Load() != 1 {
		t.Error("счётчики после паники")
	}
}

// TestPrepareHTML: без сжатия сенсор просит только страницы.
func TestPrepareHTML(t *testing.T) {
	t.Parallel()

	req := func(method string, headers ...string) (*http.Request, *http.Request) {
		in := httptest.NewRequest(method, "/", nil)
		for i := 0; i < len(headers); i += 2 {
			in.Header.Set(headers[i], headers[i+1])
		}
		out := in.Clone(in.Context())
		out.Header.Set("Accept-Encoding", "gzip, br")
		out.Header.Set("If-None-Match", `"a"`)
		return in, out
	}
	tests := []struct {
		name     string
		method   string
		headers  []string
		identity bool
	}{
		{"переход по странице", http.MethodGet, []string{"Sec-Fetch-Dest", "document"}, true},
		{"фрейм", http.MethodGet, []string{"Sec-Fetch-Dest", "iframe"}, true},
		{"без Sec-Fetch, Accept с HTML", http.MethodGet, []string{"Accept", "text/html,*/*"}, true},
		{"fetch из скрипта", http.MethodGet, []string{"Sec-Fetch-Dest", "empty", "Accept", "text/html"}, false},
		{"картинка", http.MethodGet, []string{"Sec-Fetch-Dest", "image"}, false},
		{"curl", http.MethodGet, []string{"Accept", "*/*"}, false},
		{"POST формы", http.MethodPost, []string{"Sec-Fetch-Dest", "document"}, false},
	}
	for _, tt := range tests {
		h := newHarness(t, htmlPolicy)
		in, out := req(tt.method, tt.headers...)
		h.inj.Prepare(in, out)
		if got := out.Header.Get("Accept-Encoding") == "identity"; got != tt.identity {
			t.Errorf("%s: identity = %v", tt.name, got)
		}
		// Условия остаются: на 304 браузер покажет свою копию страницы,
		// полученную от сенсора, — с наживкой.
		if out.Header.Get("If-None-Match") == "" {
			t.Errorf("%s: условный заголовок убран", tt.name)
		}
	}

	h := newHarness(t, testPolicy) // наживки только в заголовке и robots.txt
	in, out := req(http.MethodGet, "Sec-Fetch-Dest", "document")
	h.inj.Prepare(in, out)
	if out.Header.Get("Accept-Encoding") != "gzip, br" {
		t.Error("без HTML-наживок страница запрошена без сжатия")
	}

	// При перегрузке наживки не ставятся — и сжатие не отключается.
	h = newHarness(t, htmlPolicy)
	h.degraded.Store(true)
	in, out = req(http.MethodGet, "Sec-Fetch-Dest", "document")
	h.inj.Prepare(in, out)
	if out.Header.Get("Accept-Encoding") != "gzip, br" {
		t.Error("в частичном режиме страница запрошена без сжатия")
	}
}

// FuzzInjectHTML — главное свойство правки HTML. Для любой страницы:
//   - сенсор не падает;
//   - страница либо не изменена, либо изменена ровно вставкой фрагмента
//     в одном месте, остальные байты — те же;
//   - если вставка есть, браузерный токенизатор видит её как разметку —
//     комментарий и ссылку, — а не как текст скрипта, часть комментария
//     или значения атрибута.
func FuzzInjectHTML(f *testing.F) {
	for _, s := range []string{
		`<body>`, `<!-- <body> --><body>`, `<script>"<body>"</script><body>`,
		`<script><!--<script></script><body></script><body>`, `<body class="a>b">`,
		`<title><body></title><body>`, `<noscript><body></noscript><body>`, `<svg><body>`,
		`<template><body></template><body>`, "<body\x00>", `<body a="`, `<!--`, `<![CDATA[<body>]]>`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		h := newHarness(t, htmlPolicy)
		r := run(t, h, page(input))
		if r.body == input {
			return
		}
		i := strings.Index(r.body, fragment)
		if i < 0 || r.body[:i]+r.body[i+len(fragment):] != input {
			t.Fatalf("страница изменена не только вставкой:\nбыло  %q\nстало %q", input, r.body)
		}
		// Токенизатор на выходе видит после <body> именно комментарий и ссылку.
		z := html.NewTokenizer(strings.NewReader(r.body))
		pos := 0
		for pos < i {
			if z.Next() == html.ErrorToken {
				t.Fatalf("токенизатор не дошёл до вставки: %q", r.body)
			}
			pos += len(z.Raw())
		}
		if pos != i {
			t.Fatalf("вставка не на границе токена: %q", r.body)
		}
		if z.Next() != html.CommentToken || !bytes.Contains(z.Raw(), []byte("documentation moved")) {
			t.Fatalf("комментарий не комментарий: %q", r.body)
		}
		if z.Next() != html.StartTagToken {
			t.Fatalf("ссылка не тег: %q", r.body)
		}
		if name, _ := z.TagName(); string(name) != "a" {
			t.Fatalf("вместо ссылки тег %q", name)
		}
	})
}
