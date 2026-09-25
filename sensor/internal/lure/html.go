package lure

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Правка HTML — самое рискованное место сенсора (ADR-0028). Сенсор
// вставляет в чужую страницу готовый фрагмент — комментарий и скрытую
// ссылку, собранные при разборе политики, — и обязан:
//   - вставить его туда, где браузер увидит именно разметку: не внутрь
//     <script>, комментария или значения атрибута. Место ищет токенизатор
//     HTML5 из golang.org/x/net/html — он разбирает эти состояния так же,
//     как браузер. Своего разборщика HTML для чужого ввода не пишем
//     по той же причине, что и своей криптографии;
//   - не изменить больше ни байта: всё до вставки и после — исходные байты
//     страницы, без пересборки;
//   - при любой неожиданности отдать страницу как есть.

// maxHTMLHead — сколько байт страницы сенсор читает в поисках <body>.
// У обычной страницы <body> — в первых килобайтах; всё, что дальше
// предела, уходит клиенту без изменений и без задержки.
const maxHTMLHead = 256 << 10

// htmlReserve — память из бюджета (budget.go) на поиск <body> в худшем
// случае: буфер прочитанного растёт удвоением, у токенизатора — свой
// буфер под самый длинный токен. Замер — TestEditReserves, около 1,7 МиБ
// на странице, где весь предел занимает один <script>.
const htmlReserve = 2 << 20

// isHTMLPage — запрос за страницей: GET, и браузер сообщил, что ждёт
// документ (Sec-Fetch-Dest), а без этого заголовка — text/html в Accept.
// Только для таких запросов сенсор просит у приложения ответ без сжатия:
// картинки, скрипты и API он не трогает.
func isHTMLPage(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		return dest == "document" || dest == "iframe" || dest == "frame"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// htmlEligible — ответ, в который можно вставить наживку, и если нет —
// почему. ok=false и reason<0 — ответ не страница, считать не нужно.
func htmlEligible(resp *http.Response) (ok bool, reason SkipReason) {
	if resp.Request == nil || resp.Request.Method != http.MethodGet || resp.StatusCode != http.StatusOK {
		return false, -1
	}
	mediaType, params, _ := strings.Cut(resp.Header.Get("Content-Type"), ";")
	if !strings.EqualFold(strings.TrimSpace(mediaType), "text/html") {
		return false, -1
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return false, SkipHTMLEncoded
	}
	// Вставка — байты ASCII. В UTF-16 и UTF-32 они стали бы мусором
	// посреди страницы. Файл на скачивание и часть файла (Content-Range) —
	// не страница, которую откроет браузер.
	charset := strings.ToLower(params)
	if strings.Contains(charset, "utf-16") || strings.Contains(charset, "utf-32") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Disposition"))), "attachment") ||
		resp.Header.Get("Content-Range") != "" {
		return false, SkipHTMLNotPage
	}
	return true, 0
}

// bodyInsertOffset ищет место сразу после стартового тега <body>.
// Возвращает смещение в прочитанных байтах или -1, если тега нет
// в пределах maxHTMLHead. Всё, что прочитал токенизатор, копится
// в consumed; err — ошибка чтения тела приложения (не конец данных).
func bodyInsertOffset(body io.Reader, consumed *bytes.Buffer) (offset int, err error) {
	z := html.NewTokenizer(io.TeeReader(io.LimitReader(body, maxHTMLHead), consumed))
	pos := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if e := z.Err(); !errors.Is(e, io.EOF) {
				err = e
			}
			return -1, err
		}
		// Raw — байты токена как есть; их сумма — смещение в странице.
		pos += len(z.Raw())
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			name, _ := z.TagName()
			if atom.Lookup(name) == atom.Body {
				return pos, nil
			}
		}
	}
}

// injectHTML вставляет фрагмент сразу после <body>. Тело читается
// в e.consumed — чтобы при панике, в том числе внутри токенизатора, ответ
// можно было собрать обратно.
func (inj *Injector) injectHTML(resp *http.Response, fragment string, e *edit) {
	if e.mem = inj.mem.lease(htmlReserve); e.mem == nil {
		inj.Stats.Skipped[SkipMemory].Add(1)
		return
	}
	orig := resp.Body
	buf := &bytes.Buffer{}
	e.consumed = buf
	offset, err := bodyInsertOffset(orig, buf)
	read := buf.Bytes()
	// Буфер токенизатора больше не нужен; до конца отправки клиенту
	// в памяти остаётся только прочитанное.
	e.mem.shrink(int64(buf.Cap()))
	if offset < 0 {
		// Тега нет, страница оборвалась или больше предела: как есть.
		if err == nil {
			inj.Stats.Skipped[SkipHTMLNoBody].Add(1)
		}
		resp.Body = heldBody{io.MultiReader(bytes.NewReader(read), errReader{err, orig}), orig, e.mem}
		e.consumed = nil
		return
	}

	// Вставка — между кусками прочитанного, без копирования страницы.
	resp.Body = heldBody{io.MultiReader(bytes.NewReader(read[:offset]), strings.NewReader(fragment),
		bytes.NewReader(read[offset:]), orig), orig, e.mem}
	e.consumed = nil

	if resp.ContentLength >= 0 {
		resp.ContentLength += int64(len(fragment))
		resp.Header.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	// Сильный ETag обещает побайтно то же тело, а тело теперь другое.
	// Слабый («W/») говорит «по смыслу то же» — и кэши не соберут
	// страницу из кусков разных версий по Range. Сводки содержимого
	// описывали байты приложения.
	if etag := resp.Header.Get("ETag"); etag != "" && !strings.HasPrefix(etag, "W/") {
		resp.Header.Set("ETag", "W/"+etag)
	}
	for _, h := range []string{"Content-MD5", "Digest", "Content-Digest", "Repr-Digest"} {
		resp.Header.Del(h)
	}
	inj.Stats.HTML.Add(1)
}
