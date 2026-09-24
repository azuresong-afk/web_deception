// Package lure — наживки в ответах приложения: строки, которые ведут
// атакующего к ловушкам (ADR-0027).
//
// Наживка — не ответ вместо приложения, а правка его ответа: сенсор
// добавляет заголовок или строки в robots.txt. Поэтому правила здесь
// строже, чем у ловушек:
//   - текст наживки собирается сенсором по шаблону, из политики в ответ
//     попадают только путь ловушки и имя заголовка — оба проверены
//     при разборе политики (T15);
//   - правка — fail-open: паника или неожиданный ответ приложения —
//     ответ уходит клиенту как есть, а паника записывается событием;
//   - в режиме частичного обнаружения (ADR-0024) наживки не ставятся:
//     это тоже работа обнаружения.
//
// Граница доверия: ответ приложения доверенный лишь частично — в нём
// может быть то, что сохранил атакующий. Тело robots.txt читается
// с пределом, заголовки только сравниваются.
package lure

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/azuresong-afk/web_deception/sensor/internal/policy"
)

// maxRobotsBytes — самый большой robots.txt, который сенсор дополняет.
// Google читает только первые 500 КиБ; больше — ответ уходит как есть.
const maxRobotsBytes = 512 << 10

// robotsPath — путь robots.txt. Роботы запрашивают ровно его.
const robotsPath = "/robots.txt"

// SkipReason — почему наживка не поставлена.
type SkipReason int

const (
	// SkipDegraded — обнаружение перегружено (ADR-0024).
	SkipDegraded SkipReason = iota
	// SkipHeaderExists — такой заголовок уже есть в ответе приложения.
	SkipHeaderExists
	// SkipRobotsStatus — robots.txt ответил не 200 и не 404: например,
	// 5xx для роботов значит «не заходить никуда», и подменять его нельзя.
	SkipRobotsStatus
	// SkipRobotsNotText — robots.txt не text/plain.
	SkipRobotsNotText
	// SkipRobotsEncoded — robots.txt сжат, хотя сенсор просил без сжатия.
	SkipRobotsEncoded
	// SkipRobotsTooLarge — robots.txt больше maxRobotsBytes.
	SkipRobotsTooLarge
	// SkipPanic — паника при правке ответа; ответ ушёл как есть.
	SkipPanic
	numSkipReasons
)

// skipNames — значения метки reason в /metrics. Константы из кода.
var skipNames = [numSkipReasons]string{
	SkipDegraded:       "degraded",
	SkipHeaderExists:   "header_exists",
	SkipRobotsStatus:   "robots_status",
	SkipRobotsNotText:  "robots_not_text",
	SkipRobotsEncoded:  "robots_encoded",
	SkipRobotsTooLarge: "robots_too_large",
	SkipPanic:          "panic",
}

// String — имя причины для метки метрики.
func (s SkipReason) String() string { return skipNames[s] }

// SkipReasons — все причины по порядку, для /metrics.
func SkipReasons() []SkipReason {
	out := make([]SkipReason, numSkipReasons)
	for i := range out {
		out[i] = SkipReason(i)
	}
	return out
}

// Stats — счётчики для /metrics.
type Stats struct {
	// Headers — ответы, получившие заголовок-наживку.
	Headers atomic.Uint64
	// Robots — ответы на robots.txt со строками-наживками: дополненные
	// или созданные вместо 404.
	Robots atomic.Uint64
	// Skipped — наживки, которые не поставлены, по причине.
	Skipped [numSkipReasons]atomic.Uint64
}

// Config — зависимости Injector. Все поля обязательны.
type Config struct {
	// Policy — текущая политика (decoy.Detector.Current).
	Policy func() *policy.Compiled
	// Degraded — включён ли режим частичного обнаружения (failopen.Guard).
	Degraded func() bool
	// OnPanic записывает панику: событие, счётчик, стек в лог
	// (failopen.Guard.RecordPanic).
	OnPanic func(r *http.Request, p any, stage string)
}

// Injector ставит наживки в ответы приложения.
type Injector struct {
	cfg   Config
	Stats Stats
}

// New создаёт Injector.
func New(cfg Config) *Injector {
	if cfg.Policy == nil || cfg.Degraded == nil || cfg.OnPanic == nil {
		panic("lure: в Config не заданы все поля")
	}
	return &Injector{cfg: cfg}
}

// Prepare правит запрос, который сенсор отправит приложению, если ответ
// на него получит наживку. in — запрос клиента, out — исходящий.
//
// Для robots.txt сенсор просит ответ без сжатия и без условий: сжатый
// robots.txt не дополнить, а на условный запрос приложение ответило бы 304,
// и клиент остался бы с копией без наживок. robots.txt — несколько сотен
// байт, и лишний трафик здесь ничего не стоит.
func (inj *Injector) Prepare(in, out *http.Request) {
	if !isRobots(in) || len(inj.cfg.Policy().RobotsDisallow()) == 0 || inj.cfg.Degraded() {
		return
	}
	out.Header.Set("Accept-Encoding", "identity")
	for _, h := range []string{"If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "If-Range", "Range"} {
		out.Header.Del(h)
	}
}

// Modify ставит наживки в ответ приложения. Ошибку не возвращает никогда:
// ошибка из ModifyResponse означала бы 502 для клиента, а сбой наживки
// не должен ломать сайт.
func (inj *Injector) Modify(resp *http.Response) error {
	p := inj.cfg.Policy()
	if len(p.Lures()) == 0 {
		return nil
	}
	if inj.cfg.Degraded() {
		inj.Stats.Skipped[SkipDegraded].Add(1)
		return nil
	}

	// Тело читается до правки. Если правка упадёт, ответ собирается
	// обратно из прочитанного и непрочитанного — клиент получит его
	// как есть.
	orig := resp.Body
	var consumed []byte
	defer func() {
		if rec := recover(); rec != nil {
			inj.Stats.Skipped[SkipPanic].Add(1)
			if consumed != nil {
				resp.Body = readCloser{io.MultiReader(bytes.NewReader(consumed), orig), orig}
			}
			inj.cfg.OnPanic(resp.Request, rec, "lure")
		}
	}()

	inj.addHeaders(resp, p)
	if resp.Request != nil && isRobots(resp.Request) && len(p.RobotsDisallow()) > 0 {
		inj.robots(resp, p.RobotsDisallow(), &consumed)
	}
	return nil
}

// addHeaders добавляет заголовки-наживки. Заголовок, который уже есть
// в ответе приложения, не трогается: его значение — дело приложения.
func (inj *Injector) addHeaders(resp *http.Response, p *policy.Compiled) {
	added := false
	for _, l := range p.HeaderLures() {
		if resp.Header.Get(l.Header) != "" {
			inj.Stats.Skipped[SkipHeaderExists].Add(1)
			continue
		}
		// Имя и путь проверены при разборе политики: только латиница,
		// цифры и символы пути — ни перевода строки, ни «;».
		resp.Header.Set(l.Header, l.Path())
		added = true
	}
	if added {
		inj.Stats.Headers.Add(1)
	}
}

// robots дополняет robots.txt строками «Disallow» или создаёт его вместо
// 404. Прочитанное тело сразу кладётся в consumed — чтобы при панике
// ответ можно было собрать обратно.
func (inj *Injector) robots(resp *http.Response, paths []string, consumed *[]byte) {
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// robots.txt у приложения нет. Сенсор отвечает своим: для роботов
		// «нет файла» и «файл, запрещающий только ловушки» значат почти
		// одно и то же — ходить можно везде, кроме ловушек.
		_ = resp.Body.Close()
		setBody(resp, robotsGroup(paths))
		resp.StatusCode = http.StatusOK
		resp.Status = "200 OK"
		for _, h := range bodyHeaders {
			resp.Header.Del(h)
		}
		resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
		resp.Header.Set("Content-Length", strconv.Itoa(int(resp.ContentLength)))
		inj.Stats.Robots.Add(1)
		return
	default:
		inj.Stats.Skipped[SkipRobotsStatus].Add(1)
		return
	}

	mediaType, _, _ := strings.Cut(resp.Header.Get("Content-Type"), ";")
	if !strings.EqualFold(strings.TrimSpace(mediaType), "text/plain") {
		inj.Stats.Skipped[SkipRobotsNotText].Add(1)
		return
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		inj.Stats.Skipped[SkipRobotsEncoded].Add(1)
		return
	}

	orig := resp.Body
	data, err := io.ReadAll(io.LimitReader(orig, maxRobotsBytes+1))
	*consumed = data
	if err != nil || len(data) > maxRobotsBytes {
		// Больше предела или обрыв: отдаём как есть — прочитанное
		// и остаток, ошибка чтения дойдёт до клиента так же, как без
		// сенсора.
		if err == nil {
			inj.Stats.Skipped[SkipRobotsTooLarge].Add(1)
		}
		resp.Body = readCloser{io.MultiReader(bytes.NewReader(data), errReader{err, orig}), orig}
		*consumed = nil
		return
	}

	var b bytes.Buffer
	b.Grow(len(data) + 64*len(paths))
	b.Write(data)
	if len(data) > 0 && data[len(data)-1] != '\n' {
		b.WriteByte('\n')
	}
	// Своя группа «User-agent: *» в конце: по RFC 9309 группы для одного
	// робота объединяются, поэтому существующие правила не меняются,
	// а наши добавляются ко всем роботам.
	b.WriteByte('\n')
	b.WriteString(robotsGroup(paths))
	// Исходное тело прочитано до конца; закрываем его только теперь,
	// когда новое тело готово.
	_ = orig.Close()
	setBody(resp, b.String())
	// Валидаторы описывали другие байты: ETag и сводки содержимого
	// убираем, иначе кэш принял бы наш ответ за ответ приложения.
	for _, h := range []string{"ETag", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest"} {
		resp.Header.Del(h)
	}
	resp.Header.Set("Content-Length", strconv.Itoa(int(resp.ContentLength)))
	inj.Stats.Robots.Add(1)
}

// bodyHeaders — заголовки, которые описывают тело ответа приложения
// и неверны для тела, созданного сенсором.
var bodyHeaders = []string{
	"Content-Type", "Content-Length", "Content-Encoding", "Content-Range", "Content-Language",
	"Content-Location", "Content-Disposition", "ETag", "Last-Modified",
	"Content-MD5", "Digest", "Content-Digest", "Repr-Digest",
}

// robotsGroup — группа robots.txt со строками-наживками.
func robotsGroup(paths []string) string {
	var b strings.Builder
	b.WriteString("User-agent: *\n")
	for _, p := range paths {
		b.WriteString("Disallow: ")
		b.WriteString(p)
		b.WriteByte('\n')
	}
	return b.String()
}

// setBody заменяет тело ответа и его длину.
func setBody(resp *http.Response, body string) {
	resp.Body = io.NopCloser(strings.NewReader(body))
	resp.ContentLength = int64(len(body))
	// Длина теперь известна: без chunked.
	resp.TransferEncoding = nil
}

// isRobots — запрос за robots.txt.
func isRobots(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL != nil && r.URL.Path == robotsPath
}

// readCloser — Reader с Close исходного тела: соединение с приложением
// закрывается как обычно.
type readCloser struct {
	io.Reader
	io.Closer
}

// errReader возвращает ошибку чтения, если она была, иначе читает дальше
// из исходного тела.
type errReader struct {
	err  error
	rest io.Reader
}

func (e errReader) Read(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	return e.rest.Read(p)
}
