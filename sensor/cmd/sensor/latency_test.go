//go:build latency

package main

// Замер задержки сенсора под нагрузкой (ADR-0030). Не обычный тест: идёт
// минуты и зависит от машины, поэтому собирается только с тегом latency
// и запускается из make bench, а не из make test и CI.
//
// Как устроен замер:
//   - приложение-заглушка отвечает сразу, без своей задержки: всё, что
//     добавилось, — это сенсор;
//   - сенсор запускается целиком (run), с учебной политикой
//     deploy/policy/demo.json: ловушки, наживки, cookie-наживка;
//   - один и тот же поток запросов идёт напрямую в приложение и через
//     сенсор; разница перцентилей — цена сенсора;
//   - открытая модель нагрузки: запросы отправляются по расписанию
//     (rate в секунду), не дожидаясь ответов на предыдущие. Задержка
//     считается от момента, когда запрос ДОЛЖЕН был уйти. Иначе медленный
//     ответ задерживал бы отправку следующих и прятал бы сам себя
//     (coordinated omission).
//
// Генератор, приложение и сенсор делят одну машину и её процессоры.
// Это завышает цену сенсора, а не занижает: оценка осторожная.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	latRates    = flag.String("latency.rates", "200,1000", "нагрузка, запросов в секунду, через запятую")
	latDuration = flag.Duration("latency.duration", 3*time.Second, "длительность замера одного сценария")
	latWarmup   = flag.Duration("latency.warmup", time.Second, "прогрев перед замером")
	latRounds   = flag.Int("latency.rounds", 3, "повторов; в отчёте — медиана по повторам")
)

// latencyBudget — бюджет сенсора: не больше +5 мс к p99 (roadmap, шаг 11).
const latencyBudget = 5 * time.Millisecond

// scenario — вид запроса. rateDiv делит нагрузку: скачивание 256 КиБ
// на полной нагрузке мерило бы пропускную способность loopback, а не сенсор.
type scenario struct {
	name    string
	method  string
	path    string
	headers map[string]string
	body    string
	rateDiv int
	// budget — проверять ли бюджет. Касание ловушки отвечает сам сенсор,
	// без приложения, и сравнивать его с прямым запросом бессмысленно.
	budget bool
}

var scenarios = []scenario{
	{name: "API: GET JSON", method: http.MethodGet, path: "/api/Products/42",
		headers: map[string]string{"Accept": "application/json", "Sec-Fetch-Dest": "empty"}, rateDiv: 1, budget: true},
	{name: "страница с наживками", method: http.MethodGet, path: "/",
		headers: map[string]string{"Accept": "text/html", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate",
			"Accept-Encoding": "gzip, br"}, rateDiv: 1, budget: true},
	{name: "API: POST JSON 2 КиБ", method: http.MethodPost, path: "/api/BasketItems",
		headers: map[string]string{"Content-Type": "application/json"}, body: `{"data":"` + strings.Repeat("x", 2048) + `"}`,
		rateDiv: 1, budget: true},
	{name: "robots.txt", method: http.MethodGet, path: "/robots.txt", rateDiv: 1, budget: true},
	{name: "скачивание 256 КиБ", method: http.MethodGet, path: "/main.js", rateDiv: 10, budget: true},
	{name: "касание ловушки", method: http.MethodGet, path: "/.env", rateDiv: 1},
}

// benchApp — приложение-заглушка: отвечает сразу. Страница — размером
// со стартовую Juice Shop, <body> после 9 КиБ <head>.
func benchApp() http.Handler {
	page := "<!doctype html><html><head><title>shop</title>" +
		strings.Repeat(`<link rel="stylesheet" href="/styles.css"><script src="/main.js" defer></script>`, 90) +
		`</head><body class="app"><app-root></app-root></body></html>`
	js := strings.Repeat("console.log(1);\n", 256<<10/16)
	product := `{"status":"success","data":{"id":42,"name":"Apple Juice","description":"` + strings.Repeat("x", 900) + `"}}`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("ETag", `"v1"`)
			_, _ = io.WriteString(w, page)
		case "/api/Products/42":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, product)
		case "/api/BasketItems":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"status":"success"}`)
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "User-agent: *\nDisallow: /ftp\n")
		case "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = io.WriteString(w, js)
		default:
			http.NotFound(w, r)
		}
	})
}

// result — перцентили одного замера.
type result struct {
	p50, p99, p999, max time.Duration
	errors              int
}

// measure отправляет rate запросов в секунду в течение dur по расписанию
// и возвращает перцентили задержки от запланированного момента отправки.
func measure(ctx context.Context, client *http.Client, base string, sc scenario, rate int, dur time.Duration) result {
	n := int(float64(rate) * dur.Seconds())
	lat := make([]time.Duration, n)
	var errs atomic.Int64
	interval := time.Second / time.Duration(rate)
	start := time.Now().Add(5 * time.Millisecond)
	var wg sync.WaitGroup
	for i := range n {
		due := start.Add(time.Duration(i) * interval)
		if d := time.Until(due); d > 0 {
			time.Sleep(d)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var body io.Reader
			if sc.body != "" {
				body = strings.NewReader(sc.body)
			}
			req, err := http.NewRequestWithContext(ctx, sc.method, base+sc.path, body)
			if err != nil {
				errs.Add(1)
				return
			}
			for k, v := range sc.headers {
				req.Header.Set(k, v)
			}
			resp, err := client.Do(req)
			if err != nil {
				errs.Add(1)
				lat[i] = -1
				return
			}
			_, copyErr := io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if copyErr != nil || resp.StatusCode >= 500 {
				errs.Add(1)
			}
			lat[i] = time.Since(due)
		}()
	}
	wg.Wait()

	lat = slices.DeleteFunc(lat, func(d time.Duration) bool { return d <= 0 })
	slices.Sort(lat)
	at := func(q float64) time.Duration {
		if len(lat) == 0 {
			return 0
		}
		return lat[min(len(lat)-1, int(q*float64(len(lat))))]
	}
	return result{p50: at(0.50), p99: at(0.99), p999: at(0.999), max: at(1), errors: int(errs.Load())}
}

// median — медиана по повторам: один случайный всплеск (сборка мусора,
// соседний процесс) не решает исход.
func median(rs []result, f func(result) time.Duration) time.Duration {
	v := make([]time.Duration, len(rs))
	for i, r := range rs {
		v[i] = f(r)
	}
	slices.Sort(v)
	return v[len(v)/2]
}

func newClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns: 2048, MaxIdleConnsPerHost: 2048, IdleConnTimeout: time.Minute,
			// Без распаковки: клиент видит ответ как есть, как браузер
			// видит байты.
			DisableCompression: true,
		},
		Timeout: 10 * time.Second,
	}
}

// metric читает значение счётчика из /metrics сенсора.
func metric(t *testing.T, admin, name string) int {
	t.Helper()
	_, body := httpGet(t, "http://"+admin+"/metrics")
	m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(name) + ` (\d+)$`).FindStringSubmatch(body)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

func TestLatencyBudget(t *testing.T) {
	app := httptest.NewServer(benchApp())
	defer app.Close()

	cfg := testConfig(t, app.URL)
	cfg.MaxConns = 1024
	dir := t.TempDir()
	cfg.PolicyFile = filepath.Join("..", "..", "..", "deploy", "policy", "demo.json")
	cfg.PolicyCacheFile = filepath.Join(dir, "policy.last-valid.json")
	if _, err := os.Stat(cfg.PolicyFile); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addrs, runErr := startSensor(ctx, t, cfg)
	targets := []struct{ name, base string }{
		{"напрямую", app.URL},
		{"через сенсор", "http://" + addrs.Proxy.String()},
	}

	var rates []int
	for _, s := range strings.Split(*latRates, ",") {
		r, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || r <= 0 {
			t.Fatalf("latency.rates: %q", s)
		}
		rates = append(rates, r)
	}

	var report strings.Builder
	fmt.Fprintf(&report, "\n| Нагрузка | Сценарий | p50 напрямую | p50 сенсор | p99 напрямую | p99 сенсор | +p99 | p99.9 сенсор | ошибки |\n")
	fmt.Fprintf(&report, "|---|---|---|---|---|---|---|---|---|\n")
	htmlBefore := metric(t, addrs.Admin.String(), `sensor_lures_total{kind="html"}`)
	pagesSent := 0

	for _, rate := range rates {
		for _, sc := range scenarios {
			r := max(1, rate/sc.rateDiv)
			rounds := make([][]result, len(targets))
			for round := range *latRounds {
				for k := range targets {
					// Порядок меняется от повтора к повтору: тот, кто идёт
					// вторым, получает прогретую машину.
					ti := (k + round) % len(targets)
					client := newClient()
					measure(ctx, client, targets[ti].base, sc, r, *latWarmup)
					res := measure(ctx, client, targets[ti].base, sc, r, *latDuration)
					client.CloseIdleConnections()
					rounds[ti] = append(rounds[ti], res)
					if ti == 1 && sc.path == "/" {
						pagesSent += int(float64(r) * (latWarmup.Seconds() + latDuration.Seconds()))
					}
				}
			}
			d, s := rounds[0], rounds[1]
			p99 := func(r result) time.Duration { return r.p99 }
			extra := median(s, p99) - median(d, p99)
			errsN := 0
			for _, x := range s {
				errsN += x.errors
			}
			fmt.Fprintf(&report, "| %d/с | %s | %s | %s | %s | %s | %s | %s | %d |\n", r, sc.name,
				ms(median(d, func(r result) time.Duration { return r.p50 })), ms(median(s, func(r result) time.Duration { return r.p50 })),
				ms(median(d, p99)), ms(median(s, p99)), ms(extra),
				ms(median(s, func(r result) time.Duration { return r.p999 })), errsN)
			if errsN > 0 {
				t.Errorf("%s при %d/с: %d ошибок через сенсор", sc.name, r, errsN)
			}
			if sc.budget && extra > latencyBudget {
				t.Errorf("%s при %d/с: сенсор добавил %s к p99 — больше бюджета %s", sc.name, r, extra, latencyBudget)
			}
		}
	}

	// Наживки под нагрузкой ставились, а не пропускались: каждая страница
	// через сенсор получила вставку.
	html := metric(t, addrs.Admin.String(), `sensor_lures_total{kind="html"}`) - htmlBefore
	skipped := metric(t, addrs.Admin.String(), `sensor_lures_skipped_total{reason="memory"}`)
	fmt.Fprintf(&report, "\nСтраниц через сенсор: %d, с наживкой: %d, пропущено по памяти: %d\n", pagesSent, html, skipped)
	if html != pagesSent {
		t.Errorf("наживка поставлена на %d страниц из %d", html, pagesSent)
	}
	t.Log(report.String())

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("остановка: %v", err)
	}
}

// ms — длительность в миллисекундах с двумя знаками.
func ms(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', 2, 64) + " мс"
}
