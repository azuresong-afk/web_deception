// Команда sensor — точка входа сенсора web-deception.
//
// Сенсор поднимает два слушателя:
//   - клиентский — принимает трафик из сети и передаёт его защищаемому
//     приложению (пакет proxy);
//   - служебный — /healthz и /readyz для проверок живости, только на
//     localhost по умолчанию (пакет admin).
//
// Обнаружение — ловушки из файла политики (пакеты policy и decoy) — стоит
// внутри защиты fail-open (пакет failopen): его сбой или перегрузка
// не ломают трафик. Политика перечитывается по SIGHUP. События (запуск, остановка, попытки CONNECT,
// переходы в fail-open) пишутся в файл JSON Lines
// через буфер, который никогда не задерживает трафик (пакет event),
// счётчики — на служебном слушателе в /metrics (пакет metrics).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/azuresong-afk/web_deception/sensor/internal/admin"
	"github.com/azuresong-afk/web_deception/sensor/internal/config"
	"github.com/azuresong-afk/web_deception/sensor/internal/decoy"
	"github.com/azuresong-afk/web_deception/sensor/internal/event"
	"github.com/azuresong-afk/web_deception/sensor/internal/failopen"
	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
	"github.com/azuresong-afk/web_deception/sensor/internal/healthcheck"
	"github.com/azuresong-afk/web_deception/sensor/internal/lure"
	"github.com/azuresong-afk/web_deception/sensor/internal/metrics"
	"github.com/azuresong-afk/web_deception/sensor/internal/proxy"
	"github.com/azuresong-afk/web_deception/sensor/internal/version"
)

func main() {
	// Разбор аргументов без библиотеки флагов: вариантов ровно два, и любой
	// третий — ошибка, а не повод молча его проигнорировать. Проигнорированный
	// аргумент — это настройка, которую администратор считает действующей.
	switch {
	case len(os.Args) == 1:
		// Обычный запуск сервера — ниже.
	case len(os.Args) == 2 && os.Args[1] == "healthcheck":
		os.Exit(runHealthcheck(os.Getenv, os.Stderr))
	default:
		fmt.Fprintln(os.Stderr, "использование: sensor [healthcheck]")
		os.Exit(2)
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		// Логгер ещё не создан: его уровень берётся из конфигурации,
		// которую мы как раз не смогли прочитать. Пишем напрямую в stderr.
		//
		// Код возврата 2 отличает ошибку конфигурации от ошибки работы.
		// Это видно в docker compose и systemd сразу, без чтения логов:
		// 2 — «поправь переменные окружения», 1 — «что-то сломалось».
		fmt.Fprintf(os.Stderr, "ошибка конфигурации: %v\n", err)
		os.Exit(2)
	}

	// Логи пишем в stderr в формате JSON. stderr — потому что stdout
	// зарезервирован под данные; JSON — потому что логи сенсора будет
	// читать машина, а не только человек.
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))

	// Предупреждения не останавливают запуск, но обязаны остаться в логе:
	// при разборе инцидента должно быть видно, что рискованная настройка
	// была сделана осознанно.
	for _, w := range cfg.Warnings() {
		logger.Warn(w)
	}

	if err := run(context.Background(), cfg, logger, nil); err != nil {
		logger.Error("сенсор остановлен из-за ошибки", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

// listenAddrs — фактические адреса обоих слушателей после открытия.
type listenAddrs struct {
	Admin net.Addr
	Proxy net.Addr
}

// run поднимает сенсор и работает, пока контекст не будет отменён сигналом.
//
// Параметр onListen вызывается с фактическими адресами слушателей сразу
// после их открытия. В main он не нужен и передаётся nil; он существует ради
// тестов, которые запускают сенсор на порту 0 (любой свободный) и иначе
// не смогли бы узнать, куда стучаться. Альтернатива — фиксированный порт
// в тестах — делает тесты нестабильными: порт может быть занят.
func run(ctx context.Context, cfg *config.Config, logger *slog.Logger, onListen func(listenAddrs)) error {
	// NotifyContext отменяет контекст при SIGINT (Ctrl+C) или SIGTERM.
	// SIGTERM посылают docker stop и Kubernetes. Без его обработки
	// контейнер живёт положенные секунды и получает SIGKILL, который
	// обрывает все активные запросы клиентов на полуслове.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP — «перечитай политику». Подписываемся сразу, до всего
	// остального: по умолчанию Go при SIGHUP завершает процесс, и без этой
	// строки команда перезагрузки политики уронила бы сенсор, а с ним сайт.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)

	// Файл событий открываем первым, до слушателей. Не открылся — сенсор
	// не стартует: сенсор, который пропускает трафик и молча ничего
	// не записывает, создаёт ложное чувство защищённости. Это ошибка
	// развёртывания, и видна она сразу при запуске (ADR-0023).
	sink, err := event.OpenFile(cfg.EventsFile)
	if err != nil {
		return fmt.Errorf("не удалось открыть файл событий: %w", err)
	}
	events := event.NewRecorder(sink, event.QueueSize, logger)
	// Recorder закрываем при любом выходе из run, в том числе при ошибке
	// открытия слушателей: иначе принятые события не допишутся в файл.
	// Повторный Close безопасен.
	defer closeEvents(events, logger)

	var ready atomic.Bool
	stats := &proxy.Stats{}
	trust := forwarded.NewResolver(cfg.TrustedProxies)

	// Обнаружение — ловушки из политики (ADR-0025) — внутри защиты
	// fail-open (ADR-0024). Политика загружается до открытия слушателей:
	// первый же запрос проверяется по ней.
	detector := decoy.New(events, trust)
	var loader *decoy.Loader
	if cfg.PolicyFile != "" {
		loader = decoy.NewLoader(cfg.PolicyFile, cfg.PolicyCacheFile, detector, events, logger)
		loader.Startup()
	} else {
		logger.Warn("политика обнаружения не задана (SENSOR_POLICY_FILE): сенсор работает без ловушек")
	}
	go reloadOnHUP(ctx, hup, loader, logger)

	guard := failopen.NewGuard(failopen.Config{
		Detector: detector,
		Events:   events,
		Trust:    trust,
		Logger:   logger,
	})
	// Наживки в ответах (ADR-0027) — по той же политике и под той же
	// защитой fail-open, что и ловушки.
	lures := lure.New(lure.Config{
		Policy:   detector.Current,
		Degraded: guard.Degraded,
		OnPanic:  guard.RecordPanic,
	})

	adminSrv := admin.NewServer(admin.NewHandler(&ready,
		metrics.Handler(sensorMetrics(events, stats, guard, detector, loader, lures))), logger)
	proxySrv := proxy.NewServer(proxy.NewHandler(cfg.Upstream, proxy.Options{
		Trust:  trust,
		Events: events,
		Guard:  guard,
		Stats:  stats,
		Logger: logger,
		Lures:  lures,
	}), logger)

	// Слушатели открываем синхронно, до запуска горутин. Если порт занят,
	// сенсор должен упасть сразу с понятной ошибкой. Вариант с
	// ListenAndServe внутри горутины приводит к тому, что процесс
	// рапортует об успешном старте и молча не слушает ничего.
	//
	// ListenConfig с контекстом, а не просто net.Listen: если в адресе имя
	// хоста, его разрешение при старте может зависнуть, и без контекста
	// такое зависание нельзя прервать даже сигналом остановки.
	var lc net.ListenConfig
	adminLn, err := lc.Listen(ctx, "tcp", cfg.AdminAddr)
	if err != nil {
		return fmt.Errorf("не удалось открыть служебный слушатель на %s: %w", cfg.AdminAddr, err)
	}
	proxyLn, err := lc.Listen(ctx, "tcp", cfg.ListenAddr)
	if err != nil {
		_ = adminLn.Close()
		return fmt.Errorf("не удалось открыть клиентский слушатель на %s: %w", cfg.ListenAddr, err)
	}
	// Предел соединений — только на клиентском слушателе: служебный
	// по умолчанию доступен лишь с самой машины, и ограничивать проверки
	// живости значило бы рисковать ложным «сенсор мёртв» под нагрузкой.
	saturationLog := proxy.SaturationLogger(logger, cfg.MaxConns)
	proxyLn = proxy.LimitListener(proxyLn, cfg.MaxConns, func() {
		stats.Saturated.Add(1)
		saturationLog()
	})

	// Буфер на оба сервера: каждая горутина должна суметь записать результат
	// и завершиться, даже если никто ещё не читает канал. Без буфера
	// она зависнет навсегда, и это утечка горутины.
	serveErr := make(chan error, 2)
	serve := func(name string, srv *http.Server, ln net.Listener) {
		// Serve всегда возвращает ошибку, никогда nil. После Shutdown
		// это http.ErrServerClosed — штатное завершение, а не сбой.
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			serveErr <- nil
			return
		}
		serveErr <- fmt.Errorf("%s: %w", name, err)
	}
	go serve("служебный слушатель", adminSrv, adminLn)
	go serve("клиентский слушатель", proxySrv, proxyLn)

	ready.Store(true)
	logger.Info("сенсор запущен",
		slog.String("listen_addr", proxyLn.Addr().String()),
		slog.String("upstream", cfg.Upstream.String()),
		slog.Int("max_conns", cfg.MaxConns),
		// Список доверенных прокси — в лог при каждом запуске: по нему
		// видно, кому сенсор верит в X-Forwarded-For. В JSON — массив
		// строк вида "10.0.0.0/24"; null — не доверяет никому.
		slog.Any("trusted_proxies", cfg.TrustedProxies),
		slog.String("admin_addr", adminLn.Addr().String()),
		slog.String("version", version.Version),
	)
	started := event.New(event.TypeSensorStarted, event.SeverityInfo)
	started.Data = map[string]string{"version": version.Version}
	events.Emit(started)

	if onListen != nil {
		onListen(listenAddrs{Admin: adminLn.Addr(), Proxy: proxyLn.Addr()})
	}

	// Ждём сигнала — или того, что один из серверов упал сам. Во втором
	// случае останавливаем и другой: сенсор без клиентского слушателя
	// бесполезен, а без служебного — невидим для проверок живости,
	// и оркестратор не узнает, что его пора перезапустить.
	var runErr error
	pending := 2
	reason := "signal"
	select {
	case runErr = <-serveErr:
		pending = 1
		reason = "error"
	case <-ctx.Done():
	}

	stopping := event.New(event.TypeSensorStopping, event.SeverityInfo)
	stopping.Data = map[string]string{"reason": reason}
	events.Emit(stopping)

	// Порядок здесь важен. Сначала снимаем готовность, и только потом
	// останавливаем серверы: балансировщик или kubelet, опрашивающий
	// /readyz, успеет увести трафик до того, как сенсор перестанет
	// принимать соединения.
	//
	// В боевом развёртывании между этими двумя действиями нужна пауза
	// на длительность одного интервала опроса. Добавим её на этапе 10.
	ready.Store(false)
	logger.Info("остановка: завершаем активные запросы",
		// Duration в JSON выводится наносекундами ("10000000000"), что
		// нечитаемо в логе. Отдаём строку "10s".
		slog.String("timeout", cfg.ShutdownTimeout.String()),
	)

	// Контекст остановки создаём отдельно, а не от ctx: ctx уже отменён
	// сигналом, и производный от него контекст был бы отменён сразу,
	// то есть корректного завершения не случилось бы вообще.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	// Сначала клиентский слушатель: он дожидается активных запросов клиентов.
	// Служебный — последним, чтобы до конца отвечать на проверки.
	if err := proxySrv.Shutdown(shutdownCtx); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("активные запросы не завершились за %s: %w", cfg.ShutdownTimeout, err))
	}
	if err := adminSrv.Shutdown(shutdownCtx); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("служебный слушатель не остановился: %w", err))
	}
	for range pending {
		if err := <-serveErr; err != nil {
			runErr = errors.Join(runErr, err)
		}
	}
	if runErr != nil {
		return runErr
	}

	logger.Info("сенсор остановлен")
	return nil
}

// reloadOnHUP перечитывает политику по каждому SIGHUP, пока сенсор работает.
// Неверная политика не применяется: Loader оставляет прежнюю.
func reloadOnHUP(ctx context.Context, hup <-chan os.Signal, loader *decoy.Loader, logger *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			if loader == nil {
				logger.Info("получен SIGHUP, но политика не задана (SENSOR_POLICY_FILE): перечитывать нечего")
				continue
			}
			logger.Info("получен SIGHUP: перечитываем политику")
			loader.Reload()
		}
	}
}

// eventsCloseTimeout — сколько при остановке ждать, пока допишутся события.
// Отдельно от SENSOR_SHUTDOWN_TIMEOUT: тот к этому моменту может быть
// израсходован на ожидание запросов клиентов.
const eventsCloseTimeout = 5 * time.Second

// closeEvents дописывает накопленные события и закрывает файл. Ошибка
// здесь не меняет код выхода: трафик уже остановлен, а о потере событий
// скажут лог и счётчики.
func closeEvents(events *event.Recorder, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), eventsCloseTimeout)
	defer cancel()
	if err := events.Close(ctx); err != nil {
		logger.Error("события при остановке записаны не полностью", slog.String("error", err.Error()))
	}
}

// sensorMetrics — список счётчиков для /metrics. Имена и метки — только
// константы: ни одно значение из запроса не становится меткой.
func sensorMetrics(events *event.Recorder, stats *proxy.Stats, guard *failopen.Guard,
	detector *decoy.Detector, loader *decoy.Loader, lures *lure.Injector) []metrics.Metric {
	// Без SENSOR_POLICY_FILE загрузчика нет, и счётчики загрузок — нули.
	loads := func(pick func(*decoy.LoaderStats) uint64) func() uint64 {
		return func() uint64 {
			if loader == nil {
				return 0
			}
			return pick(&loader.Stats)
		}
	}

	const droppedHelp = "События, отброшенные сенсором, по причине: буфер полон, ошибка записи, сенсор останавливается."
	ms := []metrics.Metric{
		{Name: "sensor_events_emitted_total", Help: "События, принятые в буфер.", Kind: metrics.Counter,
			Value: events.Stats.Emitted.Load},
		{Name: "sensor_events_written_total", Help: "События, записанные в файл.", Kind: metrics.Counter,
			Value: events.Stats.Written.Load},
		{Name: "sensor_events_dropped_total", Help: droppedHelp, Kind: metrics.Counter,
			Label: `reason="queue_full"`, Value: events.Stats.DroppedQueueFull.Load},
		{Name: "sensor_events_dropped_total", Help: droppedHelp, Kind: metrics.Counter,
			Label: `reason="write_error"`, Value: events.Stats.DroppedWriteError.Load},
		{Name: "sensor_events_dropped_total", Help: droppedHelp, Kind: metrics.Counter,
			Label: `reason="stopped"`, Value: events.Stats.DroppedStopped.Load},
		{Name: "sensor_events_sink_errors_total", Help: "Ошибки записи и сброса файла событий.", Kind: metrics.Counter,
			Value: events.Stats.SinkErrors.Load},
		{Name: "sensor_events_queue_length", Help: "События в буфере, ожидающие записи.", Kind: metrics.Gauge,
			Value: events.QueueLen},
		{Name: "sensor_events_queue_capacity", Help: "Ёмкость буфера событий.", Kind: metrics.Gauge,
			Value: events.QueueCap},
		{Name: "sensor_connect_rejected_total", Help: "Отвергнутые запросы CONNECT.", Kind: metrics.Counter,
			Value: stats.ConnectRejected.Load},
		{Name: "sensor_client_chain_broken_total", Help: "Запросы от доверенного прокси с неразобранным X-Forwarded-For.",
			Kind: metrics.Counter, Value: stats.ChainBroken.Load},
		{Name: "sensor_connections_saturated_total", Help: "Сколько раз новое соединение ждало из-за предела соединений.",
			Kind: metrics.Counter, Value: stats.Saturated.Load},
	}
	ms = append(ms,
		metrics.Metric{Name: "sensor_fail_open", Help: "1 — обнаружение перегружено и проверяет только часть запросов (fail-open).",
			Kind: metrics.Gauge, Value: func() uint64 {
				if guard.Degraded() {
					return 1
				}
				return 0
			}},
		metrics.Metric{Name: "sensor_fail_open_transitions_total", Help: "Переходы в fail-open из-за перегрузки обнаружения.",
			Kind: metrics.Counter, Value: guard.Stats.Transitions.Load},
		metrics.Metric{Name: "sensor_detection_inspected_total", Help: "Запросы, прошедшие обнаружение.",
			Kind: metrics.Counter, Value: guard.Stats.Inspected.Load},
		metrics.Metric{Name: "sensor_detection_bypassed_total", Help: "Запросы, пропущенные без обнаружения в режиме fail-open.",
			Kind: metrics.Counter, Value: guard.Stats.Bypassed.Load},
		metrics.Metric{Name: "sensor_detection_slow_total", Help: "Проверки обнаружения дольше порога.",
			Kind: metrics.Counter, Value: guard.Stats.Slow.Load},
		metrics.Metric{Name: "sensor_detection_panics_total", Help: "Паники в обнаружении; запрос ушёл в приложение без проверки.",
			Kind: metrics.Counter, Value: guard.Stats.Panics.Load},
		metrics.Metric{Name: "sensor_detection_aborted_total", Help: "Запросы, оборванные после паники в обнаружении: ответ уже начат или тело прочитано.",
			Kind: metrics.Counter, Value: guard.Stats.Aborted.Load},
	)
	ms = append(ms,
		metrics.Metric{Name: "sensor_policy_traps", Help: "Ловушки в текущей политике, включая cookie-ловушки.",
			Kind: metrics.Gauge, Value: func() uint64 { return uint64(max(detector.Current().Len(), 0)) }},
		metrics.Metric{Name: "sensor_policy_loads_total", Help: "Загрузки политики: применена или отвергнута проверкой.",
			Kind: metrics.Counter, Label: `result="loaded"`,
			Value: loads(func(s *decoy.LoaderStats) uint64 { return s.Loaded.Load() })},
		metrics.Metric{Name: "sensor_policy_loads_total", Help: "Загрузки политики: применена или отвергнута проверкой.",
			Kind: metrics.Counter, Label: `result="rejected"`,
			Value: loads(func(s *decoy.LoaderStats) uint64 { return s.Rejected.Load() })},
		metrics.Metric{Name: "sensor_decoy_touches_total", Help: "Касания ловушек по режиму: ответила ловушка или только записано.",
			Kind: metrics.Counter, Label: `mode="enforce"`, Value: detector.Stats.Enforced.Load},
		metrics.Metric{Name: "sensor_decoy_touches_total", Help: "Касания ловушек по режиму: ответила ловушка или только записано.",
			Kind: metrics.Counter, Label: `mode="observe"`, Value: detector.Stats.Observed.Load},
		metrics.Metric{Name: "sensor_cookie_touches_total", Help: "Запросы с изменённой cookie-наживкой.",
			Kind: metrics.Counter, Value: detector.Stats.CookieTouches.Load},
		metrics.Metric{Name: "sensor_cookie_baits_total", Help: "Выданные cookie-наживки (Set-Cookie к ответу на переход по странице).",
			Kind: metrics.Counter, Value: detector.Stats.CookieBaits.Load},
		metrics.Metric{Name: "sensor_preflights_refused_total", Help: "Предварительные запросы CORS к ловушкам с preflight_only, которые сенсор не одобрил.",
			Kind: metrics.Counter, Value: detector.Stats.PreflightsRefused.Load},
		metrics.Metric{Name: "sensor_lures_total", Help: "Ответы приложения, получившие наживку, по виду наживки.",
			Kind: metrics.Counter, Label: `kind="header"`, Value: lures.Stats.Headers.Load},
		metrics.Metric{Name: "sensor_lures_total", Help: "Ответы приложения, получившие наживку, по виду наживки.",
			Kind: metrics.Counter, Label: `kind="robots_txt"`, Value: lures.Stats.Robots.Load},
		metrics.Metric{Name: "sensor_lures_total", Help: "Ответы приложения, получившие наживку, по виду наживки.",
			Kind: metrics.Counter, Label: `kind="html"`, Value: lures.Stats.HTML.Load},
		metrics.Metric{Name: "sensor_lures_memory_bytes", Help: "Память, которую держат правки тел ответов до отправки клиенту; предел 32 МиБ.",
			Kind: metrics.Gauge, Value: lures.EditMemory},
	)
	for _, r := range lure.SkipReasons() {
		ms = append(ms, metrics.Metric{
			Name: "sensor_lures_skipped_total", Help: "Наживки, которые не поставлены, по причине.",
			Kind: metrics.Counter, Label: `reason="` + r.String() + `"`, Value: lures.Stats.Skipped[r].Load,
		})
	}
	for _, c := range proxy.ErrorClasses() {
		ms = append(ms, metrics.Metric{
			Name: "sensor_upstream_errors_total", Help: "Запросы без ответа приложения, по классу причины.",
			Kind: metrics.Counter, Label: `class="` + c.String() + `"`, Value: stats.UpstreamErrors[c].Load,
		})
	}
	return ms
}

// runHealthcheck выполняет одну проверку готовности и возвращает код выхода.
//
// Возвращает только 0 или 1. Docker трактует 0 как «здоров», 1 как «нездоров»,
// а код 2 зарезервирован и использовать его в проверке здоровья запрещено
// документацией Docker. Поэтому здесь даже ошибка конфигурации даёт 1,
// хотя обычный запуск при ней завершается с кодом 2.
func runHealthcheck(getenv config.Getenv, stderr io.Writer) int {
	cfg, err := config.Load(getenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "healthcheck: ошибка конфигурации: %v\n", err)
		return 1
	}

	url, err := healthcheck.TargetURL(cfg.AdminAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return 1
	}

	if err := healthcheck.Probe(context.Background(), url); err != nil {
		_, _ = fmt.Fprintf(stderr, "healthcheck: %v\n", err)
		return 1
	}
	return 0
}
