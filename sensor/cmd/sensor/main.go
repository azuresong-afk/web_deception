// Команда sensor — точка входа сенсора web-deception.
//
// Сенсор поднимает два слушателя:
//   - клиентский — принимает трафик из сети и передаёт его защищаемому
//     приложению (пакет proxy);
//   - служебный — /healthz и /readyz для проверок живости, только на
//     localhost по умолчанию (пакет admin).
//
// Приманок и событий пока нет: на этом шаге сенсор — прозрачный прокси.
// Они появятся на следующих шагах этапа 2.
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

	"github.com/azuresong-afk/web_deception/sensor/internal/admin"
	"github.com/azuresong-afk/web_deception/sensor/internal/config"
	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
	"github.com/azuresong-afk/web_deception/sensor/internal/healthcheck"
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

	var ready atomic.Bool

	adminSrv := admin.NewServer(admin.NewHandler(&ready), logger)
	proxySrv := proxy.NewServer(proxy.NewHandler(cfg.Upstream, forwarded.NewResolver(cfg.TrustedProxies), logger), logger)

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
	proxyLn = proxy.LimitListener(proxyLn, cfg.MaxConns, proxy.SaturationLogger(logger, cfg.MaxConns))

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
	if onListen != nil {
		onListen(listenAddrs{Admin: adminLn.Addr(), Proxy: proxyLn.Addr()})
	}

	// Ждём сигнала — или того, что один из серверов упал сам. Во втором
	// случае останавливаем и другой: сенсор без клиентского слушателя
	// бесполезен, а без служебного — невидим для проверок живости,
	// и оркестратор не узнает, что его пора перезапустить.
	var runErr error
	pending := 2
	select {
	case runErr = <-serveErr:
		pending = 1
	case <-ctx.Done():
	}

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
