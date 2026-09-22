// Package config читает и проверяет конфигурацию сенсора.
//
// Почему только переменные окружения, а не файл конфигурации: секреты
// не должны попадать в репозиторий (правило проекта), а переменные окружения
// одинаково работают в docker compose, systemd и Kubernetes и не требуют
// монтировать файлы внутрь контейнера.
//
// Граница доверия: конфигурация приходит от администратора, который запускает
// сенсор, а не от атакующего. Мы всё равно проверяем каждое значение.
// Причина не в недоверии к администратору, а в цене ошибки: сенсор стоит
// в критическом пути чужого трафика, и опечатка в переменной окружения
// означает либо отказ в обслуживании приложения клиента, либо служебный порт,
// открытый в интернет.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// Служебный слушатель по умолчанию доступен только с самой машины.
	// Это осознанный выбор: /healthz и /readyz на публичном адресе — это
	// и признак нашего продукта для атакующего (угроза T5), и бесплатная
	// цель для нагрузки, не защищённая ничем.
	defaultAdminAddr = "127.0.0.1:9090"

	defaultShutdownTimeout = 10 * time.Second

	// Верхняя граница нужна, чтобы опечатка вида "10m" вместо "10s"
	// не превратила штатный перезапуск сенсора в десятиминутное зависание.
	// Kubernetes и docker stop всё равно добьют процесс по SIGKILL раньше.
	maxShutdownTimeout = 60 * time.Second

	defaultLogLevel = slog.LevelInfo
)

// Config — конфигурация сенсора на текущем этапе. Проксирования трафика ещё
// нет, поэтому здесь только служебный слушатель и параметры остановки.
type Config struct {
	// AdminAddr — адрес служебного слушателя (/healthz, /readyz).
	AdminAddr string

	// ShutdownTimeout — сколько ждём завершения активных запросов при остановке.
	ShutdownTimeout time.Duration

	// LogLevel — минимальный уровень сообщений в логе.
	LogLevel slog.Level
}

// Getenv — источник переменных окружения.
//
// Передаём его параметром вместо прямого вызова os.Getenv, чтобы тесты
// не меняли окружение самого процесса. Тесты, которые правят глобальное
// окружение, нельзя запускать параллельно, и они незаметно влияют друг
// на друга — а такие тесты со временем перестают ловить ошибки.
type Getenv func(string) string

// Load читает конфигурацию и возвращает ошибку при любом некорректном
// значении. Сенсор с неверной конфигурацией не должен стартовать вообще:
// «запустился, но слушает не тот адрес» — худший из возможных исходов.
func Load(getenv Getenv) (*Config, error) {
	cfg := &Config{
		AdminAddr:       defaultAdminAddr,
		ShutdownTimeout: defaultShutdownTimeout,
		LogLevel:        defaultLogLevel,
	}

	if v := strings.TrimSpace(getenv("SENSOR_ADMIN_ADDR")); v != "" {
		if err := validateAddr(v); err != nil {
			return nil, fmt.Errorf("SENSOR_ADMIN_ADDR: %w", err)
		}
		cfg.AdminAddr = v
	}

	if v := strings.TrimSpace(getenv("SENSOR_SHUTDOWN_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("SENSOR_SHUTDOWN_TIMEOUT: не удалось разобрать %q, ожидается длительность вида 10s", v)
		}
		if d <= 0 {
			return nil, fmt.Errorf("SENSOR_SHUTDOWN_TIMEOUT: должен быть больше нуля, получено %s", d)
		}
		if d > maxShutdownTimeout {
			return nil, fmt.Errorf("SENSOR_SHUTDOWN_TIMEOUT: не должен превышать %s, получено %s", maxShutdownTimeout, d)
		}
		cfg.ShutdownTimeout = d
	}

	if v := strings.TrimSpace(getenv("SENSOR_LOG_LEVEL")); v != "" {
		lvl, err := parseLogLevel(v)
		if err != nil {
			return nil, fmt.Errorf("SENSOR_LOG_LEVEL: %w", err)
		}
		cfg.LogLevel = lvl
	}

	return cfg, nil
}

// Warnings возвращает предупреждения о конфигурации, которая формально
// корректна, но рискованна.
//
// Почему это не ошибки: запретить, например, привязку служебного порта
// ко всем интерфейсам нельзя — в Kubernetes проверки живости приходят
// извне пода, и слушать только localhost там невозможно. Но и промолчать
// нельзя: решение должно остаться видимым в логах, чтобы при разборе
// инцидента было понятно, что порт был открыт осознанно.
func (c *Config) Warnings() []string {
	var out []string

	host, port, err := net.SplitHostPort(c.AdminAddr)
	if err != nil {
		// Сюда попасть нельзя: адрес уже прошёл validateAddr в Load.
		return out
	}

	if !isLoopbackHost(host) {
		out = append(out, fmt.Sprintf(
			"служебный слушатель привязан к %q и доступен не только с локальной машины: "+
				"/healthz и /readyz будут видны в сети и выдадут присутствие сенсора (угроза T5); "+
				"порт должен быть закрыт файрволом или сетевой политикой", c.AdminAddr))
	}

	if port == "0" {
		out = append(out, "порт служебного слушателя равен 0: адрес будет выбран случайно при каждом запуске; "+
			"это допустимо только в тестах")
	}

	return out
}

// validateAddr проверяет, что строка похожа на host:port с портом
// в допустимом диапазоне.
func validateAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("ожидается адрес вида host:port, получено %q", addr)
	}

	// Пустой host означает «все интерфейсы» — это допустимо, но попадёт
	// в предупреждения. Имя хоста мы намеренно не резолвим: обращение
	// к DNS в момент старта может зависнуть на таймауте резолвера
	// и превратить перезапуск сенсора в многосекундную паузу.
	if strings.ContainsAny(host, " \t") {
		return fmt.Errorf("имя хоста содержит пробелы: %q", host)
	}

	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("порт должен быть числом, получено %q", port)
	}
	if n < 0 || n > 65535 {
		return fmt.Errorf("порт вне диапазона 0-65535: %d", n)
	}

	return nil
}

// isLoopbackHost сообщает, доступен ли адрес только с локальной машины.
func isLoopbackHost(host string) bool {
	if host == "" {
		// Пустой host в "…:9090" означает привязку ко всем интерфейсам.
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// parseLogLevel разбирает уровень логирования.
//
// Уровень debug влияет только на количество служебных сообщений. Он никогда
// не включает логирование тел запросов, заголовков Authorization и Cookie:
// это запрещено правилами проекта и проверяется правилами Semgrep в CI.
func parseLogLevel(v string) (slog.Level, error) {
	switch strings.ToLower(v) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("неизвестный уровень %q, допустимы debug, info, warn, error", v)
	}
}
