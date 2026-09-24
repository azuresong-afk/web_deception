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
	"net/netip"
	"net/url"
	"path/filepath"
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

	// Файл событий по умолчанию. Каталог /var/lib/sensor есть в образе
	// сенсора и принадлежит его пользователю; в compose на него смонтирован
	// том, чтобы события переживали перезапуск контейнера.
	defaultEventsFile = "/var/lib/sensor/events.jsonl"

	// Копия последней валидной политики — в том же каталоге состояния
	// сенсора, что и события: его пишет только сенсор (ADR-0025).
	defaultPolicyCacheFile = "/var/lib/sensor/policy.last-valid.json"

	// Клиентский слушатель, в отличие от служебного, по умолчанию открыт
	// на всех интерфейсах: принимать трафик из сети — его работа. За ним
	// нет ничего, что не было бы уже открыто самим приложением клиента.
	defaultListenAddr = ":8080"

	// Предел одновременных соединений клиентов. Каждое соединение с активным
	// запросом стоит порядка десятков килобайт (буферы чтения, записи,
	// копирования тела), и тысяча таких — это десятки мегабайт. Значение
	// по умолчанию рассчитано на лимит памяти контейнера 128 МБ; поднимать
	// его нужно вместе с лимитом памяти.
	defaultMaxConns = 1024

	// Верхняя граница отсекает опечатку с лишними нулями: миллион соединений
	// не выдержит ни один разумный лимит памяти, и сенсор упадёт раньше,
	// чем предел сработает.
	maxMaxConns = 100_000

	// Верхняя граница числа доверенных сетей. Самые длинные настоящие
	// списки — диапазоны CDN — это десятки–сотни записей. Тысяча с запасом
	// покрывает их и отсекает ошибку, при которой в переменную попал
	// не тот файл.
	maxTrustedProxies = 1024

	// Самые широкие сети, которые можно объявить доверенными. /8 для IPv4 —
	// это 10.0.0.0/8, самая большая частная сеть; /7 для IPv6 — fc00::/7,
	// все уникальные локальные адреса. Шире не бывает сети «своих прокси»:
	// такая запись — почти наверняка ошибка вроде 0.0.0.0/0, которая
	// объявляет доверенным весь интернет (угроза T1).
	minTrustedBits4 = 8
	minTrustedBits6 = 7
)

// Config — конфигурация сенсора: слой запуска по ADR-0018. Здесь только то,
// что задаётся при развёртывании и определяет границы доверия. Политика
// обнаружения (приманки, правила) появится отдельно на шаге 8.
type Config struct {
	// ListenAddr — адрес клиентского слушателя: сюда приходит трафик,
	// который сенсор передаёт приложению.
	ListenAddr string

	// Upstream — адрес защищаемого приложения. Берётся только отсюда
	// и никогда из запроса: иначе сенсор становится открытым прокси,
	// через который можно ходить во внутреннюю сеть (угроза T17).
	Upstream *url.URL

	// MaxConns — предел одновременных соединений клиентов.
	MaxConns int

	// TrustedProxies — сети доверенных прокси: балансировщиков и CDN
	// перед сенсором. Только соединениям из них сенсор верит, когда они
	// сообщают адрес клиента в X-Forwarded-For (пакет forwarded, ADR-0022).
	// Пусто — не доверять никому: адрес клиента всегда адрес соединения.
	TrustedProxies []netip.Prefix

	// AdminAddr — адрес служебного слушателя (/healthz, /readyz).
	AdminAddr string

	// ShutdownTimeout — сколько ждём завершения активных запросов при остановке.
	ShutdownTimeout time.Duration

	// LogLevel — минимальный уровень сообщений в логе.
	LogLevel slog.Level

	// EventsFile — файл событий в формате JSON Lines (ADR-0023). Рядом
	// с ним появляются старые файлы после ротации: EventsFile.1 … .4.
	EventsFile string

	// PolicyFile — политика обнаружения (ADR-0025). Пусто — ловушек нет.
	PolicyFile string

	// PolicyCacheFile — копия последней валидной политики, которую ведёт
	// сам сенсор: с ней он работает, если файл администратора сломан.
	PolicyCacheFile string
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
		ListenAddr:      defaultListenAddr,
		MaxConns:        defaultMaxConns,
		AdminAddr:       defaultAdminAddr,
		ShutdownTimeout: defaultShutdownTimeout,
		LogLevel:        defaultLogLevel,
		EventsFile:      defaultEventsFile,
		PolicyCacheFile: defaultPolicyCacheFile,
	}

	// Адрес приложения обязателен. Значения по умолчанию нет намеренно:
	// любое угаданное значение — это трафик клиента, отправленный не туда.
	v := strings.TrimSpace(getenv("SENSOR_UPSTREAM_URL"))
	if v == "" {
		return nil, fmt.Errorf("SENSOR_UPSTREAM_URL: не задан адрес защищаемого приложения, например http://app:3000")
	}
	u, err := parseUpstream(v)
	if err != nil {
		return nil, fmt.Errorf("SENSOR_UPSTREAM_URL: %w", err)
	}
	cfg.Upstream = u

	if v := strings.TrimSpace(getenv("SENSOR_LISTEN_ADDR")); v != "" {
		if err := validateAddr(v); err != nil {
			return nil, fmt.Errorf("SENSOR_LISTEN_ADDR: %w", err)
		}
		cfg.ListenAddr = v
	}

	if v := strings.TrimSpace(getenv("SENSOR_MAX_CONNS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("SENSOR_MAX_CONNS: ожидается целое число, получено %q", v)
		}
		if n < 1 || n > maxMaxConns {
			return nil, fmt.Errorf("SENSOR_MAX_CONNS: допустимо от 1 до %d, получено %d", maxMaxConns, n)
		}
		cfg.MaxConns = n
	}

	if v := strings.TrimSpace(getenv("SENSOR_TRUSTED_PROXIES")); v != "" {
		p, err := parseTrustedProxies(v)
		if err != nil {
			return nil, fmt.Errorf("SENSOR_TRUSTED_PROXIES: %w", err)
		}
		cfg.TrustedProxies = p
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

	for _, f := range []struct {
		name string
		dst  *string
	}{
		{"SENSOR_EVENTS_FILE", &cfg.EventsFile},
		{"SENSOR_POLICY_FILE", &cfg.PolicyFile},
		{"SENSOR_POLICY_CACHE_FILE", &cfg.PolicyCacheFile},
	} {
		if v := strings.TrimSpace(getenv(f.name)); v != "" {
			p, err := parseFilePath(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", f.name, err)
			}
			*f.dst = p
		}
	}

	// Файл администратора и копия сенсора в одном месте — сенсор затирал бы
	// файл администратора своими копиями.
	if cfg.PolicyFile != "" && cfg.PolicyFile == cfg.PolicyCacheFile {
		return nil, fmt.Errorf("SENSOR_POLICY_FILE и SENSOR_POLICY_CACHE_FILE совпадают (%s)", cfg.PolicyFile)
	}

	// Два слушателя на одном адресе — это не «один из них не запустится»,
	// а непредсказуемо, какой именно: лучше отказаться стартовать сразу.
	if cfg.ListenAddr == cfg.AdminAddr {
		return nil, fmt.Errorf("SENSOR_LISTEN_ADDR и SENSOR_ADMIN_ADDR совпадают (%s): "+
			"служебный слушатель не должен делить порт с клиентским", cfg.ListenAddr)
	}

	return cfg, nil
}

// parseUpstream разбирает и проверяет адрес защищаемого приложения.
//
// Разрешён только самый простой вид: схема, хост и необязательный порт.
// Всё остальное отвергается, а не молча игнорируется — каждое такое поле
// означало бы поведение, которого администратор не ожидает:
//   - логин и пароль в адресе — секрет в переменной, которую видно в
//     docker inspect, да ещё и непонятно, передавать ли его приложению;
//   - путь — непонятно, как склеивать его с путём запроса;
//   - параметры и фрагмент — непонятно, добавлять ли их к каждому запросу.
//
// Имя хоста при старте не разрешается в IP: DNS может быть ещё недоступен
// (контейнер приложения стартует параллельно), а разрешение на каждое
// соединение даёт и так транспорт HTTP.
func parseUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать адрес %q", raw)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("схема должна быть http или https, получено %q", u.Scheme)
	}
	if u.Opaque != "" || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("в адресе нет имени хоста: %q", raw)
	}
	if u.User != nil {
		// В сообщение адрес целиком не выводим: в нём пароль.
		return nil, fmt.Errorf("логин и пароль в адресе приложения не поддерживаются")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("путь в адресе приложения пока не поддерживается, получено %q", u.Path)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("параметры и фрагмент в адресе приложения не поддерживаются: %q", raw)
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("порт вне диапазона 1-65535: %q", port)
		}
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

// parseFilePath проверяет путь к файлу: событий, политики, копии политики.
//
// Существование каталога и права здесь не проверяются: файлы открываются
// при запуске сенсора, и ошибка открытия видна там с понятным сообщением.
// Здесь — только то, что точно ошибка записи пути.
func parseFilePath(v string) (string, error) {
	if strings.ContainsRune(v, 0) {
		return "", fmt.Errorf("путь содержит нулевой байт")
	}
	// Путь, оканчивающийся на «/», — это каталог, а не файл: скорее всего,
	// имя файла забыли.
	if strings.HasSuffix(v, "/") {
		return "", fmt.Errorf("%q — каталог; укажите файл, например %s", v, filepath.Join(v, "events.jsonl"))
	}
	return filepath.Clean(v), nil
}

// parseTrustedProxies разбирает список доверенных прокси: адреса и сети
// через запятую, например "10.0.0.5, 10.0.1.0/24, fd00::/8".
//
// Ошибка в этом списке — либо дыра (доверие чужим адресам, угроза T1),
// либо сломанный продукт (адрес клиента всегда адрес балансировщика).
// Поэтому проверка строгая: любое сомнительное значение — отказ стартовать
// с объяснением, а не догадка, что имел в виду администратор.
func parseTrustedProxies(v string) ([]netip.Prefix, error) {
	parts := strings.Split(v, ",")
	if len(parts) > maxTrustedProxies {
		return nil, fmt.Errorf("не больше %d записей, получено %d", maxTrustedProxies, len(parts))
	}
	out := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("пустой элемент списка: лишняя запятая?")
		}
		p, err := parseTrustedPrefix(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// parseTrustedPrefix разбирает одну запись: адрес или сеть.
func parseTrustedPrefix(s string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		parsed, err := netip.ParsePrefix(s)
		if err != nil {
			return p, fmt.Errorf("%q: ожидается адрес или сеть вида 10.0.0.0/24", s)
		}
		// 10.0.0.1/8 синтаксически верно, но неоднозначно: имелась
		// в виду сеть 10.0.0.0/8 или один адрес 10.0.0.1? Первое доверяет
		// 16 миллионам адресов, второе — одному. Не угадываем.
		if parsed != parsed.Masked() {
			return p, fmt.Errorf("%q: адрес сети содержит биты узла; имелась в виду сеть %s или один адрес %s?",
				s, parsed.Masked(), parsed.Addr())
		}
		p = parsed
	} else {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return p, fmt.Errorf("%q: ожидается адрес или сеть вида 10.0.0.0/24", s)
		}
		if addr.Zone() != "" {
			return p, fmt.Errorf("%q: зона IPv6 в адресе прокси не поддерживается", s)
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}

	// ::ffff:10.0.0.1 — IPv4 в записи IPv6. Сенсор приводит такие адреса
	// клиентов к IPv4, и сеть в записи IPv6 не совпала бы ни с одним из
	// них: прокси молча перестал бы считаться доверенным.
	if p.Addr().Is4In6() {
		return p, fmt.Errorf("%q: IPv4 в записи IPv6 (::ffff:…) — запишите адрес как IPv4", s)
	}

	minBits := minTrustedBits4
	if p.Addr().Is6() {
		minBits = minTrustedBits6
	}
	if p.Bits() < minBits {
		return p, fmt.Errorf("%q: сеть шире /%d не может быть сетью своих прокси; "+
			"доверие ей позволило бы кому угодно подставить чужой адрес клиента (угроза T1)", s, minBits)
	}
	return p, nil
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
				"/healthz, /readyz и /metrics будут видны в сети и выдадут присутствие сенсора (угроза T5), "+
				"а /metrics ещё и покажет, замечены ли действия атакующего; "+
				"порт должен быть закрыт файрволом или сетевой политикой", c.AdminAddr))
	}

	if port == "0" {
		out = append(out, "порт служебного слушателя равен 0: адрес будет выбран случайно при каждом запуске; "+
			"это допустимо только в тестах")
	}

	if _, listenPort, err := net.SplitHostPort(c.ListenAddr); err == nil && listenPort == "0" {
		out = append(out, "порт клиентского слушателя равен 0: адрес будет выбран случайно при каждом запуске; "+
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
