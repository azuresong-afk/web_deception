package config

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// testUpstream — адрес приложения для тестов, которым он не важен.
const testUpstream = "http://app:3000"

// envMap превращает обычную карту в источник переменных окружения.
// Благодаря этому ни один тест не трогает окружение процесса и все они
// могут выполняться параллельно.
//
// Адрес приложения обязателен, поэтому подставляется по умолчанию: иначе
// каждый тест, проверяющий что-то другое, падал бы на его отсутствии.
// Тест, которому нужен другой адрес или его отсутствие, задаёт ключ явно.
func envMap(m map[string]string) Getenv {
	return func(k string) string {
		if v, ok := m[k]; ok {
			return v
		}
		if k == "SENSOR_UPSTREAM_URL" {
			return testUpstream
		}
		return ""
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	cfg, err := Load(envMap(nil))
	if err != nil {
		t.Fatalf("Load на пустом окружении вернул ошибку: %v", err)
	}

	// Значение по умолчанию — часть модели безопасности, а не деталь удобства:
	// служебный порт не должен оказаться открытым наружу у того, кто просто
	// запустил сенсор и ничего не настраивал.
	if cfg.AdminAddr != "127.0.0.1:9090" {
		t.Errorf("AdminAddr по умолчанию = %q, ожидался 127.0.0.1:9090", cfg.AdminAddr)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr по умолчанию = %q, ожидался :8080", cfg.ListenAddr)
	}
	if cfg.MaxConns != 1024 {
		t.Errorf("MaxConns по умолчанию = %d, ожидалось 1024", cfg.MaxConns)
	}
	if cfg.Upstream == nil || cfg.Upstream.String() != testUpstream {
		t.Errorf("Upstream = %v, ожидался %s", cfg.Upstream, testUpstream)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout по умолчанию = %s, ожидалось 10s", cfg.ShutdownTimeout)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel по умолчанию = %s, ожидался info", cfg.LogLevel)
	}
	if cfg.EventsFile != "/var/lib/sensor/events.jsonl" {
		t.Errorf("EventsFile по умолчанию = %q", cfg.EventsFile)
	}
	// Без политики сенсор работает без ловушек; копия — в каталоге состояния.
	if cfg.PolicyFile != "" || cfg.PolicyCacheFile != "/var/lib/sensor/policy.last-valid.json" {
		t.Errorf("политика по умолчанию: %q, копия %q", cfg.PolicyFile, cfg.PolicyCacheFile)
	}
	// По умолчанию не доверяем никому: X-Forwarded-For не читается.
	if len(cfg.TrustedProxies) != 0 {
		t.Errorf("TrustedProxies по умолчанию = %v, ожидался пустой список", cfg.TrustedProxies)
	}
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("конфигурация по умолчанию не должна давать предупреждений, получено: %v", w)
	}
}

func TestLoadReadsEnvironment(t *testing.T) {
	t.Parallel()

	cfg, err := Load(envMap(map[string]string{
		// Пробелы вокруг значения — частый результат копирования в .env,
		// и это не должно ломать запуск.
		"SENSOR_ADMIN_ADDR":       "  127.0.0.1:18080  ",
		"SENSOR_SHUTDOWN_TIMEOUT": "25s",
		"SENSOR_LOG_LEVEL":        "DEBUG",
		"SENSOR_LISTEN_ADDR":      "0.0.0.0:8443",
		"SENSOR_UPSTREAM_URL":     " https://app.internal:8443/ ",
		"SENSOR_MAX_CONNS":        "5000",
		"SENSOR_TRUSTED_PROXIES":  " 10.0.0.5 , 10.0.1.0/24,fd00::/8, 2001:db8::1 ",
		"SENSOR_EVENTS_FILE":      " ./data//events.jsonl ",
	}))
	if err != nil {
		t.Fatalf("Load вернул ошибку: %v", err)
	}

	if cfg.ListenAddr != "0.0.0.0:8443" {
		t.Errorf("ListenAddr = %q, ожидался 0.0.0.0:8443", cfg.ListenAddr)
	}
	// Завершающий слеш допустим и отбрасывается: для администратора
	// "https://app/" и "https://app" — один и тот же адрес.
	if got := cfg.Upstream.String(); got != "https://app.internal:8443" {
		t.Errorf("Upstream = %q, ожидался https://app.internal:8443", got)
	}
	if cfg.MaxConns != 5000 {
		t.Errorf("MaxConns = %d, ожидалось 5000", cfg.MaxConns)
	}
	// Путь приводится к каноническому виду: без «./» и двойных «/».
	if cfg.EventsFile != "data/events.jsonl" {
		t.Errorf("EventsFile = %q, ожидался data/events.jsonl", cfg.EventsFile)
	}
	// Одиночный адрес становится сетью из одного адреса.
	if got := fmt.Sprint(cfg.TrustedProxies); got != "[10.0.0.5/32 10.0.1.0/24 fd00::/8 2001:db8::1/128]" {
		t.Errorf("TrustedProxies = %s", got)
	}

	if cfg.AdminAddr != "127.0.0.1:18080" {
		t.Errorf("AdminAddr = %q, ожидался 127.0.0.1:18080 без пробелов", cfg.AdminAddr)
	}
	if cfg.ShutdownTimeout != 25*time.Second {
		t.Errorf("ShutdownTimeout = %s, ожидалось 25s", cfg.ShutdownTimeout)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %s, ожидался debug (регистр не должен иметь значения)", cfg.LogLevel)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		env          map[string]string
		wantContains string
	}{
		{"адрес без порта", map[string]string{"SENSOR_ADMIN_ADDR": "127.0.0.1"}, "host:port"},
		{"нечисловой порт", map[string]string{"SENSOR_ADMIN_ADDR": "127.0.0.1:http"}, "числом"},
		{"порт вне диапазона", map[string]string{"SENSOR_ADMIN_ADDR": "127.0.0.1:70000"}, "диапазона"},
		{"пробел в имени хоста", map[string]string{"SENSOR_ADMIN_ADDR": "local host:9090"}, "пробелы"},
		{"мусор вместо длительности", map[string]string{"SENSOR_SHUTDOWN_TIMEOUT": "скоро"}, "разобрать"},
		{"нулевая длительность", map[string]string{"SENSOR_SHUTDOWN_TIMEOUT": "0s"}, "больше нуля"},
		{"отрицательная длительность", map[string]string{"SENSOR_SHUTDOWN_TIMEOUT": "-1s"}, "больше нуля"},
		// Ровно та опечатка, ради которой введена верхняя граница:
		// минуты вместо секунд.
		{"слишком большая длительность", map[string]string{"SENSOR_SHUTDOWN_TIMEOUT": "10m"}, "не должен превышать"},
		{"неизвестный уровень лога", map[string]string{"SENSOR_LOG_LEVEL": "verbose"}, "неизвестный уровень"},

		// Адрес приложения: только схема, хост и порт.
		{"адрес приложения не задан", map[string]string{"SENSOR_UPSTREAM_URL": ""}, "не задан"},
		{"адрес приложения из пробелов", map[string]string{"SENSOR_UPSTREAM_URL": "   "}, "не задан"},
		{"схема не http", map[string]string{"SENSOR_UPSTREAM_URL": "ftp://app"}, "схема"},
		{"адрес без схемы", map[string]string{"SENSOR_UPSTREAM_URL": "app:3000"}, "схема"},
		{"схема без хоста", map[string]string{"SENSOR_UPSTREAM_URL": "http://"}, "имени хоста"},
		{"только порт без хоста", map[string]string{"SENSOR_UPSTREAM_URL": "http://:3000"}, "имени хоста"},
		{"путь в адресе", map[string]string{"SENSOR_UPSTREAM_URL": "http://app/api"}, "путь"},
		{"параметры в адресе", map[string]string{"SENSOR_UPSTREAM_URL": "http://app?debug=1"}, "параметры"},
		{"фрагмент в адресе", map[string]string{"SENSOR_UPSTREAM_URL": "http://app#x"}, "фрагмент"},
		{"нулевой порт", map[string]string{"SENSOR_UPSTREAM_URL": "http://app:0"}, "порт"},
		{"порт больше 65535", map[string]string{"SENSOR_UPSTREAM_URL": "http://app:99999"}, "порт"},
		{"неразбираемый адрес", map[string]string{"SENSOR_UPSTREAM_URL": "http://[::1"}, "разобрать"},

		// Клиентский слушатель и предел соединений.
		{"адрес слушателя без порта", map[string]string{"SENSOR_LISTEN_ADDR": "8080"}, "host:port"},
		{"предел соединений не число", map[string]string{"SENSOR_MAX_CONNS": "много"}, "целое"},
		{"нулевой предел соединений", map[string]string{"SENSOR_MAX_CONNS": "0"}, "от 1"},
		{"отрицательный предел соединений", map[string]string{"SENSOR_MAX_CONNS": "-5"}, "от 1"},
		{"предел соединений с лишними нулями", map[string]string{"SENSOR_MAX_CONNS": "1000000"}, "от 1"},

		// Доверенные прокси: любая ошибка здесь — подделка адреса клиента
		// или сломанное определение адреса, поэтому отказ, а не догадка.
		{"весь интернет IPv4", map[string]string{"SENSOR_TRUSTED_PROXIES": "0.0.0.0/0"}, "шире /8"},
		{"весь интернет IPv6", map[string]string{"SENSOR_TRUSTED_PROXIES": "::/0"}, "шире /7"},
		{"половина интернета", map[string]string{"SENSOR_TRUSTED_PROXIES": "0.0.0.0/1, 128.0.0.0/1"}, "шире /8"},
		{"все глобальные IPv6", map[string]string{"SENSOR_TRUSTED_PROXIES": "2000::/3"}, "шире /7"},
		{"биты узла в адресе сети", map[string]string{"SENSOR_TRUSTED_PROXIES": "10.0.0.1/8"}, "10.0.0.0/8"},
		{"IPv4 в записи IPv6", map[string]string{"SENSOR_TRUSTED_PROXIES": "::ffff:10.0.0.1"}, "как IPv4"},
		{"сеть IPv4 в записи IPv6", map[string]string{"SENSOR_TRUSTED_PROXIES": "::ffff:10.0.0.0/104"}, "как IPv4"},
		{"зона IPv6", map[string]string{"SENSOR_TRUSTED_PROXIES": "fe80::1%eth0"}, "зона"},
		{"имя хоста", map[string]string{"SENSOR_TRUSTED_PROXIES": "lb.internal"}, "10.0.0.0/24"},
		{"маска числом", map[string]string{"SENSOR_TRUSTED_PROXIES": "10.0.0.0/255.0.0.0"}, "10.0.0.0/24"},
		{"лишняя запятая", map[string]string{"SENSOR_TRUSTED_PROXIES": "10.0.0.1,"}, "пустой элемент"},
		{"точка с запятой вместо запятой", map[string]string{"SENSOR_TRUSTED_PROXIES": "10.0.0.1; 10.0.0.2"}, "10.0.0.0/24"},
		// Файл событий.
		{"каталог вместо файла", map[string]string{"SENSOR_EVENTS_FILE": "/var/lib/sensor/"}, "каталог"},
		{"нулевой байт в пути", map[string]string{"SENSOR_EVENTS_FILE": "/tmp/a\x00b"}, "нулевой байт"},
		{"политика — каталог", map[string]string{"SENSOR_POLICY_FILE": "/etc/sensor/"}, "каталог"},
		{"политика и копия в одном файле", map[string]string{
			"SENSOR_POLICY_FILE": "/var/lib/sensor/p.json", "SENSOR_POLICY_CACHE_FILE": "/var/lib/sensor/p.json",
		}, "совпадают"},

		{"слишком много записей", map[string]string{"SENSOR_TRUSTED_PROXIES": strings.Repeat("10.0.0.1,", 1024) + "10.0.0.1"}, "не больше 1024"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := Load(envMap(tt.env))
			if err == nil {
				t.Fatalf("ожидалась ошибка, получена конфигурация %+v", cfg)
			}
			if !strings.Contains(err.Error(), tt.wantContains) {
				t.Errorf("сообщение об ошибке %q не содержит %q; администратор не поймёт, что чинить",
					err.Error(), tt.wantContains)
			}
			// Сообщение должно называть переменную окружения — иначе
			// его бесполезно читать в логе контейнера.
			for k := range tt.env {
				if !strings.Contains(err.Error(), k) {
					t.Errorf("сообщение об ошибке не называет переменную %s: %q", k, err.Error())
				}
			}
		})
	}
}

// TestTrustedProxiesWidestAccepted: самые широкие допустимые сети
// принимаются — граница проверки не должна отсечь настоящую частную сеть.
func TestTrustedProxiesWidestAccepted(t *testing.T) {
	t.Parallel()

	for _, v := range []string{"10.0.0.0/8", "fc00::/7"} {
		if _, err := Load(envMap(map[string]string{"SENSOR_TRUSTED_PROXIES": v})); err != nil {
			t.Errorf("%s должна приниматься: %v", v, err)
		}
	}
}

// TestUpstreamPasswordNotInError: адрес с паролем отвергается, и пароль
// не должен попасть в сообщение об ошибке — оно уйдёт в лог контейнера.
func TestUpstreamPasswordNotInError(t *testing.T) {
	t.Parallel()

	_, err := Load(envMap(map[string]string{"SENSOR_UPSTREAM_URL": "http://admin:s3cr3t-pa55@app:3000"}))
	if err == nil {
		t.Fatal("адрес с логином и паролем должен отвергаться")
	}
	if strings.Contains(err.Error(), "s3cr3t-pa55") {
		t.Errorf("пароль попал в сообщение об ошибке: %q", err.Error())
	}
}

// TestUpstreamAcceptedForms — формы адреса, которые должны приниматься.
func TestUpstreamAcceptedForms(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"http://app":                "http://app",
		"http://app:3000/":          "http://app:3000",
		"https://app.internal:8443": "https://app.internal:8443",
		"http://10.0.0.5":           "http://10.0.0.5",
		"http://[::1]:3000":         "http://[::1]:3000",
		"http://juice-shop:3000":    "http://juice-shop:3000",
		"HTTP://APP:3000":           "http://APP:3000",
	}

	for in, want := range tests {
		t.Run(in, func(t *testing.T) {
			t.Parallel()

			cfg, err := Load(envMap(map[string]string{"SENSOR_UPSTREAM_URL": in}))
			if err != nil {
				t.Fatalf("адрес %q должен приниматься, получена ошибка: %v", in, err)
			}
			if got := cfg.Upstream.String(); got != want {
				t.Errorf("адрес %q разобран как %q, ожидался %q", in, got, want)
			}
		})
	}
}

func TestListenAndAdminMustDiffer(t *testing.T) {
	t.Parallel()

	_, err := Load(envMap(map[string]string{
		"SENSOR_LISTEN_ADDR": "127.0.0.1:9090",
		"SENSOR_ADMIN_ADDR":  "127.0.0.1:9090",
	}))
	if err == nil {
		t.Fatal("одинаковые адреса клиентского и служебного слушателей должны отвергаться")
	}
}

func TestWarnings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		addr         string
		wantWarnings int
		wantContains string
	}{
		{"локальный адрес", "127.0.0.1:9090", 0, ""},
		{"localhost по имени", "localhost:9090", 0, ""},
		{"адрес IPv6 localhost", "[::1]:9090", 0, ""},
		{"все интерфейсы через 0.0.0.0", "0.0.0.0:9090", 1, "T5"},
		{"все интерфейсы через пустой хост", ":9090", 1, "T5"},
		{"конкретный внешний адрес", "10.1.2.3:9090", 1, "T5"},
		{"случайный порт", "127.0.0.1:0", 1, "только в тестах"},
	}

	// Клиентский слушатель на всех интерфейсах — норма, предупреждение
	// только о случайном порте.
	cfg, err := Load(envMap(map[string]string{"SENSOR_LISTEN_ADDR": "127.0.0.1:0"}))
	if err != nil {
		t.Fatalf("Load вернул ошибку: %v", err)
	}
	if got := cfg.Warnings(); len(got) != 1 || !strings.Contains(got[0], "клиентского слушателя") {
		t.Errorf("для клиентского слушателя на порту 0 ожидалось одно предупреждение, получено %v", got)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := Load(envMap(map[string]string{"SENSOR_ADMIN_ADDR": tt.addr}))
			if err != nil {
				t.Fatalf("адрес %q должен быть валидным, получена ошибка: %v", tt.addr, err)
			}

			got := cfg.Warnings()
			if len(got) != tt.wantWarnings {
				t.Fatalf("для %q получено %d предупреждений (%v), ожидалось %d",
					tt.addr, len(got), got, tt.wantWarnings)
			}
			if tt.wantContains != "" && !strings.Contains(strings.Join(got, " "), tt.wantContains) {
				t.Errorf("предупреждение %v не содержит %q", got, tt.wantContains)
			}
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	t.Parallel()

	tests := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"Info":    slog.LevelInfo,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"ERROR":   slog.LevelError,
	}

	for in, want := range tests {
		t.Run(in, func(t *testing.T) {
			t.Parallel()

			cfg, err := Load(envMap(map[string]string{"SENSOR_LOG_LEVEL": in}))
			if err != nil {
				t.Fatalf("уровень %q должен приниматься, получена ошибка: %v", in, err)
			}
			if cfg.LogLevel != want {
				t.Errorf("уровень %q разобран как %s, ожидался %s", in, cfg.LogLevel, want)
			}
		})
	}
}
