package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

// envMap превращает обычную карту в источник переменных окружения.
// Благодаря этому ни один тест не трогает окружение процесса и все они
// могут выполняться параллельно.
func envMap(m map[string]string) Getenv {
	return func(k string) string { return m[k] }
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
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout по умолчанию = %s, ожидалось 10s", cfg.ShutdownTimeout)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel по умолчанию = %s, ожидался info", cfg.LogLevel)
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
	}))
	if err != nil {
		t.Fatalf("Load вернул ошибку: %v", err)
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
