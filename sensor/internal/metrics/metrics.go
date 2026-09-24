// Package metrics отдаёт счётчики сенсора на служебном слушателе в текстовом
// формате Prometheus.
//
// Формат пишется вручную, без библиотеки client_golang: счётчиков
// несколько, а библиотека принесла бы в сенсор десяток модулей
// с зависимостями (решение этапа 2, docs/roadmap.md). Формат простой:
//
//	# HELP sensor_events_dropped_total События, отброшенные сенсором.
//	# TYPE sensor_events_dropped_total counter
//	sensor_events_dropped_total{reason="queue_full"} 0
//
// Граница доверия: в метриках нет ни одного значения из запросов. Имена
// и метки — константы из кода, значения — числа. Метка из данных
// запроса (путь, адрес) позволила бы атакующему создавать новые строки
// метрик без предела и раздуть память сенсора и хранилище Prometheus.
package metrics

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/azuresong-afk/web_deception/sensor/internal/respond"
)

// Kind — тип метрики.
type Kind string

const (
	// Counter только растёт: число событий с момента запуска.
	Counter Kind = "counter"
	// Gauge — текущее значение: сколько событий ждут записи сейчас.
	Gauge Kind = "gauge"
)

// Metric — одна строка вывода.
type Metric struct {
	Name string
	Help string
	Kind Kind
	// Label — одна метка вида reason="queue_full" или пусто.
	Label string
	// Value читает текущее значение; вызывается при каждом запросе /metrics
	// одновременно с работой сенсора, поэтому должно читать атомарно.
	Value func() uint64
}

var (
	nameRe  = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
	labelRe = regexp.MustCompile(`^[a-z_][a-z0-9_]*="[a-z0-9_]+"$`)
)

// Handler возвращает обработчик /metrics.
//
// Список проверяется здесь, при запуске: ошибка в имени или метке — ошибка
// программиста, и лучше упасть при старте и в тестах, чем отдавать
// Prometheus строки, которые он не разберёт. Метрики с одним именем
// должны идти подряд: заголовок HELP/TYPE у имени один.
func Handler(ms []Metric) http.Handler {
	if err := validate(ms); err != nil {
		panic("metrics: " + err.Error())
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		respond.Plain(w, http.StatusOK, render(ms))
	})
}

func render(ms []Metric) string {
	var b strings.Builder
	prev := ""
	for _, m := range ms {
		if m.Name != prev {
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", m.Name, m.Help, m.Name, m.Kind)
			prev = m.Name
		}
		b.WriteString(m.Name)
		if m.Label != "" {
			b.WriteString("{" + m.Label + "}")
		}
		b.WriteString(" " + strconv.FormatUint(m.Value(), 10) + "\n")
	}
	// Перевод строки в конце добавит respond.Plain.
	return strings.TrimSuffix(b.String(), "\n")
}

func validate(ms []Metric) error {
	seen := map[string]Metric{}
	prev := ""
	for _, m := range ms {
		switch {
		case !nameRe.MatchString(m.Name):
			return fmt.Errorf("недопустимое имя %q", m.Name)
		case m.Kind != Counter && m.Kind != Gauge:
			return fmt.Errorf("%s: недопустимый тип %q", m.Name, m.Kind)
		case m.Help == "" || strings.ContainsAny(m.Help, "\\\n"):
			return fmt.Errorf("%s: описание пустое или с «\\» и переводом строки", m.Name)
		case m.Label != "" && !labelRe.MatchString(m.Label):
			return fmt.Errorf("%s: недопустимая метка %q", m.Name, m.Label)
		case m.Value == nil:
			return fmt.Errorf("%s: нет функции значения", m.Name)
		}
		if first, ok := seen[m.Name]; ok {
			if m.Name != prev {
				return fmt.Errorf("%s: строки с одним именем должны идти подряд", m.Name)
			}
			if first.Kind != m.Kind || first.Help != m.Help {
				return fmt.Errorf("%s: разные тип или описание у одного имени", m.Name)
			}
		} else {
			seen[m.Name] = m
		}
		prev = m.Name
	}
	return nil
}
