package decoy

import (
	"errors"
	"io/fs"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/azuresong-afk/web_deception/sensor/internal/event"
	"github.com/azuresong-afk/web_deception/sensor/internal/policy"
)

// maxErrorInEvent — сколько байт текста ошибки проверки класть в событие.
// Текст составлен из имён полей и значений из политики, но и его длина
// должна быть ограничена.
const maxErrorInEvent = 1024

// LoaderStats — счётчики загрузок для /metrics.
type LoaderStats struct {
	Loaded   atomic.Uint64
	Rejected atomic.Uint64
}

// Loader читает политику из файла и применяет её к Detector.
type Loader struct {
	file      string
	cacheFile string
	detector  *Detector
	events    event.Emitter
	logger    *slog.Logger

	// mu — чтобы две перезагрузки подряд (два SIGHUP) не применялись
	// вперемешку.
	mu sync.Mutex

	Stats LoaderStats
}

// NewLoader создаёт Loader. file — политика от администратора, cacheFile —
// копия последней валидной, которую сенсор ведёт сам.
func NewLoader(file, cacheFile string, d *Detector, events event.Emitter, logger *slog.Logger) *Loader {
	return &Loader{file: file, cacheFile: cacheFile, detector: d, events: events, logger: logger}
}

// Startup — загрузка при запуске сенсора. Ошибка в политике не мешает
// запуску: политика — не граница доверия, как адрес приложения, и сайт
// клиента не должен лежать из-за опечатки в ней. Порядок:
//  1. файл политики — если он верен, применяется и сохраняется копия;
//  2. иначе копия последней валидной — сенсор продолжает с ней;
//  3. иначе — без ловушек.
//
// Каждый исход — событие и строка в логе.
func (l *Loader) Startup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.loadFile() {
		return
	}
	c, _, err := policy.LoadFile(l.cacheFile)
	switch {
	case err == nil:
		l.apply(c, "last_valid")
	case errors.Is(err, fs.ErrNotExist):
		l.logger.Error("политика не принята и копии последней валидной нет: сенсор работает без ловушек")
	default:
		// Копию мог испортить сбой диска или кто-то чужой: она проверяется
		// так же строго, как файл администратора.
		l.logger.Error("копия последней валидной политики тоже неверна: сенсор работает без ловушек",
			slog.String("error", err.Error()))
	}
}

// Reload — перечитать файл по SIGHUP. Неверная политика не применяется:
// остаётся текущая, то есть последняя валидная.
func (l *Loader) Reload() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.loadFile()
}

// loadFile читает файл администратора; при успехе применяет его
// и сохраняет копию.
func (l *Loader) loadFile() bool {
	c, raw, err := policy.LoadFile(l.file)
	if err != nil {
		l.reject(err)
		return false
	}
	l.apply(c, "file")
	if err := policy.WriteCache(l.cacheFile, raw); err != nil {
		// Политика применена; не сохранилась только копия на случай
		// следующей ошибки. Это не повод отказываться от политики.
		l.logger.Warn("не удалось сохранить копию последней валидной политики",
			slog.String("error", err.Error()))
	}
	return true
}

func (l *Loader) apply(c *policy.Compiled, source string) {
	l.detector.Swap(c)
	l.Stats.Loaded.Add(1)

	ev := event.New(event.TypePolicyLoaded, event.SeverityInfo)
	ev.Data = map[string]string{
		"version": c.Version,
		"traps":   strconv.Itoa(c.Len()),
		"source":  source,
	}
	l.events.Emit(ev)
	l.logger.Info("политика применена",
		slog.String("version", c.Version), slog.Int("traps", c.Len()), slog.String("source", source))
}

func (l *Loader) reject(err error) {
	l.Stats.Rejected.Add(1)
	kept := l.detector.Current().Version

	msg, _ := event.Clean(err.Error(), maxErrorInEvent)
	ev := event.New(event.TypePolicyRejected, event.SeverityHigh)
	ev.Data = map[string]string{"error": msg, "kept_version": kept}
	l.events.Emit(ev)
	l.logger.Error("политика не принята: остаётся прежняя",
		slog.String("error", err.Error()), slog.String("kept_version", kept))
}
