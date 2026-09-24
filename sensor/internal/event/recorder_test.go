package event

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// memSink — Sink в памяти. block, если задан, задерживает каждую запись,
// пока канал не закроют: так тест изображает зависший диск.
type memSink struct {
	mu       sync.Mutex
	lines    []string
	block    chan struct{}
	writeErr error
	closed   bool
}

func (s *memSink) Write(line []byte) error {
	if s.block != nil {
		<-s.block
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writeErr != nil {
		return s.writeErr
	}
	s.lines = append(s.lines, string(line))
	return nil
}

func (s *memSink) Flush() error { return nil }

func (s *memSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *memSink) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func discard() *slog.Logger { return slog.New(slog.NewJSONHandler(io.Discard, nil)) }

func closeRecorder(t *testing.T, r *Recorder) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestRecorderWritesInOrder: события одной очереди записываются в том
// порядке, в каком переданы, каждое — отдельной строкой.
func TestRecorderWritesInOrder(t *testing.T) {
	t.Parallel()

	sink := &memSink{}
	r := NewRecorder(sink, 16, discard())
	for i := range 3 {
		ev := New(TypeConnectRejected, SeverityLow)
		ev.Data = map[string]string{"n": strconv.Itoa(i)}
		r.Emit(ev)
	}
	closeRecorder(t, r)

	lines := sink.snapshot()
	if len(lines) != 3 || !sink.closed {
		t.Fatalf("записано %d строк, Sink закрыт: %v", len(lines), sink.closed)
	}
	for i, line := range lines {
		if !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
			t.Errorf("строка %d не заканчивается ровно одним переводом строки: %q", i, line)
		}
		var ev Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.Data["n"] != strconv.Itoa(i) {
			t.Errorf("строка %d: номер %q, ошибка %v", i, ev.Data["n"], err)
		}
	}
	if r.Stats.Emitted.Load() != 3 || r.Stats.Written.Load() != 3 {
		t.Errorf("счётчики: принято %d, записано %d", r.Stats.Emitted.Load(), r.Stats.Written.Load())
	}
}

// TestPriorityEventSurvivesFlood — ради этого и заведён приоритетный
// буфер: запись зависла, атакующий заливает буфер тысячами касаний,
// а событие о переходе в fail-open всё равно записано.
func TestPriorityEventSurvivesFlood(t *testing.T) {
	t.Parallel()

	sink := &memSink{block: make(chan struct{})}
	r := NewRecorder(sink, 4, discard())

	r.Emit(New(TypeConnectRejected, SeverityLow)) // займёт горутину записи
	r.Emit(New(TypeFailOpen, SeverityCritical))
	for range 10_000 {
		r.Emit(New(TypeDetectionPanic, SeverityHigh))
	}
	close(sink.block)
	closeRecorder(t, r)

	found := false
	for _, line := range sink.snapshot() {
		if strings.Contains(line, `"type":"sensor.fail_open"`) {
			found = true
		}
	}
	if !found {
		t.Error("событие о переходе в fail-open вытеснено потоком других событий")
	}
}

// TestPriorityWrittenFirst: накопившиеся события о состоянии сенсора
// записываются раньше накопившихся остальных. Поэтому файл не строго
// хронологичен — порядок событий восстанавливают по полю ts.
func TestPriorityWrittenFirst(t *testing.T) {
	t.Parallel()

	sink := &memSink{block: make(chan struct{})}
	r := NewRecorder(sink, 16, discard())
	for range 5 {
		r.Emit(New(TypeConnectRejected, SeverityLow))
	}
	r.Emit(New(TypeFailOpen, SeverityCritical))
	close(sink.block)
	closeRecorder(t, r)

	lines := sink.snapshot()
	// Первое событие горутина записи могла взять до появления
	// приоритетного — тогда приоритетное второе.
	if !strings.Contains(lines[0]+lines[1], `"type":"sensor.fail_open"`) {
		t.Errorf("приоритетное событие записано не первым: %v", lines)
	}
}

// panicSink падает при записи события с заданной строкой внутри.
type panicSink struct {
	memSink
	on string
}

func (s *panicSink) Write(line []byte) error {
	if strings.Contains(string(line), s.on) {
		panic("сбой записи")
	}
	return s.memSink.Write(line)
}

// TestWritePanicDoesNotCrash: паника в записи события не роняет сенсор —
// событие потеряно и учтено, следующие пишутся.
func TestWritePanicDoesNotCrash(t *testing.T) {
	t.Parallel()

	sink := &panicSink{on: `"n":"1"`}
	r := NewRecorder(sink, 16, discard())
	for i := range 3 {
		ev := New(TypeConnectRejected, SeverityLow)
		ev.Data = map[string]string{"n": strconv.Itoa(i)}
		r.Emit(ev)
	}
	closeRecorder(t, r)

	if got := len(sink.snapshot()); got != 2 {
		t.Errorf("записано %d событий, ожидалось 2 — все, кроме вызвавшего панику", got)
	}
	if r.Stats.DroppedWriteError.Load() != 1 || r.Stats.SinkErrors.Load() != 1 {
		t.Errorf("потеряно %d, ошибок %d; ожидалось 1 и 1",
			r.Stats.DroppedWriteError.Load(), r.Stats.SinkErrors.Load())
	}
}

// TestEmitNeverBlocks — главное свойство Recorder: запись зависла, а Emit
// всё равно возвращается сразу. Лишнее вытесняется: теряются старые
// события, а самое свежее обязательно доходит до файла.
func TestEmitNeverBlocks(t *testing.T) {
	t.Parallel()

	sink := &memSink{block: make(chan struct{})}
	const queue, total = 4, 100
	r := NewRecorder(sink, queue, discard())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range total {
			ev := New(TypeConnectRejected, SeverityLow)
			ev.Data = map[string]string{"n": strconv.Itoa(i)}
			r.Emit(ev)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Emit ждёт зависшую запись: обработчик запроса задержал бы трафик")
	}

	close(sink.block)
	closeRecorder(t, r)

	lines := sink.snapshot()
	// Одно событие горутина записи держала в зависшем Write, queue — в буфере.
	// Сколько именно успела взять горутина — вопрос расписания.
	if len(lines) < queue || len(lines) > queue+1 {
		t.Errorf("записано %d событий, ожидалось %d–%d", len(lines), queue, queue+1)
	}
	var last Event
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil || last.Data["n"] != strconv.Itoa(total-1) {
		t.Errorf("последним записано событие %q, ожидалось самое свежее %d", last.Data["n"], total-1)
	}
	// Каждое событие либо записано, либо учтено как потерянное.
	if got := r.Stats.Written.Load() + r.Stats.DroppedQueueFull.Load(); got != total {
		t.Errorf("записано %d + потеряно %d = %d, ожидалось %d",
			r.Stats.Written.Load(), r.Stats.DroppedQueueFull.Load(), got, total)
	}
}

// TestEmitAfterClose: обработчик, не успевший завершиться к остановке,
// вызывает Emit — это не паника, а учтённая потеря.
func TestEmitAfterClose(t *testing.T) {
	t.Parallel()

	r := NewRecorder(&memSink{}, 4, discard())
	closeRecorder(t, r)
	r.Emit(New(TypeConnectRejected, SeverityLow))
	if r.Stats.DroppedStopped.Load() != 1 {
		t.Errorf("DroppedStopped = %d, ожидалось 1", r.Stats.DroppedStopped.Load())
	}
	// Повторный Close безопасен.
	closeRecorder(t, r)
}

// TestCloseDoesNotHang: диск завис — остановка сенсора ждёт не дольше
// отведённого срока.
func TestCloseDoesNotHang(t *testing.T) {
	t.Parallel()

	sink := &memSink{block: make(chan struct{})}
	defer close(sink.block)
	r := NewRecorder(sink, 4, discard())
	r.Emit(New(TypeSensorStopping, SeverityInfo))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := r.Close(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close вернул %v, ожидался DeadlineExceeded", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("Close ждал %s при сроке 100 мс", time.Since(start))
	}
}

// TestWriteErrorCountedAndLoggedOnce: диск полон — каждое событие учтено
// как потерянное, а в лог уходит одно сообщение, а не по строке на событие.
func TestWriteErrorCountedAndLoggedOnce(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	var mu sync.Mutex
	logger := slog.New(slog.NewJSONHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(p)
	}), nil))

	sink := &memSink{writeErr: errors.New("no space left on device")}
	r := NewRecorder(sink, 16, logger)
	for range 10 {
		r.Emit(New(TypeConnectRejected, SeverityLow))
	}
	closeRecorder(t, r)

	if r.Stats.DroppedWriteError.Load() != 10 || r.Stats.SinkErrors.Load() != 10 {
		t.Errorf("потеряно %d, ошибок %d; ожидалось 10 и 10",
			r.Stats.DroppedWriteError.Load(), r.Stats.SinkErrors.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if n := strings.Count(logs.String(), "не удалось записать события"); n != 1 {
		t.Errorf("сообщений об ошибке записи в логе: %d, ожидалось 1", n)
	}
}

// TestDropsReported: о потерях из-за полного буфера сообщает горутина
// записи — одним сообщением с числом, а не строкой на каждое событие.
func TestDropsReported(t *testing.T) {
	t.Parallel()

	var logs bytes.Buffer
	var mu sync.Mutex
	logger := slog.New(slog.NewJSONHandler(writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return logs.Write(p)
	}), nil))

	sink := &memSink{block: make(chan struct{})}
	r := NewRecorder(sink, 2, logger)
	for range 50 {
		r.Emit(New(TypeConnectRejected, SeverityLow))
	}
	close(sink.block)
	closeRecorder(t, r)

	mu.Lock()
	defer mu.Unlock()
	if n := strings.Count(logs.String(), "буфер событий переполнялся"); n != 1 {
		t.Errorf("сообщений о потерях: %d, ожидалось 1; лог: %s", n, logs.String())
	}
}

// TestConcurrentEmitAndClose: сотни обработчиков вызывают Emit, пока сенсор
// останавливается. Без паники и без гонок (тесты идут с -race).
func TestConcurrentEmitAndClose(t *testing.T) {
	t.Parallel()

	r := NewRecorder(&memSink{}, 64, discard())
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				r.Emit(New(TypeConnectRejected, SeverityLow))
			}
		}()
	}
	closeRecorder(t, r)
	wg.Wait()

	// Учёт точный: каждое событие либо записано, либо ровно в одном
	// счётчике потерь — даже те, что пришли в момент остановки.
	s := &r.Stats
	total := s.Written.Load() + s.DroppedWriteError.Load() + s.DroppedQueueFull.Load() + s.DroppedStopped.Load()
	if total != 100*50 {
		t.Errorf("учтено %d событий из %d: записано %d, потеряно: буфер %d, остановка %d",
			total, 100*50, s.Written.Load(), s.DroppedQueueFull.Load(), s.DroppedStopped.Load())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// TestRecorderWithFile: Recorder с настоящим файлом. Одиночное событие
// появляется в файле сразу, без остановки сенсора, — иначе при редких
// событиях администратор не увидел бы их, пока буфер не заполнится.
func TestRecorderWithFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "events.jsonl")
	sink, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r := NewRecorder(sink, QueueSize, discard())
	if r.QueueCap() != QueueSize {
		t.Errorf("ёмкость буфера %d, ожидалась %d", r.QueueCap(), QueueSize)
	}
	r.Emit(New(TypeSensorStarted, SeverityInfo))

	deadline := time.Now().Add(5 * time.Second)
	for {
		b, err := os.ReadFile(path)
		if err == nil && bytes.Contains(b, []byte(`"type":"sensor.started"`)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("событие не появилось в файле без остановки: %q", b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r.QueueLen() != 0 {
		t.Errorf("в буфере осталось %d событий", r.QueueLen())
	}
	closeRecorder(t, r)
}
