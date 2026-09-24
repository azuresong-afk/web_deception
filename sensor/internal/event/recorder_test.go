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

func TestRecorderWritesInOrder(t *testing.T) {
	t.Parallel()

	sink := &memSink{}
	r := NewRecorder(sink, 16, discard())
	for _, typ := range []Type{TypeSensorStarted, TypeConnectRejected, TypeSensorStopping} {
		r.Emit(New(typ, SeverityInfo))
	}
	closeRecorder(t, r)

	lines := sink.snapshot()
	if len(lines) != 3 || !sink.closed {
		t.Fatalf("записано %d строк, Sink закрыт: %v", len(lines), sink.closed)
	}
	for i, want := range []Type{TypeSensorStarted, TypeConnectRejected, TypeSensorStopping} {
		if !strings.HasSuffix(lines[i], "\n") || strings.Count(lines[i], "\n") != 1 {
			t.Errorf("строка %d не заканчивается ровно одним переводом строки: %q", i, lines[i])
		}
		var ev Event
		if err := json.Unmarshal([]byte(lines[i]), &ev); err != nil || ev.Type != want {
			t.Errorf("строка %d: тип %q, ошибка %v; ожидался %q", i, ev.Type, err, want)
		}
	}
	if r.Stats.Emitted.Load() != 3 || r.Stats.Written.Load() != 3 {
		t.Errorf("счётчики: принято %d, записано %d", r.Stats.Emitted.Load(), r.Stats.Written.Load())
	}
}

// TestEmitNeverBlocks — главное свойство Recorder: запись зависла, а Emit
// всё равно возвращается сразу, лишнее отбрасывается и учитывается.
func TestEmitNeverBlocks(t *testing.T) {
	t.Parallel()

	sink := &memSink{block: make(chan struct{})}
	const queue = 4
	r := NewRecorder(sink, queue, discard())

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			r.Emit(New(TypeConnectRejected, SeverityLow))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Emit ждёт зависшую запись: обработчик запроса задержал бы трафик")
	}

	// Одно событие горутина записи держит в зависшем Write, queue — в буфере,
	// остальные отброшены. Сколько именно успела взять горутина — вопрос
	// расписания, поэтому проверяем границы, а не точное число.
	dropped := r.Stats.DroppedQueueFull.Load()
	if dropped < 100-queue-1 || r.Stats.Emitted.Load()+dropped != 100 {
		t.Errorf("принято %d, отброшено %d из 100 при буфере %d",
			r.Stats.Emitted.Load(), dropped, queue)
	}

	close(sink.block)
	closeRecorder(t, r)
	if got := uint64(len(sink.snapshot())); got != r.Stats.Emitted.Load() {
		t.Errorf("записано %d, принято %d: принятые события должны дописаться при остановке",
			got, r.Stats.Emitted.Load())
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

	s := &r.Stats
	total := s.Emitted.Load() + s.DroppedQueueFull.Load() + s.DroppedStopped.Load()
	if total != 100*50 {
		t.Errorf("учтено %d событий из %d: каждое должно быть либо принято, либо учтено как потерянное", total, 100*50)
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
