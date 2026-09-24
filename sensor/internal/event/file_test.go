package event

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("чтение %s: %v", path, err)
	}
	return string(b)
}

func TestFileSinkAppendsAcrossRestarts(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "events.jsonl")
	for _, line := range []string{"first\n", "second\n"} {
		s, err := OpenFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	// Второй запуск дописал, а не затёр события первого.
	if got := readFile(t, path); got != "first\nsecond\n" {
		t.Errorf("содержимое файла %q", got)
	}
}

// TestFileSinkPermissions: файл событий доступен только владельцу — в нём
// адреса клиентов.
func TestFileSinkPermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("права доступа Unix")
	}

	path := filepath.Join(t.TempDir(), "events.jsonl")
	s, err := OpenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("права файла %v: ожидался доступ только владельцу", perm)
	}
}

// TestFileSinkRotation: при превышении размера файл уходит в .1, .1 в .2
// и так далее; файлов не больше keep+1, самые старые удаляются.
func TestFileSinkRotation(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "events.jsonl")
	// Предел 10 байт, строки по 6: в каждом файле ровно одна строка.
	s, err := openFile(path, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"line1\n", "line2\n", "line3\n", "line4\n"} {
		if err := s.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		path:        "line4\n",
		path + ".1": "line3\n",
		path + ".2": "line2\n",
	}
	for p, content := range want {
		if got := readFile(t, p); got != content {
			t.Errorf("%s: %q, ожидалось %q", filepath.Base(p), got, content)
		}
	}
	// line1 была в .3, а keep = 2: её не должно остаться нигде.
	if _, err := os.Stat(path + ".3"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("файлов больше, чем keep+1: %v", err)
	}
}

// TestFileSinkRejectsNonRegular: путь указывает не на обычный файл —
// сенсор отказывается стартовать, а не пишет события в никуда.
func TestFileSinkRejectsNonRegular(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if _, err := OpenFile(dir); err == nil {
		t.Error("каталог принят как файл событий")
	}
	if _, err := OpenFile(filepath.Join(dir, "нет-такого-каталога", "events.jsonl")); err == nil {
		t.Error("файл в несуществующем каталоге принят")
	}
}

// TestFileSinkRecoversAfterFailedOpen: ротация не смогла открыть новый
// файл — следующая запись пробует снова и, когда причина ушла, пишет.
func TestFileSinkRecoversAfterFailedOpen(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "events")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "events.jsonl")
	s, err := openFile(path, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Write([]byte("line1\n")); err != nil {
		t.Fatal(err)
	}

	// Каталог пропал (например, отмонтировали том): ротация не может
	// открыть новый файл. Права каталога тут не подошли бы — тесты
	// в контейнере идут от root, которому права не помеха.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := s.Write([]byte("line2\n")); err == nil {
		t.Error("запись без каталога не вернула ошибку")
	}

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Write([]byte("line3\n")); err != nil {
		t.Fatalf("после восстановления каталога запись не удалась: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "line3\n" {
		t.Errorf("после восстановления в файле %q, ожидалось %q", got, "line3\n")
	}
}
