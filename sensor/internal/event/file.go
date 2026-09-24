package event

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
)

// Пределы файла событий. Константы, а не настройки: вместе они задают
// верхнюю границу места на диске — (keepFiles + 1) × maxFileBytes = 160 МиБ.
// Атакующий, который касается приманок без остановки, может заполнить
// эти 160 МиБ, но не диск хоста (угроза T3): старые файлы удаляются.
const (
	maxFileBytes = 32 << 20 // 32 МиБ
	keepFiles    = 4        // events.jsonl.1 … events.jsonl.4

	// Буфер записи. Без него каждое событие — отдельный системный вызов.
	fileBufferBytes = 64 << 10

	// Файл читает только сенсор: в событиях адреса клиентов, а это
	// персональные данные (ADR-0007).
	filePerm = 0o600
)

// FileSink пишет строки событий в файл и ротирует его по размеру:
// events.jsonl → events.jsonl.1 → … → events.jsonl.4 → удаляется.
//
// Не безопасен для одновременного использования: пишет в него только
// горутина Recorder.
type FileSink struct {
	path     string
	maxBytes int64
	keep     int

	f    *os.File
	w    *bufio.Writer
	size int64
}

// OpenFile открывает файл событий для дописывания. Файл создаётся, если его
// нет; каталог должен существовать.
func OpenFile(path string) (*FileSink, error) {
	return openFile(path, maxFileBytes, keepFiles)
}

func openFile(path string, maxBytes int64, keep int) (*FileSink, error) {
	s := &FileSink{path: path, maxBytes: maxBytes, keep: keep}
	if err := s.open(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *FileSink) open() error {
	// O_APPEND: после перезапуска сенсор дописывает в конец, а не затирает
	// события прошлого запуска.
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, filePerm)
	if err != nil {
		return fmt.Errorf("файл событий: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("файл событий: %w", err)
	}
	// Не обычный файл — например, путь указывает на устройство или канал.
	// Писать туда события и ротировать их нельзя.
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return fmt.Errorf("файл событий %s: это не обычный файл", s.path)
	}
	s.f = f
	s.size = st.Size()
	if s.w == nil {
		s.w = bufio.NewWriterSize(f, fileBufferBytes)
	} else {
		s.w.Reset(f)
	}
	return nil
}

// Write дописывает одну строку. Если файл превысит предел, сначала
// ротирует его.
func (s *FileSink) Write(line []byte) error {
	// Файл не открыт — прошлая ротация не смогла открыть новый. Пробуем
	// снова: место на диске могло освободиться.
	if s.f == nil {
		if err := s.open(); err != nil {
			return err
		}
	}
	if s.size > 0 && s.size+int64(len(line)) > s.maxBytes {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	n, err := s.w.Write(line)
	s.size += int64(n)
	return err
}

// Flush отдаёт накопленное в буфере операционной системе.
func (s *FileSink) Flush() error {
	if s.f == nil {
		return nil
	}
	return s.w.Flush()
}

// Close сбрасывает буфер, просит систему записать файл на диск и закрывает
// его. Sync — только здесь, а не после каждого события: он ждёт диск,
// а при остановке это ожидание оправдано.
func (s *FileSink) Close() error {
	if s.f == nil {
		return nil
	}
	err := errors.Join(s.w.Flush(), s.f.Sync(), s.f.Close())
	s.f = nil
	return err
}

// rotate сдвигает старые файлы на один номер и открывает новый.
func (s *FileSink) rotate() error {
	// Ошибки собираем, но не останавливаемся: при любом исходе нужно
	// попробовать открыть новый файл, иначе события перестанут писаться
	// совсем.
	errs := []error{s.w.Flush(), s.f.Close()}
	s.f = nil

	// Переименование поверх существующего файла заменяет его, поэтому
	// events.jsonl.3 → events.jsonl.4 заодно удаляет самый старый.
	for i := s.keep - 1; i >= 1; i-- {
		errs = append(errs, renameIfExists(s.numbered(i), s.numbered(i+1)))
	}
	errs = append(errs, renameIfExists(s.path, s.numbered(1)))
	errs = append(errs, s.open())
	return errors.Join(errs...)
}

func (s *FileSink) numbered(i int) string {
	return s.path + "." + strconv.Itoa(i)
}

func renameIfExists(from, to string) error {
	err := os.Rename(from, to)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
