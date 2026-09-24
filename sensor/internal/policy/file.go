package policy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// cachePerm — копию последней валидной политики читает только сенсор:
// по ней видно, где стоят ловушки, и это не должно быть видно другим.
const cachePerm = 0o600

// LoadFile читает и проверяет политику из файла. Возвращает и исходные
// байты — их сенсор сохраняет как копию последней валидной.
func LoadFile(path string) (*Compiled, []byte, error) {
	// Путь — из конфигурации запуска (администратор), а не из запроса.
	// Clean — чтобы это было видно и линтеру gosec: путь уже приведён
	// к каноническому виду и не содержит «..», склеенных из частей.
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, nil, fmt.Errorf("файл политики: %w", err)
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("файл политики: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("файл политики %s: это не обычный файл", path)
	}

	// Читаем на байт больше предела: так отличаем «ровно предел» от
	// «больше», не читая в память весь огромный файл.
	data, err := io.ReadAll(io.LimitReader(f, MaxPolicyBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("файл политики: %w", err)
	}
	c, err := Parse(data)
	if err != nil {
		return nil, nil, err
	}
	return c, data, nil
}

// WriteCache атомарно сохраняет копию последней валидной политики.
//
// Атомарно — через временный файл в том же каталоге и переименование:
// сбой посреди записи оставляет прежнюю копию целой, а не половину новой.
// Переименование в пределах одного каталога в Linux атомарно.
func WriteCache(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".policy-*.tmp")
	if err != nil {
		return fmt.Errorf("копия политики: %w", err)
	}
	// Если что-то пошло не так — временный файл не оставляем.
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()

	if err = tmp.Chmod(cachePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("копия политики: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("копия политики: %w", err)
	}
	// Sync до переименования: иначе после сбоя питания на месте копии мог бы
	// оказаться пустой файл с новым именем.
	if err = errors.Join(tmp.Sync(), tmp.Close()); err != nil {
		return fmt.Errorf("копия политики: %w", err)
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("копия политики: %w", err)
	}
	return nil
}
