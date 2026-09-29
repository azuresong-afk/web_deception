package policy

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Микробенчмарки горячего пути (ADR-0030). Match и Preflighted
// вызываются на каждом запросе, поэтому их стоимость — часть бюджета
// сенсора +5 мс к p99. Запуск: make bench.

func demoPolicy(b *testing.B) *Compiled {
	b.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "deploy", "policy", "demo.json"))
	if err != nil {
		b.Fatal(err)
	}
	c, err := Parse(data)
	if err != nil {
		b.Fatal(err)
	}
	return c
}

// BenchmarkMatch — поиск ловушки по пути: промах (обычный запрос),
// попадание и путь, который нужно нормализовать.
func BenchmarkMatch(b *testing.B) {
	c := demoPolicy(b)
	for _, path := range []string{"/api/Products/42", "/.env", "//./api/../.env", "/" + string(make([]byte, 200))} {
		b.Run(path[:min(len(path), 20)], func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				c.Match(path)
			}
		})
	}
}

// BenchmarkPreflighted — проверка «непростого» запроса (ADR-0026).
func BenchmarkPreflighted(b *testing.B) {
	r := httptest.NewRequest("POST", "/api/internal/v1/users/export", nil)
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	b.ReportAllocs()
	for b.Loop() {
		Preflighted(r)
	}
}
