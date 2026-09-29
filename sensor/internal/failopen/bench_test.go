package failopen

import (
	"testing"
	"time"
)

// BenchmarkController — блокировка контроллера режима на каждой проверке
// под конкуренцией (долг шага 7, ADR-0024, ADR-0030). RunParallel запускает
// по горутине на процессор: так видно, во что обходится ожидание чужой
// блокировки, а не только сама запись в окно.
func BenchmarkController(b *testing.B) {
	c := newController(time.Now())
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			now := time.Now()
			if inspect, _ := c.shouldInspect(now); inspect {
				c.record(now, false)
			}
		}
	})
}
