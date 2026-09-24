package failopen

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

// feed записывает n проверок, из них slow медленных, по одной на каждые
// step времени, начиная с now. Медленные распределены равномерно: решение
// о режиме принимается на каждой проверке, и медленные, собранные в начале,
// дали бы другую долю в момент решения. Возвращает время после последней
// и все смены режима.
func feed(c *controller, now time.Time, n, slow int, step time.Duration) (time.Time, []*Transition) {
	var trs []*Transition
	for i := range n {
		isSlow := (i+1)*slow/n > i*slow/n
		if tr := c.record(now, isSlow); tr != nil {
			trs = append(trs, tr)
		}
		now = now.Add(step)
	}
	return now, trs
}

func TestEnterNeedsMinimumSample(t *testing.T) {
	t.Parallel()

	// 40 проверок, все медленные, — меньше минимума в 50: тихая минута
	// с парой медленных запросов не должна переключать режим.
	c := newController(t0)
	if _, trs := feed(c, t0, enterMinInspected-10, enterMinInspected-10, 10*time.Millisecond); len(trs) != 0 {
		t.Errorf("режим переключился на выборке меньше минимума: %+v", trs[0])
	}
}

func TestEnterAtThreshold(t *testing.T) {
	t.Parallel()

	// 100 проверок за секунду, 9 медленных — меньше 10%: режим прежний.
	c := newController(t0)
	if _, trs := feed(c, t0, 100, 9, time.Millisecond); len(trs) != 0 {
		t.Fatal("9% медленных переключили режим, порог 10%")
	}

	// Ещё 100, из них 20 медленных: в окне 29 из 200 — больше 10%.
	c = newController(t0)
	_, trs := feed(c, t0, 100, 20, time.Millisecond)
	if len(trs) != 1 || !trs[0].Degraded || !c.degraded.Load() {
		t.Fatalf("20%% медленных не включили частичный режим: %+v", trs)
	}
}

// TestHysteresis: вошли при 20% медленных; 5% — между порогами — не
// выводит из режима, сколько бы ни длилось; меньше 1% за 30 секунд — выводит.
func TestHysteresis(t *testing.T) {
	t.Parallel()

	c := newController(t0)
	now, _ := feed(c, t0, 100, 20, time.Millisecond)
	if !c.degraded.Load() {
		t.Fatal("режим не включился")
	}

	// Две минуты по 20 проверок в секунду, 5% медленных.
	for range 120 {
		var trs []*Transition
		now, trs = feed(c, now, 20, 1, 50*time.Millisecond)
		if len(trs) != 0 {
			t.Fatalf("режим снят при 5%% медленных: %+v", trs[0])
		}
	}

	// Дальше без медленных — режим снят, как только в окне выхода
	// медленных стало меньше 1%.
	var recovered *Transition
	for range 40 {
		var trs []*Transition
		now, trs = feed(c, now, 20, 0, 50*time.Millisecond)
		if len(trs) > 0 {
			recovered = trs[0]
			break
		}
	}
	if recovered == nil || recovered.Degraded || c.degraded.Load() {
		t.Fatalf("режим не снят после 30 секунд без медленных проверок: %+v", recovered)
	}
	if recovered.Slow*100 >= recovered.Inspected*exitSlowPercent {
		t.Errorf("в окне выхода %d медленных из %d — не меньше 1%%", recovered.Slow, recovered.Inspected)
	}
}

func TestNoEarlyRecovery(t *testing.T) {
	t.Parallel()

	c := newController(t0)
	now, _ := feed(c, t0, 100, 20, time.Millisecond)
	// Через 29 секунд без единой проверки выходить рано.
	if tr := c.maybeRecover(now.Add(minDegraded - time.Second)); tr != nil {
		t.Fatal("режим снят раньше минимального срока")
	}
	// Через 30 — можно: трафика нет, значит, и нагрузки нет.
	c.mu.Lock()
	tr := c.maybeRecover(now.Add(minDegraded + time.Second))
	c.mu.Unlock()
	if tr == nil || tr.Degraded {
		t.Fatal("режим не снят после 30 секунд без трафика")
	}
}

// TestSampling: в частичном режиме проверяется ровно каждый SampleEvery-й
// запрос, в обычном — каждый.
func TestSampling(t *testing.T) {
	t.Parallel()

	c := newController(t0)
	for range 100 {
		if ok, _ := c.shouldInspect(t0); !ok {
			t.Fatal("в обычном режиме запрос не проверен")
		}
	}

	now, _ := feed(c, t0, 100, 20, time.Millisecond)
	inspected := 0
	for range 1000 {
		if ok, _ := c.shouldInspect(now); ok {
			inspected++
		}
	}
	if inspected != 1000/SampleEvery {
		t.Errorf("в частичном режиме проверено %d из 1000, ожидалось %d", inspected, 1000/SampleEvery)
	}
}

// TestWindowForgetsOldSeconds: окно помнит только последние секунды —
// медленные проверки минуту назад на решение не влияют.
func TestWindowForgetsOldSeconds(t *testing.T) {
	t.Parallel()

	var w window
	for i := range 10 {
		w.add(t0.Add(time.Duration(i)*time.Second), true)
	}
	later := t0.Add(time.Minute)
	w.add(later, false)
	if inspected, slow := w.sum(later, exitWindow); inspected != 1 || slow != 0 {
		t.Errorf("в окне %d проверок, %d медленных; ожидалось 1 и 0", inspected, slow)
	}
}
