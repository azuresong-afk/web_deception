package event

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/web_deception/sensor/internal/forwarded"
)

// TestFormatV0 — «золотой» тест формата: событие с известными полями
// кодируется ровно в эту строку. Любое изменение формата — имени поля,
// порядка, представления времени — роняет тест и видно в ревью.
// Для версии 0 менять формат можно, но осознанно.
func TestFormatV0(t *testing.T) {
	t.Parallel()

	ev := Event{
		V:        Version,
		ID:       "TESTID",
		Time:     time.Date(2026, 9, 24, 16, 0, 0, 123_000_000, time.UTC),
		Type:     TypeConnectRejected,
		Severity: SeverityLow,
		Client:   &Client{IP: "203.0.113.7", Peer: "10.0.0.1", ViaTrustedProxy: true},
		Request:  &Request{Method: "CONNECT", UserAgent: "curl/8.0"},
		Data:     map[string]string{"target": "internal:22"},
	}
	got, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":0,"id":"TESTID","ts":"2026-09-24T16:00:00.123Z","type":"request.connect_rejected",` +
		`"severity":"low","client":{"ip":"203.0.113.7","peer":"10.0.0.1","via_trusted_proxy":true},` +
		`"request":{"method":"CONNECT","user_agent":"curl/8.0"},"data":{"target":"internal:22"}}`
	if string(got) != want {
		t.Errorf("формат события изменился:\nполучено: %s\nожидалось: %s", got, want)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	a, b := New(TypeSensorStarted, SeverityInfo), New(TypeSensorStarted, SeverityInfo)
	if a.V != Version || a.Type != TypeSensorStarted || a.Severity != SeverityInfo {
		t.Errorf("поля события: %+v", a)
	}
	// 128 бит из crypto/rand в base32 — 26 символов; два подряд не совпадают.
	if len(a.ID) != 26 || a.ID == b.ID {
		t.Errorf("идентификаторы %q и %q: ожидались разные, по 26 символов", a.ID, b.ID)
	}
	if a.Time.Location() != time.UTC || time.Since(a.Time) > time.Minute {
		t.Errorf("время события %v: ожидалось текущее в UTC", a.Time)
	}
}

func TestClientFrom(t *testing.T) {
	t.Parallel()

	got := ClientFrom(forwarded.Client{
		Addr: netip.MustParseAddr("203.0.113.7"),
		Peer: netip.MustParseAddr("10.0.0.1"),
	})
	if got.IP != "203.0.113.7" || got.Peer != "10.0.0.1" {
		t.Errorf("ClientFrom = %+v", got)
	}

	// Цепочка оборвана: адреса клиента нет, и в JSON поля ip нет вовсе,
	// а не пустая строка или адрес прокси.
	broken := ClientFrom(forwarded.Client{Peer: netip.MustParseAddr("10.0.0.1"), ChainBroken: true})
	line, _ := json.Marshal(broken)
	if bytes.Contains(line, []byte(`"ip"`)) || !bytes.Contains(line, []byte(`"chain_broken":true`)) {
		t.Errorf("оборванная цепочка закодирована как %s", line)
	}
}

// TestRequestFromReadsOnlyMetadata: из запроса в событие попадают метод,
// замаскированный путь, User-Agent и факт наличия параметров — и ничего
// больше: ни значений параметров, ни cookie, ни Authorization, ни тела.
func TestRequestFromReadsOnlyMetadata(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodPost,
		"/reset/9f8a7c6e5d4b3a2f1e0d?token=SECRET-QUERY-VALUE", strings.NewReader("password=SECRET-BODY"))
	r.Header.Set("User-Agent", "sqlmap/1.8")
	r.Header.Set("Cookie", "session=SECRET-COOKIE")
	r.Header.Set("Authorization", "Bearer SECRET-AUTH")

	req := RequestFrom(r)
	if req.Method != "POST" || req.Path != "/reset/{hex}" || !req.HasQuery || req.UserAgent != "sqlmap/1.8" {
		t.Errorf("RequestFrom = %+v", req)
	}

	line, _ := json.Marshal(req)
	for _, secret := range []string{"SECRET-QUERY-VALUE", "SECRET-BODY", "SECRET-COOKIE", "SECRET-AUTH", "9f8a7c6e5d4b3a2f1e0d"} {
		if bytes.Contains(line, []byte(secret)) {
			t.Errorf("в событие попало %q: %s", secret, line)
		}
	}
}

// TestNoLineInjection: атакующий кладёт в User-Agent перевод строки
// и «своё событие». В файле это должно остаться одной строкой с одним
// событием, а управляющие символы — экранированными (угроза T19).
func TestNoLineInjection(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header["User-Agent"] = []string{"x\r\n{\"type\":\"sensor.started\"}\n\x1b[31mred\x1b[0m <script>"}
	ev := New(TypeConnectRejected, SeverityLow)
	ev.Request = RequestFrom(r)

	line, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []byte{'\n', '\r', 0x1b} {
		if bytes.IndexByte(line, c) >= 0 {
			t.Errorf("в строке события неэкранированный символ %q: %s", c, line)
		}
	}
	for _, s := range []string{" ", "<script>"} {
		if bytes.Contains(line, []byte(s)) {
			t.Errorf("в строке события неэкранированное %q: %s", s, line)
		}
	}

	// Разбор строки даёт одно событие исходного типа, а не подставленного.
	var back Event
	if err := json.Unmarshal(line, &back); err != nil || back.Type != TypeConnectRejected {
		t.Errorf("событие после разбора: %+v, ошибка %v", back, err)
	}
}

func TestClean(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		in            string
		max           int
		want          string
		wantTruncated bool
	}{
		{"короткая строка", "curl/8.0", 16, "curl/8.0", false},
		{"обрезается", "abcdefgh", 4, "abcd", true},
		{"недопустимый UTF-8 заменён", "a\xffb", 16, "a�b", false},
		{"не режет символ пополам", "ааа", 5, "аа", true},
		{"замена не выходит за предел", "\xff\xff\xff\xff", 4, "�", false},
		{"рост от замены обрезается", "a\xffb\xffc", 4, "a\uFFFD", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, truncated := Clean(tt.in, tt.max)
			if got != tt.want || truncated != tt.wantTruncated {
				t.Errorf("Clean(%q, %d) = %q, %v; ожидалось %q, %v", tt.in, tt.max, got, truncated, tt.want, tt.wantTruncated)
			}
			if len(got) > tt.max || !utf8.ValidString(got) {
				t.Errorf("результат %q длиннее %d байт или не UTF-8", got, tt.max)
			}
		})
	}
}

// TestEventSizeBounded: событие от самого неудобного запроса всё равно
// ограничено по размеру. Иначе атакующий управлял бы тем, сколько места
// на диске и в буфере занимает одно событие.
func TestEventSizeBounded(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequest(http.MethodGet, "/"+strings.Repeat("1/", 30000), nil)
	r.Method = strings.Repeat("M", 10000)
	r.Header["User-Agent"] = []string{strings.Repeat("\x01\xff", 30000)}
	r.Host = strings.Repeat("h", 60000)

	ev := New(TypeConnectRejected, SeverityLow)
	ev.Client = &Client{IP: "2001:db8::7", Peer: "2001:db8::1"}
	ev.Request = RequestFrom(r)
	ev.Data = map[string]string{"target": ConnectTarget(r)}

	line, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	// Путь ≤ 1024, User-Agent ≤ 256 байт, но управляющий символ в JSON
	// занимает 6 байт (\u0001) — отсюда запас.
	if len(line) > 4096 {
		t.Errorf("событие занимает %d байт, ожидалось не больше 4096", len(line))
	}
	if !ev.Request.PathTruncated {
		t.Error("длинный путь не отмечен как обрезанный")
	}
}
