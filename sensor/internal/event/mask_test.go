package event

import (
	"strings"
	"testing"
)

func TestMaskPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, want string
	}{
		// Обычные пути и приманки не меняются: по ним понятно, что трогали.
		{"/", "/"},
		{"/.env", "/.env"},
		{"/.git/config", "/.git/config"},
		{"/api/v2/users", "/api/v2/users"},
		{"/assets/app.3f2a.js", "/assets/app.3f2a.js"},
		{"/configuration-management", "/configuration-management"},
		{"/facade", "/facade"},
		{"//double//slash", "//double//slash"},

		// Числа — идентификаторы.
		{"/api/users/12345", "/api/users/{num}"},
		{"/page/1", "/page/{num}"},

		// Почта — персональные данные, в том числе в процентной записи.
		{"/users/john@example.com", "/users/{email}"},
		{"/users/john%40example.com", "/users/{email}"},

		// Идентификаторы и токены.
		{"/files/550e8400-e29b-41d4-a716-446655440000", "/files/{uuid}"},
		{"/reset/9f8a7c6e5d4b3a2f", "/reset/{hex}"},
		{"/objects/507F1F77BCF86CD799439011", "/objects/{hex}"},
		{"/auth/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "/auth/{jwt}"},
		{"/magic/aZ3kQ9pL2mX7vB1nR8tY", "/magic/{token}"},
		{"/key/k_4eC39HqLyjWDarjtT1zdp7dcXz", "/key/{token}"},
		{"/t/abc%2Bdef%3D1234567890", "/t/{token}"},
		{"/download/3f2a9b7c1d4e5f60718293a4b5c6d7e8.pdf", "/download/{token}"},

		// Параметры сегмента после «;» — идентификатор сессии Tomcat.
		{"/shop;jsessionid=0123ABCD4567EF89", "/shop;{params}"},
		{"/users/42;v=1", "/users/{num};{params}"},

		// Пограничные случаи порогов.
		{"/abcdef0123456789", "/{hex}"},                  // ровно 16 — маскируется
		{"/abcdef012345678", "/abcdef012345678"},         // 15 — нет
		{"/a1b2c3d4e5f6g7h8i9j0", "/{token}"},            // ровно 20 — маскируется
		{"/a1b2c3d4e5f6g7h8i9j", "/a1b2c3d4e5f6g7h8i9j"}, // 19 — нет
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()

			got, truncated := MaskPath(tt.in)
			if got != tt.want || truncated {
				t.Errorf("MaskPath(%q) = %q, %v; ожидалось %q, false", tt.in, got, truncated, tt.want)
			}
		})
	}
}

// TestMaskPathTruncation: длинный путь обрезается по границе сегмента,
// и обрезанный сегмент не попадает в результат даже частично.
func TestMaskPathTruncation(t *testing.T) {
	t.Parallel()

	// Токен из 40 символов начинается в самом конце предела: его начало
	// короче порога токена и маскировку бы не прошло.
	prefix := "/" + strings.Repeat("a", maxPathBytes-10) + "/"
	// Собран в коде, а не записан строкой: настоящий на вид токен в исходниках
	// справедливо находит поиск секретов (gitleaks), а маскированию всё
	// равно, случайные ли символы — важны длина и состав.
	token := strings.Repeat("q7", 20)
	got, truncated := MaskPath(prefix + token)

	if !truncated {
		t.Error("длинный путь не отмечен как обрезанный")
	}
	if len(got) > maxPathBytes {
		t.Errorf("длина результата %d больше предела %d", len(got), maxPathBytes)
	}
	if strings.Contains(got, token[:5]) {
		t.Errorf("начало токена попало в результат: %q", got[len(got)-20:])
	}
	if !strings.HasSuffix(got, "/") {
		t.Errorf("путь обрезан не по границе сегмента: …%q", got[len(got)-20:])
	}
}

// TestMaskPathExpansionBounded: метка длиннее сегмента («1» → «{num}»),
// но результат всё равно не длиннее предела.
func TestMaskPathExpansionBounded(t *testing.T) {
	t.Parallel()

	got, truncated := MaskPath(strings.Repeat("/1", 500))
	if len(got) > maxPathBytes || !truncated {
		t.Errorf("длина %d, обрезан %v: ожидалось не больше %d и отметка", len(got), truncated, maxPathBytes)
	}
}

func FuzzMaskPath(f *testing.F) {
	for _, s := range []string{"/", "/a;b;c", "/x@y", "/eyJ.", strings.Repeat("/1", 600)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got, _ := MaskPath(p)
		if len(got) > maxPathBytes {
			t.Fatalf("длина %d больше предела", len(got))
		}
	})
}
