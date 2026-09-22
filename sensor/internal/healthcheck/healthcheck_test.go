package healthcheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTargetURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		addr string
		want string
	}{
		{"127.0.0.1:9090", "http://127.0.0.1:9090/readyz"},
		// «Все интерфейсы» — адрес для прослушивания, подключаться надо к локальному.
		{"0.0.0.0:9090", "http://127.0.0.1:9090/readyz"},
		{":9090", "http://127.0.0.1:9090/readyz"},
		{"[::]:9090", "http://[::1]:9090/readyz"},
		{"[::1]:9090", "http://[::1]:9090/readyz"},
		{"localhost:9090", "http://localhost:9090/readyz"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			t.Parallel()

			got, err := TargetURL(tt.addr)
			if err != nil {
				t.Fatalf("TargetURL(%q) вернул ошибку: %v", tt.addr, err)
			}
			if got != tt.want {
				t.Errorf("TargetURL(%q) = %q, ожидалось %q", tt.addr, got, tt.want)
			}
		})
	}

	if _, err := TargetURL("без-порта"); err == nil {
		t.Error("адрес без порта должен давать ошибку")
	}
}

func TestProbe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		wantErr bool
	}{
		{
			name:    "готов",
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
			wantErr: false,
		},
		{
			name:    "не готов",
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
			wantErr: true,
		},
		{
			// Редирект на «здоровый» адрес не должен засчитываться как здоровье.
			name: "редирект не выполняется",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/elsewhere" {
					w.WriteHeader(http.StatusOK)
					return
				}
				http.Redirect(w, r, "/elsewhere", http.StatusFound)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(tt.handler)
			defer srv.Close()

			err := Probe(context.Background(), srv.URL+"/readyz")
			if (err != nil) != tt.wantErr {
				t.Errorf("Probe вернул ошибку %v, ожидалась ошибка: %v", err, tt.wantErr)
			}
		})
	}
}

func TestProbeFailsWhenNobodyListens(t *testing.T) {
	t.Parallel()

	// Поднимаем и сразу закрываем сервер: адрес гарантированно никто не слушает.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL + "/readyz"
	srv.Close()

	if err := Probe(context.Background(), url); err == nil {
		t.Error("проверка прошла, хотя сенсор не запущен")
	}
}

func TestProbeRespectsTimeout(t *testing.T) {
	t.Parallel()

	// Зависший сенсор должен давать провал проверки, а не зависшую проверку.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	start := time.Now()
	err := Probe(context.Background(), srv.URL+"/readyz")

	if err == nil {
		t.Fatal("проверка прошла, хотя сенсор не ответил")
	}
	if elapsed := time.Since(start); elapsed > Timeout+time.Second {
		t.Errorf("проверка длилась %s, хотя таймаут %s", elapsed, Timeout)
	}
}
