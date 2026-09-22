// Тестовые примеры для правила go-untrusted-forwarded-headers.
package examples

import "net/http"

func clientIP(r *http.Request) string {
	// ruleid: go-untrusted-forwarded-headers
	ip := r.Header.Get("X-Forwarded-For")

	// ruleid: go-untrusted-forwarded-headers
	_ = r.Header.Get("x-real-ip")

	// ruleid: go-untrusted-forwarded-headers
	_ = r.Header["X-Forwarded-For"]

	// ok: go-untrusted-forwarded-headers
	_ = r.Header.Get("User-Agent")

	// ok: go-untrusted-forwarded-headers
	_ = r.RemoteAddr

	return ip
}
