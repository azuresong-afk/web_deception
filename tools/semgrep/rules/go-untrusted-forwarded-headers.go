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

	// ruleid: go-untrusted-forwarded-headers
	_ = r.Header.Get("X-Forwarded-Proto")

	// ruleid: go-untrusted-forwarded-headers
	_ = r.Header.Values("X-Forwarded-Prefix")

	// ruleid: go-untrusted-forwarded-headers
	_ = r.Header.Get("X_Forwarded_For")

	// ruleid: go-untrusted-forwarded-headers
	_ = r.Header.Get("CF-Connecting-IP")

	// ok: go-untrusted-forwarded-headers
	_ = r.Header.Get("X-Forwarded")

	// ok: go-untrusted-forwarded-headers
	_ = r.Header.Get("X-Request-Id")

	// ok: go-untrusted-forwarded-headers
	_ = r.Header.Get("User-Agent")

	// ok: go-untrusted-forwarded-headers
	_ = r.RemoteAddr

	return ip
}
