// Тестовые примеры для правила go-mac-compare-constant-time.
package examples

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
)

func verify(got, expectedMAC, signature, token []byte, digest string) bool {
	// ruleid: go-mac-compare-constant-time
	if bytes.Equal(got, expectedMAC) {
		return true
	}

	// ruleid: go-mac-compare-constant-time
	if string(got) == digest {
		return true
	}

	// ruleid: go-mac-compare-constant-time
	if bytes.Equal(signature, got) {
		return true
	}

	// ok: go-mac-compare-constant-time
	if hmac.Equal(got, expectedMAC) {
		return true
	}

	// ok: go-mac-compare-constant-time
	if subtle.ConstantTimeCompare(got, signature) == 1 {
		return true
	}

	// Длину сравнивать можно: она не секрет.
	// ok: go-mac-compare-constant-time
	if len(expectedMAC) != 32 {
		return false
	}

	// ok: go-mac-compare-constant-time
	return bytes.Equal(got, token)
}
