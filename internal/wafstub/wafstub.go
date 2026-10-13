// Package wafstub is a test-only stand-in for a thorough WAF: it wraps an
// http.Handler and rejects, with 403, any request whose query string or
// body — decompressed, repeatedly URL-decoded, and Unicode-folded —
// carries a SQL injection, XSS, or path traversal signature.
package wafstub

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/url"
	"strings"
)

var signatures = []string{"' or 1=1", "union select", "<script", "onerror=", "../", "..\\"}

// Wrap returns next behind the stub WAF.
func Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))

		if r.Header.Get("Content-Encoding") == "gzip" {
			if zr, err := gzip.NewReader(bytes.NewReader(body)); err == nil {
				body, _ = io.ReadAll(zr)
			}
		}

		if Malicious(r.URL.RawQuery) || Malicious(string(body)) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Malicious reports whether s carries a signature once URL-decoded (up to
// three layers deep) and Unicode-folded (fullwidth forms to ASCII).
func Malicious(s string) bool {
	for range 3 {
		folded := strings.ToLower(Fold(s))
		for _, sig := range signatures {
			if strings.Contains(folded, sig) {
				return true
			}
		}
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	return false
}

// Fold maps fullwidth forms (U+FF01..U+FF5E) to their ASCII counterparts.
func Fold(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 0xFF01 && r <= 0xFF5E {
			return r - 0xFEE0
		}
		return r
	}, s)
}
