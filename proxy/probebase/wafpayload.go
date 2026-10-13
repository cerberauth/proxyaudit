package probebase

import (
	"fmt"
	"net/url"
	"strings"
	"unicode"
)

// WAFParam is the query/form/JSON field name a WAF probe carries its value
// in when the target URL has no query parameter of its own; see
// WAFParamFor.
const WAFParam = "proxyaudit"

// WAFParamFor returns the field name to carry a payload in: the first
// parameter already in baseURL's query string — the application's own, so
// a filter scoped to a particular endpoint/parameter is actually exercised
// — or WAFParam if there is none.
func WAFParamFor(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.RawQuery == "" {
		return WAFParam
	}
	name, _, _ := strings.Cut(strings.SplitN(u.RawQuery, "&", 2)[0], "=")
	if name, err = url.QueryUnescape(name); err != nil || name == "" {
		return WAFParam
	}
	return name
}

// WAFBenignValue is the innocuous control value sent in place of a payload,
// so a payload's response can be compared against what the same request
// shape returns when nothing in it looks malicious.
const WAFBenignValue = "proxyaudit-waf-probe"

// Payload categories of the baseline set.
const (
	WAFCategorySQLi          = "sqli"
	WAFCategoryXSS           = "xss"
	WAFCategoryPathTraversal = "path_traversal"
)

// WAFPayload is a single inert attack string any WAF/filtering layer worth
// the name is expected to reject on sight.
type WAFPayload struct {
	Category string
	Value    string
}

// WAFPayloads is the baseline set (SQLi, XSS, path traversal): the most
// textbook strings of each class, matched by every managed rule set (e.g.
// OWASP CRS) and by even a naive signature filter, deliberately read-only
// so a backend that does receive one has nothing to execute.
var WAFPayloads = []WAFPayload{
	{WAFCategorySQLi, "' OR 1=1--"},
	{WAFCategorySQLi, "1 UNION SELECT NULL,NULL,NULL--"},
	{WAFCategoryXSS, "<script>alert(1)</script>"},
	{WAFCategoryPathTraversal, "../../../../etc/passwd"},
}

// WAFCategoryLabel is the human-readable name of a WAFPayload.Category.
func WAFCategoryLabel(category string) string {
	switch category {
	case WAFCategorySQLi:
		return "SQL injection"
	case WAFCategoryXSS:
		return "Cross-site scripting"
	case WAFCategoryPathTraversal:
		return "Path traversal"
	}
	return category
}

// WAFVariant is a re-encoding of a payload that decodes (or normalizes) back
// to the same string on a backend more permissive than the filter in front
// of it.
type WAFVariant struct {
	Technique string
	RawQuery  string // ready to send as-is, including the "<param>=" prefix
}

// EncodingVariants returns the encoding-based bypass attempts for value in
// the query parameter param:
// case variation, double URL-encoding, and Unicode (fullwidth) forms that
// NFKC normalization folds back to ASCII. A technique that would leave the
// query identical to the plain payload is omitted.
func EncodingVariants(param, value string) []WAFVariant {
	plain := QueryValue(value)
	candidates := []WAFVariant{
		{"case variation", QueryValue(alternateCase(value))},
		{"double URL-encoding", percentEncode(percentEncode(value, isAlnum), isAlnum)},
		{"Unicode fullwidth forms", QueryValue(fullwidth(value))},
	}

	var variants []WAFVariant
	for _, v := range candidates {
		if v.RawQuery == plain {
			continue
		}
		variants = append(variants, WAFVariant{Technique: v.Technique, RawQuery: param + "=" + v.RawQuery})
	}
	return variants
}

// QueryValue percent-encodes value for a query string, leaving only
// unreserved characters (and "/") as-is.
func QueryValue(value string) string {
	return percentEncode(value, func(c byte) bool { return isAlnum(c) || strings.IndexByte("-._~/", c) >= 0 })
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func percentEncode(s string, keep func(byte) bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if keep(s[i]) {
			b.WriteByte(s[i])
		} else {
			fmt.Fprintf(&b, "%%%02X", s[i])
		}
	}
	return b.String()
}

// alternateCase lowercases and uppercases successive letters ("sElEcT").
func alternateCase(s string) string {
	var b strings.Builder
	upper := false
	for _, r := range s {
		switch {
		case !unicode.IsLetter(r):
			b.WriteRune(r)
		case upper:
			b.WriteRune(unicode.ToUpper(r))
			upper = false
		default:
			b.WriteRune(unicode.ToLower(r))
			upper = true
		}
	}
	return b.String()
}

// fullwidth maps printable ASCII (U+0021..U+007E) to its Unicode fullwidth
// counterpart (U+FF01..U+FF5E).
func fullwidth(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 0x21 && r <= 0x7E {
			return r + 0xFEE0
		}
		return r
	}, s)
}
