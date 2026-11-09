package internaltargetaccess

import (
	"net/http"
	"strconv"

	"github.com/cerberauth/proxyaudit/proxy/checks/ssrf/ssrfprobe"
)

// gatewayStatuses are the responses a proxy returns when it tried to
// forward but the upstream connection failed.
var gatewayStatuses = map[int]bool{
	http.StatusBadGateway:         true, // 502
	http.StatusServiceUnavailable: true, // 503
	http.StatusGatewayTimeout:     true, // 504
}

// rejectionStatuses are the responses a proxy returns when it refuses a
// forward target outright rather than attempting it.
var rejectionStatuses = map[int]bool{
	http.StatusBadRequest: true, // 400
	http.StatusForbidden:  true, // 403
	http.StatusNotFound:   true, // 404
}

// distinctFailure reports whether r is a recognizable "can't / won't
// forward" outcome — a transport error or a gateway/rejection status —
// as opposed to the proxy quietly serving its backend.
func distinctFailure(r *ssrfprobe.Response) bool {
	if r == nil || r.Err != nil {
		return true
	}
	return gatewayStatuses[r.StatusCode] || rejectionStatuses[r.StatusCode]
}

// sameOutcome reports whether two responses look like the same handling
// (both transport errors, or the same status with the same body
// signature), used to tell a reached internal host apart from the
// can't-forward baseline.
func sameOutcome(a, b *ssrfprobe.Response) bool {
	if a.Err != nil || b.Err != nil {
		return a.Err != nil && b.Err != nil
	}
	return a.StatusCode == b.StatusCode && ssrfprobe.BodySignature(a.Body) == ssrfprobe.BodySignature(b.Body)
}

func status(r *ssrfprobe.Response) string {
	if r.Err != nil {
		return "connection error"
	}
	return strconv.Itoa(r.StatusCode) + " " + http.StatusText(r.StatusCode)
}

func baselineDesc(r *ssrfprobe.Response) string {
	if r.Err != nil {
		return "connection error"
	}
	return status(r)
}
