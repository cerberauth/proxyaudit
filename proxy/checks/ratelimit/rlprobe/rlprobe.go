// Package rlprobe holds the small request helpers the rate-limit checks
// share: a single GET that reports only its status, a bounded burst, and
// the predicate for a throttled response. Bursts are deliberately small so
// the probe measures throttling behaviour without approximating a flood.
package rlprobe

import (
	"context"
	"net/http"

	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// BurstSize is the number of requests a burst sends — enough to cross a
// modest per-IP limit, not enough to be a denial-of-service in itself.
const BurstSize = 20

// Throttled reports whether status is a rate-limit rejection.
func Throttled(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
}

// Get sends one GET to url with the given headers set and returns the
// response status code (0 on a transport error).
func Get(ctx context.Context, sctx *scanctx.ScanContext, url string, headers map[string]string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	// Don't follow redirects to another origin; the status of the proxy's
	// own immediate response is what matters.
	client := &http.Client{
		Transport: sctx.HTTPClient.Transport,
		Timeout:   sctx.HTTPClient.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// Burst sends n sequential GETs to url and returns each status (0 for a
// transport error). It stops early once a throttled status appears, since
// callers only need to know whether and when throttling kicks in.
func Burst(ctx context.Context, sctx *scanctx.ScanContext, url string, n int) ([]int, error) {
	statuses := make([]int, 0, n)
	for range n {
		status, err := Get(ctx, sctx, url, nil)
		if err != nil {
			return statuses, err
		}
		statuses = append(statuses, status)
		if Throttled(status) {
			break
		}
	}
	return statuses, nil
}

// AnyThrottled reports whether any status in the slice is a throttle.
func AnyThrottled(statuses []int) bool {
	for _, s := range statuses {
		if Throttled(s) {
			return true
		}
	}
	return false
}
