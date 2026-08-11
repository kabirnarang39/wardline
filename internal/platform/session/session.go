// Package session derives a stable session id from an explicit client-
// supplied header, or a TTL-window fallback bucket when no header is
// present. Shared by every feature that needs to bucket per-caller
// activity into a "session" without requiring client cooperation: taint
// tracking (this function's original home), per-job budget, and per-job
// cost budget all key off it today, each with its own configurable
// window (SessionWindowSeconds on each feature's own Config) so any one
// of them works without the others being on.
package session

import (
	"strconv"
	"time"
)

// SessionID derives the session component of a composite key. An explicit
// header value wins when present (precise when the caller stamps one id
// per run); absent one, it falls back to a per-identity sliding TTL
// window bucket, stable within the window and rolling at the boundary —
// so a feature built on this stays drop-in with zero client cooperation.
func SessionID(headerVal, tenant, identity string, now time.Time, windowSeconds int) string {
	if headerVal != "" {
		return headerVal
	}
	if windowSeconds <= 0 {
		windowSeconds = 1
	}
	return identity + "|" + strconv.FormatInt(now.Unix()/int64(windowSeconds), 10)
}
