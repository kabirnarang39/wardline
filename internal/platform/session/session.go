// Package session derives a stable session id from an explicit client-
// supplied header, or a TTL-window fallback bucket when no header is
// present. Shared by every feature that needs to bucket per-caller
// activity into a "session" without requiring client cooperation: taint
// tracking (this function's original home) and per-job budget both key
// off it today.
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
