package usecase

import (
	"net/url"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
)

// StatusProvider assembles a point-in-time StatusInfo snapshot. now is
// injected (defaults to time.Now in production wiring) so tests don't
// need a real clock.
type StatusProvider struct {
	version   string
	listen    string
	upstream  string
	features  map[string]bool
	startedAt time.Time
	now       func() time.Time
}

func NewStatusProvider(version, listen, upstream string, features map[string]bool, startedAt time.Time, now func() time.Time) *StatusProvider {
	return &StatusProvider{
		version:   version,
		listen:    listen,
		upstream:  redactUserinfo(upstream),
		features:  features,
		startedAt: startedAt,
		now:       now,
	}
}

func (p *StatusProvider) Status() domain.StatusInfo {
	return domain.StatusInfo{
		Version:       p.version,
		UptimeSeconds: int64(p.now().Sub(p.startedAt).Seconds()),
		Listen:        p.listen,
		Upstream:      p.upstream,
		Features:      p.features,
	}
}

// redactUserinfo strips any embedded userinfo (e.g. "user:pass@") from
// raw, an upstream URL string, before it's exposed via
// /dashboard/api/status — an operator's upstream URL might carry
// credentials that shouldn't be readable by anyone who can reach the
// dashboard. If raw doesn't parse as a URL, it's returned unchanged:
// cfg.Upstream is already validated elsewhere in main.go, so a parse
// failure here should be effectively unreachable, and status display
// shouldn't fail startup over it either way.
func redactUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}
