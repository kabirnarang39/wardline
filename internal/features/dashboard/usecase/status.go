package usecase

import (
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
		upstream:  upstream,
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
