// Package domain holds the approval-workflow entities and store interface.
package domain

import "time"

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDenied   Status = "denied"
)

// Request is one write held for operator approval.
type Request struct {
	ID        string
	Identity  string
	Tenant    string
	Tool      string
	Method    string
	Params    map[string]string // redacted mutating params
	Session   string
	CreatedAt time.Time
	Status    Status
	DecidedAt time.Time
	DecidedBy string
}

// Grant is a single-use, TTL-bounded allowance minted on approval. It
// authorizes exactly one subsequent call matching its key, then is consumed.
type Grant struct {
	Key       string
	ExpiresAt time.Time
}

type Store interface {
	CreateRequest(Request) error
	GetRequest(id string) (Request, bool)
	ListPending(tenant string) []Request // tenant "" = all tenants
	DecideRequest(id string, status Status, decidedBy string, now time.Time) (Request, error)
	PutGrant(Grant)
	// ConsumeGrant atomically returns and removes an unexpired grant for key.
	ConsumeGrant(key string, now time.Time) (Grant, bool)
}

type Clock func() time.Time
