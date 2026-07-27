package domain

import "time"

// Claims are the JWT claims Wardline issues and verifies for an agent
// identity. Subject carries the identity string threaded through
// policy/budget/audit exactly as X-Wardline-Identity does today.
type Claims struct {
	Subject   string
	IssuedAt  time.Time
	ExpiresAt time.Time
	ID        string // jti, unique per issued token
}
