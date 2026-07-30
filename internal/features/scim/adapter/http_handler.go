package adapter

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/kabirnarang39/wardline/internal/features/scim/domain"
)

// maxSCIMBodyBytes caps how much of a SCIM request body we'll read
// before decoding -- a User resource this cycle tracks only userName and
// active, so 64 KiB is generous headroom, not a real limit in practice
// (same rationale as credential/adapter's maxTokenRequestBodyBytes).
const maxSCIMBodyBytes = 64 << 10

// UserProvisioner is the subset of usecase.ProvisioningService's
// User-related behavior Handler depends on -- a narrow interface so
// tests can supply a fake without importing the real usecase package,
// same pattern as rbac/adapter's Checker.
type UserProvisioner interface {
	CreateUser(userName string, active bool) (domain.User, error)
	GetUser(id string) (domain.User, error)
	ListUsers() []domain.User
	DeleteUser(id string) error
	PatchUserActive(id string, active bool) error
}

// GroupProvisioner is the subset of Group-related behavior wired in
// Task 13 -- declared here (nil-able) so this task's Handler compiles
// and mounts standalone; Task 13 fills it in and wires /scim/v2/Groups.
type GroupProvisioner interface {
	CreateGroup(displayName string, memberUserNames []string) (domain.Group, error)
	GetGroup(id string) (domain.Group, error)
	ListGroups() []domain.Group
	DeleteGroup(id string) error
	PatchGroupMembers(id string, add, remove []string) error
}

// Handler serves the SCIM 2.0 Users HTTP surface: POST/GET
// /scim/v2/Users, GET/DELETE/PATCH /scim/v2/Users/{id}. Every request
// must carry "Authorization: Bearer <token>" matching the single shared
// bearerToken this Handler was constructed with, compared in constant
// time to avoid a timing side-channel on the token value. groups is
// accepted (nil-able) so this task's Handler compiles standalone ahead
// of Task 13's /scim/v2/Groups wiring.
type Handler struct {
	users       UserProvisioner
	groups      GroupProvisioner
	bearerToken string
	mux         *http.ServeMux
}

func NewHandler(users UserProvisioner, groups GroupProvisioner, bearerToken string) *Handler {
	h := &Handler{users: users, groups: groups, bearerToken: bearerToken}
	mux := http.NewServeMux()
	mux.HandleFunc("/scim/v2/Users", h.handleUsersCollection)
	mux.HandleFunc("/scim/v2/Users/", h.handleUserItem)
	h.mux = mux
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.authenticated(r) {
		// remote_addr only -- never log the presented token or the
		// requested path's identifying detail, which would leak an
		// enumeration signal to logs for an unauthenticated caller.
		slog.Warn("scim request authentication failed", "remote_addr", r.RemoteAddr)
		writeSCIMError(w, http.StatusUnauthorized, "invalid bearer token")
		return
	}
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) authenticated(r *http.Request) bool {
	const prefix = "Bearer "
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	token := strings.TrimPrefix(header, prefix)
	// Constant-time comparison -- a bearer token is a shared secret, and
	// a plain == would let response timing narrow it down byte by byte.
	return subtle.ConstantTimeCompare([]byte(token), []byte(h.bearerToken)) == 1
}

type userResource struct {
	ID       string `json:"id,omitempty"`
	UserName string `json:"userName"`
	Active   bool   `json:"active"`
}

func (h *Handler) handleUsersCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxSCIMBodyBytes)
		var req userResource
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserName == "" {
			writeSCIMError(w, http.StatusBadRequest, "userName is required")
			return
		}
		u, err := h.users.CreateUser(req.UserName, req.Active)
		if err != nil {
			writeSCIMError(w, http.StatusConflict, "user already exists")
			return
		}
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, userResource{ID: u.ID, UserName: u.UserName, Active: u.Active})
	case http.MethodGet:
		users := h.users.ListUsers()
		out := make([]userResource, 0, len(users))
		for _, u := range users {
			out = append(out, userResource{ID: u.ID, UserName: u.UserName, Active: u.Active})
		}
		writeJSON(w, out)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleUserItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Users/")
	if id == "" {
		writeSCIMError(w, http.StatusNotFound, "not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		u, err := h.users.GetUser(id)
		if err != nil {
			writeSCIMError(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, userResource{ID: u.ID, UserName: u.UserName, Active: u.Active})
	case http.MethodDelete:
		if err := h.users.DeleteUser(id); err != nil {
			writeSCIMError(w, http.StatusNotFound, "not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPatch:
		r.Body = http.MaxBytesReader(w, r.Body, maxSCIMBodyBytes)
		var req struct {
			Operations []struct {
				Op    string `json:"op"`
				Path  string `json:"path"`
				Value bool   `json:"value"`
			} `json:"Operations"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalid PATCH body")
			return
		}
		for _, op := range req.Operations {
			if strings.EqualFold(op.Op, "replace") && op.Path == "active" {
				if err := h.users.PatchUserActive(id, op.Value); err != nil {
					writeSCIMError(w, http.StatusNotFound, "not found")
					return
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeSCIMError writes an RFC 7644 §3.12-shaped error body.
func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"detail":  detail,
		"status":  status,
	})
}
