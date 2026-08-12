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

// GroupProvisioner is the subset of usecase.ProvisioningService's
// Group-related behavior Handler depends on -- same narrow-interface
// pattern as UserProvisioner. Members are always User IDs (SCIM's own
// Group member-reference shape), never UserNames -- ProvisioningService
// resolves ID to UserName itself when it syncs to BindingStore.
type GroupProvisioner interface {
	CreateGroup(displayName string, memberUserIDs []string) (domain.Group, error)
	GetGroup(id string) (domain.Group, error)
	ListGroups() []domain.Group
	DeleteGroup(id string) error
	PatchGroupMembers(id string, addUserIDs, removeUserIDs []string) error
}

// Handler serves the SCIM 2.0 Users HTTP surface: POST/GET
// /scim/v2/Users, GET/DELETE/PATCH /scim/v2/Users/{id}. Every request
// must carry "Authorization: Bearer <token>" matching the single shared
// bearerToken this Handler was constructed with, compared in constant
// time to avoid a timing side-channel on the token value. It also serves
// POST/GET /scim/v2/Groups and GET/DELETE/PATCH /scim/v2/Groups/{id}.
// groups stays nil-able -- a caller that only needs Users provisioning
// (no RBAC-via-SCIM-groups) can pass nil and the Groups routes answer
// 501 rather than panicking.
type Handler struct {
	users       UserProvisioner
	groups      GroupProvisioner
	bearerToken string
	logger      *slog.Logger
	mux         *http.ServeMux
}

// NewHandler wires a Handler. bearerToken must be non-empty -- an empty
// configured token would let an empty "Authorization: Bearer " header
// pass the constant-time comparison, so this panics rather than silently
// accepting an unauthenticated deployment (same fail-fast-at-construction
// posture as credential/adapter.LoadBootstrapper's "must have a secret"
// check, just via panic since Handler constructors in this codebase
// don't return an error).
func NewHandler(users UserProvisioner, groups GroupProvisioner, bearerToken string, logger *slog.Logger) *Handler {
	if bearerToken == "" {
		panic("scim: bearerToken must not be empty")
	}
	h := &Handler{users: users, groups: groups, bearerToken: bearerToken, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("/scim/v2/Users", h.handleUsersCollection)
	mux.HandleFunc("/scim/v2/Users/", h.handleUserItem)
	mux.HandleFunc("/scim/v2/Groups", h.handleGroupsCollection)
	mux.HandleFunc("/scim/v2/Groups/", h.handleGroupItem)
	mux.HandleFunc("/scim/v2/Bulk", h.handleBulk)
	mux.HandleFunc("/scim/v2/ServiceProviderConfig", h.handleServiceProviderConfig)
	mux.HandleFunc("/scim/v2/ResourceTypes", h.handleResourceTypes)
	mux.HandleFunc("/scim/v2/ResourceTypes/", h.handleResourceTypeItem)
	mux.HandleFunc("/scim/v2/Schemas", h.handleSchemas)
	mux.HandleFunc("/scim/v2/Schemas/", h.handleSchemaItem)
	h.mux = mux
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.authenticated(r) {
		// remote_addr only -- never log the presented token or the
		// requested path's identifying detail, which would leak an
		// enumeration signal to logs for an unauthenticated caller.
		h.logger.Warn("scim request authentication failed", "remote_addr", r.RemoteAddr)
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

// (Filter parsing itself -- tokenizer, recursive-descent parser, AST
// evaluator -- lives in filter.go: parseSCIMFilter/filterNode.)

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
		// RFC 7644 §3.3: a successful POST create response must include
		// the new resource's Location. Set before writeJSON, which
		// calls WriteHeader and locks in the header set -- Bulk's own
		// dispatchBulkOperation (bulk.go) reads exactly this header to
		// populate its per-operation "location" field, so a create
		// without it silently loses Location on both the direct
		// endpoint and every Bulk-batched create.
		w.Header().Set("Location", "/scim/v2/Users/"+u.ID)
		writeJSON(w, http.StatusCreated, userResource{ID: u.ID, UserName: u.UserName, Active: u.Active})
	case http.MethodGet:
		filter, filtered, err := parseSCIMFilter(r.URL.Query().Get("filter"))
		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, err.Error())
			return
		}
		users := h.users.ListUsers()
		out := make([]userResource, 0, len(users))
		for _, u := range users {
			if filtered && !filter.evaluate(map[string]any{"userName": u.UserName, "active": u.Active, "id": u.ID}) {
				continue
			}
			out = append(out, userResource{ID: u.ID, UserName: u.UserName, Active: u.Active})
		}
		writeJSON(w, http.StatusOK, out)
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
		writeJSON(w, http.StatusOK, userResource{ID: u.ID, UserName: u.UserName, Active: u.Active})
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
		// RFC 7644 §3.5.2 requires at least one operation. A body missing the
		// Operations wrapper (e.g. a flat {"op":...,"path":"active"}) decodes to
		// an empty slice here; without this guard the loop below would no-op yet
		// still return 204, silently reporting a deactivation that never happened
		// -- a real offboarding footgun.
		if len(req.Operations) == 0 {
			writeSCIMError(w, http.StatusBadRequest, "PATCH body must contain a non-empty Operations array")
			return
		}
		applied := false
		for _, op := range req.Operations {
			if strings.EqualFold(op.Op, "replace") && op.Path == "active" {
				if err := h.users.PatchUserActive(id, op.Value); err != nil {
					writeSCIMError(w, http.StatusNotFound, "not found")
					return
				}
				applied = true
			}
		}
		if !applied {
			writeSCIMError(w, http.StatusBadRequest, "no supported operation in PATCH; only replace of \"active\" is supported")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

type groupMemberResource struct {
	Value string `json:"value"`
}

type groupResource struct {
	ID          string                `json:"id,omitempty"`
	DisplayName string                `json:"displayName"`
	Members     []groupMemberResource `json:"members,omitempty"`
}

func toGroupResource(g domain.Group) groupResource {
	members := make([]groupMemberResource, 0, len(g.Members))
	for _, id := range g.Members {
		members = append(members, groupMemberResource{Value: id})
	}
	return groupResource{ID: g.ID, DisplayName: g.DisplayName, Members: members}
}

func (h *Handler) handleGroupsCollection(w http.ResponseWriter, r *http.Request) {
	if h.groups == nil {
		writeSCIMError(w, http.StatusNotImplemented, "groups not configured")
		return
	}
	switch r.Method {
	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, maxSCIMBodyBytes)
		var req groupResource
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.DisplayName == "" {
			writeSCIMError(w, http.StatusBadRequest, "displayName is required")
			return
		}
		memberIDs := make([]string, 0, len(req.Members))
		for _, m := range req.Members {
			memberIDs = append(memberIDs, m.Value)
		}
		g, err := h.groups.CreateGroup(req.DisplayName, memberIDs)
		if err != nil {
			writeSCIMError(w, http.StatusConflict, "group already exists")
			return
		}
		// See the matching comment in handleUsersCollection's POST path.
		w.Header().Set("Location", "/scim/v2/Groups/"+g.ID)
		writeJSON(w, http.StatusCreated, toGroupResource(g))
	case http.MethodGet:
		filter, filtered, err := parseSCIMFilter(r.URL.Query().Get("filter"))
		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, err.Error())
			return
		}
		groups := h.groups.ListGroups()
		out := make([]groupResource, 0, len(groups))
		for _, g := range groups {
			if filtered && !filter.evaluate(map[string]any{"displayName": g.DisplayName, "id": g.ID}) {
				continue
			}
			out = append(out, toGroupResource(g))
		}
		writeJSON(w, http.StatusOK, out)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleGroupItem(w http.ResponseWriter, r *http.Request) {
	if h.groups == nil {
		writeSCIMError(w, http.StatusNotImplemented, "groups not configured")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Groups/")
	if id == "" {
		writeSCIMError(w, http.StatusNotFound, "not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		g, err := h.groups.GetGroup(id)
		if err != nil {
			writeSCIMError(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, toGroupResource(g))
	case http.MethodDelete:
		if err := h.groups.DeleteGroup(id); err != nil {
			writeSCIMError(w, http.StatusNotFound, "not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPatch:
		r.Body = http.MaxBytesReader(w, r.Body, maxSCIMBodyBytes)
		var req struct {
			Operations []struct {
				Op    string                `json:"op"`
				Path  string                `json:"path"`
				Value []groupMemberResource `json:"value"`
			} `json:"Operations"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalid PATCH body")
			return
		}
		var add, remove []string
		for _, op := range req.Operations {
			if op.Path != "members" {
				continue
			}
			ids := make([]string, 0, len(op.Value))
			for _, v := range op.Value {
				ids = append(ids, v.Value)
			}
			switch {
			case strings.EqualFold(op.Op, "add"):
				add = append(add, ids...)
			case strings.EqualFold(op.Op, "remove"):
				remove = append(remove, ids...)
			}
		}
		if err := h.groups.PatchGroupMembers(id, add, remove); err != nil {
			writeSCIMError(w, http.StatusNotFound, "not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// writeJSON is the only path that writes a success response's status
// line -- Content-Type must be set before WriteHeader (Go freezes
// headers at WriteHeader/first-Write time), so status and body are
// always written together here rather than a caller calling
// WriteHeader itself first.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
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
