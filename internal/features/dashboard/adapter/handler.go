package adapter

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	"github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
	federationusecase "github.com/kabirnarang39/wardline/internal/features/federation/usecase"
	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
)

// AuditSource is the subset of RingBuffer's behavior Handler depends on —
// a narrow interface so tests can supply a fake without importing the
// real usecase package, matching the BudgetChecker pattern in
// proxy/adapter/handler.go. tenantFilter == "" means unfiltered; Handler
// derives it once per request (see tenantFilter method below) and never
// takes it from anything the client sends.
type AuditSource interface {
	Since(afterID int64, limit int, tenantFilter string) []domain.LiveEntry
}

// StatusSource is the subset of StatusProvider's behavior Handler depends
// on.
type StatusSource interface {
	Status() domain.StatusInfo
}

// AnomalySource is the subset of anomaly/usecase.AlertBuffer's behavior
// Handler depends on -- one method, matching AuditSource's pattern.
// Unlike AuditSource it does name the foreign usecase type in its
// signature (usecase.Alert is the ID-plus-Anomaly pair AlertBuffer
// allocates, and there is no dashboard-owned equivalent to return
// instead), so a fake must import that package too. handleAnomalies
// still converts to this package's own domain.AnomalyEntry before
// writing, so the endpoint's wire shape is not tied to that type.
type AnomalySource interface {
	Since(afterID int64, limit int, tenantFilter string) []anomalyusecase.Alert
}

// FederationSource is the subset of federation/usecase.CorrelatedAlertBuffer's
// behavior Handler depends on -- same one-method pattern as AnomalySource.
type FederationSource interface {
	Since(afterID int64, limit int) []federationusecase.CorrelatedAlertEntry
}

// BlockedSource is the subset of anomaly/usecase.BlockChecker's behavior
// Handler depends on.
type BlockedSource interface {
	List(tenantFilter string) []anomalydomain.BlockedEntry
	Unblock(identity, tenantName string) bool
}

// RBACSource is the subset of rbacadapter.StaticAuthorizer's behavior
// Handler depends on -- read-only, matching every other Source
// interface's narrow-slice pattern in this file.
type RBACSource interface {
	Roles() []rbacdomain.Role
	ClusterRoleBindings() []rbacdomain.ClusterRoleBinding
	RoleBindings() []rbacdomain.RoleBinding
}

// BudgetSource is the subset of budgetdomain.Limiter's behavior Handler
// depends on -- read-only, matching every other Source interface's narrow
// pattern in this file.
type BudgetSource interface {
	DefaultLimit() budgetdomain.LimitInfo
	TenantOverrides() []budgetdomain.OverrideInfo
	ToolOverrides() []budgetdomain.OverrideInfo
}

// UnblockAuthorizer decides whether a caller may clear an active
// auto-block, within targetTenant specifically, before its TTL expires --
// mirrors credentialadapter.RevokeAuthorizer's shape and posture exactly,
// including its cross-tenant reasoning (see newRevokeAuthorizer /
// newUnblockAuthorizer in cmd/wardline/main.go): cross-tenant authority
// for this mutation must derive from the caller's own credential:revoke
// grant, never from the read-only dashboard:view permission the rest of
// this file's routes rely on (see the final-review C1 finding this
// corrected). targetTenant == "" means "the caller's own tenant" -- a
// scoped caller unblocking within the only tenant they're allowed to name.
// nil means "not wired" (rbac off); handleUnblock treats that the same as
// blocked == nil (feature not wired at all) and answers 404, matching
// every other "not wired" route in this file rather than silently
// allowing an unauthenticated unblock.
type UnblockAuthorizer interface {
	AllowedFor(r *http.Request, targetTenant string) bool
}

// TenantScopeResolver derives the effective tenant filter for the
// caller of a request: empty string means "no filter" (a global,
// ClusterRoleBinding-scoped caller, or rbac off entirely); a non-empty
// value scopes every view to that tenant only. Wired only when rbac is
// on (see main.go) -- nil means "always unfiltered," preserving today's
// behavior exactly when rbac is off. The tenant filter must NEVER be
// derived from anything the client supplies (a query parameter or
// header) -- only from the RBAC-resolved caller identity -- or a
// tenant-scoped caller could simply edit the request to see another
// tenant's data (IDOR).
type TenantScopeResolver interface {
	TenantFilter(r *http.Request) string
}

// defaultAuditLimit and maxAuditLimit bound the /api/audit endpoint's
// limit query parameter: a missing or invalid value defaults to 100; any
// requested value above 1000 (the ring buffer's own capacity — see
// dashboard/usecase.RingBuffer, wired with capacity 1000 in
// cmd/wardline/main.go) is clamped, since the buffer can never hold more
// than that anyway.
const (
	defaultAuditLimit = 100
	maxAuditLimit     = 1000
)

// Handler serves the dashboard's read-only JSON API and its embedded SPA,
// all read-only by construction — it has no dependency on any policy,
// budget, or proxy domain type, so it cannot influence a proxied request.
type Handler struct {
	audit      AuditSource
	status     StatusSource
	policy     domain.PolicyInfo
	anomalies  AnomalySource
	federation FederationSource
	blocked    BlockedSource
	scope      TenantScopeResolver
	unblock    UnblockAuthorizer
	rbac       RBACSource
	budget     BudgetSource
	mux        *http.ServeMux
}

// NewHandler expects the returned *Handler to be mounted at exactly
// "/dashboard/" — its internal routes ("/dashboard/api/audit", etc.) are
// absolute, not relative, so mounting it anywhere else (or via
// http.StripPrefix) will break routing. anomalies may be nil (the
// anomaly_detection feature is off) -- /dashboard/api/anomalies then
// answers 404, the same "not wired" posture as
// credential/adapter.Handler's nil RevokeAuthorizer. federation may
// likewise be nil (the federation feature is off) -- /dashboard/api/federation/correlated
// then answers 404 the same way. blocked may likewise be nil (the
// anomaly_detection feature is off) -- /dashboard/api/anomalies/blocked
// then answers 404 the same way. scope may likewise be nil (rbac is off)
// -- every view then answers unfiltered, identical to today's behavior;
// see tenantFilter's doc comment. unblock may likewise be nil (rbac is
// off) -- DELETE /dashboard/api/anomalies/blocked/{identity} then answers
// 404 the same way as every other "not wired" route above. rbac may
// likewise be nil (rbac is off) -- GET /dashboard/api/rbac then answers
// 404 the same way. budget may likewise be nil (budget_enforcement is
// off) -- GET /dashboard/api/budget then answers 404 the same way.
func NewHandler(audit AuditSource, status StatusSource, policy domain.PolicyInfo, assets fs.FS, anomalies AnomalySource, federation FederationSource, blocked BlockedSource, scope TenantScopeResolver, unblock UnblockAuthorizer, rbac RBACSource, budget BudgetSource) *Handler {
	h := &Handler{audit: audit, status: status, policy: policy, anomalies: anomalies, federation: federation, blocked: blocked, scope: scope, unblock: unblock, rbac: rbac, budget: budget}

	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard/api/audit", h.handleAudit)
	mux.HandleFunc("/dashboard/api/policy", h.handlePolicy)
	mux.HandleFunc("/dashboard/api/status", h.handleStatus)
	mux.HandleFunc("/dashboard/api/anomalies", h.handleAnomalies)
	mux.HandleFunc("/dashboard/api/federation/correlated", h.handleFederationCorrelated)
	mux.HandleFunc("/dashboard/api/anomalies/blocked", h.handleBlocked)
	mux.HandleFunc("/dashboard/api/anomalies/blocked/", h.handleUnblock)
	mux.HandleFunc("/dashboard/api/rbac", h.handleRBAC)
	mux.HandleFunc("/dashboard/api/budget", h.handleBudget)
	mux.Handle("/dashboard/", http.StripPrefix("/dashboard", spaHandler(assets)))
	h.mux = mux

	return h
}

// ServeHTTP sets defense-in-depth headers on every response — both the
// JSON API and the static/SPA routes — before delegating to the
// internal mux, so the protection applies consistently regardless of
// which route matches.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	h.mux.ServeHTTP(w, r)
}

// methodNotAllowed rejects any method other than GET, enforcing the
// "read-only by construction" contract at the HTTP surface, not just in
// the handlers' own logic. Returns true if the request was rejected (the
// caller must return immediately without writing anything else).
func methodNotAllowed(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	return false
}

// pagination parses the after/limit query params shared by every
// buffer-backed endpoint. A missing or unparsable value is not an error:
// both endpoints treat bad input as "start from the beginning, default
// page size" rather than 400, so a hand-typed URL degrades instead of
// failing.
func pagination(r *http.Request) (after int64, limit int) {
	after, err := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if err != nil {
		after = 0
	}
	limit, err = strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || limit <= 0 {
		limit = defaultAuditLimit
	}
	if limit > maxAuditLimit {
		limit = maxAuditLimit
	}
	return after, limit
}

// tenantFilter derives the effective tenant filter for r via h.scope --
// "" (unfiltered) when h.scope is nil (rbac off, preserving today's
// behavior exactly) or when the resolved caller holds a global grant.
// This is the ONLY place a tenant filter may originate: it is derived
// from the RBAC-resolved caller identity via h.scope, never from
// anything r itself carries (a query parameter or header) -- doing the
// latter would let a tenant-scoped caller simply edit the request to
// see another tenant's data.
func (h *Handler) tenantFilter(r *http.Request) string {
	if h.scope == nil {
		return ""
	}
	return h.scope.TenantFilter(r)
}

func (h *Handler) handleAudit(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	after, limit := pagination(r)

	entries := h.audit.Since(after, limit, h.tenantFilter(r))
	if entries == nil {
		entries = []domain.LiveEntry{}
	}
	writeJSON(w, entries)
}

func (h *Handler) handleAnomalies(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	if h.anomalies == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	after, limit := pagination(r)

	alerts := h.anomalies.Since(after, limit, h.tenantFilter(r))
	entries := make([]domain.AnomalyEntry, 0, len(alerts))
	for _, a := range alerts {
		entries = append(entries, domain.AnomalyEntry{
			ID:        a.ID,
			Timestamp: a.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"),
			Identity:  a.Identity,
			Tenant:    a.Tenant,
			Kind:      string(a.Kind),
			Detail:    a.Detail,
			Tool:      a.Entry.Tool,
		})
	}
	writeJSON(w, entries)
}

func (h *Handler) handleFederationCorrelated(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	if h.federation == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	after, limit := pagination(r)

	alerts := h.federation.Since(after, limit)
	entries := make([]domain.CorrelatedAlertEntry, 0, len(alerts))
	for _, a := range alerts {
		entries = append(entries, domain.CorrelatedAlertEntry{
			ID:          a.ID,
			Fingerprint: a.Fingerprint,
			Kind:        string(a.Kind),
			InstanceIDs: a.InstanceIDs,
			FirstSeen:   a.FirstSeen.UTC().Format("2006-01-02T15:04:05Z07:00"),
			LastSeen:    a.LastSeen.UTC().Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	writeJSON(w, entries)
}

func (h *Handler) handleBlocked(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	if h.blocked == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, h.blocked.List(h.tenantFilter(r)))
}

// handleUnblock serves DELETE /dashboard/api/anomalies/blocked/{identity},
// clearing an active auto-block before its TTL expires. This is a
// mutation with real security weight (undoing an automated enforcement
// decision), so it is gated by UnblockAuthorizer (requiring
// credential:revoke when rbac is on) separately from the read-only
// dashboard:view permission the rest of this file's routes rely on.
func (h *Handler) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.blocked == nil || h.unblock == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	identity := strings.TrimPrefix(r.URL.Path, "/dashboard/api/anomalies/blocked/")
	if identity == "" {
		http.Error(w, "identity is required", http.StatusBadRequest)
		return
	}
	// Resolved design (locked by the coordinator, not a guess): h.tenantFilter(r)
	// returns "" in exactly two cases -- rbac off, or the caller holds a
	// global (IsGlobal) dashboard:view grant -- both of which already carry
	// read-scope over every tenant, same as every other route in this
	// file. A scoped caller (non-empty tenantFilter) unblocks only within
	// their own tenant, and that value is NEVER overridable by anything
	// the client supplies -- identical IDOR posture to every other route
	// in this file. A caller with "" scope must name which tenant's block
	// to clear via an explicit ?tenant= query parameter -- but naming a
	// tenant is not the same as having authority over it: h.unblock.AllowedFor
	// below makes THAT decision from credential:revoke, the permission this
	// mutation actually exercises, never from dashboard:view (see the
	// final-review C1 finding: reusing dashboard:view's global-ness here
	// was a privilege-escalation bug). Missing ?tenant= for such a caller
	// is a 400, not a silent no-op -- BlockChecker.Unblock's
	// tenantName=="" is a real, distinct key (unlike domain.Revoker's
	// wildcard convention in Task 1), so an accidental empty string must
	// never reach it.
	targetTenant := h.tenantFilter(r)
	if targetTenant == "" {
		targetTenant = r.URL.Query().Get("tenant")
		if targetTenant == "" {
			http.Error(w, "tenant query parameter is required for a caller with cross-tenant authority", http.StatusBadRequest)
			return
		}
	}
	if !h.unblock.AllowedFor(r, targetTenant) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if !h.blocked.Unblock(identity, targetTenant) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRBAC serves GET /dashboard/api/rbac -- a read-only snapshot of
// every role and binding h.rbac (the real *rbacadapter.StaticAuthorizer,
// wired in main.go) currently holds. Gated only by the outer
// dashboard:view RequirePermission wrap around the whole /dashboard/
// tree in main.go -- never config:edit, since this is a read, not a
// mutation, and no edit capability exists yet.
func (h *Handler) handleRBAC(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	if h.rbac == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	clusterBindings := h.rbac.ClusterRoleBindings()
	roleBindings := h.rbac.RoleBindings()
	bindingCounts := map[string]int{}
	bindings := make([]domain.BindingEntry, 0, len(clusterBindings)+len(roleBindings))
	for _, b := range clusterBindings {
		bindingCounts[b.RoleName]++
		bindings = append(bindings, domain.BindingEntry{Subject: b.Subject, Role: b.RoleName})
	}
	for _, b := range roleBindings {
		bindingCounts[b.RoleName]++
		bindings = append(bindings, domain.BindingEntry{Subject: b.Subject, Role: b.RoleName, Tenant: b.Tenant})
	}
	roles := make([]domain.RoleEntry, 0, len(h.rbac.Roles()))
	for _, role := range h.rbac.Roles() {
		perms := make([]string, len(role.Permissions))
		for i, p := range role.Permissions {
			perms[i] = string(p)
		}
		roles = append(roles, domain.RoleEntry{Name: role.Name, Permissions: perms, BindingCount: bindingCounts[role.Name]})
	}
	writeJSON(w, struct {
		Roles    []domain.RoleEntry    `json:"roles"`
		Bindings []domain.BindingEntry `json:"bindings"`
	}{roles, bindings})
}

// handleBudget serves GET /dashboard/api/budget -- a read-only snapshot of
// the global default rate limit and every tenant/tool override h.budget
// (the real budgetdomain.Limiter, wired in main.go) currently holds.
// Gated only by the outer dashboard:view RequirePermission wrap around the
// whole /dashboard/ tree in main.go -- never config:edit, since this is a
// read, not a mutation, and no edit capability exists yet.
func (h *Handler) handleBudget(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	if h.budget == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	def := h.budget.DefaultLimit()
	overrides := make([]domain.BudgetOverrideEntry, 0)
	for _, o := range h.budget.TenantOverrides() {
		overrides = append(overrides, domain.BudgetOverrideEntry{Scope: o.Scope, Name: o.Name, RequestsPerWindow: o.RequestsPerWindow, WindowSeconds: int(o.Window.Seconds())})
	}
	for _, o := range h.budget.ToolOverrides() {
		overrides = append(overrides, domain.BudgetOverrideEntry{Scope: o.Scope, Name: o.Name, RequestsPerWindow: o.RequestsPerWindow, WindowSeconds: int(o.Window.Seconds())})
	}
	writeJSON(w, struct {
		Default   domain.BudgetDefaultEntry    `json:"default"`
		Overrides []domain.BudgetOverrideEntry `json:"overrides"`
	}{domain.BudgetDefaultEntry{RequestsPerWindow: def.RequestsPerWindow, WindowSeconds: int(def.Window.Seconds())}, overrides})
}

func (h *Handler) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	writeJSON(w, h.policy)
}

// statusResponse wraps domain.StatusInfo with one per-request field
// (CallerTenant) StatusInfo itself cannot carry -- StatusInfo is a
// process-wide value cached by StatusProvider, computed once, identical
// for every caller; CallerTenant is derived fresh per request from
// h.tenantFilter, the same RBAC-resolved scoping every other route in
// this file already uses.
type statusResponse struct {
	domain.StatusInfo
	CallerTenant string
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	writeJSON(w, statusResponse{StatusInfo: h.status.Status(), CallerTenant: h.tenantFilter(r)})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// spaHandler serves static assets from assets, falling back to
// index.html for any path assets doesn't have — the SPA's own
// client-side view state (Activity/Policy/Status) isn't real server
// routes, so any unrecognized sub-path under /dashboard/ is a client
// route, not a 404.
//
// index.html's bytes are read once at construction and written directly
// on the root/fallback path rather than delegated to http.FileServer:
// FileServer redirects any request whose path is exactly ".../index.html"
// to its containing directory, so handing it a re-pointed "/index.html"
// path (the naive fallback approach) produces a redirect loop instead of
// the page.
func spaHandler(assets fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(assets))
	index, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		panic(err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if f, err := assets.Open(p); err == nil {
				_ = f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(index)
	})
}
