package adapter

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	anomalydomain "github.com/kabirnarang39/wardline/internal/features/anomaly/domain"
	anomalyusecase "github.com/kabirnarang39/wardline/internal/features/anomaly/usecase"
	approvaldomain "github.com/kabirnarang39/wardline/internal/features/approval/domain"
	budgetdomain "github.com/kabirnarang39/wardline/internal/features/budget/domain"
	compliancedomain "github.com/kabirnarang39/wardline/internal/features/compliance/domain"
	costbudgetdomain "github.com/kabirnarang39/wardline/internal/features/costbudget/domain"
	"github.com/kabirnarang39/wardline/internal/features/dashboard/domain"
	federationusecase "github.com/kabirnarang39/wardline/internal/features/federation/usecase"
	jobbudgetdomain "github.com/kabirnarang39/wardline/internal/features/jobbudget/domain"
	policydomain "github.com/kabirnarang39/wardline/internal/features/policy/domain"
	rbacdomain "github.com/kabirnarang39/wardline/internal/features/rbac/domain"
	"github.com/kabirnarang39/wardline/internal/platform/reload"
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

// ApprovalSource is the subset of approval/usecase.Manager's behavior
// Handler depends on -- the pending queue read plus the two decision
// mutations. ListPending("") returns every tenant's pending requests
// (the dashboard is operator-global). Approve/Deny return an error for an
// unknown or already-decided id, which handleApprovalDecision maps to 404.
type ApprovalSource interface {
	ListPending(tenant string) []approvaldomain.Request
	Approve(id, by string) error
	Deny(id, by string) error
}

// JobBudgetSource is the subset of jobbudget's optional Lister capability
// Handler depends on -- a read-only view of job keys nearing/at their
// per-job budget ceiling. jobbudget/domain.Meter (InMemoryMeter/
// PostgresMeter) deliberately does NOT expose enumeration itself --
// widening Meter would force every Meter implementation to support it,
// which the core Checker never needs -- so main.go wires the concrete
// meter through this interface directly (a type assertion onto
// jobbudgetdomain.Lister) rather than through the narrow domain.Meter
// interface. Entries carry the opaque job key and its running count only:
// the key's tenant/identity/session are NOT decomposed for display (the
// length-prefixed key format is one-way by design), a known, documented
// limitation (see jobbudgetdomain.Lister's own doc comment).
type JobBudgetSource interface {
	ListNearCeiling(limit int) []jobbudgetdomain.Entry
}

// CostBudgetSource is the subset of costbudget's optional Lister capability
// Handler depends on -- a read-only view of job keys nearing/at their
// per-job cost/token ceiling. Mirrors JobBudgetSource exactly: main.go
// wires the concrete meter through this interface via a type assertion
// onto costbudgetdomain.Lister, for the same reason JobBudgetSource does
// (widening costbudgetdomain.Meter would force every Meter implementation
// to support enumeration, which the core Checker never needs). Entries
// carry the opaque job key and its running total only -- the key's
// tenant/identity/session are NOT decomposed for display, the same known,
// documented limitation as JobBudgetSource (see costbudgetdomain.Lister's
// own doc comment).
type CostBudgetSource interface {
	ListNearCeiling(limit int) []costbudgetdomain.Entry
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

// ReloadAuthorizer decides whether a caller may trigger a hot-reload of
// policy/rbac/budget configuration via POST
// /dashboard/api/reload/{domain}, gating that mutation the same way
// UnblockAuthorizer gates handleUnblock -- via an injected Authorizer
// requiring a specific permission (config:edit here, credential:revoke
// there), separately from the read-only dashboard:view permission the
// rest of this file's routes rely on. Unlike UnblockAuthorizer, Authorize
// also returns the resolved caller identity: ReloadResult.AppliedBy needs
// it for the audit trail, and a bare AllowedFor(r) bool has nowhere to
// carry that value back out. nil means "not wired" (rbac off) --
// handleReload then answers 404, the same posture as every other
// nil-source route in this file.
type ReloadAuthorizer interface {
	Authorize(r *http.Request) (identity string, ok bool)
}

// ReloadHistorySource is the subset of reload.ReloadEventBuffer's
// behavior Handler depends on -- same one-method pattern as
// AnomalySource/FederationSource. handleReloadHistory converts to this
// package's own domain.ReloadEntry before writing, so the endpoint's
// wire shape is not tied to reload.ReloadEvent. Gated on
// PermissionDashboardView like every other read route in this file, NOT
// config:edit -- viewing history is a read, not a mutation, unlike
// POST /dashboard/api/reload/{domain} itself.
type ReloadHistorySource interface {
	Since(afterID int64, limit int) []reload.ReloadEvent
}

// ComplianceSource backs GET /dashboard/api/compliance -- a live,
// aggregate-only preview of what a `wardline export-evidence` CLI run
// over the same range would produce (counts and histograms, never raw
// audit entries -- see handleCompliance's doc comment for why this stays
// narrower than a full evidence browser). Unlike every other Source
// interface in this file, Query can fail per-request (a bad range, an
// unreachable Postgres), not just return an empty/zero value.
type ComplianceSource interface {
	Query(ctx context.Context, from, to time.Time) (compliancedomain.Manifest, error)
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

// PolicySource resolves the dashboard's current view of the active
// policy engine's backend/source -- Current() re-reads live state on
// every call, never a snapshot frozen at construction time. This matters
// once a policy write-and-reload can happen at runtime (see
// PolicyWriter below): a plain domain.PolicyInfo field, fixed at
// startup, would silently keep serving pre-reload content forever
// after a hot-reload. See domain.PolicyInfo.Current for the trivial
// "a fixed value is its own current state" implementation every test
// (and any single-snapshot caller) keeps using unchanged.
type PolicySource interface {
	Current() domain.PolicyInfo
}

// PolicyWriter writes a new rule set to the yaml policy backend's
// configured file and reloads the live engine from it -- the structured
// half of Policy view's "Rule editor" (Source tab edits raw text
// instead, but both paths funnel through the same POST
// /dashboard/api/reload/policy machinery so a rejected rule set surfaces
// through the exact same Reload log every other reload does). nil for
// any non-yaml backend (opa/cedar have no such structured rule
// representation) or when rbac is off -- WriteAndReload then answers 404,
// matching every other "not wired" route in this file.
type PolicyWriter interface {
	// WriteAndReload validates rules/def, writes them to the policy
	// file, and reloads the live engine from the freshly written file --
	// one atomic operation from the caller's perspective, mirroring how
	// the reference prototype's "Validate & apply" button is a single
	// action. appliedBy is the resolved caller identity, recorded in the
	// same Reload log entry POST /dashboard/api/reload/policy itself
	// would produce -- never a value the client supplies.
	WriteAndReload(rules []policydomain.Rule, def policydomain.Effect, appliedBy string) error
}

// BudgetWriter writes a new default limit and tenant/tool overrides to
// the config file's budget: section and reloads the live limiter from
// it -- the Budget view's editor equivalent of PolicyWriter, funneling
// through the exact same reloadCoordinator.Reload("budget", ...) a raw
// POST /dashboard/api/reload/budget would use, so a rejected edit
// surfaces through the identical Reload log. nil when budget_enforcement
// is off or rbac is off, matching PolicyWriter's own nil posture.
type BudgetWriter interface {
	// WriteAndReload validates and persists def/tenantOverrides/toolOverrides,
	// then reloads. appliedBy is the resolved caller identity from
	// ReloadAuthorizer.Authorize, never anything the client supplies.
	WriteAndReload(def budgetdomain.LimitInfo, tenantOverrides, toolOverrides []budgetdomain.OverrideInfo, appliedBy string) error
}

// CallerInfoResolver resolves the caller's own identity string and
// whether they hold config:edit, purely for the dashboard topbar's
// identity display -- never used for any authorization decision
// (TenantScopeResolver/UnblockAuthorizer/ReloadAuthorizer already own
// that, independently). identity == "" means unresolved (no identity
// header, or rbac off), in which case the topbar shows no name/initials
// -- this must never be a display-only guess or placeholder value,
// since a wrong displayed identity is a trust problem for an operator
// console even though it drives no access decision. nil means "not
// wired" (rbac off): the topbar then shows only the generic icon,
// identical to today's behavior before this field existed.
type CallerInfoResolver interface {
	CallerInfo(r *http.Request) (identity string, canConfigEdit bool)
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
	audit             AuditSource
	status            StatusSource
	policy            PolicySource
	policyWriter      PolicyWriter
	anomalies         AnomalySource
	federation        FederationSource
	blocked           BlockedSource
	scope             TenantScopeResolver
	unblock           UnblockAuthorizer
	rbac              RBACSource
	budget            BudgetSource
	budgetWriter      BudgetWriter
	reloadCoordinator *reload.ReloadCoordinator
	reloadAuth        ReloadAuthorizer
	reloadHistory     ReloadHistorySource
	callerInfo        CallerInfoResolver
	compliance        ComplianceSource
	approvals         ApprovalSource
	jobBudget         JobBudgetSource
	costBudget        CostBudgetSource
	mux               *http.ServeMux
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
// reloadCoordinator and reloadAuth gate POST /dashboard/api/reload/{domain}
// the same pairing as blocked/unblock above (a source plus its
// authorizer) -- either nil answers 404 the same way. reloadHistory backs
// GET /dashboard/api/reload/history -- unlike reloadCoordinator/reloadAuth
// it needs no separate authorizer of its own: it's a read, gated by the
// same dashboard:view permission wrapping this whole handler (see
// main.go), never config:edit. nil (dashboard enabled without the reload
// buffer wired) answers 404, the same "not wired" posture as every other
// nil-source route above. callerInfo backs the topbar's identity display
// (GET /dashboard/api/status's CallerIdentity/CallerCanConfigEdit
// fields) -- nil (rbac off) leaves both fields zero-valued, and the
// topbar falls back to its generic icon, identical to behavior before
// this field existed. policyWriter backs the Policy view's structured
// rule editor (PUT /dashboard/api/policy) -- nil (non-yaml backend, or
// rbac off) leaves the editor unavailable, the Source tab's read-only
// view still works via policy alone. budgetWriter backs the Budget
// view's editor (PUT /dashboard/api/budget) the same way, nil when
// budget_enforcement or rbac is off.
// compliance backs GET /dashboard/api/compliance -- nil (audit trail not
// queryable, e.g. audit.output is stdout) answers 404, the same
// "not wired" posture as every other nil-source route above.
// approvals backs GET /dashboard/api/approvals and POST
// /dashboard/api/approvals/{id}/{approve,deny} -- nil (approval_workflow
// off, or web_ui off) answers 404 the same way; the two mutating routes
// are additionally gated by the same config:edit reloadAuth the policy/
// budget editors use. jobBudget backs GET /dashboard/api/job-budget -- nil
// (job_budget off, or web_ui off) answers 404 the same way; unlike
// approvals this view is read-only with no decision/mutation counterpart.
// costBudget backs GET /dashboard/api/cost-budget -- nil (job_cost_budget
// off, or web_ui off) answers 404 the same way; mirrors jobBudget exactly,
// including the read-only, no-mutation-counterpart posture.
func NewHandler(audit AuditSource, status StatusSource, policy PolicySource, assets fs.FS, anomalies AnomalySource, federation FederationSource, blocked BlockedSource, scope TenantScopeResolver, unblock UnblockAuthorizer, rbac RBACSource, budget BudgetSource, reloadCoordinator *reload.ReloadCoordinator, reloadAuth ReloadAuthorizer, reloadHistory ReloadHistorySource, callerInfo CallerInfoResolver, policyWriter PolicyWriter, budgetWriter BudgetWriter, compliance ComplianceSource, approvals ApprovalSource, jobBudget JobBudgetSource, costBudget CostBudgetSource) *Handler {
	h := &Handler{audit: audit, status: status, policy: policy, policyWriter: policyWriter, anomalies: anomalies, federation: federation, blocked: blocked, scope: scope, unblock: unblock, rbac: rbac, budget: budget, budgetWriter: budgetWriter, reloadCoordinator: reloadCoordinator, reloadAuth: reloadAuth, reloadHistory: reloadHistory, callerInfo: callerInfo, compliance: compliance, approvals: approvals, jobBudget: jobBudget, costBudget: costBudget}

	mux := http.NewServeMux()
	mux.HandleFunc("/dashboard/api/audit", h.handleAudit)
	mux.HandleFunc("/dashboard/api/policy", h.handlePolicy)
	mux.HandleFunc("/dashboard/api/status", h.handleStatus)
	mux.HandleFunc("/dashboard/api/anomalies", h.handleAnomalies)
	mux.HandleFunc("/dashboard/api/approvals", h.handleApprovals)
	mux.HandleFunc("/dashboard/api/approvals/", h.handleApprovalDecision)
	mux.HandleFunc("/dashboard/api/job-budget", h.handleJobBudget)
	mux.HandleFunc("/dashboard/api/cost-budget", h.handleCostBudget)
	mux.HandleFunc("/dashboard/api/federation/correlated", h.handleFederationCorrelated)
	mux.HandleFunc("/dashboard/api/anomalies/blocked", h.handleBlocked)
	mux.HandleFunc("/dashboard/api/anomalies/blocked/", h.handleUnblock)
	mux.HandleFunc("/dashboard/api/rbac", h.handleRBAC)
	mux.HandleFunc("/dashboard/api/budget", h.handleBudget)
	mux.HandleFunc("/dashboard/api/reload/history", h.handleReloadHistory)
	mux.HandleFunc("/dashboard/api/reload/", h.handleReload)
	mux.HandleFunc("/dashboard/api/compliance", h.handleCompliance)
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
	// frame-ancestors 'none' (and X-Frame-Options as a defense-in-depth
	// fallback for browsers/scanners that only check the older header) --
	// this console can trigger config:edit actions (policy/budget reload,
	// credential revoke) with one click, so letting it render inside a
	// third-party iframe would open a real clickjacking path: an attacker
	// overlays invisible controls over "Validate & apply"/"Revoke
	// credential" and tricks an already-authenticated admin into clicking
	// them. Nothing about this console's design calls for iframe embedding.
	w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
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
			ID:               a.ID,
			Timestamp:        a.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"),
			Identity:         a.Identity,
			Tenant:           a.Tenant,
			Kind:             string(a.Kind),
			Detail:           a.Detail,
			Tool:             a.Entry.Tool,
			Score:            a.Score,
			AutoBlockSeconds: a.AutoBlockSeconds,
		})
	}
	writeJSON(w, entries)
}

// handleApprovals serves GET /dashboard/api/approvals -- the pending
// approval queue, operator-global (ListPending("")), gated only by the
// outer dashboard:view wrap like every other read route. nil source
// (approval_workflow off) answers 404, matching handleAnomalies.
func (h *Handler) handleApprovals(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	if h.approvals == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	pending := h.approvals.ListPending("")
	if pending == nil {
		pending = []approvaldomain.Request{}
	}
	writeJSON(w, pending)
}

// handleApprovalDecision serves POST /dashboard/api/approvals/{id}/approve
// and .../deny -- deciding a pending request. This is a mutation with real
// security weight (releasing a held write, or refusing it), so it is gated
// by the same config:edit ReloadAuthorizer the policy/budget editors use,
// separately from the read-only dashboard:view permission. appliedBy comes
// only from ReloadAuthorizer.Authorize, never anything the client supplies.
// An unknown or already-decided id surfaces as 404.
func (h *Handler) handleApprovalDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.approvals == nil || h.reloadAuth == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	// Authorization checked before the path is parsed: a caller without
	// config-edit rights gets a uniform 403 regardless of whether their
	// path happens to be well-formed, rather than a 400 that leaks "your
	// path shape was wrong" to an unauthorized caller.
	appliedBy, ok := h.reloadAuth.Authorize(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, action, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/dashboard/api/approvals/"), "/")
	if !ok || id == "" || (action != "approve" && action != "deny") {
		http.Error(w, "path must be /dashboard/api/approvals/{id}/{approve|deny}", http.StatusBadRequest)
		return
	}
	decide := h.approvals.Approve
	if action == "deny" {
		decide = h.approvals.Deny
	}
	if err := decide(id, appliedBy); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleJobBudget serves GET /dashboard/api/job-budget -- a read-only
// snapshot of job keys nearing/at their per-job budget ceiling, sourced
// from jobbudget's optional Lister capability (see JobBudgetSource's doc
// comment). nil source (job_budget off, or web_ui off) answers 404,
// matching handleApprovals; unlike approvals this view has no
// decision/mutation counterpart -- a Lister only reads.
func (h *Handler) handleJobBudget(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	if h.jobBudget == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	entries := h.jobBudget.ListNearCeiling(defaultAuditLimit)
	if entries == nil {
		entries = []jobbudgetdomain.Entry{}
	}
	writeJSON(w, entries)
}

// handleCostBudget serves GET /dashboard/api/cost-budget -- a read-only
// snapshot of job keys nearing/at their per-job cost/token budget
// ceiling, sourced from costbudget's optional Lister capability (see
// CostBudgetSource's doc comment). Mirrors handleJobBudget exactly: nil
// source (job_cost_budget off, or web_ui off) answers 404, and this view
// has no decision/mutation counterpart -- a Lister only reads.
func (h *Handler) handleCostBudget(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	if h.costBudget == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	entries := h.costBudget.ListNearCeiling(defaultAuditLimit)
	if entries == nil {
		entries = []costbudgetdomain.Entry{}
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

// handleCompliance serves GET /dashboard/api/compliance?from=&to=
// (RFC3339 query params, both required) -- a live, aggregate-only
// preview of what `wardline export-evidence` over the same range would
// produce: entry counts and decision/kind histograms, via
// compliance/domain.Manifest, the exact same shape the CLI's bundle
// carries in manifest.json. Deliberately NOT a raw-entry browser (see
// docs/superpowers/specs/2026-08-08-compliance-evidence-export-hardening-design.md
// "5. Live query API") -- a manifest-level summary is a strict subset of
// what the existing Activity view (raw entries, ring-buffer-backed)
// already discloses to the same dashboard:view caller, so this route is
// gated identically (the outer dashboard:view RequirePermission wrap
// around the whole /dashboard/ tree in main.go), never a stricter
// permission.
func (h *Handler) handleCompliance(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	if h.compliance == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		http.Error(w, "from and to query params are required (RFC3339)", http.StatusBadRequest)
		return
	}
	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		http.Error(w, "invalid from: "+err.Error(), http.StatusBadRequest)
		return
	}
	to, err := time.Parse(time.RFC3339, toStr)
	if err != nil {
		http.Error(w, "invalid to: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !from.Before(to) {
		http.Error(w, "from must be before to", http.StatusBadRequest)
		return
	}
	manifest, err := h.compliance.Query(r.Context(), from, to)
	if err != nil {
		http.Error(w, "failed to query compliance evidence: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, manifest)
}

// handleBudget serves GET /dashboard/api/budget -- a read-only snapshot of
// the global default rate limit and every tenant/tool override h.budget
// (the real budgetdomain.Limiter, wired in main.go) currently holds.
// Gated only by the outer dashboard:view RequirePermission wrap around the
// whole /dashboard/ tree in main.go -- never config:edit, since this is a
// read, not a mutation, and no edit capability exists yet.
func (h *Handler) handleBudget(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleBudgetRead(w, r)
	case http.MethodPut:
		h.handleBudgetWrite(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) handleBudgetRead(w http.ResponseWriter, r *http.Request) {
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

// budgetOverrideInput/budgetWriteRequest are PUT /dashboard/api/budget's
// wire shape -- deliberately dashboard-owned JSON, not budgetdomain
// types directly, same reasoning as policyWriteRequest.
type budgetOverrideInput struct {
	Scope             string `json:"scope"`
	Name              string `json:"name"`
	RequestsPerWindow int    `json:"requests_per_window"`
	WindowSeconds     int    `json:"window_seconds"`
}

type budgetWriteRequest struct {
	Default struct {
		RequestsPerWindow int `json:"requests_per_window"`
		WindowSeconds     int `json:"window_seconds"`
	} `json:"default"`
	TenantOverrides []budgetOverrideInput `json:"tenant_overrides"`
	ToolOverrides   []budgetOverrideInput `json:"tool_overrides"`
}

// handleBudgetWrite serves PUT /dashboard/api/budget -- the Budget
// view's editor equivalent of handlePolicyWrite, gated by the same
// config:edit ReloadAuthorizer. appliedBy comes only from
// ReloadAuthorizer.Authorize, never the request body.
func (h *Handler) handleBudgetWrite(w http.ResponseWriter, r *http.Request) {
	if h.budgetWriter == nil || h.reloadAuth == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	appliedBy, ok := h.reloadAuth.Authorize(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var req budgetWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	toOverrides := func(in []budgetOverrideInput) []budgetdomain.OverrideInfo {
		out := make([]budgetdomain.OverrideInfo, len(in))
		for i, o := range in {
			out[i] = budgetdomain.OverrideInfo{Scope: o.Scope, Name: o.Name, LimitInfo: budgetdomain.LimitInfo{RequestsPerWindow: o.RequestsPerWindow, Window: time.Duration(o.WindowSeconds) * time.Second}}
		}
		return out
	}
	def := budgetdomain.LimitInfo{RequestsPerWindow: req.Default.RequestsPerWindow, Window: time.Duration(req.Default.WindowSeconds) * time.Second}

	if err := h.budgetWriter.WriteAndReload(def, toOverrides(req.TenantOverrides), toOverrides(req.ToolOverrides), appliedBy); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
		return
	}
	h.handleBudgetRead(w, r)
}

// handleReload serves POST /dashboard/api/reload/{domain}, triggering a
// hot-reload of the named domain's configuration (policy, rbac, or
// budget -- see cmd/wardline's ReloadCoordinator wiring for the exact
// set). This is a mutation with real operational/security weight, so it
// is gated by ReloadAuthorizer (requiring config:edit when rbac is on)
// separately from the read-only dashboard:view permission the rest of
// this file's routes rely on -- same posture as handleUnblock/
// credential:revoke. appliedBy comes from ReloadAuthorizer.Authorize,
// the resolved caller identity, never from anything the client supplies.
func (h *Handler) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if h.reloadCoordinator == nil || h.reloadAuth == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	domainName := strings.TrimPrefix(r.URL.Path, "/dashboard/api/reload/")
	if domainName == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}
	appliedBy, ok := h.reloadAuth.Authorize(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeJSON(w, h.reloadCoordinator.Reload(domainName, appliedBy))
}

// handleReloadHistory serves GET /dashboard/api/reload/history, the
// read-only counterpart to POST /dashboard/api/reload/{domain} -- same
// pagination/writeJSON/nil-source-404 shape as handleAnomalies, but
// gated only by the dashboard:view permission wrapping this whole
// handler (see main.go), never config:edit: viewing history is a read,
// not a mutation. Registered as an exact path so it takes precedence
// over "/dashboard/api/reload/"'s subtree match (handleReload) for this
// one literal path -- ServeMux always prefers the more specific pattern.
func (h *Handler) handleReloadHistory(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	if h.reloadHistory == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	after, limit := pagination(r)

	events := h.reloadHistory.Since(after, limit)
	entries := make([]domain.ReloadEntry, 0, len(events))
	for _, e := range events {
		entries = append(entries, domain.ReloadEntry{
			ID:        e.ID,
			Timestamp: e.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"),
			Domain:    e.Domain,
			OK:        e.OK,
			Error:     e.Error,
			AppliedBy: e.AppliedBy,
		})
	}
	writeJSON(w, entries)
}

func (h *Handler) handlePolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, h.policy.Current())
	case http.MethodPut:
		h.handlePolicyWrite(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// policyRuleInput/policyWriteRequest are PUT /dashboard/api/policy's wire
// shape for the Rule editor's "Validate & apply" -- deliberately a
// dashboard-owned JSON shape, not policydomain.Rule directly, same
// reasoning as every other *Entry type in domain/entry.go: the wire
// contract shouldn't change just because the domain type's fields do.
type policyRuleInput struct {
	Identity string `json:"identity"`
	Tool     string `json:"tool"`
	Tenant   string `json:"tenant"`
	Effect   string `json:"effect"`
	Method   string `json:"method"`
}

type policyWriteRequest struct {
	Rules   []policyRuleInput `json:"rules"`
	Default string            `json:"default"`
}

// handlePolicyWrite serves PUT /dashboard/api/policy -- the Rule
// editor's "Validate & apply", writing a new rule set to the yaml
// backend's policy file and reloading the live engine from it, gated by
// the exact same config:edit ReloadAuthorizer POST
// /dashboard/api/reload/{domain} uses (this is at least as sensitive a
// mutation). appliedBy comes only from ReloadAuthorizer.Authorize, the
// resolved caller identity -- never from anything the client's JSON
// body supplies, mirroring handleReload exactly.
func (h *Handler) handlePolicyWrite(w http.ResponseWriter, r *http.Request) {
	if h.policyWriter == nil || h.reloadAuth == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	appliedBy, ok := h.reloadAuth.Authorize(r)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var req policyWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	rules := make([]policydomain.Rule, len(req.Rules))
	for i, ri := range req.Rules {
		rules[i] = policydomain.Rule{Identity: ri.Identity, Tool: ri.Tool, Tenant: ri.Tenant, Effect: policydomain.Effect(ri.Effect), Method: ri.Method}
	}

	if err := h.policyWriter.WriteAndReload(rules, policydomain.Effect(req.Default), appliedBy); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(struct {
			Error string `json:"error"`
		}{Error: err.Error()})
		return
	}
	writeJSON(w, h.policy.Current())
}

// statusResponse wraps domain.StatusInfo with per-request fields
// StatusInfo itself cannot carry -- StatusInfo is a process-wide value
// cached by StatusProvider, computed once, identical for every caller;
// CallerTenant/CallerIdentity/CallerCanConfigEdit are derived fresh per
// request from h.tenantFilter/h.callerInfo, the same RBAC-resolved
// scoping every other route in this file already uses. CallerIdentity
// is "" (and CallerCanConfigEdit false) whenever callerInfo is nil or
// the identity doesn't resolve -- the topbar must never display a
// fabricated name for an unresolved caller.
type statusResponse struct {
	domain.StatusInfo
	CallerTenant        string
	CallerIdentity      string
	CallerCanConfigEdit bool
}

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if methodNotAllowed(w, r) {
		return
	}
	resp := statusResponse{StatusInfo: h.status.Status(), CallerTenant: h.tenantFilter(r)}
	if h.callerInfo != nil {
		resp.CallerIdentity, resp.CallerCanConfigEdit = h.callerInfo.CallerInfo(r)
	}
	writeJSON(w, resp)
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
