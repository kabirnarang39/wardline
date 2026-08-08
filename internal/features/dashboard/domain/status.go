package domain

// StatusInfo is a point-in-time snapshot of the running server, shown on
// the dashboard's Status view.
type StatusInfo struct {
	Version       string
	UptimeSeconds int64
	Listen        string
	Upstream      string
	Features      map[string]bool
}

// PolicyRuleEntry is the dashboard's JSON view of one policy rule --
// deliberately its own type (not a reuse of policydomain.Rule), same
// reasoning as every *Entry type in domain/entry.go: the wire shape
// shouldn't change just because the domain type's fields do.
type PolicyRuleEntry struct {
	Identity string `json:"identity"`
	Tool     string `json:"tool"`
	Tenant   string `json:"tenant,omitempty"`
	Effect   string `json:"effect"`
	// Method is "" (displayed/edited as "tools/call") or an MCP
	// resources/*/prompts/* method -- see policydomain.Rule.Method.
	Method string `json:"method,omitempty"`
}

// PolicyInfo is the active policy engine's backend name and raw source.
// Rules/Default are the SAME content as Source, already parsed into the
// Rule editor's structured shape -- populated only when Backend ==
// "yaml" (opa/cedar have no such structured representation), nil/""
// otherwise. Populating this server-side, from the real parser
// (policyadapter.ParseRules) rather than a hand-rolled duplicate YAML
// parser in JS, is deliberate: the editor's table can never show
// anything other than what the real engine actually loaded.
type PolicyInfo struct {
	Backend string
	Source  string
	Rules   []PolicyRuleEntry `json:"Rules,omitempty"`
	Default string            `json:"Default,omitempty"`
}

// Current makes a plain PolicyInfo value satisfy dashboard/adapter's
// PolicySource interface trivially -- a fixed value's "current" state is
// just itself. This is what every test (and any future single-snapshot
// caller) keeps working against unchanged; only cmd/wardline's real
// wiring needs a non-trivial PolicySource that re-reads a live,
// hot-reloadable holder instead (see main.go's policySourceFunc).
func (p PolicyInfo) Current() PolicyInfo { return p }
