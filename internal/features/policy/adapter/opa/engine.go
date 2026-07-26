package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	//nolint:staticcheck // SA1019: the v1 package requires Rego v1 syntax
	// (explicit `if`/`contains` keywords) and rejects this engine's verified
	// v0-style rule bodies (e.g. `allow { ... }`) with a parse error; the
	// deprecated v0-compat package is the deliberate, correct choice here.
	"github.com/open-policy-agent/opa/ast"
	//nolint:staticcheck // SA1019: see ast import above — same v0/v1 syntax reason.
	"github.com/open-policy-agent/opa/rego"

	"github.com/kabirnarang39/wardline/internal/features/policy/domain"
)

// wantPackagePath is the fully-qualified Rego package path every policy
// loaded by this engine must declare. A mismatched package compiles
// successfully but produces an empty ResultSet on every future query —
// silently denying every request forever with no diagnostic. Checking
// this at load time turns that into a fail-fast startup error instead.
const wantPackagePath = "data.wardline.authz"

// queryPath is what Evaluate asks OPA for: the whole exported object under
// the wardline.authz package, so both "allow" and an optional "reason" key
// come back in a single evaluation.
const queryPath = "data.wardline.authz"

// evalTimeout bounds a single policy evaluation so a runaway or malicious
// Rego policy can't hang a request indefinitely.
const evalTimeout = 5 * time.Second

// OPAEngine is a policydomain.Engine backed by an embedded, in-process OPA
// evaluator — no external `opa run --server` process, no network hop.
type OPAEngine struct {
	query rego.PreparedEvalQuery
}

// NewOPAEngine compiles a Rego module (source, identified by filename in
// error messages) and prepares it for repeated evaluation. Compiling and
// preparing happen once here; Evaluate reuses the prepared query on every
// call — a proxy's hot path must not recompile Rego per request.
func NewOPAEngine(filename string, source []byte) (*OPAEngine, error) {
	mod, err := ast.ParseModule(filename, string(source))
	if err != nil {
		return nil, fmt.Errorf("parse rego module %s: %w", filename, err)
	}
	if got := mod.Package.Path.String(); got != wantPackagePath {
		return nil, fmt.Errorf("rego module %s must declare package wardline.authz, got package path %s", filename, got)
	}

	ctx := context.Background()
	r := rego.New(
		rego.Query(queryPath),
		rego.Module(filename, string(source)),
	)
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare rego module %s: %w", filename, err)
	}
	return &OPAEngine{query: pq}, nil
}

// LoadRegoFile reads a .rego policy file and returns an OPAEngine, or an
// error describing the first problem found (parse error, wrong package,
// or a compile/prepare failure).
func LoadRegoFile(path string) (*OPAEngine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rego policy file %s: %w", path, err)
	}
	return NewOPAEngine(path, data)
}

// contextInput is the JSON shape handed to Rego as `input`. Params is
// decoded from json.RawMessage into a native value here — this decode
// happens only at this adapter's translation boundary; the domain model
// (policydomain.Context) keeps Params as json.RawMessage throughout.
type contextInput struct {
	Identity   string `json:"identity"`
	Tool       string `json:"tool"`
	Params     any    `json:"params,omitempty"`
	Timestamp  string `json:"timestamp"`
	RemoteAddr string `json:"remote_addr"`
	UserAgent  string `json:"user_agent"`
}

// Evaluate runs the prepared query against pc and extracts an allow/deny
// decision. Any ambiguous outcome — no rule matched, a non-boolean allow
// value, or a genuine evaluation error — is treated as fail-closed deny,
// matching the YAML Matcher's default-deny philosophy.
func (e *OPAEngine) Evaluate(pc domain.Context) domain.Decision {
	input, err := buildInput(pc)
	if err != nil {
		return domain.Decision{Effect: domain.EffectDeny, Reason: fmt.Sprintf("failed to build policy input: %v", err)}
	}

	// domain.Engine.Evaluate takes no context.Context (widening that
	// interface is a separate future change), so a bounded timeout is
	// enforced internally instead — a runaway or malicious policy (e.g.
	// http.send to a slow endpoint, an expensive comprehension over
	// attacker-controlled params) must not hang a request indefinitely.
	// A timeout surfaces as a genuine Eval error, which the existing
	// fail-closed handling below already turns into a deny.
	ctx, cancel := context.WithTimeout(context.Background(), evalTimeout)
	defer cancel()

	rs, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return domain.Decision{Effect: domain.EffectDeny, Reason: fmt.Sprintf("policy evaluation failed: %v", err)}
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return domain.Decision{Effect: domain.EffectDeny, Reason: "policy produced no decision for this input"}
	}

	result, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return domain.Decision{Effect: domain.EffectDeny, Reason: "policy result was not an object"}
	}

	allow, ok := result["allow"].(bool)
	if !ok {
		return domain.Decision{Effect: domain.EffectDeny, Reason: "policy's allow value is missing or not a boolean"}
	}

	reason, _ := result["reason"].(string)
	if reason == "" {
		reason = "opa decision"
	}

	effect := domain.EffectDeny
	if allow {
		effect = domain.EffectAllow
	}
	return domain.Decision{Effect: effect, Reason: reason}
}

func buildInput(pc domain.Context) (contextInput, error) {
	var params any
	if len(pc.Params) > 0 {
		// UseNumber preserves large integers (e.g. snowflake IDs, account
		// numbers) as json.Number instead of decoding them into float64,
		// which only has 53 bits of integer precision — silently rounding
		// a large integer could make it compare unequal to the same
		// literal in a Rego policy, letting an attacker bypass a denylist
		// keyed on that ID. OPA's Go SDK natively handles json.Number.
		dec := json.NewDecoder(bytes.NewReader(pc.Params))
		dec.UseNumber()
		if err := dec.Decode(&params); err != nil {
			return contextInput{}, fmt.Errorf("decode params: %w", err)
		}
	}
	return contextInput{
		Identity:   pc.Identity,
		Tool:       pc.Tool,
		Params:     params,
		Timestamp:  pc.Timestamp.UTC().Format("2006-01-02T15:04:05Z07:00"),
		RemoteAddr: pc.RemoteAddr,
		UserAgent:  pc.UserAgent,
	}, nil
}
