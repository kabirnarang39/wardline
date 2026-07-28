package cedar

import (
	"fmt"
	"os"
	"time"

	cedarsdk "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"github.com/kabirnarang39/wardline/internal/features/policy/domain"
)

// actionCallTool is the single fixed Cedar action every Wardline tool
// call maps to — Wardline's action space genuinely is just "call a
// tool"; the tool being called is the resource, not the action.
const actionCallTool = "call_tool"

// CedarEngine is a policydomain.Engine backed by an embedded Cedar
// evaluator (github.com/cedar-policy/cedar-go) — no external process, no
// network hop. Cedar's language is deliberately non-Turing-complete (no
// loops, no recursion, no http.send), so unlike the OPA adapter's
// explicit evalTimeout, evaluation terminates by construction and needs
// no timeout wrapper.
type CedarEngine struct {
	policySet *cedarsdk.PolicySet
}

// NewCedarEngine parses a Cedar policy set (source, identified by
// filename in error messages) and holds the parsed policy set for
// repeated evaluation. Parsing happens once here; Evaluate reuses it on
// every call — a proxy's hot path must not re-parse Cedar text per
// request.
func NewCedarEngine(filename string, source []byte) (*CedarEngine, error) {
	ps, err := cedarsdk.NewPolicySetFromBytes(filename, source)
	if err != nil {
		return nil, fmt.Errorf("parse cedar policy %s: %w", filename, err)
	}
	return &CedarEngine{policySet: ps}, nil
}

// LoadCedarFile reads a .cedar policy file and returns a CedarEngine, or
// an error describing the first problem found (read failure or parse
// error).
func LoadCedarFile(path string) (*CedarEngine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read cedar policy file %s: %w", path, err)
	}
	return NewCedarEngine(path, data)
}

// Evaluate maps pc onto a Cedar request (principal=identity,
// action=call_tool, resource=tool, context={params, timestamp,
// remote_addr, user_agent}) and asks the policy set for a decision.
// Cedar's own semantics are already default-deny — no matching `permit`
// denies with no adapter-side work required.
func (e *CedarEngine) Evaluate(pc domain.Context) domain.Decision {
	contextRecord, err := buildContext(pc)
	if err != nil {
		return domain.Decision{Effect: domain.EffectDeny, Reason: fmt.Sprintf("failed to build policy context: %v", err)}
	}

	req := cedarsdk.Request{
		Principal: cedarsdk.NewEntityUID("Wardline::Identity", cedarsdk.String(pc.Identity)),
		Action:    cedarsdk.NewEntityUID("Wardline::Action", actionCallTool),
		Resource:  cedarsdk.NewEntityUID("Wardline::Tool", cedarsdk.String(pc.Tool)),
		Context:   contextRecord,
	}

	decision, diag := cedarsdk.Authorize(e.policySet, types.EntityMap{}, req)

	// Cedar does NOT fail closed on a policy evaluation error: a policy
	// whose when/unless clause errors at runtime (e.g. a missing JSON
	// record key) is silently skipped and dropped from the decision
	// entirely, not treated as a deny. That means an erroring `forbid`
	// policy (Cedar's denylist mechanism — forbid overrides permit)
	// simply vanishes, and any separately-matching `permit` would win,
	// silently allowing a request the denylist was meant to block. So we
	// must check diag.Errors FIRST, before looking at the decision at
	// all, and fail closed regardless of what Cedar decided.
	if len(diag.Errors) > 0 {
		first := diag.Errors[0]
		return domain.Decision{
			Effect: domain.EffectDeny,
			Reason: fmt.Sprintf("cedar: policy %q errored during evaluation, failing closed: %s", first.PolicyID, first.Message),
		}
	}

	if bool(decision) {
		reason := "cedar decision"
		if len(diag.Reasons) > 0 {
			reason = fmt.Sprintf("cedar: permitted by policy %q", diag.Reasons[0].PolicyID)
		}
		return domain.Decision{Effect: domain.EffectAllow, Reason: reason}
	}

	if len(diag.Reasons) > 0 {
		return domain.Decision{Effect: domain.EffectDeny, Reason: fmt.Sprintf("cedar: denied by policy %q", diag.Reasons[0].PolicyID)}
	}
	return domain.Decision{Effect: domain.EffectDeny, Reason: "cedar: no matching permit policy"}
}

// buildContext decodes pc.Params into a Cedar value (an empty Record if
// Params is empty, so a policy can reference context.params without a
// separate presence check on the key itself) and wraps it with the
// metadata fields every Cedar policy may need but that aren't already
// surfaced as principal/action/resource.
func buildContext(pc domain.Context) (types.Record, error) {
	var paramsValue types.Value = types.NewRecord(types.RecordMap{})
	if len(pc.Params) > 0 {
		if err := types.UnmarshalJSON(pc.Params, &paramsValue); err != nil {
			return types.Record{}, fmt.Errorf("decode params: %w", err)
		}
	}
	return types.NewRecord(types.RecordMap{
		"params":      paramsValue,
		"timestamp":   types.String(pc.Timestamp.UTC().Format(time.RFC3339)),
		"remote_addr": types.String(pc.RemoteAddr),
		"user_agent":  types.String(pc.UserAgent),
	}), nil
}
