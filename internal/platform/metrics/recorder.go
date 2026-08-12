// Package metrics observes completed proxy requests for external
// monitoring. It follows the same disabled/real split as
// internal/platform/tracing: NewDisabled costs nothing and is what every
// caller gets unless features.prometheus_metrics is on (see
// cmd/wardline/main.go), NewPrometheus is the real implementation wired in
// that case.
package metrics

import "time"

// Recorder observes one completed proxy request's outcome. decision is the
// same closed set of literals proxy/adapter.Handler.finish already
// produces ("allow", "deny", "throttled", ...) -- never the tool name,
// which is attacker-controlled input (see anomaly detection's novel-tool-
// burst attack pattern) and would otherwise let a caller balloon this
// process's metric cardinality by sending an unbounded number of distinct
// tool names.
type Recorder interface {
	ObserveRequest(decision string, duration time.Duration)
}

type disabled struct{}

// NewDisabled is a zero-cost Recorder: every call is a no-op. The default
// for every Handler unless features.prometheus_metrics is on.
func NewDisabled() Recorder { return disabled{} }

func (disabled) ObserveRequest(string, time.Duration) {}
