package domain

// FederationConfig configures cross-instance anomaly correlation. Only
// validated (and only meaningful) when the federation feature flag is
// on, which itself requires anomaly_detection also be on.
type FederationConfig struct {
	PublishIntervalSeconds     int
	MinInstancesForCorrelation int
	CorrelationWindowSeconds   int
	GCIntervalSeconds          int
}
