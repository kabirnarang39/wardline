package domain

// Writer persists a flagged Anomaly. Mirrors audit/domain.Writer.
type Writer interface {
	Write(Anomaly) error
}
