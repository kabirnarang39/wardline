package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kabirnarang39/wardline/internal/features/federation/domain"
)

// HTTPSender is Publisher's real BatchSender: a plain HTTP POST of the
// batch as JSON to the peer's configured endpoint.
type HTTPSender struct {
	client *http.Client
}

func NewHTTPSender(client *http.Client) *HTTPSender {
	return &HTTPSender{client: client}
}

func (s *HTTPSender) Send(ctx context.Context, endpoint string, batch domain.SignedSummaryBatch) error {
	body, err := json.Marshal(struct {
		InstanceID string                  `json:"instance_id"`
		Summaries  []domain.AnomalySummary `json:"summaries"`
		Signature  []byte                  `json:"signature"`
	}{InstanceID: batch.InstanceID, Summaries: batch.Summaries, Signature: batch.Signature})
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("peer returned status %d", resp.StatusCode)
	}
	return nil
}
