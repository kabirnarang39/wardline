package adapter_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/scim/usecase"
)

func TestHandler_Bulk_CreatesUsersViaOperations(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	body := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
		"Operations": [
			{"method": "POST", "path": "/Users", "bulkId": "1", "data": {"userName":"alice","active":true}},
			{"method": "POST", "path": "/Users", "bulkId": "2", "data": {"userName":"bob","active":false}}
		]
	}`
	rec := doRequest(h, http.MethodPost, "/scim/v2/Bulk", body, "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Operations []struct {
			BulkID string `json:"bulkId"`
			Status string `json:"status"`
		} `json:"Operations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(out.Operations) != 2 {
		t.Fatalf("expected 2 operation results, got %d", len(out.Operations))
	}
	for _, op := range out.Operations {
		if op.Status != "201" {
			t.Errorf("bulkId %q: got status %q, want 201", op.BulkID, op.Status)
		}
	}

	listRec := doRequest(h, http.MethodGet, "/scim/v2/Users", "", "secret-token")
	var users []struct{ UserName string }
	if err := json.Unmarshal(listRec.Body.Bytes(), &users); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected the bulk request to have actually created 2 users via the real ProvisioningService, got %d", len(users))
	}
}

// TestHandler_Bulk_MixedSuccessAndFailure proves each operation is
// dispatched through the SAME handler logic the individual endpoints
// use -- a conflict (duplicate userName) surfaces as its own 409 within
// the batch, not an all-or-nothing failure.
func TestHandler_Bulk_MixedSuccessAndFailure(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)
	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")

	body := `{
		"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
		"Operations": [
			{"method": "POST", "path": "/Users", "bulkId": "1", "data": {"userName":"alice","active":true}},
			{"method": "POST", "path": "/Users", "bulkId": "2", "data": {"userName":"carol","active":true}}
		]
	}`
	rec := doRequest(h, http.MethodPost, "/scim/v2/Bulk", body, "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200 (the Bulk envelope itself succeeds even when an operation inside it fails), body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Operations []struct {
			BulkID string `json:"bulkId"`
			Status string `json:"status"`
		} `json:"Operations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if out.Operations[0].Status != "409" {
		t.Errorf("bulkId 1 (duplicate userName): got status %q, want 409", out.Operations[0].Status)
	}
	if out.Operations[1].Status != "201" {
		t.Errorf("bulkId 2 (new userName): got status %q, want 201", out.Operations[1].Status)
	}
}

func TestHandler_Bulk_EmptyOperationsRejected(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	rec := doRequest(h, http.MethodPost, "/scim/v2/Bulk", `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[]}`, "secret-token")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400 for an empty Operations array", rec.Code)
	}
}

func TestHandler_Bulk_RequiresAuth(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	rec := doRequest(h, http.MethodPost, "/scim/v2/Bulk", `{"Operations":[{"method":"POST","path":"/Users","data":{"userName":"alice"}}]}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401 for an unauthenticated bulk request", rec.Code)
	}
}

func TestHandler_Bulk_DeleteViaOperations(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)
	createRec := doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	var created struct{ ID string }
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}

	body := `{"Operations":[{"method":"DELETE","path":"/Users/` + created.ID + `","bulkId":"1"}]}`
	rec := doRequest(h, http.MethodPost, "/scim/v2/Bulk", body, "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Operations []struct{ Status string } `json:"Operations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if out.Operations[0].Status != "204" {
		t.Errorf("got status %q, want 204", out.Operations[0].Status)
	}

	getRec := doRequest(h, http.MethodGet, "/scim/v2/Users/"+created.ID, "", "secret-token")
	if getRec.Code != http.StatusNotFound {
		t.Errorf("expected the bulk DELETE to have actually removed the user, GET now returns %d", getRec.Code)
	}
}
