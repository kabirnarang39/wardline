package main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

// scimAuthedRequest issues req with SCIM's required Bearer auth and
// content type set, returning the raw response -- shared by the Bulk
// and filter tests below since neither fits scimCreateUser/
// scimCreateGroup's narrower create-only shape
// (e2e_tenant_isolation_test.go).
func scimAuthedRequest(t *testing.T, method, url, scimToken, body string) *http.Response {
	t.Helper()
	var bodyReader *bytes.Buffer
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	} else {
		bodyReader = bytes.NewBufferString("")
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+scimToken)
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestServeEndToEnd_SCIMBulkCreatesUsers proves POST /scim/v2/Bulk (RFC
// 7644 §3.7) against a real running wardline serve: a batch of Create
// operations is dispatched through the real routing/handler logic (not
// a bulk-specific reimplementation, per bulk.go's own doc comment), each
// getting its own 201 in the response, and each user is independently
// fetchable afterward via GET /scim/v2/Users/{id} -- proving the batch
// really provisioned real, persisted resources, not just echoed a
// synthetic per-operation status.
func TestServeEndToEnd_SCIMBulkCreatesUsers(t *testing.T) {
	const scimToken = "scim-bulk-e2e-token"
	t.Setenv("WARDLINE_E2E_SCIM_BULK_TOKEN", scimToken)

	addr, _, stderr, _, _ := startWardline(t, "policy.yaml", `default: allow`, `features:
  scim: true
scim:
  bearer_token_env: "WARDLINE_E2E_SCIM_BULK_TOKEN"`)

	bulkBody := `{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
  "Operations": [
    {"method": "POST", "path": "/Users", "bulkId": "u1", "data": {"userName": "bulk-alice", "active": true}},
    {"method": "POST", "path": "/Users", "bulkId": "u2", "data": {"userName": "bulk-bob", "active": true}},
    {"method": "POST", "path": "/Users", "bulkId": "u3", "data": {"userName": "bulk-carol", "active": false}}
  ]
}`
	resp := scimAuthedRequest(t, http.MethodPost, "http://"+addr+"/scim/v2/Bulk", scimToken, bulkBody)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a well-formed Bulk request, got %d (stderr: %s)", resp.StatusCode, stderr.String())
	}

	var parsed struct {
		Operations []struct {
			BulkID   string `json:"bulkId"`
			Status   string `json:"status"`
			Location string `json:"location"`
		} `json:"Operations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("invalid bulk response: %v", err)
	}
	if len(parsed.Operations) != 3 {
		t.Fatalf("expected 3 operation results, got %d", len(parsed.Operations))
	}
	for _, op := range parsed.Operations {
		if op.Status != "201" {
			t.Errorf("expected bulkId %q to report status 201, got %q", op.BulkID, op.Status)
		}
		if op.Location == "" {
			t.Errorf("expected bulkId %q to report a location, got none", op.BulkID)
		}
		// Each created user is independently fetchable -- the batch
		// provisioned real, persisted resources.
		getResp := scimAuthedRequest(t, http.MethodGet, "http://"+addr+op.Location, scimToken, "")
		_ = getResp.Body.Close()
		if getResp.StatusCode != http.StatusOK {
			t.Errorf("expected the bulk-created user at %s to be independently fetchable, got %d", op.Location, getResp.StatusCode)
		}
	}
}

// TestServeEndToEnd_SCIMBulkTooManyOperationsRejected proves the
// bulk.maxOperations ceiling (RFC 7644 §3.7) is enforced against a real
// server, not just documented -- an unbounded batch is exactly the kind
// of resource-exhaustion gap this repo's conventions call out as a
// silent security/availability risk if left unenforced.
func TestServeEndToEnd_SCIMBulkTooManyOperationsRejected(t *testing.T) {
	const scimToken = "scim-bulk-toomany-e2e-token"
	t.Setenv("WARDLINE_E2E_SCIM_BULK_TOOMANY_TOKEN", scimToken)

	addr, _, stderr, _, _ := startWardline(t, "policy.yaml", `default: allow`, `features:
  scim: true
scim:
  bearer_token_env: "WARDLINE_E2E_SCIM_BULK_TOOMANY_TOKEN"`)

	var ops bytes.Buffer
	ops.WriteString(`{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[`)
	for i := range 101 { // one past maxBulkOperations (100)
		if i > 0 {
			ops.WriteString(",")
		}
		fmt.Fprintf(&ops, `{"method":"POST","path":"/Users","data":{"userName":"bulk-user-%d"}}`, i)
	}
	ops.WriteString(`]}`)

	resp := scimAuthedRequest(t, http.MethodPost, "http://"+addr+"/scim/v2/Bulk", scimToken, ops.String())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 413 or 400 for a Bulk request over maxOperations, got %d (stderr: %s)", resp.StatusCode, stderr.String())
	}
}

// TestServeEndToEnd_SCIMFilterQuery proves GET /scim/v2/Users?filter=...
// (RFC 7644 §3.4.2.2) against a real server: a real filter expression
// (not the old eq-only substring heuristic filter.go's doc comment
// describes replacing) narrows the result set correctly, and a
// malformed filter expression is rejected with 400 rather than
// silently matching everything or nothing.
func TestServeEndToEnd_SCIMFilterQuery(t *testing.T) {
	const scimToken = "scim-filter-e2e-token"
	t.Setenv("WARDLINE_E2E_SCIM_FILTER_TOKEN", scimToken)

	addr, _, stderr, _, _ := startWardline(t, "policy.yaml", `default: allow`, `features:
  scim: true
scim:
  bearer_token_env: "WARDLINE_E2E_SCIM_FILTER_TOKEN"`)

	scimCreateUser(t, addr, scimToken, "filter-active-alice")
	scimCreateUser(t, addr, scimToken, "filter-active-bob")
	inactiveID := scimCreateUser(t, addr, scimToken, "filter-inactive-carol")
	deactivateResp := scimAuthedRequest(t, http.MethodPatch, "http://"+addr+"/scim/v2/Users/"+inactiveID, scimToken,
		`{"Operations":[{"op":"replace","path":"active","value":false}]}`)
	_ = deactivateResp.Body.Close()
	if deactivateResp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 deactivating carol, got %d (stderr: %s)", deactivateResp.StatusCode, stderr.String())
	}

	// Happy path: a real comparison filter narrows the result set.
	activeResp := scimAuthedRequest(t, http.MethodGet, "http://"+addr+"/scim/v2/Users?filter="+url.QueryEscape("active eq true"), scimToken, "")
	defer func() { _ = activeResp.Body.Close() }()
	if activeResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for a valid filter query, got %d (stderr: %s)", activeResp.StatusCode, stderr.String())
	}
	// handleUsersCollection's GET path returns a bare JSON array, not a
	// ListResponse envelope -- see http_handler.go's own
	// writeJSON(w, http.StatusOK, out) call.
	var users []struct {
		UserName string `json:"userName"`
	}
	if err := json.NewDecoder(activeResp.Body).Decode(&users); err != nil {
		t.Fatalf("invalid filtered list response: %v", err)
	}
	names := make(map[string]bool, len(users))
	for _, u := range users {
		names[u.UserName] = true
	}
	if !names["filter-active-alice"] || !names["filter-active-bob"] {
		t.Errorf("expected both active users in filtered results, got %+v", users)
	}
	if names["filter-inactive-carol"] {
		t.Errorf("expected the deactivated user excluded from an active eq true filter, got %+v", users)
	}

	// Edge case: a malformed filter expression is a real parse error,
	// not silently ignored.
	badFilterResp := scimAuthedRequest(t, http.MethodGet, "http://"+addr+"/scim/v2/Users?filter="+url.QueryEscape("active eq"), scimToken, "")
	_ = badFilterResp.Body.Close()
	if badFilterResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for a malformed filter expression, got %d (stderr: %s)", badFilterResp.StatusCode, stderr.String())
	}
}
