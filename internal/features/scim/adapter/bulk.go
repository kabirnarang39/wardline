package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// maxBulkOperations bounds how many operations one Bulk request may
// contain -- RFC 7644 §3.7 requires the server to advertise and enforce
// this (see ServiceProviderConfig's own bulk.maxOperations), so a
// client can't submit an unbounded batch in one request.
const maxBulkOperations = 100

// maxBulkPayloadBytes bounds the whole Bulk request body -- advertised
// as bulk.maxPayloadSize in ServiceProviderConfig, same reasoning as
// maxSCIMBodyBytes for every other endpoint, just larger since a Bulk
// request legitimately batches many resources' worth of JSON.
const maxBulkPayloadBytes = 1 << 20 // 1 MiB

// bulkOperationRequest is one RFC 7644 §3.7.2 BulkRequest Operation.
type bulkOperationRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	BulkID string          `json:"bulkId,omitempty"`
	Data   json.RawMessage `json:"data,omitempty"`
}

type bulkRequest struct {
	Schemas      []string               `json:"schemas"`
	Operations   []bulkOperationRequest `json:"Operations"`
	FailOnErrors int                    `json:"failOnErrors,omitempty"`
}

// bulkOperationResponse is one RFC 7644 §3.7.3 BulkResponse Operation.
type bulkOperationResponse struct {
	Location string          `json:"location,omitempty"`
	Method   string          `json:"method"`
	BulkID   string          `json:"bulkId,omitempty"`
	Status   string          `json:"status"`
	Response json.RawMessage `json:"response,omitempty"`
}

type bulkResponse struct {
	Schemas    []string                `json:"schemas"`
	Operations []bulkOperationResponse `json:"Operations"`
}

// recordingResponseWriter is a minimal http.ResponseWriter that
// captures the status/body a sub-request produced, so handleBulk can
// fan an operation out through the SAME routing and handler logic every
// individual /scim/v2/Users, /scim/v2/Groups endpoint already
// implements (validation, 404s, conflict handling, PATCH semantics --
// all of it) rather than re-implementing any of that a second time for
// the bulk path specifically. Deliberately not net/http/httptest's
// ResponseRecorder: that's a testing package, and this runs on the real
// request path, not in a test.
type recordingResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newRecordingResponseWriter() *recordingResponseWriter {
	return &recordingResponseWriter{header: make(http.Header), status: http.StatusOK}
}

func (w *recordingResponseWriter) Header() http.Header { return w.header }

func (w *recordingResponseWriter) Write(p []byte) (int, error) { return w.body.Write(p) }

func (w *recordingResponseWriter) WriteHeader(status int) { w.status = status }

// handleBulk serves POST /scim/v2/Bulk (RFC 7644 §3.7): a client-defined
// list of Create/Update/Delete operations against /Users and /Groups,
// executed in order, one response entry per operation. Each operation
// is dispatched through h.mux -- the exact same routing and handler
// logic (validation, conflict/404 handling, PATCH semantics) the
// individual endpoints already implement, so Bulk can never drift from
// what a direct call to the same path/method/body would do.
//
// Deliberately out of scope, and this is a real, documented scope
// boundary, not a silent gap: cross-operation bulkId substitution (RFC
// 7644 §3.7.2's "bulkId:<id>" reference syntax, letting a later
// operation in the same request reference an earlier operation's
// not-yet-known resource ID -- e.g. create a User then add it to a
// Group by referencing that User's bulkId in the same batch). Each
// operation here executes independently; a client that needs to
// reference a just-created resource's ID within the same batch must
// split it across two Bulk requests instead. This is the shape every
// SCIM client actually generates for bulk User/Group provisioning
// (batches of independent Create operations against a stable target),
// not the rarer same-batch cross-reference case.
func (h *Handler) handleBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBulkPayloadBytes)
	var req bulkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalid bulk request body")
		return
	}
	if len(req.Operations) == 0 {
		writeSCIMError(w, http.StatusBadRequest, "bulk request must contain a non-empty Operations array")
		return
	}
	if len(req.Operations) > maxBulkOperations {
		writeSCIMError(w, http.StatusBadRequest, fmt.Sprintf("bulk request exceeds the maximum of %d operations", maxBulkOperations))
		return
	}

	resp := bulkResponse{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:BulkResponse"}}
	errorCount := 0
	for _, op := range req.Operations {
		opResp := h.dispatchBulkOperation(op)
		resp.Operations = append(resp.Operations, opResp)
		if opResp.Status[0] != '2' { // not a 2xx
			errorCount++
			// failOnErrors (RFC 7644 §3.7.2): stop after this many
			// operation failures rather than running the rest of the
			// batch. 0 (the default, unset) means "no limit" -- run
			// every operation regardless of earlier failures, matching
			// the spec's own default.
			if req.FailOnErrors > 0 && errorCount >= req.FailOnErrors {
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) dispatchBulkOperation(op bulkOperationRequest) bulkOperationResponse {
	if op.Method == "" || op.Path == "" {
		return bulkOperationResponse{Method: op.Method, BulkID: op.BulkID, Status: "400"}
	}
	subReq, err := http.NewRequest(op.Method, "/scim/v2"+op.Path, bytes.NewReader(op.Data))
	if err != nil {
		return bulkOperationResponse{Method: op.Method, BulkID: op.BulkID, Status: "400"}
	}
	subReq.Header.Set("Content-Type", "application/scim+json")
	rec := newRecordingResponseWriter()
	h.mux.ServeHTTP(rec, subReq)

	opResp := bulkOperationResponse{
		Method: op.Method,
		BulkID: op.BulkID,
		Status: fmt.Sprintf("%d", rec.status),
	}
	if rec.body.Len() > 0 {
		opResp.Response = json.RawMessage(rec.body.Bytes())
	}
	if location := rec.header.Get("Location"); location != "" {
		opResp.Location = location
	}
	return opResp
}
