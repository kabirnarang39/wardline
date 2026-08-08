package adapter_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/scim/adapter"
	"github.com/kabirnarang39/wardline/internal/features/scim/usecase"
)

// testLogger discards output -- same pattern as every other test in this
// repo that needs a *slog.Logger (see rbac/adapter/middleware_test.go).
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestHandler(svc *usecase.ProvisioningService) *adapter.Handler {
	return adapter.NewHandler(svc, nil, "secret-token", testLogger())
}

func doRequest(h *adapter.Handler, method, path, body, bearer string) *httptest.ResponseRecorder {
	var r io.Reader
	if body != "" {
		r = bytes.NewReader([]byte(body))
	}
	req := httptest.NewRequest(method, path, r)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHandler_CreateUser_RequiresBearerToken(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(`{"userName":"alice","active":true}`)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer token: got %d, want 401", rec.Code)
	}
}

func TestHandler_CreateUser_WrongBearerToken_Returns401(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	// A nonempty-but-wrong token must fail exactly like no token at all --
	// this is the case a degenerate "just check the prefix" regression
	// would slip past, since it doesn't touch the empty-header path.
	rec := doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "not-the-secret")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer token: got %d, want 401", rec.Code)
	}
	if _, ok := svc.GetUserByName("alice"); ok {
		t.Fatal("user must not be created when auth fails")
	}
}

func TestHandler_CreateAndGetUser(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(`{"userName":"alice","active":true}`)))
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, want 201, body %s", rec.Code, rec.Body.String())
	}

	u, ok := svc.GetUserByName("alice")
	if !ok || !u.Active {
		t.Fatalf("alice not found or inactive after create: %+v, ok=%v", u, ok)
	}
}

func TestHandler_CreateUser_SetsSCIMContentType(t *testing.T) {
	// Regression test: writeJSON must set Content-Type before
	// WriteHeader -- Go freezes headers at WriteHeader/first-Write time,
	// so a 201 written before the header is set silently drops it.
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	rec := doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, want 201, body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/scim+json" {
		t.Fatalf("Content-Type: got %q, want %q", got, "application/scim+json")
	}
}

func TestHandler_CreateUser_DuplicateUserName_Returns409(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	rec := doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":false}`, "secret-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate userName: got %d, want 409, body %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_CreateUser_MalformedJSON_Returns400(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	rec := doRequest(h, http.MethodPost, "/scim/v2/Users", `not json`, "secret-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: got %d, want 400", rec.Code)
	}
}

func TestHandler_CreateUser_OversizedBody_Returns400(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	// One byte over the 64 KiB cap; content doesn't matter since the
	// reader should be cut off before the body is parsed as JSON.
	oversized := bytes.Repeat([]byte("a"), (64<<10)+1)
	rec := doRequest(h, http.MethodPost, "/scim/v2/Users", string(oversized), "secret-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d, want 400", rec.Code)
	}
}

func TestHandler_ListUsers(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"bob","active":false}`, "secret-token")

	rec := doRequest(h, http.MethodGet, "/scim/v2/Users", "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out []struct {
		UserName string `json:"userName"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 users, got %d", len(out))
	}
}

// TestHandler_ListUsers_FilterByUserNameEq covers the one filter shape
// real SCIM clients (Okta, Azure AD) send: an existence check before
// create. Anything wider than this is deliberately out of scope -- see
// TestHandler_ListUsers_UnsupportedFilterExpression_Returns400.
func TestHandler_ListUsers_FilterByUserNameEq(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"bob","active":false}`, "secret-token")

	path := "/scim/v2/Users?filter=" + url.QueryEscape(`userName eq "alice"`)
	rec := doRequest(h, http.MethodGet, path, "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered list: got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out []struct {
		UserName string `json:"userName"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(out) != 1 || out[0].UserName != "alice" {
		t.Fatalf("got %d users, want exactly [alice]: %+v", len(out), out)
	}
}

// TestHandler_ListUsers_NoFilterReturnsFullList is explicit regression
// coverage: adding filter support must not change the no-filter default
// (byte-for-byte backward compat), duplicating TestHandler_ListUsers'
// assertions on the un-filtered request path.
func TestHandler_ListUsers_NoFilterReturnsFullList(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"bob","active":false}`, "secret-token")

	rec := doRequest(h, http.MethodGet, "/scim/v2/Users", "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out []struct {
		UserName string `json:"userName"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 users, got %d", len(out))
	}
}

// TestHandler_ListUsers_UnsupportedFilterExpression_Returns400 is the
// scope boundary: any filter expression beyond the narrow `eq` case
// (a different operator, a different attribute, "and"/"or") must be
// rejected with 400, not silently answered with the unfiltered list --
// a client that sent a filter it expected honored getting the wrong
// list back is a worse silent-failure mode than a clear rejection.
func TestHandler_ListUsers_UnsupportedFilterExpression_Returns400(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")

	cases := []string{
		`userName co "ali"`,
		`userName eq "alice" and active eq true`,
		`displayName eq "alice"`,
		// Regression: this also starts with `userName eq "` and ends with
		// `"`, so a naive prefix/suffix check alone wrongly accepts it
		// (extracting the garbage value `alice" and userName eq "bob`).
		`userName eq "alice" and userName eq "bob"`,
		// M1 regression: exactly the prefix, with no closing quote of its
		// own -- the same trailing quote satisfies both HasPrefix and
		// HasSuffix, so a naive check alone wrongly accepts this as an
		// empty-value filter (200 + empty list) instead of rejecting an
		// unterminated one (400).
		`userName eq "`,
	}
	for _, filter := range cases {
		path := "/scim/v2/Users?filter=" + url.QueryEscape(filter)
		rec := doRequest(h, http.MethodGet, path, "", "secret-token")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("filter %q: got %d, want 400, body %s", filter, rec.Code, rec.Body.String())
		}
	}
}

func TestHandler_GetUserByID(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	created, _ := svc.GetUserByName("alice")

	rec := doRequest(h, http.MethodGet, "/scim/v2/Users/"+created.ID, "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var got struct {
		UserName string `json:"userName"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if got.UserName != "alice" {
		t.Fatalf("expected alice, got %q", got.UserName)
	}
}

func TestHandler_GetUserByID_NotFound_Returns404(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	rec := doRequest(h, http.MethodGet, "/scim/v2/Users/does-not-exist", "", "secret-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing user: got %d, want 404", rec.Code)
	}
}

func TestHandler_DeleteUser(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	created, _ := svc.GetUserByName("alice")

	rec := doRequest(h, http.MethodDelete, "/scim/v2/Users/"+created.ID, "", "secret-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d, want 204, body %s", rec.Code, rec.Body.String())
	}
	if _, ok := svc.GetUserByName("alice"); ok {
		t.Fatal("expected alice to be gone after delete")
	}
}

func TestHandler_DeleteUser_NotFound_Returns404(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	rec := doRequest(h, http.MethodDelete, "/scim/v2/Users/does-not-exist", "", "secret-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing user: got %d, want 404", rec.Code)
	}
}

func TestHandler_PatchActive_TogglesActive(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	created, _ := svc.GetUserByName("alice")

	body := `{"Operations":[{"op":"replace","path":"active","value":false}]}`
	rec := doRequest(h, http.MethodPatch, "/scim/v2/Users/"+created.ID, body, "secret-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("patch active: got %d, want 204, body %s", rec.Code, rec.Body.String())
	}

	u, ok := svc.GetUserByName("alice")
	if !ok || u.Active {
		t.Fatalf("expected alice to be inactive after PATCH: %+v, ok=%v", u, ok)
	}
}

func TestHandler_PatchActive_NotFound_Returns404(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	body := `{"Operations":[{"op":"replace","path":"active","value":false}]}`
	rec := doRequest(h, http.MethodPatch, "/scim/v2/Users/does-not-exist", body, "secret-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("patch missing user: got %d, want 404", rec.Code)
	}
}

// TestHandler_PatchActive_FlatBody_Returns400_NoSilentNoOp is the
// regression for the offboarding footgun: a PATCH missing the Operations
// wrapper (a flat {"op":...,"path":"active"}) must be rejected with 400,
// NOT silently 204'd while leaving the user active -- an operator
// deactivating a user must never see success without the change applying.
func TestHandler_PatchActive_FlatBody_Returns400_NoSilentNoOp(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	created, _ := svc.GetUserByName("alice")

	body := `{"op":"replace","path":"active","value":false}`
	rec := doRequest(h, http.MethodPatch, "/scim/v2/Users/"+created.ID, body, "secret-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("flat PATCH body: got %d, want 400, body %s", rec.Code, rec.Body.String())
	}
	if u, ok := svc.GetUserByName("alice"); !ok || !u.Active {
		t.Fatalf("alice must remain active after a rejected PATCH: %+v, ok=%v", u, ok)
	}
}

// TestHandler_PatchActive_UnsupportedOp_Returns400 rejects a well-formed
// Operations array that contains no operation this handler supports (only
// replace of "active" is), rather than 204'ing a no-op the client believes
// took effect.
func TestHandler_PatchActive_UnsupportedOp_Returns400(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"alice","active":true}`, "secret-token")
	created, _ := svc.GetUserByName("alice")

	body := `{"Operations":[{"op":"replace","path":"displayName","value":false}]}`
	rec := doRequest(h, http.MethodPatch, "/scim/v2/Users/"+created.ID, body, "secret-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported op: got %d, want 400, body %s", rec.Code, rec.Body.String())
	}
}

func TestNewHandler_EmptyBearerTokenPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected NewHandler to panic on an empty bearerToken")
		}
	}()
	adapter.NewHandler(usecase.NewProvisioningService(), nil, "", testLogger())
}

// --- Groups ---

// newGroupTestHandler wires a Handler whose ProvisioningService feeds a
// real BindingStore, so tests can assert group membership changes are
// actually derived into RBAC bindings, not just stored inertly.
func newGroupTestHandler(svc *usecase.ProvisioningService, store *usecase.BindingStore) *adapter.Handler {
	svc.SetBindingStore(store)
	return adapter.NewHandler(svc, svc, "secret-token", testLogger())
}

// createTestUser creates a User via the handler and returns its ID --
// group membership references User IDs, so every Groups test needs at
// least one User to exist first.
func createTestUser(t *testing.T, h *adapter.Handler, userName string) string {
	t.Helper()
	rec := doRequest(h, http.MethodPost, "/scim/v2/Users", `{"userName":"`+userName+`","active":true}`, "secret-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user %q: got %d, want 201, body %s", userName, rec.Code, rec.Body.String())
	}
	var created struct{ ID string }
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("invalid create-user response: %v", err)
	}
	return created.ID
}

func TestHandler_CreateGroup_ProvisionsBinding(t *testing.T) {
	svc := usecase.NewProvisioningService()
	store := usecase.NewBindingStore()
	h := newGroupTestHandler(svc, store)

	aliceID := createTestUser(t, h, "alice")

	groupBody := `{"displayName":"wardline:tenant-acme:role-admin","members":[{"value":"` + aliceID + `"}]}`
	rec := doRequest(h, http.MethodPost, "/scim/v2/Groups", groupBody, "secret-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create group: got %d, want 201, body %s", rec.Code, rec.Body.String())
	}

	cluster, scoped := store.Bindings("alice")
	if len(cluster) != 0 || len(scoped) != 1 || scoped[0].RoleName != "admin" || scoped[0].Tenant != "acme" {
		t.Fatalf("alice's derived bindings = cluster=%+v scoped=%+v, want one scoped admin/acme binding", cluster, scoped)
	}
}

func TestHandler_CreateGroup_RequiresBearerToken(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader([]byte(`{"displayName":"wardline:role-viewer"}`)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer token: got %d, want 401", rec.Code)
	}
}

func TestHandler_CreateGroup_WrongBearerToken_Returns401(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	rec := doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-viewer"}`, "not-the-secret")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong bearer token: got %d, want 401", rec.Code)
	}
}

func TestHandler_CreateGroup_SetsSCIMContentType(t *testing.T) {
	// Regression test, same rationale as the Users equivalent -- writeJSON
	// must set Content-Type before WriteHeader.
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	rec := doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-viewer"}`, "secret-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: got %d, want 201, body %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/scim+json" {
		t.Fatalf("Content-Type: got %q, want %q", got, "application/scim+json")
	}
}

func TestHandler_CreateGroup_DuplicateDisplayName_Returns409(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-viewer"}`, "secret-token")
	rec := doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-viewer"}`, "secret-token")
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate displayName: got %d, want 409, body %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_CreateGroup_MalformedJSON_Returns400(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	rec := doRequest(h, http.MethodPost, "/scim/v2/Groups", `not json`, "secret-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed body: got %d, want 400", rec.Code)
	}
}

func TestHandler_CreateGroup_OversizedBody_Returns400(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	oversized := bytes.Repeat([]byte("a"), (64<<10)+1)
	rec := doRequest(h, http.MethodPost, "/scim/v2/Groups", string(oversized), "secret-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d, want 400", rec.Code)
	}
}

func TestHandler_ListGroups(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-viewer"}`, "secret-token")
	doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-admin"}`, "secret-token")

	rec := doRequest(h, http.MethodGet, "/scim/v2/Groups", "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out []struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(out))
	}
}

// TestHandler_ListGroups_FilterByDisplayNameEq mirrors
// TestHandler_ListUsers_FilterByUserNameEq for Groups.
func TestHandler_ListGroups_FilterByDisplayNameEq(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-viewer"}`, "secret-token")
	doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-admin"}`, "secret-token")

	path := "/scim/v2/Groups?filter=" + url.QueryEscape(`displayName eq "wardline:role-viewer"`)
	rec := doRequest(h, http.MethodGet, path, "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered list: got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out []struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(out) != 1 || out[0].DisplayName != "wardline:role-viewer" {
		t.Fatalf("got %d groups, want exactly [wardline:role-viewer]: %+v", len(out), out)
	}
}

// TestHandler_ListGroups_NoFilterReturnsFullList mirrors
// TestHandler_ListUsers_NoFilterReturnsFullList for Groups.
func TestHandler_ListGroups_NoFilterReturnsFullList(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-viewer"}`, "secret-token")
	doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-admin"}`, "secret-token")

	rec := doRequest(h, http.MethodGet, "/scim/v2/Groups", "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out []struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(out))
	}
}

// TestHandler_ListGroups_UnsupportedFilterExpression_Returns400 mirrors
// TestHandler_ListUsers_UnsupportedFilterExpression_Returns400 for Groups.
func TestHandler_ListGroups_UnsupportedFilterExpression_Returns400(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-viewer"}`, "secret-token")

	cases := []string{
		`displayName co "viewer"`,
		`displayName eq "wardline:role-viewer" and active eq true`,
		`userName eq "wardline:role-viewer"`,
		// Regression: Groups equivalent of the Users
		// eq-followed-by-another-eq-clause repro above.
		`displayName eq "wardline:role-viewer" and displayName eq "wardline:role-admin"`,
		// M1 regression: Groups equivalent of the Users unterminated-filter
		// repro above.
		`displayName eq "`,
	}
	for _, filter := range cases {
		path := "/scim/v2/Groups?filter=" + url.QueryEscape(filter)
		rec := doRequest(h, http.MethodGet, path, "", "secret-token")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("filter %q: got %d, want 400, body %s", filter, rec.Code, rec.Body.String())
		}
	}
}

func TestHandler_GetGroupByID(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	rec := doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-viewer"}`, "secret-token")
	var created struct{ ID string }
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	getRec := doRequest(h, http.MethodGet, "/scim/v2/Groups/"+created.ID, "", "secret-token")
	if getRec.Code != http.StatusOK {
		t.Fatalf("get: got %d, want 200, body %s", getRec.Code, getRec.Body.String())
	}
	var got struct {
		DisplayName string `json:"displayName"`
	}
	if err := json.Unmarshal(getRec.Body.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if got.DisplayName != "wardline:role-viewer" {
		t.Fatalf("expected wardline:role-viewer, got %q", got.DisplayName)
	}
}

func TestHandler_GetGroupByID_NotFound_Returns404(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	rec := doRequest(h, http.MethodGet, "/scim/v2/Groups/does-not-exist", "", "secret-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing group: got %d, want 404", rec.Code)
	}
}

func TestHandler_DeleteGroup_RemovesBinding(t *testing.T) {
	svc := usecase.NewProvisioningService()
	store := usecase.NewBindingStore()
	h := newGroupTestHandler(svc, store)

	aliceID := createTestUser(t, h, "alice")
	createRec := doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-admin","members":[{"value":"`+aliceID+`"}]}`, "secret-token")
	var created struct{ ID string }
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	if cluster, _ := store.Bindings("alice"); len(cluster) != 1 {
		t.Fatalf("expected alice to have a binding before delete, got %+v", cluster)
	}

	rec := doRequest(h, http.MethodDelete, "/scim/v2/Groups/"+created.ID, "", "secret-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d, want 204, body %s", rec.Code, rec.Body.String())
	}

	if cluster, _ := store.Bindings("alice"); len(cluster) != 0 {
		t.Fatalf("expected alice's binding to be revoked after group delete, got %+v", cluster)
	}
	if _, err := svc.GetGroup(created.ID); err == nil {
		t.Fatal("expected group to be gone after delete")
	}
}

func TestHandler_DeleteGroup_NotFound_Returns404(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	rec := doRequest(h, http.MethodDelete, "/scim/v2/Groups/does-not-exist", "", "secret-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing group: got %d, want 404", rec.Code)
	}
}

func TestHandler_PatchGroupMembers_AddMember_UpdatesBinding(t *testing.T) {
	svc := usecase.NewProvisioningService()
	store := usecase.NewBindingStore()
	h := newGroupTestHandler(svc, store)

	aliceID := createTestUser(t, h, "alice")
	bobID := createTestUser(t, h, "bob")

	createRec := doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-admin","members":[{"value":"`+aliceID+`"}]}`, "secret-token")
	var created struct{ ID string }
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	patchBody := `{"Operations":[{"op":"add","path":"members","value":[{"value":"` + bobID + `"}]}]}`
	rec := doRequest(h, http.MethodPatch, "/scim/v2/Groups/"+created.ID, patchBody, "secret-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("patch add member: got %d, want 204, body %s", rec.Code, rec.Body.String())
	}

	cluster, _ := store.Bindings("bob")
	if len(cluster) != 1 || cluster[0].RoleName != "admin" {
		t.Fatalf("bob's bindings after add = %+v, want one ClusterRoleBinding{RoleName: admin}", cluster)
	}
	// alice must still be bound -- add must not have dropped her.
	cluster, _ = store.Bindings("alice")
	if len(cluster) != 1 {
		t.Fatalf("alice's bindings after adding bob = %+v, want still one binding", cluster)
	}
}

func TestHandler_PatchGroupMembers_RemoveMember_UpdatesBinding(t *testing.T) {
	svc := usecase.NewProvisioningService()
	store := usecase.NewBindingStore()
	h := newGroupTestHandler(svc, store)

	aliceID := createTestUser(t, h, "alice")
	bobID := createTestUser(t, h, "bob")

	createRec := doRequest(h, http.MethodPost, "/scim/v2/Groups",
		`{"displayName":"wardline:role-admin","members":[{"value":"`+aliceID+`"},{"value":"`+bobID+`"}]}`, "secret-token")
	var created struct{ ID string }
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	patchBody := `{"Operations":[{"op":"remove","path":"members","value":[{"value":"` + bobID + `"}]}]}`
	rec := doRequest(h, http.MethodPatch, "/scim/v2/Groups/"+created.ID, patchBody, "secret-token")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("patch remove member: got %d, want 204, body %s", rec.Code, rec.Body.String())
	}

	cluster, _ := store.Bindings("bob")
	if len(cluster) != 0 {
		t.Fatalf("bob's bindings after removal = %+v, want none", cluster)
	}
	cluster, _ = store.Bindings("alice")
	if len(cluster) != 1 {
		t.Fatalf("alice's bindings after removing bob = %+v, want still one binding", cluster)
	}
}

func TestHandler_PatchGroupMembers_NotFound_Returns404(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	patchBody := `{"Operations":[{"op":"add","path":"members","value":[{"value":"some-id"}]}]}`
	rec := doRequest(h, http.MethodPatch, "/scim/v2/Groups/does-not-exist", patchBody, "secret-token")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("patch missing group: got %d, want 404", rec.Code)
	}
}

func TestHandler_PatchGroupMembers_MalformedJSON_Returns400(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	createRec := doRequest(h, http.MethodPost, "/scim/v2/Groups", `{"displayName":"wardline:role-admin"}`, "secret-token")
	var created struct{ ID string }
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}

	rec := doRequest(h, http.MethodPatch, "/scim/v2/Groups/"+created.ID, `not json`, "secret-token")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed patch body: got %d, want 400", rec.Code)
	}
}

func TestHandler_GroupsRoute_NilGroupProvisioner_Returns501(t *testing.T) {
	// A caller that only wires Users (nil GroupProvisioner) must not
	// panic when a request lands on /scim/v2/Groups.
	svc := usecase.NewProvisioningService()
	h := adapter.NewHandler(svc, nil, "secret-token", testLogger())

	rec := doRequest(h, http.MethodGet, "/scim/v2/Groups", "", "secret-token")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("groups route with nil GroupProvisioner: got %d, want 501", rec.Code)
	}
}
