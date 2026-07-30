package adapter_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/scim/adapter"
	"github.com/kabirnarang39/wardline/internal/features/scim/usecase"
)

func TestHandler_CreateUser_RequiresBearerToken(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := adapter.NewHandler(svc, nil, "secret-token")

	req := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", bytes.NewReader([]byte(`{"userName":"alice","active":true}`)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no bearer token: got %d, want 401", rec.Code)
	}
}

func TestHandler_CreateAndGetUser(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := adapter.NewHandler(svc, nil, "secret-token")

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
