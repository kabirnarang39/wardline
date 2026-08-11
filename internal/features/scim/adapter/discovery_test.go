package adapter_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/kabirnarang39/wardline/internal/features/scim/usecase"
)

func TestHandler_ServiceProviderConfig_ReflectsActualSupport(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	rec := doRequest(h, http.MethodGet, "/scim/v2/ServiceProviderConfig", "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Patch  struct{ Supported bool } `json:"patch"`
		Bulk   struct{ Supported bool } `json:"bulk"`
		Filter struct{ Supported bool } `json:"filter"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if !out.Patch.Supported || !out.Bulk.Supported || !out.Filter.Supported {
		t.Errorf("expected patch/bulk/filter all supported=true (this Handler really implements all three), got %+v", out)
	}
}

func TestHandler_ServiceProviderConfig_RequiresAuth(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	rec := doRequest(h, http.MethodGet, "/scim/v2/ServiceProviderConfig", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401 for an unauthenticated discovery request", rec.Code)
	}
}

func TestHandler_ResourceTypes_OmitsGroupWhenNotConfigured(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc) // groups == nil

	rec := doRequest(h, http.MethodGet, "/scim/v2/ResourceTypes", "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out []struct{ Name string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(out) != 1 || out[0].Name != "User" {
		t.Errorf("expected exactly [User] when groups isn't configured, got %+v", out)
	}
}

func TestHandler_ResourceTypes_IncludesGroupWhenConfigured(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	rec := doRequest(h, http.MethodGet, "/scim/v2/ResourceTypes", "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out []struct{ Name string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(out) != 2 {
		t.Errorf("expected [User, Group] when groups is configured, got %+v", out)
	}
}

func TestHandler_ResourceTypeItem_UserFound(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	rec := doRequest(h, http.MethodGet, "/scim/v2/ResourceTypes/User", "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_ResourceTypeItem_GroupNotFoundWhenNotConfigured(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc) // groups == nil

	rec := doRequest(h, http.MethodGet, "/scim/v2/ResourceTypes/Group", "", "secret-token")
	if rec.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404 for /ResourceTypes/Group when groups isn't configured", rec.Code)
	}
}

func TestHandler_Schemas_ListsUserAndGroupAttributes(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newGroupTestHandler(svc, usecase.NewBindingStore())

	rec := doRequest(h, http.MethodGet, "/scim/v2/Schemas", "", "secret-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200, body %s", rec.Code, rec.Body.String())
	}
	var out []struct {
		Name       string
		Attributes []struct{ Name string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 schemas (User, Group), got %d", len(out))
	}
	foundUserName, foundActive := false, false
	for _, attr := range out[0].Attributes {
		if attr.Name == "userName" {
			foundUserName = true
		}
		if attr.Name == "active" {
			foundActive = true
		}
	}
	if !foundUserName || !foundActive {
		t.Errorf("expected User schema to list userName and active attributes, got %+v", out[0].Attributes)
	}
}

func TestHandler_SchemaItem_NotFound(t *testing.T) {
	svc := usecase.NewProvisioningService()
	h := newTestHandler(svc)

	rec := doRequest(h, http.MethodGet, "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:NoSuchThing", "", "secret-token")
	if rec.Code != http.StatusNotFound {
		t.Errorf("got %d, want 404 for an unknown schema ID", rec.Code)
	}
}
