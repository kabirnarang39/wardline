package adapter

import (
	"net/http"
	"strings"
)

// This file serves the three RFC 7643 discovery endpoints a real SCIM
// client (Okta, Azure AD) probes before provisioning anything:
// /ServiceProviderConfig (§5, what this server supports),
// /ResourceTypes (§6, which resource types exist and where), and
// /Schemas (§7, each resource type's actual attributes). Every value
// below describes what this Handler ACTUALLY implements -- e.g.
// patch.supported=true because handleUserItem/handleGroupItem really
// do serve PATCH, filter.supported=true because filter.go really does
// parse a general SCIM filter grammar now -- not a boilerplate template
// claiming capabilities this server doesn't have; an IdP that trusts
// this document to decide what requests to send would get a working
// integration, not a false promise it discovers by trial and error.

type serviceProviderConfigFeature struct {
	Supported bool `json:"supported"`
}

type serviceProviderConfigBulk struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

type serviceProviderConfigFilter struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

type authenticationScheme struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Primary     bool   `json:"primary"`
}

type serviceProviderConfig struct {
	Schemas               []string                     `json:"schemas"`
	Patch                 serviceProviderConfigFeature `json:"patch"`
	Bulk                  serviceProviderConfigBulk    `json:"bulk"`
	Filter                serviceProviderConfigFilter  `json:"filter"`
	ChangePassword        serviceProviderConfigFeature `json:"changePassword"`
	Sort                  serviceProviderConfigFeature `json:"sort"`
	ETag                  serviceProviderConfigFeature `json:"etag"`
	AuthenticationSchemes []authenticationScheme       `json:"authenticationSchemes"`
}

func (h *Handler) handleServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, serviceProviderConfig{
		Schemas:        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		Patch:          serviceProviderConfigFeature{Supported: true},
		Bulk:           serviceProviderConfigBulk{Supported: true, MaxOperations: maxBulkOperations, MaxPayloadSize: maxBulkPayloadBytes},
		Filter:         serviceProviderConfigFilter{Supported: true, MaxResults: 0}, // 0 -- this implementation has no page-size cap of its own to advertise (no pagination yet)
		ChangePassword: serviceProviderConfigFeature{Supported: false},
		Sort:           serviceProviderConfigFeature{Supported: false},
		ETag:           serviceProviderConfigFeature{Supported: false},
		AuthenticationSchemes: []authenticationScheme{{
			Type:        "oauthbearertoken",
			Name:        "OAuth Bearer Token",
			Description: "A single, per-deployment shared bearer token (scim.bearer_token_env) presented as \"Authorization: Bearer <token>\"",
			Primary:     true,
		}},
	})
}

type resourceType struct {
	Schemas  []string         `json:"schemas"`
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Endpoint string           `json:"endpoint"`
	Schema   string           `json:"schema"`
	Meta     resourceTypeMeta `json:"meta"`
}

type resourceTypeMeta struct {
	ResourceType string `json:"resourceType"`
	Location     string `json:"location"`
}

var resourceTypes = []resourceType{
	{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		ID:       "User",
		Name:     "User",
		Endpoint: "/Users",
		Schema:   "urn:ietf:params:scim:schemas:core:2.0:User",
		Meta:     resourceTypeMeta{ResourceType: "ResourceType", Location: "/scim/v2/ResourceTypes/User"},
	},
	{
		Schemas:  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		ID:       "Group",
		Name:     "Group",
		Endpoint: "/Groups",
		Schema:   "urn:ietf:params:scim:schemas:core:2.0:Group",
		Meta:     resourceTypeMeta{ResourceType: "ResourceType", Location: "/scim/v2/ResourceTypes/Group"},
	},
}

func (h *Handler) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// Groups isn't wired (h.groups == nil): don't advertise a resource
	// type this deployment can't actually serve -- an IdP that discovers
	// /Groups here but gets 501 on every request to it is worse off than
	// one that never saw it listed.
	types := resourceTypes
	if h.groups == nil {
		types = resourceTypes[:1]
	}
	writeJSON(w, http.StatusOK, types)
}

func (h *Handler) handleResourceTypeItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/scim/v2/ResourceTypes/")
	for _, rt := range resourceTypes {
		if rt.ID == id {
			if id == "Group" && h.groups == nil {
				break
			}
			writeJSON(w, http.StatusOK, rt)
			return
		}
	}
	writeSCIMError(w, http.StatusNotFound, "not found")
}

type schemaAttribute struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	MultiValued bool   `json:"multiValued"`
	Required    bool   `json:"required"`
	CaseExact   bool   `json:"caseExact"`
	Mutability  string `json:"mutability"`
	Returned    string `json:"returned"`
	Uniqueness  string `json:"uniqueness"`
}

type schema struct {
	Schemas     []string          `json:"schemas"`
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Attributes  []schemaAttribute `json:"attributes"`
	Meta        resourceTypeMeta  `json:"meta"`
}

var schemas = []schema{
	{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		ID:          "urn:ietf:params:scim:schemas:core:2.0:User",
		Name:        "User",
		Description: "Wardline SCIM User -- tracks only userName and active (see scim.md's known limitations: no name, email, or other SCIM User attributes)",
		Attributes: []schemaAttribute{
			{Name: "userName", Type: "string", Required: true, CaseExact: false, Mutability: "readWrite", Returned: "default", Uniqueness: "server"},
			{Name: "active", Type: "boolean", Required: false, Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
		},
		Meta: resourceTypeMeta{ResourceType: "Schema", Location: "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"},
	},
	{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Schema"},
		ID:          "urn:ietf:params:scim:schemas:core:2.0:Group",
		Name:        "Group",
		Description: "Wardline SCIM Group -- displayName and members (User ID references) only",
		Attributes: []schemaAttribute{
			{Name: "displayName", Type: "string", Required: true, CaseExact: false, Mutability: "readWrite", Returned: "default", Uniqueness: "server"},
			{Name: "members", Type: "complex", MultiValued: true, Required: false, Mutability: "readWrite", Returned: "default", Uniqueness: "none"},
		},
		Meta: resourceTypeMeta{ResourceType: "Schema", Location: "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:Group"},
	},
}

func (h *Handler) handleSchemas(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	out := schemas
	if h.groups == nil {
		out = schemas[:1]
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) handleSchemaItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeSCIMError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/scim/v2/Schemas/")
	for _, s := range schemas {
		if s.ID == id {
			if s.Name == "Group" && h.groups == nil {
				break
			}
			writeJSON(w, http.StatusOK, s)
			return
		}
	}
	writeSCIMError(w, http.StatusNotFound, "not found")
}
