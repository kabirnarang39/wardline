package adapter_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kabirnarang39/wardline/internal/features/credential/adapter"
	proxyadapter "github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
)

type fakeBootstrapIssuer struct {
	accessToken, refreshToken string
	err                       error
}

func (f fakeBootstrapIssuer) Bootstrap(secret string) (string, string, error) {
	if f.err != nil {
		return "", "", f.err
	}
	return f.accessToken, f.refreshToken, nil
}

func TestLoginHandler_GET_ServesForm(t *testing.T) {
	h := adapter.NewLoginHandler(fakeBootstrapIssuer{}, 15*time.Minute, true)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/login", nil)

	h.HandleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<form") {
		t.Error("expected the response body to contain a login form")
	}
}

// TestLoginHandler_POST_ValidSecretSetsCookieAndRedirects is the actual
// point of this feature: a successful exchange sets the exact cookie
// name bearerIdentity.Authenticate reads as a fallback, httpOnly,
// SameSite=Strict, and redirects into the dashboard.
func TestLoginHandler_POST_ValidSecretSetsCookieAndRedirects(t *testing.T) {
	h := adapter.NewLoginHandler(fakeBootstrapIssuer{accessToken: "the-access-token"}, 15*time.Minute, true)
	rec := httptest.NewRecorder()
	form := url.Values{"secret": {"good-secret"}}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	h.HandleLogin(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303 (redirect to dashboard)", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard/" {
		t.Errorf("expected redirect to /dashboard/, got %q", loc)
	}
	resp := rec.Result()
	var found *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == proxyadapter.SessionCookieName {
			found = c
		}
	}
	if found == nil {
		t.Fatal("expected a session cookie to be set")
	}
	if found.Value != "the-access-token" {
		t.Errorf("expected the cookie to carry the issued access token, got %q", found.Value)
	}
	if !found.HttpOnly {
		t.Error("expected the session cookie to be HttpOnly")
	}
	if found.SameSite != http.SameSiteStrictMode {
		t.Error("expected the session cookie to be SameSite=Strict")
	}
	if !found.Secure {
		t.Error("expected the session cookie to be Secure when cookieSecure=true")
	}
}

func TestLoginHandler_POST_InsecureCookieOptOut(t *testing.T) {
	h := adapter.NewLoginHandler(fakeBootstrapIssuer{accessToken: "tok"}, 15*time.Minute, false)
	rec := httptest.NewRecorder()
	form := url.Values{"secret": {"good-secret"}}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	h.HandleLogin(rec, req)

	resp := rec.Result()
	for _, c := range resp.Cookies() {
		if c.Name == proxyadapter.SessionCookieName && c.Secure {
			t.Error("expected the session cookie to NOT be Secure when cookieSecure=false")
		}
	}
}

func TestLoginHandler_POST_InvalidSecretReturns401WithNoCookie(t *testing.T) {
	h := adapter.NewLoginHandler(fakeBootstrapIssuer{err: errors.New("invalid credentials")}, 15*time.Minute, true)
	rec := httptest.NewRecorder()
	form := url.Values{"secret": {"wrong"}}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	h.HandleLogin(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
	resp := rec.Result()
	for _, c := range resp.Cookies() {
		if c.Name == proxyadapter.SessionCookieName {
			t.Error("expected no session cookie to be set for a failed login")
		}
	}
}

func TestLoginHandler_POST_MissingSecretReturns401(t *testing.T) {
	h := adapter.NewLoginHandler(fakeBootstrapIssuer{}, 15*time.Minute, true)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dashboard/login", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	h.HandleLogin(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 for a missing secret field", rec.Code)
	}
}

func TestLoginHandler_UnsupportedMethodReturns405(t *testing.T) {
	h := adapter.NewLoginHandler(fakeBootstrapIssuer{}, 15*time.Minute, true)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/dashboard/login", nil)

	h.HandleLogin(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d, want 405", rec.Code)
	}
}

func TestLoginHandler_Logout_ClearsCookieAndRedirects(t *testing.T) {
	h := adapter.NewLoginHandler(fakeBootstrapIssuer{}, 15*time.Minute, true)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dashboard/logout", nil)

	h.HandleLogout(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/dashboard/login" {
		t.Errorf("expected redirect to /dashboard/login, got %q", loc)
	}
	resp := rec.Result()
	var found *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == proxyadapter.SessionCookieName {
			found = c
		}
	}
	if found == nil {
		t.Fatal("expected a Set-Cookie clearing the session cookie")
	}
	if found.MaxAge >= 0 {
		t.Errorf("expected MaxAge < 0 (delete the cookie), got %d", found.MaxAge)
	}
}

func TestLoginHandler_Logout_GETNotAllowed(t *testing.T) {
	h := adapter.NewLoginHandler(fakeBootstrapIssuer{}, 15*time.Minute, true)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/logout", nil)

	h.HandleLogout(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d, want 405 -- logout must not be triggerable by a bare GET (link/prefetch)", rec.Code)
	}
}

// TestLoginHandler_ErrorMessageIsHTMLEscaped guards serveLoginForm's own
// XSS-safety contract even though its current only caller passes static
// strings.
func TestLoginHandler_FormErrorContainsNoRawSecret(t *testing.T) {
	h := adapter.NewLoginHandler(fakeBootstrapIssuer{err: errors.New("boom")}, 15*time.Minute, true)
	rec := httptest.NewRecorder()
	form := url.Values{"secret": {"<script>alert(1)</script>"}}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	h.HandleLogin(rec, req)

	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Error("the submitted secret must never be echoed back into the error page")
	}
}
