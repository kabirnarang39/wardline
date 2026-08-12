package adapter

import (
	"html"
	"net/http"
	"time"

	proxyadapter "github.com/kabirnarang39/wardline/internal/features/proxy/adapter"
)

// maxLoginFormBodyBytes bounds the login form POST body -- a single
// secret/token field, same generous-headroom reasoning as
// maxTokenRequestBodyBytes.
const maxLoginFormBodyBytes = 64 << 10

// LoginHandler serves GET/POST /dashboard/login and POST
// /dashboard/logout -- the browser-native token-entry flow that closes
// the gap documented on web-dashboard.md's "Known limitations": a
// browser navigating to /dashboard/ (or submitting Blocked's Unblock/
// Credentials' Revoke as a plain HTML form) cannot attach a custom
// "Authorization: Bearer <token>" header the way an API client can, so
// there was previously no way to deliver a token to those surfaces from
// a browser at all.
//
// The exchange itself is NOT a new authentication mechanism: POST
// /dashboard/login calls the exact same issuance.Bootstrap(secret) path
// POST /credentials/token already uses -- a preshared secret or OIDC ID
// token in, a signed access token out. What's new is only the DELIVERY
// channel for that access token: instead of returning it as a JSON
// body (which a browser navigation can't do anything useful with), it
// is set as an httpOnly cookie (proxyadapter.SessionCookieName) the
// browser then sends automatically on every subsequent request to
// /dashboard/, Blocked's Unblock, and Credentials' Revoke --
// bearerIdentity.Authenticate reads it as a fallback token source when
// no Authorization header is present.
//
// Session lifetime is exactly the access token's own TTL
// (accessTokenTTL, config.CredentialConfig.AccessTokenTTLSeconds) --
// there is no refresh-token cookie or silent renewal in this cycle,
// deliberately: a lightweight re-login-when-it-expires flow keeps this
// bounded, and a proper silent-refresh-via-cookie flow (rotating a
// refresh-token cookie, an auto-refresh middleware) is a genuinely
// separate, larger feature, not implicitly promised by "closes the
// browser-native login gap" -- noted here rather than left
// undocumented.
type LoginHandler struct {
	issuance     BootstrapIssuer
	accessTTL    time.Duration
	cookieSecure bool
}

// BootstrapIssuer is the subset of credentialusecase.IssuanceService's
// behavior LoginHandler depends on -- a narrow interface (matching this
// package's own http_handler.go pattern for UserProvisioner etc. in
// other features) so a test can supply a fake without constructing a
// real IssuanceService.
type BootstrapIssuer interface {
	Bootstrap(secret string) (accessToken, refreshToken string, err error)
}

// NewLoginHandler wires a LoginHandler. cookieSecure sets the session
// cookie's Secure attribute -- true (send the cookie over HTTPS only)
// is correct whenever a TLS-terminating ingress/mesh sits in front of
// Wardline (the expected production posture: Wardline never terminates
// TLS itself, see mTLS/SPIFFE Bootstrap's own doc comment on that
// architectural stance), and MUST be set false only for a genuinely
// plaintext-HTTP deployment (local dev, a loopback-only setup) --
// deliberately an explicit config knob
// (dashboard.session_cookie_secure), not inferred from r.TLS (which is
// nil on Wardline's own side even in the correct, secure production
// posture, since TLS terminates upstream of it) or from a
// client-spoofable header like X-Forwarded-Proto.
func NewLoginHandler(issuance BootstrapIssuer, accessTTL time.Duration, cookieSecure bool) *LoginHandler {
	return &LoginHandler{issuance: issuance, accessTTL: accessTTL, cookieSecure: cookieSecure}
}

// HandleLogin serves GET /dashboard/login (the form) and POST
// /dashboard/login (the exchange).
func (h *LoginHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.serveLoginForm(w, "")
	case http.MethodPost:
		h.handleLoginSubmit(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *LoginHandler) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		h.serveLoginForm(w, "invalid form submission")
		return
	}
	secret := r.PostFormValue("secret")
	if secret == "" {
		h.serveLoginForm(w, "secret is required")
		return
	}
	accessToken, _, err := h.issuance.Bootstrap(secret)
	if err != nil {
		// Generic message regardless of cause -- same non-enumerable-
		// failure posture as every other credential-rejection path in
		// this package (HandleToken, HandleRefresh). The secret value
		// itself must never be logged or echoed back into the form.
		h.serveLoginForm(w, "invalid credentials")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     proxyadapter.SessionCookieName,
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		// SameSite=Strict is this cookie's actual CSRF defense: a
		// cross-site page (malicious or merely careless) cannot make
		// the browser attach this cookie to a request at all, matching
		// OWASP's current guidance that the SameSite attribute is a
		// primary CSRF mitigation, appropriate here since this is an
		// admin-facing session with no cross-site linking use case to
		// preserve (unlike, say, a payment redirect flow, which is the
		// usual reason a site reaches for the weaker Lax instead).
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.accessTTL.Seconds()),
	})
	http.Redirect(w, r, "/dashboard/", http.StatusSeeOther)
}

// HandleLogout serves POST /dashboard/logout -- clears the session
// cookie by setting MaxAge to a negative value (the standard
// net/http-documented way to tell the browser to delete a cookie
// immediately) and redirects to the login form. GET is deliberately
// not supported: a logout is a state change (ends the session) and
// belongs behind a method that isn't triggerable by a bare link/image
// tag/prefetch the way GET is.
func (h *LoginHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     proxyadapter.SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.cookieSecure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/dashboard/login", http.StatusSeeOther)
}

// serveLoginForm renders a minimal, self-contained (no external CSS/JS
// -- this is the one dashboard surface reachable before any
// authentication exists, so it must not depend on anything a
// not-yet-authenticated browser might be blocked from fetching) HTML
// login form. errMsg, when non-empty, is HTML-escaped and shown above
// the form -- html.EscapeString, not a raw fmt.Sprintf into the page,
// since errMsg's only current caller passes static strings but this
// function's own contract must not silently become an XSS vector if
// that ever changes.
func (h *LoginHandler) serveLoginForm(w http.ResponseWriter, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if errMsg != "" {
		w.WriteHeader(http.StatusUnauthorized)
	}
	var errBlock string
	if errMsg != "" {
		errBlock = `<p style="color:#b00020">` + html.EscapeString(errMsg) + `</p>`
	}
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Wardline — Sign in</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:360px;margin:10vh auto;padding:0 16px;color:#1a1a1a}
h1{font-size:1.25rem}
input{width:100%;box-sizing:border-box;padding:8px;margin:8px 0;font-size:1rem}
button{width:100%;padding:8px;font-size:1rem;cursor:pointer}
</style></head>
<body>
<h1>Wardline</h1>
` + errBlock + `
<form method="POST" action="/dashboard/login">
<label for="secret">Bootstrap secret or OIDC ID token</label>
<input type="password" id="secret" name="secret" autofocus required>
<button type="submit">Sign in</button>
</form>
</body></html>`))
}
