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
// loginPageStyle is the dashboard's own design system (self-hosted
// fonts, --ink/--surface/--status-* tokens -- see
// internal/features/dashboard/adapter/web/dist/style.css's v4 block),
// duplicated as literal values rather than imported: this package
// cannot import dashboard/adapter without violating the feature-slice
// boundary (CLAUDE.md), and the font/asset URLs below are plain HTTP
// references to files the dashboard's own spaHandler already serves at
// /dashboard/fonts/*, not a Go-level dependency. Keep these values in
// sync with style.css's :root and :root[data-theme="light"] blocks by
// hand if that palette ever changes -- there is no single source of
// truth shared between the two today.
const loginPageStyle = `
@font-face{font-family:'Space Grotesk';font-weight:500 700;font-display:swap;src:url(/dashboard/fonts/space-grotesk-variable.woff2) format('woff2')}
@font-face{font-family:'IBM Plex Sans';font-weight:400 600;font-display:swap;src:url(/dashboard/fonts/ibm-plex-sans-variable.woff2) format('woff2')}
@font-face{font-family:'IBM Plex Mono';font-weight:400;font-display:swap;src:url(/dashboard/fonts/ibm-plex-mono-400.woff2) format('woff2')}
:root{--ink:#0F1419;--surface:#181D23;--surface-raised:#20262E;--border:#2A3038;--text:#E4E7EB;--text-muted:#8B95A1;--status-ok:#3FB950;--status-critical:#F85149;--status-critical-soft:rgba(248,81,73,.14);--status-info:#58A6FF;--status-info-soft:rgba(88,166,255,.14);--radius-panel:6px;--radius-control:4px;--shadow-raised:0 8px 24px rgba(0,0,0,.4);--font-heading:'Space Grotesk',system-ui,sans-serif;--font-body:'IBM Plex Sans',system-ui,sans-serif;--font-data:'IBM Plex Mono',ui-monospace,monospace;--ease-out:cubic-bezier(.16,1,.3,1)}
:root[data-theme="light"]{--ink:#F6F8FA;--surface:#FFFFFF;--surface-raised:#F0F2F5;--border:#D8DEE5;--text:#0F1419;--text-muted:#5B6B82;--status-ok:#1A7F37;--status-critical:#CF222E;--status-critical-soft:rgba(207,34,46,.08);--status-info:#0969DA;--status-info-soft:rgba(9,105,218,.10);--shadow-raised:0 8px 24px rgba(15,20,25,.16)}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{background:var(--ink);color:var(--text);font-family:var(--font-body);display:flex;align-items:center;justify-content:center;padding:24px}
.theme-toggle{position:fixed;top:20px;right:20px;width:32px;height:32px;border-radius:var(--radius-control);border:1px solid var(--border);background:var(--surface);color:var(--text-muted);display:flex;align-items:center;justify-content:center;cursor:pointer}
.theme-toggle:hover{color:var(--text);border-color:var(--text-muted)}
.theme-toggle svg{width:15px;height:15px}
.scene{width:100%;max-width:380px}
.brand{display:flex;align-items:center;gap:9px;font-family:var(--font-heading);font-weight:700;font-size:19px;letter-spacing:-.01em;justify-content:center;margin-bottom:8px}
.brand-mark{display:inline-block;width:8px;height:22px;border-radius:2px;background:linear-gradient(180deg,var(--status-info),var(--status-ok));animation:brand-blink 280ms var(--ease-out) 1}
@keyframes brand-blink{0%{opacity:0}50%{opacity:1}75%{opacity:.3}100%{opacity:1}}
@media (prefers-reduced-motion: reduce){.brand-mark{animation:none}}
.tagline{text-align:center;color:var(--text-muted);font-size:13px;margin:0 0 32px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-panel);box-shadow:var(--shadow-raised);padding:28px 28px 24px}
.card h1{font-family:var(--font-heading);font-size:16px;font-weight:600;margin:0 0 4px}
.card .sub{color:var(--text-muted);font-size:13px;margin:0 0 22px;line-height:1.5}
.field{margin-bottom:16px}
label{display:block;font-size:12px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:7px}
input[type="password"]{width:100%;background:var(--surface-raised);border:1px solid var(--border);border-radius:var(--radius-control);color:var(--text);font-family:var(--font-data);font-size:13.5px;padding:10px 12px;transition:border-color 120ms var(--ease-out)}
input::placeholder{color:var(--text-muted);font-family:var(--font-body)}
input:focus{outline:none;border-color:var(--status-info);box-shadow:0 0 0 3px var(--status-info-soft)}
.hint{font-size:11.5px;color:var(--text-muted);margin-top:6px;line-height:1.5}
button.submit{width:100%;background:var(--status-ok);color:#06170A;border:none;border-radius:var(--radius-control);font-family:var(--font-body);font-weight:600;font-size:14px;padding:10px;cursor:pointer;transition:filter 120ms var(--ease-out);margin-top:4px}
button.submit:hover{filter:brightness(1.08)}
button.submit:active{filter:brightness(.95)}
button.submit:focus-visible{outline:2px solid var(--status-info);outline-offset:2px}
.error-banner{display:flex;align-items:center;gap:8px;background:var(--status-critical-soft);border:1px solid var(--status-critical);color:var(--status-critical);border-radius:var(--radius-control);padding:9px 12px;font-size:12.5px;margin-bottom:18px}
.error-banner svg{width:14px;height:14px;flex-shrink:0}
.footer-note{text-align:center;color:var(--text-muted);font-size:11.5px;margin-top:20px;font-family:var(--font-data)}
.footer-note code{background:var(--surface-raised);padding:1px 5px;border-radius:3px;border:1px solid var(--border)}
`

// loginPageScript reads/writes the exact same localStorage key
// app.js's own theme toggle uses ('wardline-theme') so a returning
// user's theme choice carries over between the login page and the
// dashboard behind it, rather than the login page always defaulting to
// dark regardless of what they picked last time.
const loginPageScript = `
(function(){var t=localStorage.getItem('wardline-theme')||'dark';if(t==='light')document.documentElement.setAttribute('data-theme','light');})();
document.querySelector('.theme-toggle').addEventListener('click',function(){
  var next=document.documentElement.getAttribute('data-theme')==='light'?'dark':'light';
  if(next==='light'){document.documentElement.setAttribute('data-theme','light')}else{document.documentElement.removeAttribute('data-theme')}
  localStorage.setItem('wardline-theme',next);
});
`

func (h *LoginHandler) serveLoginForm(w http.ResponseWriter, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if errMsg != "" {
		w.WriteHeader(http.StatusUnauthorized)
	}
	var errBlock string
	if errMsg != "" {
		errBlock = `<div class="error-banner"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/></svg>` +
			html.EscapeString(errMsg) + `</div>`
	}
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Wardline — Sign in</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>` + loginPageStyle + `</style></head>
<body>
<button class="theme-toggle" aria-label="Toggle theme"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg></button>
<div class="scene">
<div class="brand"><span class="brand-mark" aria-hidden="true"></span><span>Wardline</span></div>
<p class="tagline">Control-plane console</p>
<div class="card">
<h1>Sign in</h1>
<p class="sub">Enter a bootstrap secret or an OIDC ID token issued for this instance.</p>
` + errBlock + `
<form method="POST" action="/dashboard/login">
<div class="field">
<label for="secret">Bootstrap secret or OIDC ID token</label>
<input type="password" id="secret" name="secret" autofocus required>
<p class="hint">Exchanged once for a short-lived session — never stored, never logged.</p>
</div>
<button class="submit" type="submit">Sign in</button>
</form>
<div class="footer-note">wardline · /dashboard/login</div>
</div>
</div>
<script>` + loginPageScript + `</script>
</body></html>`))
}
