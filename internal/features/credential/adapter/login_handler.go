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
:root{--ink:#0F1419;--surface:#181D23;--surface-raised:#20262E;--border:#2A3038;--text:#E4E7EB;--text-muted:#8B95A1;--status-ok:#3FB950;--status-ok-soft:rgba(63,185,80,.14);--status-critical:#F85149;--status-critical-soft:rgba(248,81,73,.14);--status-info:#58A6FF;--status-info-soft:rgba(88,166,255,.14);--radius-panel:6px;--radius-control:4px;--font-heading:'Space Grotesk',system-ui,sans-serif;--font-body:'IBM Plex Sans',system-ui,sans-serif;--font-data:'IBM Plex Mono',ui-monospace,monospace;--ease-out:cubic-bezier(.16,1,.3,1);--vignette:radial-gradient(120% 90% at 50% 40%,transparent 55%,rgba(0,0,0,.45));--scan:rgba(255,255,255,.022);--console-shadow:0 24px 70px rgba(0,0,0,.5);--agent-body:#333B46;--agent-face:#434D58;--agent-line:#66727F;--agent-line2:#8B98A7}
:root[data-theme="light"]{--ink:#EEF1F4;--surface:#FFFFFF;--surface-raised:#F4F6F9;--border:#D8DEE5;--text:#0F1419;--text-muted:#5B6B82;--status-ok:#1A7F37;--status-ok-soft:rgba(26,127,55,.10);--status-critical:#CF222E;--status-critical-soft:rgba(207,34,46,.08);--status-info:#0969DA;--status-info-soft:rgba(9,105,218,.10);--vignette:radial-gradient(120% 90% at 50% 40%,transparent 62%,rgba(15,20,25,.05));--scan:rgba(15,20,25,.028);--console-shadow:0 24px 56px rgba(15,20,25,.14);--agent-body:#B0BBC9;--agent-face:#C7D0DA;--agent-line:#68788C;--agent-line2:#55657A}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
/* matte: flat deep ground + a soft vignette for depth — no glossy glow,
   no gradient blobs. The whole page is one operator console. */
body{min-height:100%;background:var(--ink);color:var(--text);font-family:var(--font-data);display:flex;align-items:center;justify-content:center;padding:24px;position:relative;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;pointer-events:none;background:var(--vignette);z-index:0}
.theme-toggle{position:fixed;top:20px;right:20px;z-index:3;width:32px;height:32px;border-radius:var(--radius-control);border:1px solid var(--border);background:var(--surface);color:var(--text-muted);display:flex;align-items:center;justify-content:center;cursor:pointer}
.theme-toggle:hover{color:var(--text);border-color:var(--text-muted)}
.theme-toggle svg{width:15px;height:15px}
/* brand mascots: two hand-built vector "sentinel agents" flanking the
   console, theme-aware via the design tokens */
/* the mascots use dedicated --agent-* tokens (not the panel surfaces),
   so they keep a real silhouette against the ground in both themes;
   custom properties cross the <use> shadow boundary, attribute
   selectors do not */
.agents{position:fixed;inset:0;width:100%;height:100%;z-index:0;pointer-events:none;opacity:.95}
@media (max-width:1080px){.agents{display:none}}
/* the console frame */
.console{position:relative;z-index:1;width:100%;max-width:560px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-panel);box-shadow:var(--console-shadow);overflow:hidden;animation:wl-rise .5s var(--ease-out) both}
/* matte CRT scanlines — flat, non-reflective, fixed */
.console::after{content:"";position:absolute;inset:0;pointer-events:none;z-index:4;background:repeating-linear-gradient(180deg,var(--scan) 0 1px,transparent 1px 3px)}
.bar{display:flex;align-items:center;gap:10px;padding:11px 16px;border-bottom:1px solid var(--border);background:var(--surface-raised);font-size:12.5px}
.bar .mk{width:7px;height:16px;border-radius:2px;background:linear-gradient(180deg,var(--status-info),var(--status-ok))}
.bar .nm{font-weight:600;letter-spacing:.02em;color:var(--text)}
.bar .sec{margin-left:auto;display:flex;align-items:center;gap:7px;color:var(--text-muted)}
.bar .sec .pip{width:7px;height:7px;border-radius:50%;background:var(--status-ok);box-shadow:0 0 0 3px var(--status-ok-soft)}
.body{padding:26px 26px 24px;font-size:13px;line-height:1.65}
.boot{color:var(--text)}
.boot .pmt{color:var(--status-ok);margin-right:9px}
.status{display:flex;gap:20px;margin:15px 0 7px;color:var(--text-muted);font-size:12.5px;flex-wrap:wrap}
.status .s{display:flex;align-items:center;gap:8px;opacity:0;animation:wl-rise .3s var(--ease-out) both}
.status .s:nth-child(1){animation-delay:.35s}
.status .s:nth-child(2){animation-delay:.5s}
.status .s:nth-child(3){animation-delay:.65s}
.status .s .d{width:6px;height:6px;border-radius:50%;background:var(--status-ok)}
.ready{color:var(--text-muted);font-size:12.5px;margin:0 0 24px;opacity:0;animation:wl-rise .3s var(--ease-out) .8s both}
.ready .cur{display:inline-block;width:7px;height:13px;background:var(--status-ok);vertical-align:-2px;margin-left:2px;animation:wl-blink 1.1s step-end infinite}
.pfield{margin-bottom:6px}
.plabel{display:flex;align-items:center;gap:9px;color:var(--text-muted);font-size:12.5px;margin-bottom:10px}
.plabel .arw{color:var(--status-ok);font-weight:600}
input[type="password"]{width:100%;background:var(--ink);border:1px solid var(--border);border-radius:var(--radius-control);color:var(--text);font-family:var(--font-data);font-size:13.5px;padding:11px 13px;transition:border-color 120ms var(--ease-out),box-shadow 120ms var(--ease-out)}
input::placeholder{color:var(--text-muted)}
input:focus{outline:none;border-color:var(--status-ok);box-shadow:0 0 0 3px var(--status-ok-soft)}
.hint{color:var(--text-muted);font-size:11.5px;line-height:1.6;margin:10px 0 20px}
/* action rendered as a terminal command, matte fill on hover */
button.submit{width:100%;display:flex;align-items:center;justify-content:center;gap:9px;background:var(--status-ok-soft);color:var(--status-ok);border:1px solid var(--status-ok);border-radius:var(--radius-control);font-family:var(--font-data);font-weight:600;font-size:13.5px;padding:11px;cursor:pointer;transition:background 120ms var(--ease-out),color 120ms var(--ease-out)}
button.submit:hover{background:var(--status-ok);color:var(--ink)}
button.submit:active{opacity:.9}
button.submit:focus-visible{outline:2px solid var(--status-info);outline-offset:2px}
button.submit .ret{font-size:14px;line-height:1}
.error-banner{display:flex;align-items:center;gap:8px;background:var(--status-critical-soft);border:1px solid var(--status-critical);color:var(--status-critical);border-radius:var(--radius-control);padding:9px 12px;font-size:12.5px;margin-bottom:18px}
.error-banner svg{width:14px;height:14px;flex-shrink:0}
.footline{display:flex;justify-content:space-between;gap:12px;color:var(--text-muted);font-size:11px;margin-top:20px}
@keyframes wl-rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes wl-blink{0%,100%{opacity:1}50%{opacity:0}}
@media (prefers-reduced-motion: reduce){
  .console,.status .s,.ready,.ready .cur{animation:none;opacity:1;transform:none}
}
@media (max-width:520px){
  .body{padding:22px 20px 20px}
  .status{gap:14px}
  .footline{flex-direction:column;gap:4px}
}
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
<svg class="agents" viewBox="0 0 1440 900" preserveAspectRatio="xMidYMax slice" aria-hidden="true" xmlns="http://www.w3.org/2000/svg">
<defs>
<linearGradient id="wl-visor" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="var(--status-info)"/><stop offset="1" stop-color="var(--status-ok)"/></linearGradient>
<symbol id="wl-agent" viewBox="0 0 200 320">
<g>
<animateTransform attributeName="transform" type="translate" values="0 0;0 -6;0 0" dur="5s" repeatCount="indefinite"/>
<ellipse cx="100" cy="315" rx="58" ry="7" fill="var(--ink)" opacity=".3"/>
<path d="M86 150 Q66 132 70 106 L92 150 Z" fill="var(--agent-body)" stroke="var(--agent-line)" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M114 150 Q134 132 130 106 L108 150 Z" fill="var(--agent-body)" stroke="var(--agent-line)" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M58 320 V176 Q58 150 100 146 Q142 150 142 176 V320 Z" fill="var(--agent-body)" stroke="var(--agent-line)" stroke-width="3"/>
<path d="M78 178 V320" stroke="var(--agent-line)" stroke-width="1.5" opacity=".5"/>
<path d="M122 178 V320" stroke="var(--agent-line)" stroke-width="1.5" opacity=".5"/>
<path d="M100 150 L72 202 L92 176 Z" fill="var(--agent-face)" stroke="var(--agent-line)" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M100 150 L128 202 L108 176 Z" fill="var(--agent-face)" stroke="var(--agent-line)" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M92 174 L100 212 L108 174 Z" fill="var(--agent-face)"/>
<path d="M96 176 L104 176 L107 206 L100 216 L93 206 Z" fill="url(#wl-visor)"/>
<path d="M100 214 V320" stroke="var(--agent-line)" stroke-width="2" opacity=".55"/>
<circle cx="100" cy="230" r="2.6" fill="var(--agent-line)"/>
<circle cx="100" cy="300" r="2.6" fill="var(--agent-line)"/>
<rect x="58" y="250" width="84" height="12" fill="var(--agent-face)" stroke="var(--agent-line)" stroke-width="2"/>
<rect x="94" y="250" width="12" height="12" fill="url(#wl-visor)"/>
<rect x="64" y="278" width="30" height="12" rx="3" fill="var(--agent-body)" stroke="var(--agent-line)" stroke-width="2"/>
<rect x="106" y="278" width="30" height="12" rx="3" fill="var(--agent-body)" stroke="var(--agent-line)" stroke-width="2"/>
<rect x="90" y="118" width="20" height="30" fill="var(--agent-face)" stroke="var(--agent-line)" stroke-width="2.5"/>
<rect x="78" y="72" width="44" height="54" rx="18" fill="var(--agent-face)" stroke="var(--agent-line)" stroke-width="3"/>
<rect x="78" y="86" width="44" height="12" fill="#000" opacity=".2"/>
<circle cx="91" cy="94" r="2.6" fill="var(--agent-line2)"/>
<circle cx="109" cy="94" r="2.6" fill="var(--agent-line2)"/>
<path d="M100 100 L97 108 L101 109" fill="none" stroke="var(--agent-line)" stroke-width="1.5" opacity=".6" stroke-linejoin="round"/>
<ellipse cx="100" cy="78" rx="60" ry="12" fill="var(--agent-body)" stroke="var(--agent-line)" stroke-width="3"/>
<path d="M74 78 Q72 40 100 40 Q128 40 126 78 Z" fill="var(--agent-body)" stroke="var(--agent-line)" stroke-width="3"/>
<rect x="74" y="66" width="52" height="9" fill="#000" opacity=".22"/>
<path d="M82 46 Q100 55 118 46" fill="none" stroke="var(--agent-line)" stroke-width="2" opacity=".55"/>
<path d="M48 80 Q100 91 152 80" fill="none" stroke="var(--agent-line)" stroke-width="1.5" opacity=".4"/>
<path d="M64 182 Q40 198 40 222" fill="none" stroke="var(--agent-body)" stroke-width="18" stroke-linecap="round"/>
<path d="M64 182 Q40 198 40 222" fill="none" stroke="var(--agent-line)" stroke-width="2" opacity=".55" stroke-linecap="round"/>
<path d="M33 216 L49 210" stroke="var(--agent-line)" stroke-width="2" opacity=".7"/>
<rect x="52" y="242" width="8" height="28" rx="4" transform="rotate(45 56 246)" fill="var(--agent-line2)"/>
<circle cx="40" cy="230" r="19" fill="var(--agent-face)" stroke="var(--agent-line2)" stroke-width="5"/>
<circle cx="40" cy="230" r="13" fill="url(#wl-visor)" opacity=".9"/>
<path d="M40 220 V240 M30 230 H50" stroke="#fff" stroke-width="1" opacity=".3"/>
<circle cx="40" cy="230" r="7" fill="none" stroke="#fff" stroke-width="1" opacity=".28"/>
<path d="M29 224 A19 19 0 0 1 45 214" fill="none" stroke="#fff" stroke-width="2" opacity=".3"/>
<ellipse cx="34" cy="223" rx="5" ry="3" fill="#fff" opacity=".5"><animate attributeName="opacity" values=".2;.6;.2" dur="3s" repeatCount="indefinite"/></ellipse>
</g>
</symbol>
</defs>
<use href="#wl-agent" width="300" height="480" transform="translate(24,440)"/>
<use href="#wl-agent" width="300" height="480" transform="translate(1416,440) scale(-1,1)"/>
</svg>
<button class="theme-toggle" aria-label="Toggle theme"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg></button>
<main class="console">
<div class="bar"><span class="mk" aria-hidden="true"></span><span class="nm">wardline</span><span class="sec"><span class="pip" aria-hidden="true"></span>secure</span></div>
<div class="body">
<div class="boot"><span class="pmt">$</span>wardline console --login</div>
<div class="status" aria-hidden="true">
<span class="s"><span class="d"></span>proxy</span>
<span class="s"><span class="d"></span>policy</span>
<span class="s"><span class="d"></span>audit</span>
</div>
<p class="ready">ready — authenticate to continue<span class="cur" aria-hidden="true"></span></p>
` + errBlock + `
<form method="POST" action="/dashboard/login">
<div class="pfield">
<label class="plabel" for="secret"><span class="arw">▸</span>bootstrap secret or OIDC ID token</label>
<input type="password" id="secret" name="secret" autofocus required>
<p class="hint">Exchanged once for a short-lived session — never stored, never logged.</p>
</div>
<button class="submit" type="submit"><span class="ret" aria-hidden="true">↵</span>authenticate</button>
</form>
<div class="footline"><span>session · short-lived</span><span>/dashboard/login</span></div>
</div>
</main>
<script>` + loginPageScript + `</script>
</body></html>`))
}
