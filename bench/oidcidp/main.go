// Command oidcidp is a minimal mock OIDC IdP for benchmarking the oidc
// credential-issuance bootstrap source under load: generates an RSA
// keypair at startup, serves a real JWKS endpoint over HTTP (so
// wardline's OIDCBootstrapper exercises its real discovery/JWKS-fetch
// path, not a stub), and writes one long-lived, pre-signed ID token to a
// file so bench/run.sh can feed the same token to every load-generator
// request -- mirrors how the presharedsecret scenario reuses one fixed
// secret across the whole attack.
//
// Usage: oidcidp <listen-addr> <issuer> <audience> <token-out-file>
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const kid = "oidcidp-bench-key"

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: oidcidp <listen-addr> <issuer> <audience> <token-out-file>")
		os.Exit(1)
	}
	listenAddr, issuer, audience, tokenOut := os.Args[1], os.Args[2], os.Args[3], os.Args[4]

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate key:", err)
		os.Exit(1)
	}

	pub, err := jwk.PublicKeyOf(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "derive public key:", err)
		os.Exit(1)
	}
	if err := pub.Set(jwk.KeyIDKey, kid); err != nil {
		fmt.Fprintln(os.Stderr, "set kid:", err)
		os.Exit(1)
	}
	if err := pub.Set(jwk.AlgorithmKey, jwa.RS256()); err != nil {
		fmt.Fprintln(os.Stderr, "set alg:", err)
		os.Exit(1)
	}
	set := jwk.NewSet()
	if err := set.AddKey(pub); err != nil {
		fmt.Fprintln(os.Stderr, "add key to set:", err)
		os.Exit(1)
	}

	signingKey, err := jwk.Import(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "import signing key:", err)
		os.Exit(1)
	}
	if err := signingKey.Set(jwk.KeyIDKey, kid); err != nil {
		fmt.Fprintln(os.Stderr, "set signing kid:", err)
		os.Exit(1)
	}

	// 24h TTL: comfortably outlives any single bench run, avoids the
	// load generator ever hitting an expired-token 401 mid-attack.
	// Subject "bench-agent" reuses bench/policy.bench.yaml's existing
	// allow-everything rule for that identity, rather than adding a
	// parallel one just for this scenario.
	tok, err := jwt.NewBuilder().
		Issuer(issuer).
		Audience([]string{audience}).
		Subject("bench-agent").
		Claim("tenant", "bench-tenant").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(24 * time.Hour)).
		Build()
	if err != nil {
		fmt.Fprintln(os.Stderr, "build token:", err)
		os.Exit(1)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), signingKey))
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign token:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(tokenOut, signed, 0600); err != nil {
		fmt.Fprintln(os.Stderr, "write token file:", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   issuer,
			"jwks_uri": "http://" + listenAddr + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})

	fmt.Printf("oidcidp serving on %s (issuer=%s audience=%s)\n", listenAddr, issuer, audience)
	if err := http.ListenAndServe(listenAddr, mux); err != nil { //nolint:gosec // bench-only loopback stand-in, not internet-facing
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
