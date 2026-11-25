// Package test holds API Gateway cases that drive the real OIDC flow against
// an in-process provider-neutral OIDC provider (standing in for Keycloak).
package test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	providerClientID = "flowai-api-gateway-e2e"
	adminAudience    = "flowai-api-gateway-admin"
	adminRole        = "flowai-system-admin"
)

type pendingCode struct {
	nonce, challenge, redirectURI string
}

// oidcProvider implements discovery, authorize (auto-approving one fixed
// operator), the code and refresh grants with PKCE S256 verification, JWKS
// and UserInfo.
type oidcProvider struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey

	mu             sync.Mutex
	subject        string
	idTokenClaims  map[string]any
	userinfoClaims map[string]any
	userinfoStatus int
	codes          map[string]pendingCode
	accessTokens   map[string]bool
	refreshTokens  map[string]bool
	authorizations []url.Values
	grants         []string
}

func newOIDCProvider(t *testing.T) *oidcProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &oidcProvider{t: t, key: key, subject: "operator-subject-aadmin", codes: map[string]pendingCode{}, accessTokens: map[string]bool{}, refreshTokens: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": p.issuer(), "authorization_endpoint": p.issuer() + "/authorize", "token_endpoint": p.issuer() + "/token", "userinfo_endpoint": p.issuer() + "/userinfo", "jwks_uri": p.issuer() + "/jwks"})
	})
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kid": "provider-key-1", "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("GET /userinfo", p.userinfo)
	p.server = httptest.NewServer(mux)
	t.Cleanup(p.server.Close)
	return p
}

func (p *oidcProvider) issuer() string { return p.server.URL }

func (p *oidcProvider) setClaims(idToken, userinfo map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.idTokenClaims, p.userinfoClaims = idToken, userinfo
}

func (p *oidcProvider) setUserinfoStatus(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.userinfoStatus = status
}

func (p *oidcProvider) lastAuthorization() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.authorizations) == 0 {
		return nil
	}
	return p.authorizations[len(p.authorizations)-1]
}

func (p *oidcProvider) authorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if query.Get("response_type") != "code" || query.Get("client_id") != providerClientID || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" || query.Get("state") == "" || query.Get("nonce") == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	code := randomString()
	p.mu.Lock()
	p.authorizations = append(p.authorizations, query)
	p.codes[code] = pendingCode{nonce: query.Get("nonce"), challenge: query.Get("code_challenge"), redirectURI: query.Get("redirect_uri")}
	p.mu.Unlock()
	target, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "invalid redirect", http.StatusBadRequest)
		return
	}
	values := target.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	target.RawQuery = values.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (p *oidcProvider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.PostForm.Get("client_id") != providerClientID {
		http.Error(w, "invalid_client", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	nonce := ""
	switch grant := r.PostForm.Get("grant_type"); grant {
	case "authorization_code":
		pending, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		verifier := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || pending.redirectURI != r.PostForm.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(verifier[:]) != pending.challenge {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		nonce = pending.nonce
		p.grants = append(p.grants, grant)
	case "refresh_token":
		if !p.refreshTokens[r.PostForm.Get("refresh_token")] {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		p.grants = append(p.grants, grant)
	default:
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}
	access, refresh := "access-"+randomString(), "refresh-"+randomString()
	p.accessTokens[access], p.refreshTokens[refresh] = true, true
	now := time.Now().Unix()
	claims := map[string]any{"iss": p.issuer(), "aud": providerClientID, "sub": p.subject, "iat": now, "exp": now + 300}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for name, value := range p.idTokenClaims {
		claims[name] = value
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "refresh_token": refresh, "id_token": p.sign(claims), "token_type": "Bearer", "expires_in": 300})
}

func (p *oidcProvider) userinfo(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.userinfoStatus != 0 {
		w.WriteHeader(p.userinfoStatus)
		return
	}
	if !p.accessTokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims := map[string]any{"sub": p.subject}
	for name, value := range p.userinfoClaims {
		claims[name] = value
	}
	_ = json.NewEncoder(w).Encode(claims)
}

func (p *oidcProvider) sign(claims map[string]any) string {
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "provider-key-1"})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		p.t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// adminToken is a provider-issued administrator access token.
func (p *oidcProvider) adminToken() string {
	now := time.Now().Unix()
	return p.sign(map[string]any{"iss": p.issuer(), "aud": adminAudience, "sub": "admin-subject", "iat": now, "exp": now + 300, "realm_access": map[string]any{"roles": []string{adminRole}}})
}

func randomString() string {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// browserLogin performs login -> provider authorize -> Gateway callback
// without following the final redirect, and returns the callback response.
func browserLogin(t *testing.T, gatewayURL string) *http.Response {
	t.Helper()
	login, err := noRedirect.Get(gatewayURL + "/auth/v1/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = login.Body.Close()
	if login.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d", login.StatusCode)
	}
	authorize, err := noRedirect.Get(login.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = authorize.Body.Close()
	if authorize.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d", authorize.StatusCode)
	}
	callback, err := noRedirect.Get(authorize.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return callback
}
