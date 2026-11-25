//go:build integration

package test

// Gateway stack wired exactly as cmd/api-gateway/main.go wires production,
// over a real PostgreSQL database, the in-process OIDC provider and a
// canonical-team State Registry stand-in.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/adminauth"
	"github.com/pandops/flowai-api-gateway/internal/broker"
	"github.com/pandops/flowai-api-gateway/internal/httpapi"
	"github.com/pandops/flowai-api-gateway/internal/jwtverify"
	"github.com/pandops/flowai-api-gateway/internal/oidc"
	"github.com/pandops/flowai-api-gateway/internal/sessioncrypto"
	"github.com/pandops/flowai-api-gateway/internal/store"
	"github.com/pandops/flowai-api-gateway/internal/teamregistry"
	"github.com/pandops/flowai-api-gateway/internal/workingtoken"
)

// canonicalRegistry answers team-registry.service.get.pub on a fake broker
// and records every team it was asked for.
type canonicalRegistry struct {
	broker   *fakeBroker
	mu       sync.Mutex
	requests []int64
}

func newCanonicalRegistry(t *testing.T, teams map[int64]string) *canonicalRegistry {
	t.Helper()
	registry := &canonicalRegistry{broker: newFakeBroker()}
	answer := teamRegistryResponder(teams, nil)
	registry.broker.on(teamregistry.Subject, func(request broker.Request) broker.Reply {
		var envelope struct {
			Params struct {
				TeamID int64 `json:"team_id"`
			} `json:"params"`
		}
		_ = json.Unmarshal(request.Body, &envelope)
		if _, ok := teams[envelope.Params.TeamID]; ok {
			registry.mu.Lock()
			registry.requests = append(registry.requests, envelope.Params.TeamID)
			registry.mu.Unlock()
		}
		return answer(request)
	})
	return registry
}

func (r *canonicalRegistry) seen() []int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int64(nil), r.requests...)
}

type stackOptions struct {
	claimSource      string
	adapter          oidc.TeamClaimAdapter
	scopes           []string
	membershipMaxAge time.Duration
	sessionKey       []byte
	signingKey       *rsa.PrivateKey
}

type gatewayStack struct {
	t        *testing.T
	server   *httptest.Server
	provider *oidcProvider
	registry *canonicalRegistry
	key      *rsa.PrivateKey
}

var (
	stackKeyOnce sync.Once
	stackKey     *rsa.PrivateKey
)

func defaultSigningKey() *rsa.PrivateKey {
	stackKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		stackKey = key
	})
	return stackKey
}

// newGatewayStack serves the production dependency graph over db.
func newGatewayStack(t *testing.T, db *sql.DB, provider *oidcProvider, registry *canonicalRegistry, options stackOptions) *gatewayStack {
	t.Helper()
	if options.claimSource == "" {
		options.claimSource = "id_token"
	}
	if options.adapter.Kind == "" {
		options.adapter = oidc.TeamClaimAdapter{Kind: oidc.StringArray, ClaimPointer: "/teams"}
	}
	if options.sessionKey == nil {
		options.sessionKey = []byte(strings.Repeat("7", 32))
	}
	if options.signingKey == nil {
		options.signingKey = defaultSigningKey()
	}
	var handler http.Handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	operators, err := store.NewOperators(db)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := store.NewSessionStore(db)
	if err != nil {
		t.Fatal(err)
	}
	preferences, err := store.NewOperatorPreferences(db)
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := store.NewMappingStore(db)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := sessioncrypto.New(options.sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	flow := newFlow(t, provider, server.URL+"/auth/v1/callback", options.claimSource, options.adapter, options.scopes)
	keyData, err := x509.MarshalPKCS8PrivateKey(options.signingKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := workingtoken.New(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyData}), "flowai-working-e2e-1", "https://gateway.flowai.invalid", "flowai-state-registry", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	adminVerifier, err := jwtverify.New(jwtverify.Config{Issuer: provider.issuer(), Audience: adminAudience, JWKSURL: provider.issuer() + "/jwks", Algorithms: []string{"RS256"}, ClockSkew: 30 * time.Second, TokenMaxAge: 5 * time.Minute, HTTPTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := adminauth.New(adminVerifier, "/realm_access/roles", adminRole)
	if err != nil {
		t.Fatal(err)
	}
	client, err := teamregistry.New(registry.broker)
	if err != nil {
		t.Fatal(err)
	}
	handler = httpapi.NewWithDependencies(httpapi.Dependencies{
		Login: flow, OIDC: flow, Membership: flow, MembershipMaxAge: options.membershipMaxAge,
		Sessions: sessions, OperatorPreferences: preferences, SessionEncryptor: cipher, SessionTTL: time.Hour,
		WebUIURL: server.URL + "/after-login", WorkingTokens: signer, Operators: operators, Broker: registry.broker, RPCTimeout: 5 * time.Second,
		ConfiguredIssuer: provider.issuer(), AdminAuth: authenticator, Mappings: mappings, Presentation: mappings, Teams: client,
	})
	return &gatewayStack{t: t, server: server, provider: provider, registry: registry, key: options.signingKey}
}

func (s *gatewayStack) close() { s.server.Close() }

func (s *gatewayStack) request(method, path string, headers map[string]string, body string) (int, http.Header, string) {
	s.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, s.server.URL+path, reader)
	if err != nil {
		s.t.Fatal(err)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := noRedirect.Do(request)
	if err != nil {
		s.t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, response.Header, string(data)
}

func (s *gatewayStack) registerMapping(oidcTeamID string, teamID int64) int {
	s.t.Helper()
	status, _, _ := s.request(http.MethodPost, "/admin/v1/oidc-team-mappings", map[string]string{"Authorization": "Bearer " + s.provider.adminToken(), "Content-Type": "application/json"}, `{"issuer":"`+s.provider.issuer()+`","oidc_team_id":"`+oidcTeamID+`","team_id":`+strconv.FormatInt(teamID, 10)+`}`)
	return status
}

// login returns the session cookie value and the callback response headers.
func (s *gatewayStack) login() (string, http.Header) {
	s.t.Helper()
	callback := browserLogin(s.t, s.server.URL)
	_ = callback.Body.Close()
	if callback.StatusCode != http.StatusFound || callback.Header.Get("Location") != s.server.URL+"/after-login" {
		s.t.Fatalf("callback = %d -> %s", callback.StatusCode, callback.Header.Get("Location"))
	}
	for _, cookie := range callback.Cookies() {
		if cookie.Name == "flowai_session" && cookie.Value != "" {
			return cookie.Value, callback.Header
		}
	}
	s.t.Fatal("callback set no session cookie")
	return "", nil
}

func (s *gatewayStack) teams(session string) (int, string) {
	s.t.Helper()
	status, _, body := s.request(http.MethodGet, "/auth/v1/teams", map[string]string{"Cookie": "flowai_session=" + session}, "")
	return status, strings.TrimSpace(body)
}

func (s *gatewayStack) issue(session string, teamID int64) (int, map[string]any) {
	s.t.Helper()
	status, _, body := s.request(http.MethodPost, "/auth/v1/token", map[string]string{"Cookie": "flowai_session=" + session, "Content-Type": "application/json"}, `{"team_id":`+strconv.FormatInt(teamID, 10)+`}`)
	var decoded map[string]any
	_ = json.Unmarshal([]byte(body), &decoded)
	return status, decoded
}

func (s *gatewayStack) token(session string, teamID int64) string {
	s.t.Helper()
	status, body := s.issue(session, teamID)
	token, _ := body["access_token"].(string)
	if status != http.StatusOK || token == "" {
		s.t.Fatalf("issue %d = %d %v", teamID, status, body)
	}
	return token
}
