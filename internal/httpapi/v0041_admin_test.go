package httpapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/adminauth"
	"github.com/pandops/flowai-api-gateway/internal/jwtverify"
	"github.com/pandops/flowai-api-gateway/internal/store"
	"github.com/pandops/flowai-api-gateway/internal/teamregistry"
)

const (
	v0041AdminAudience = "flowai-api-gateway-admin"
	v0041AdminRole     = "flowai-system-admin"
	v0041OIDCIssuer    = "https://oidc.flowai.invalid"
)

// v0041AdminProvider is a provider-neutral JWKS endpoint with switchable
// published keys and failure modes.
type v0041AdminProvider struct {
	server    *httptest.Server
	mu        sync.Mutex
	keys      map[string]*rsa.PrivateKey
	published []string
	status    int
	delay     time.Duration
}

func newV0041AdminProvider(t *testing.T, kids ...string) *v0041AdminProvider {
	t.Helper()
	provider := &v0041AdminProvider{keys: map[string]*rsa.PrivateKey{}}
	for _, kid := range kids {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		provider.keys[kid] = key
	}
	provider.published = kids[:1]
	provider.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		provider.mu.Lock()
		status, delay, published := provider.status, provider.delay, append([]string(nil), provider.published...)
		provider.mu.Unlock()
		time.Sleep(delay)
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		var keys []any
		for _, kid := range published {
			key := provider.keys[kid]
			keys = append(keys, map[string]any{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *v0041AdminProvider) set(published []string, status int, delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if published != nil {
		p.published = published
	}
	p.status, p.delay = status, delay
}

type v0041AdminToken struct {
	issuer, audience, alg, kid, signWith string
	iat, exp                             any
	roles                                any
}

func (p *v0041AdminProvider) token(t *testing.T, change func(*v0041AdminToken)) string {
	t.Helper()
	now := time.Now().Unix()
	spec := v0041AdminToken{issuer: p.server.URL, audience: v0041AdminAudience, alg: "RS256", kid: "admin-a", iat: now, exp: now + 60, roles: []string{v0041AdminRole}}
	if change != nil {
		change(&spec)
	}
	if spec.signWith == "" {
		spec.signWith = spec.kid
		if _, ok := p.keys[spec.signWith]; !ok {
			spec.signWith = "admin-a"
		}
	}
	header, _ := json.Marshal(map[string]any{"alg": spec.alg, "typ": "JWT", "kid": spec.kid})
	claims := map[string]any{"iss": spec.issuer, "aud": spec.audience, "sub": "admin-subject", "exp": spec.exp, "realm_access": map[string]any{"roles": spec.roles}}
	if spec.iat != nil {
		claims["iat"] = spec.iat
	}
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	var signature []byte
	var err error
	if spec.alg == "RS512" {
		digest := sha512.Sum512([]byte(input))
		signature, err = rsa.SignPKCS1v15(rand.Reader, p.keys[spec.signWith], crypto.SHA512, digest[:])
	} else {
		digest := sha256.Sum256([]byte(input))
		signature, err = rsa.SignPKCS1v15(rand.Reader, p.keys[spec.signWith], crypto.SHA256, digest[:])
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

type v0041CanonicalTeams struct {
	mu       sync.Mutex
	requests []int64
}

func (c *v0041CanonicalTeams) GetTeam(_ context.Context, teamID int64, _ string, _ int64) (teamregistry.Team, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := map[int64]string{3: "Alpha Team", 4: "Beta Team"}
	if names[teamID] == "" {
		return teamregistry.Team{}, teamregistry.ErrTeamNotFound
	}
	c.requests = append(c.requests, teamID)
	return teamregistry.Team{TeamID: teamID, TeamName: names[teamID]}, nil
}

func (c *v0041CanonicalTeams) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

// v0041Mappings has the persisted store's one-to-one registration semantics.
type v0041Mappings struct {
	mu   sync.Mutex
	rows map[string]store.Mapping
}

func (m *v0041Mappings) Register(_ context.Context, mapping store.Mapping) (store.Mapping, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[string]store.Mapping{}
	}
	if existing, ok := m.rows[mapping.OIDCTeamID]; ok {
		if existing.TeamID != mapping.TeamID {
			return store.Mapping{}, false, store.ErrMappingConflict
		}
		return existing, false, nil
	}
	for _, existing := range m.rows {
		if existing.TeamID == mapping.TeamID {
			return store.Mapping{}, false, store.ErrMappingConflict
		}
	}
	m.rows[mapping.OIDCTeamID] = mapping
	return mapping, true, nil
}

func (m *v0041Mappings) snapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rows []string
	for _, row := range m.rows {
		rows = append(rows, row.OIDCTeamID+"->"+strconv.FormatInt(row.TeamID, 10))
	}
	sort.Strings(rows)
	return rows
}

type v0041AdminGateway struct {
	server   *httptest.Server
	teams    *v0041CanonicalTeams
	mappings *v0041Mappings
}

func newV0041AdminGateway(t *testing.T, provider *v0041AdminProvider, maxAge, skew, timeout time.Duration, mappings *v0041Mappings) *v0041AdminGateway {
	t.Helper()
	verifier, err := jwtverify.New(jwtverify.Config{Issuer: provider.server.URL, Audience: v0041AdminAudience, JWKSURL: provider.server.URL + "/jwks", Algorithms: []string{"RS256"}, ClockSkew: skew, TokenMaxAge: maxAge, HTTPTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := adminauth.New(verifier, "/realm_access/roles", v0041AdminRole)
	if err != nil {
		t.Fatal(err)
	}
	if mappings == nil {
		mappings = &v0041Mappings{}
	}
	teams := &v0041CanonicalTeams{}
	server := httptest.NewServer(NewWithDependencies(Dependencies{ConfiguredIssuer: v0041OIDCIssuer, AdminAuth: authenticator, Mappings: mappings, Teams: teams}))
	t.Cleanup(server.Close)
	return &v0041AdminGateway{server: server, teams: teams, mappings: mappings}
}

func (g *v0041AdminGateway) post(t *testing.T, token, oidcTeamID string, teamID int64) (int, string, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"issuer": v0041OIDCIssuer, "oidc_team_id": oidcTeamID, "team_id": teamID})
	request, _ := http.NewRequest(http.MethodPost, g.server.URL+"/admin/v1/oidc-team-mappings", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	text := v0041ReadBody(t, response)
	var decoded map[string]any
	_ = json.Unmarshal([]byte(text), &decoded)
	return response.StatusCode, text, decoded
}

func v0041Code(t *testing.T, status int, body string, wantStatus int, wantCode string) {
	t.Helper()
	v0041Envelope(t, status, body, wantStatus, wantCode)
}

// v0007.30 v0007.33 v0007.38: a live role removal is 403, an over-age token is
// 401, and during a JWKS outage a cached kid verifies while an unknown kid is
// 502.
func TestV0007_30_LiveAdminRoleAgeAndJWKSOutage(t *testing.T) {
	t.Parallel()
	provider := newV0041AdminProvider(t, "admin-a")
	gateway := newV0041AdminGateway(t, provider, 5*time.Minute, 30*time.Second, 500*time.Millisecond, nil)
	if status, body, _ := gateway.post(t, provider.token(t, nil), "oidc-team-alpha", 3); status != http.StatusCreated {
		t.Fatalf("valid = %d %s", status, body)
	}
	status, body, _ := gateway.post(t, provider.token(t, func(s *v0041AdminToken) { s.roles = []string{"offline_access"} }), "oidc-team-beta", 4)
	v0041Code(t, status, body, http.StatusForbidden, "insufficient_admin_role")
	restored := provider.token(t, nil)
	if status, body, _ := gateway.post(t, restored, "oidc-team-beta", 4); status != http.StatusCreated {
		t.Fatalf("restored = %d %s", status, body)
	}
	aged := newV0041AdminGateway(t, provider, time.Millisecond, 0, 500*time.Millisecond, gateway.mappings)
	old := provider.token(t, func(s *v0041AdminToken) { s.iat = time.Now().Unix() - 2 })
	status, body, _ = aged.post(t, old, "aged", 3)
	v0041Code(t, status, body, http.StatusUnauthorized, "invalid_admin_token")
	provider.server.Close()
	if status, body, _ := gateway.post(t, restored, "oidc-team-beta", 4); status != http.StatusOK {
		t.Fatalf("cached kid after outage = %d %s", status, body)
	}
	parts := strings.Split(restored, ".")
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "unknown-after-outage"})
	unknown := base64.RawURLEncoding.EncodeToString(header) + "." + parts[1] + "." + parts[2]
	status, body, _ = gateway.post(t, unknown, "unknown", 3)
	v0041Code(t, status, body, http.StatusBadGateway, "admin_identity_provider_unavailable")
	if rows := gateway.mappings.snapshot(); strings.Join(rows, ",") != "oidc-team-alpha->3,oidc-team-beta->4" {
		t.Fatalf("mappings = %v", rows)
	}
}

// v0007.25: mapping registration maps created/identical/conflict to
// 201/200/409 in both uniqueness dimensions and returns the canonical row.
func TestV0007_25_MappingRegistrationStatusMapping(t *testing.T) {
	t.Parallel()
	provider := newV0041AdminProvider(t, "admin-a")
	gateway := newV0041AdminGateway(t, provider, 5*time.Minute, 30*time.Second, time.Second, nil)
	token := provider.token(t, nil)
	status, body, created := gateway.post(t, token, "same-external", 3)
	if status != http.StatusCreated || created["issuer"] != v0041OIDCIssuer || created["oidc_team_id"] != "same-external" || created["team_id"] != float64(3) || created["team_name"] != "Alpha Team" {
		t.Fatalf("create = %d %s", status, body)
	}
	for range 3 {
		if status, body, retry := gateway.post(t, token, "same-external", 3); status != http.StatusOK || retry["team_id"] != float64(3) {
			t.Fatalf("identical retry = %d %s", status, body)
		}
	}
	status, body, _ = gateway.post(t, token, "same-external", 4)
	v0041Code(t, status, body, http.StatusConflict, "mapping_conflict")
	status, body, _ = gateway.post(t, token, "canonical-b", 3)
	v0041Code(t, status, body, http.StatusConflict, "mapping_conflict")
	status, body, _ = gateway.post(t, token, "missing", 77)
	v0041Code(t, status, body, http.StatusNotFound, "canonical_team_not_found")
	if rows := gateway.mappings.snapshot(); strings.Join(rows, ",") != "same-external->3" {
		t.Fatalf("mappings = %v", rows)
	}
}
