package httpapi

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/oidc"
	"github.com/pandops/flowai-api-gateway/internal/sessioncrypto"
	"github.com/pandops/flowai-api-gateway/internal/store"
)

// v0007.1 v0007.3 v0007.24: each issue is one immutable one-team RS256 token
// with its own jti, audience and expiry, and each one is recorded.
func TestV0007_1_IssueImmutableOneTeamRS256TokensWithDistinctJTI(t *testing.T) {
	t.Parallel()
	gateway := newV0041Gateway(t, nil)
	var claims []map[string]any
	for _, team := range []int64{3, 3, 4} {
		response := gateway.issueResponse(v0041SessionID, team)
		var body struct {
			AccessToken string `json:"access_token"`
			TokenType   string `json:"token_type"`
			ExpiresIn   int    `json:"expires_in"`
		}
		err := json.NewDecoder(response.Body).Decode(&body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("issue %d: status %d err %v", team, response.StatusCode, err)
		}
		if body.TokenType != "Bearer" || body.ExpiresIn != 300 {
			t.Fatalf("token body = %+v", body)
		}
		parts := strings.Split(body.AccessToken, ".")
		var header map[string]any
		if err := json.Unmarshal(v0041Base64(t, parts[0]), &header); err != nil {
			t.Fatal(err)
		}
		if header["alg"] != "RS256" || header["kid"] != v0041KeyID {
			t.Fatalf("header = %+v", header)
		}
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		if err := rsa.VerifyPKCS1v15(&v0041PrivateKey(t).PublicKey, crypto.SHA256, digest[:], v0041Base64(t, parts[2])); err != nil {
			t.Fatalf("signature does not verify: %v", err)
		}
		claims = append(claims, v0041Claims(t, body.AccessToken))
	}
	jtis := map[any]bool{}
	for index, want := range []int64{3, 3, 4} {
		value := claims[index]
		if value["team_id"] != float64(want) || value["sub"] != "42" || value["operator_id"] != float64(v0041OperatorID) {
			t.Fatalf("claims[%d] = %+v", index, value)
		}
		if value["aud"] != v0041Audience || value["iss"] != v0041Issuer || value["exp"].(float64) <= value["iat"].(float64) {
			t.Fatalf("claims[%d] registered claims = %+v", index, value)
		}
		if _, multi := value["teams"]; multi {
			t.Fatal("multi-team claim present")
		}
		jtis[value["jti"]] = true
	}
	if len(jtis) != 3 {
		t.Fatalf("distinct jti = %d, want 3", len(jtis))
	}
	if got := gateway.sessions.recordedTokens(); got != 3 {
		t.Fatalf("recorded tokens = %d, want 3", got)
	}
}

// v0007.2 v0007.3: a team outside the session is refused and nothing is issued.
func TestV0007_2_RejectInaccessibleSelectedTeam(t *testing.T) {
	t.Parallel()
	gateway := newV0041Gateway(t, nil)
	response := gateway.issueResponse(v0041SessionID, 99)
	body := v0041ReadBody(t, response)
	v0041Envelope(t, response.StatusCode, body, http.StatusForbidden, "team_not_accessible")
	if strings.Contains(body, "access_token") || gateway.sessions.recordedTokens() != 0 {
		t.Fatalf("inaccessible team issued a token: %s", body)
	}
}

// v0007.4: logout deletes the server session, clears the cookie and stops
// further token issue (the persisted row deletion is the integration case).
func TestV0007_4_LogoutDeletesSessionAndPreventsTokenIssue(t *testing.T) {
	t.Parallel()
	gateway := newV0041Gateway(t, nil)
	logout := gateway.logout(v0041SessionID)
	if logout.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d", logout.StatusCode)
	}
	cookie := logout.Header.Get("Set-Cookie")
	for _, part := range []string{"flowai_session=", "Max-Age=0", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(cookie, part) {
			t.Fatalf("Set-Cookie %q lacks %q", cookie, part)
		}
	}
	response := gateway.issueResponse(v0041SessionID, 3)
	body := v0041ReadBody(t, response)
	v0041Envelope(t, response.StatusCode, body, http.StatusUnauthorized, "invalid_session")
	if again := gateway.logout(v0041SessionID); again.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second logout status = %d", again.StatusCode)
	}
}

type v0041Refresher struct {
	mu    sync.Mutex
	fail  bool
	calls int
}

func (r *v0041Refresher) Refresh(_ context.Context, state []byte, subject string) ([]string, []byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.fail {
		return nil, nil, oidc.ErrProviderUnavailable
	}
	if string(state) != `{"refresh_token":"provider"}` || subject != "subject-alpha" {
		return nil, nil, errors.New("unexpected provider state")
	}
	return []string{"oidc-team-alpha"}, state, nil
}

// v0041RefreshableSessions adds the persisted store's membership state.
type v0041RefreshableSessions struct {
	*v0041Sessions
	encrypted []byte
	replaced  int
}

func (s *v0041RefreshableSessions) MembershipState(context.Context, string, time.Time) (store.MembershipState, error) {
	return store.MembershipState{EncryptedProviderState: s.encrypted, Subject: "subject-alpha", ObservedAt: time.Now().Add(-time.Hour)}, nil
}

func (s *v0041RefreshableSessions) ReplaceMembership(_ context.Context, _ string, encrypted []byte, _ []string, _ time.Time) error {
	s.encrypted = encrypted
	s.replaced++
	return nil
}

// v0007.2 v0007.23: with a mandatory refresh (max age 0) an unavailable
// provider fails token issue closed and records no token.
func TestV0007_23_FailClosedWhenMandatoryMembershipRefreshUnavailable(t *testing.T) {
	t.Parallel()
	cipher, err := sessioncrypto.New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := cipher.Encrypt([]byte(`{"refresh_token":"provider"}`), []byte(v0041SessionID))
	if err != nil {
		t.Fatal(err)
	}
	refresher := &v0041Refresher{}
	var sessions *v0041RefreshableSessions
	gateway := newV0041Gateway(t, func(d *Dependencies) {
		sessions = &v0041RefreshableSessions{v0041Sessions: d.Sessions.(*v0041Sessions), encrypted: encrypted}
		d.Sessions, d.Membership, d.SessionEncryptor, d.MembershipMaxAge = sessions, refresher, cipher, 0
	})
	first := gateway.issueResponse(v0041SessionID, 3)
	_ = first.Body.Close()
	if first.StatusCode != http.StatusOK || refresher.calls != 1 || sessions.replaced != 1 {
		t.Fatalf("refreshed issue: status %d calls %d replaced %d", first.StatusCode, refresher.calls, sessions.replaced)
	}
	refresher.mu.Lock()
	refresher.fail = true
	refresher.mu.Unlock()
	response := gateway.issueResponse(v0041SessionID, 3)
	body := v0041ReadBody(t, response)
	v0041Envelope(t, response.StatusCode, body, http.StatusBadGateway, "oidc_provider_unavailable")
	if got := gateway.sessions.recordedTokens(); got != 1 {
		t.Fatalf("recorded tokens = %d, want 1", got)
	}
	if refresher.calls != 2 || sessions.replaced != 1 {
		t.Fatalf("calls %d replaced %d", refresher.calls, sessions.replaced)
	}
}

// v0007.21: the production Gateway answers health and fails unauthenticated
// team reads with the stable envelope.
func TestV0007_21_HealthAndUnauthenticatedEnvelope(t *testing.T) {
	t.Parallel()
	gateway := newV0041Gateway(t, nil)
	health, body := gateway.do(http.MethodGet, "/healthz", nil, "")
	if health.StatusCode != http.StatusOK || strings.TrimSpace(body) != `{"status":"ok"}` {
		t.Fatalf("healthz = %d %s", health.StatusCode, body)
	}
	teams, teamsBody := gateway.do(http.MethodGet, "/auth/v1/teams", nil, "")
	v0041Envelope(t, teams.StatusCode, teamsBody, http.StatusUnauthorized, "invalid_session")
}

type v0041NoSessions struct{ *v0041Sessions }

func (s v0041NoSessions) Create(context.Context, store.SessionInput) error {
	return errors.New("callback must not create a session")
}

// v0007.23: a callback with a code but an unknown state fails closed as an
// invalid identity and creates no session.
func TestV0007_23_CallbackWithUnknownStateFailsClosed(t *testing.T) {
	t.Parallel()
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("unexpected provider call %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(oidc.Discovery{Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks"})
	}))
	t.Cleanup(provider.Close)
	issuer = provider.URL
	flow, err := oidc.NewFlow(context.Background(), oidc.FlowConfig{Issuer: issuer, ClientID: "flowai-api-gateway-e2e", RedirectURI: "https://gateway.example/auth/v1/callback", Timeout: time.Second, StateTTL: time.Minute, ClockSkew: time.Second, TokenMaxAge: time.Minute, ClaimSource: "id_token", TeamClaims: oidc.TeamClaimAdapter{Kind: oidc.StringArray, ClaimPointer: "/teams"}})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := sessioncrypto.New([]byte(strings.Repeat("c", 32)))
	if err != nil {
		t.Fatal(err)
	}
	gateway := newV0041Gateway(t, func(d *Dependencies) {
		d.OIDC, d.Login, d.SessionEncryptor = flow, flow, cipher
		d.Sessions = v0041NoSessions{d.Sessions.(*v0041Sessions)}
	})
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(gateway.server.URL + "/auth/v1/callback?code=fixture-code&state=unknown")
	if err != nil {
		t.Fatal(err)
	}
	body := v0041ReadBody(t, response)
	v0041Envelope(t, response.StatusCode, body, http.StatusUnauthorized, "invalid_oidc_identity")
	if response.Header.Get("Set-Cookie") != "" {
		t.Fatalf("failed callback set a cookie: %s", response.Header.Get("Set-Cookie"))
	}
}

// v0007.27: a callback carrying both code and error is a 400 invalid_request
// envelope that never reflects the provider's error description.
func TestV0007_27_CallbackXORViolationStableEnvelope(t *testing.T) {
	t.Parallel()
	gateway := newV0041Gateway(t, nil)
	response, body := gateway.do(http.MethodGet, "/auth/v1/callback?code=fixture-code&error=access_denied&state=fixture-state&error_description=secret", nil, "")
	v0041Envelope(t, response.StatusCode, body, http.StatusBadRequest, "invalid_request")
	if strings.Contains(body, "secret") {
		t.Fatalf("error description reflected: %s", body)
	}
}

type v0041Presentation struct {
	mu      sync.Mutex
	updates []string
}

func (p *v0041Presentation) RefreshPresentation(_ context.Context, teamID, teamName string, archivedAt *time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updates = append(p.updates, teamID+"|"+teamName+"|"+map[bool]string{true: "archived", false: "active"}[archivedAt != nil])
	return nil
}
