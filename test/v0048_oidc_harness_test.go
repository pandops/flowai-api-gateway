package test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/httpapi"
	"github.com/pandops/flowai-api-gateway/internal/oidc"
	"github.com/pandops/flowai-api-gateway/internal/sessioncrypto"
	"github.com/pandops/flowai-api-gateway/internal/teamregistry"
)

// oidcGateway is a Gateway driven through the real OIDC flow against the
// in-process provider: OIDC teams oidc-team-alpha and oidc-team-beta map to
// canonical teams 3 and 4; oidc-team-unknown maps to nothing.
type oidcGateway struct {
	*gw
	provider  *oidcProvider
	operators *memOperators
}

func newOIDCGateway(t *testing.T, source string, adapter oidc.TeamClaimAdapter, audit *slog.Logger) *oidcGateway {
	t.Helper()
	provider := newOIDCProvider(t)
	var handler http.Handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	flow := newFlow(t, provider, server.URL+"/auth/v1/callback", source, adapter, nil)
	cipher, err := sessioncrypto.New([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	sessions := newMemSessions()
	sessions.mappings = map[string]int64{"oidc-team-alpha": gwTeam, "oidc-team-beta": gwOtherTeam}
	fake := newFakeBroker()
	fake.on(teamregistry.Subject, teamRegistryResponder(gwTeamNames, nil))
	teams, err := teamregistry.New(fake)
	if err != nil {
		t.Fatal(err)
	}
	operators := newMemOperators(42)
	deps := httpapi.Dependencies{Login: flow, OIDC: flow, Membership: flow, MembershipMaxAge: time.Hour, Sessions: sessions, SessionEncryptor: cipher, SessionTTL: time.Hour, WorkingTokens: gwSigner(t, 5*time.Minute), Operators: operators, Broker: fake, RPCTimeout: 300 * time.Millisecond, Teams: teams, Presentation: &memPresentation{}, AuthAudit: audit}
	handler = httpapi.NewWithDependencies(deps)
	return &oidcGateway{gw: &gw{t: t, server: server, sessions: sessions, broker: fake, deps: deps}, provider: provider, operators: operators}
}

// login completes one browser login and returns the session cookie value.
func (g *oidcGateway) login(t *testing.T) (string, *http.Response) {
	t.Helper()
	response := browserLogin(t, g.server.URL)
	_ = response.Body.Close()
	for _, cookie := range response.Cookies() {
		if cookie.Name == "flowai_session" {
			return cookie.Value, response
		}
	}
	return "", response
}

func (g *oidcGateway) teams(t *testing.T, session string) (int, []map[string]any) {
	t.Helper()
	response, body := g.do(http.MethodGet, "/auth/v1/teams", map[string]string{"Cookie": "flowai_session=" + session}, "")
	var decoded struct {
		Teams []map[string]any `json:"teams"`
	}
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.UseNumber()
	_ = decoder.Decode(&decoded)
	return response.StatusCode, decoded.Teams
}

func (g *oidcGateway) setSubject(subject string) {
	g.provider.mu.Lock()
	defer g.provider.mu.Unlock()
	g.provider.subject = subject
}

// loginWith drives login → authorize → callback, letting the test change the
// callback query the browser sends and add browser headers.
func (g *oidcGateway) loginWith(t *testing.T, change func(url.Values), headers map[string]string) *http.Response {
	t.Helper()
	login, err := noRedirect.Get(g.server.URL + "/auth/v1/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = login.Body.Close()
	authorize, err := noRedirect.Get(login.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	_ = authorize.Body.Close()
	target, err := url.Parse(authorize.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := target.Query()
	if change != nil {
		change(query)
	}
	target.RawQuery = query.Encode()
	request, _ := http.NewRequest(http.MethodGet, target.String(), nil)
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := noRedirect.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

// assertNoLogin checks a failed callback: the error envelope, no session
// cookie, no session row, no operator lookup and no broker request.
func (g *oidcGateway) assertNoLogin(t *testing.T, response *http.Response, status int, code string, secrets ...string) {
	t.Helper()
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	assertEnvelope(t, response, string(data), status, code)
	for _, cookie := range response.Cookies() {
		if cookie.Name == "flowai_session" && cookie.Value != "" {
			t.Fatal("a failed login set a session cookie")
		}
	}
	for _, secret := range secrets {
		if strings.Contains(string(data), secret) {
			t.Fatalf("error body exposes %q: %s", secret, data)
		}
	}
	if created := g.sessions.createdSessions(); len(created) != 0 {
		t.Fatalf("failed login created sessions: %d", len(created))
	}
	if got := g.broker.requests(); len(got) != 0 {
		t.Fatalf("failed login sent broker requests: %v", g.broker.subjects())
	}
}
