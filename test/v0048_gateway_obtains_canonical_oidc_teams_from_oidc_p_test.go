package test

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/oidc"
)

var (
	teamsArray  = oidc.TeamClaimAdapter{Kind: oidc.StringArray, ClaimPointer: "/groups"}
	teamsObject = oidc.TeamClaimAdapter{Kind: oidc.ObjectArray, ClaimPointer: "/membership/teams", IDField: "id", NameField: "name"}
)

// api-gateway: Gateway obtains canonical OIDC teams from OIDC provider.
func TestV0048GatewayObtainsCanonicalOIDCTeamsFromOIDCProvider(t *testing.T) {
	t.Parallel()

	t.Run("Generic OIDC array claim is normalized", func(t *testing.T) {
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-alpha", "oidc-team-alpha", "oidc-team-unknown"}}, nil)
		session, response := g.login(t)
		if response.StatusCode != http.StatusFound || session == "" {
			t.Fatalf("callback = %d", response.StatusCode)
		}
		created := g.sessions.createdSessions()
		if len(created) != 1 || !reflect.DeepEqual(created[0].OIDCTeamIDs, []string{"oidc-team-alpha", "oidc-team-unknown"}) {
			t.Fatalf("normalized OIDC teams = %+v", created)
		}
		if created[0].OperatorID != 42 || created[0].Issuer != g.provider.issuer() || created[0].Subject != "operator-subject-aadmin" {
			t.Fatalf("session identity = %d %s %s", created[0].OperatorID, created[0].Issuer, created[0].Subject)
		}
		status, teams := g.teams(t, session)
		if status != http.StatusOK || len(teams) != 1 || teams[0]["team_id"].(interface{ String() string }).String() != "3" {
			t.Fatalf("teams = %d %v", status, teams)
		}
		if got := g.broker.uiRequests(); len(got) != 0 {
			t.Fatalf("login sent ui requests: %v", g.broker.subjects())
		}
		// Provider membership never leaves the Gateway: only team-registry
		// point reads by integer team_id are sent.
		assertNoCredential(t, g.broker.requests(), "oidc-team-alpha", "oidc-team-unknown", "operator-subject-aadmin", g.provider.issuer())
	})

	t.Run("Generic object-array claim is normalized", func(t *testing.T) {
		g := newOIDCGateway(t, "userinfo", teamsObject, nil)
		g.provider.setClaims(nil, map[string]any{"membership": map[string]any{"teams": []any{
			map[string]any{"id": "oidc-team-beta", "name": "oidc-team-alpha", "team_id": 3},
		}}})
		session, _ := g.login(t)
		created := g.sessions.createdSessions()
		if len(created) != 1 || !reflect.DeepEqual(created[0].OIDCTeamIDs, []string{"oidc-team-beta"}) {
			t.Fatalf("normalized OIDC teams = %+v", created)
		}
		status, teams := g.teams(t, session)
		if status != http.StatusOK || len(teams) != 1 || teams[0]["team_id"].(interface{ String() string }).String() != "4" {
			t.Fatalf("name_field or another field authorized a team: %d %v", status, teams)
		}
	})

	t.Run("Team-claim adapter or claim shape is unusable", func(t *testing.T) {
		provider := newOIDCProvider(t)
		for _, adapter := range []oidc.TeamClaimAdapter{{Kind: "csv", ClaimPointer: "/groups"}, {Kind: oidc.ObjectArray, ClaimPointer: "/groups"}} {
			if _, err := oidc.NewFlow(context.Background(), oidc.FlowConfig{Issuer: provider.issuer(), ClientID: providerClientID, RedirectURI: "http://127.0.0.1/auth/v1/callback", Timeout: time.Second, StateTTL: time.Minute, ClockSkew: time.Second, TokenMaxAge: time.Minute, ClaimSource: "id_token", TeamClaims: adapter}); err == nil {
				t.Fatalf("startup accepted adapter %+v", adapter)
			}
		}
		for name, claim := range map[string]any{"string": "oidc-team-alpha", "null": nil, "partly empty": []any{"oidc-team-alpha", ""}, "number": []any{7}} {
			g := newOIDCGateway(t, "id_token", teamsArray, nil)
			g.provider.setClaims(map[string]any{"groups": claim}, nil)
			g.assertNoLogin(t, g.loginWith(t, nil, nil), http.StatusUnauthorized, "invalid_oidc_identity")
			if calls := len(g.operators.calls); calls != 0 {
				t.Fatalf("%s: operator lookup ran for an unusable identity", name)
			}
		}
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.assertNoLogin(t, g.loginWith(t, nil, nil), http.StatusUnauthorized, "invalid_oidc_identity")
	})

	t.Run("Browser forges OIDC team membership", func(t *testing.T) {
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-alpha"}}, nil)
		response := g.loginWith(t, func(query url.Values) {
			query.Set("groups", "oidc-team-beta")
			query.Set("team_id", "4")
		}, map[string]string{"X-FlowAI-Team-ID": "4", "X-OIDC-Groups": "oidc-team-beta"})
		_ = response.Body.Close()
		var session string
		for _, cookie := range response.Cookies() {
			if cookie.Name == "flowai_session" {
				session = cookie.Value
			}
		}
		created := g.sessions.createdSessions()
		if session == "" || len(created) != 1 || !reflect.DeepEqual(created[0].OIDCTeamIDs, []string{"oidc-team-alpha"}) {
			t.Fatalf("session from forged membership = %q %+v", session, created)
		}
		if _, teams := g.teams(t, session); len(teams) != 1 || teams[0]["team_id"].(interface{ String() string }).String() != "3" {
			t.Fatalf("teams = %v", teams)
		}
		denied, body := g.issue(session, `{"team_id":4}`)
		assertEnvelope(t, denied, body, http.StatusForbidden, "team_not_accessible")
	})

	t.Run("OIDC authorization response or ID Token is invalid", func(t *testing.T) {
		claims := map[string]map[string]any{
			"audience": {"aud": "another-client"},
			"issuer":   {"iss": "https://forged.example"},
			"expiry":   {"exp": time.Now().Add(-time.Hour).Unix()},
			"nonce":    {"nonce": "forged-nonce"},
		}
		for name, change := range claims {
			g := newOIDCGateway(t, "id_token", teamsArray, nil)
			change["groups"] = []any{"oidc-team-alpha"}
			g.provider.setClaims(change, nil)
			t.Logf("case %s", name)
			g.assertNoLogin(t, g.loginWith(t, nil, nil), http.StatusUnauthorized, "invalid_oidc_identity")
		}
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-alpha"}}, nil)
		g.assertNoLogin(t, g.loginWith(t, func(query url.Values) { query.Set("state", "forged-state") }, nil), http.StatusUnauthorized, "invalid_oidc_identity")
	})

	t.Run("OIDC endpoint is unavailable", func(t *testing.T) {
		g := newOIDCGateway(t, "userinfo", teamsArray, nil)
		g.provider.setClaims(nil, map[string]any{"groups": []any{"oidc-team-alpha"}})
		g.provider.setUserinfoStatus(http.StatusInternalServerError)
		g.assertNoLogin(t, g.loginWith(t, nil, nil), http.StatusBadGateway, "oidc_provider_unavailable", "Internal Server Error", g.provider.issuer())
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_ = listener.Close()
		if _, err := oidc.NewFlow(context.Background(), oidc.FlowConfig{Issuer: "http://" + address, ClientID: providerClientID, RedirectURI: "http://127.0.0.1/auth/v1/callback", Timeout: time.Second, StateTTL: time.Minute, ClockSkew: time.Second, TokenMaxAge: time.Minute, ClaimSource: "id_token", TeamClaims: teamsArray}); err == nil {
			t.Fatal("startup succeeded without discovery")
		}
	})
}
