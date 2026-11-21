package test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// auth: Each working token has one immutable active team.
func TestV0048EachWorkingTokenHasOneImmutableActiveTeam(t *testing.T) {
	t.Parallel()

	t.Run("Browser renews or switches the selected team", func(t *testing.T) {
		g := newGateway(t, nil)
		first := g.token(gwTeam)
		renewed := g.token(gwTeam)
		switched := g.token(gwOtherTeam)
		a, b, c := claimsOf(t, first), claimsOf(t, renewed), claimsOf(t, switched)
		if a["jti"] == b["jti"] || b["jti"] == c["jti"] || first == renewed {
			t.Fatal("renewal or switch reused a token or jti")
		}
		if a["team_id"] != json.Number("3") || b["team_id"] != json.Number("3") || c["team_id"] != json.Number("4") {
			t.Fatalf("team claims = %v %v %v", a["team_id"], b["team_id"], c["team_id"])
		}
		for _, token := range []string{first, renewed} {
			if response, _ := g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks", nil, ""); response.StatusCode != http.StatusOK {
				t.Fatalf("earlier token stopped working after a new issue: %d", response.StatusCode)
			}
		}
		g.as(switched, http.MethodGet, "/ui/v1/teams/4/tasks", nil, "")
		requests := g.broker.uiRequests()
		assertContext(t, requests[0], gwTeam, gwOperator, "Alpha-Team")
		assertContext(t, requests[2], gwOtherTeam, gwOperator, "Beta-Team")
		response, body := g.issue(gwSessionID, `{"team_id":3}`)
		if strings.Contains(body, "refresh_token") || strings.Contains(body, "id_token") || response.StatusCode != http.StatusOK {
			t.Fatalf("token response = %d %s", response.StatusCode, body)
		}
	})

	t.Run("Browser requests a stale team during token renewal", func(t *testing.T) {
		g := newGateway(t, nil)
		g.token(gwOtherTeam)
		g.sessions.revokeTeam(gwSessionID, gwOtherTeam)
		recorded := g.sessions.recordedTokens()
		response, body := g.issue(gwSessionID, `{"team_id":4}`)
		assertEnvelope(t, response, body, http.StatusForbidden, "team_not_accessible")
		if strings.Contains(body, "access_token") || g.sessions.recordedTokens() != recorded {
			t.Fatal("a token was issued for a stale team")
		}
	})

	t.Run("Browser selects a team by a non-integer identifier", func(t *testing.T) {
		g := newGateway(t, nil)
		for _, body := range []string{`{"team_id":"team-a"}`, `{"team_id":0}`, `{"team_id":-3}`, `{"team_id":3.5}`, `{"team_id":"3"}`, `{"team_id":"6f1c2a4e-1b2c-4d5e-8f90-1234567890ab"}`, `{"team_id":9223372036854775808}`, `{}`} {
			response, text := g.issue(gwSessionID, body)
			assertEnvelope(t, response, text, http.StatusBadRequest, "invalid_request")
			if strings.Contains(text, "access_token") {
				t.Fatalf("%s issued a token", body)
			}
		}
		if g.sessions.recordedTokens() != 0 || len(g.broker.requests()) != 0 {
			t.Fatal("invalid selections issued tokens or reached the broker")
		}
	})
}
