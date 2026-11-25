package test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// api-gateway: Gateway rejects unusable authenticated team context.
func TestV0048GatewayRejectsUnusableAuthenticatedTeamContext(t *testing.T) {
	t.Parallel()

	t.Run("Team claim is missing or ambiguous", func(t *testing.T) {
		journal := newFakeJournal(t)
		g := newGateway(t, withJournal(journal))
		token := g.token(gwTeam)
		for name, change := range map[string]func(map[string]any){
			"missing team":       func(c map[string]any) { delete(c, "team_id") },
			"missing operator":   func(c map[string]any) { delete(c, "operator_id") },
			"two teams":          func(c map[string]any) { c["team_id"] = []int64{3, 4} },
			"team as text":       func(c map[string]any) { c["team_id"] = "3" },
			"zero team":          func(c map[string]any) { c["team_id"] = 0 },
			"operator as text":   func(c map[string]any) { c["operator_id"] = "42"; c["sub"] = "42" },
			"unresolved team":    func(c map[string]any) { c["team_id"] = json.Number("9") },
			"fractional team":    func(c map[string]any) { c["team_id"] = 3.5 },
			"subject mismatched": func(c map[string]any) { c["sub"] = "43" },
		} {
			forged := resign(t, token, change)
			response, body := g.as(forged, http.MethodGet, "/ui/v1/teams/3/tasks", nil, "")
			if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden {
				t.Fatalf("%s = %d %s", name, response.StatusCode, body)
			}
			if status, _ := dialRejected(t, g.streamURL("/ui/v1/teams/3/stream"), map[string][]string{"Authorization": {"Bearer " + forged}}); status != http.StatusUnauthorized && status != http.StatusForbidden {
				t.Fatalf("%s stream = %d", name, status)
			}
		}
		if got := len(g.broker.requests()); got != 0 {
			t.Fatalf("unusable context reached the broker: %v", g.broker.subjects())
		}
		if got := len(journal.seen()); got != 0 {
			t.Fatalf("unusable context reached journal: %d", got)
		}
	})

	t.Run("Team claim is stale", func(t *testing.T) {
		journal := newFakeJournal(t)
		g := newGateway(t, withJournal(journal))
		token := g.token(gwTeam)
		g.sessions.revokeTeam(gwSessionID, gwTeam)
		response, body := g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks", nil, "")
		assertEnvelope(t, response, body, http.StatusForbidden, "team_not_accessible")
		if status, _ := dialRejected(t, g.streamURL("/ui/v1/teams/3/stream"), map[string][]string{"Authorization": {"Bearer " + token}}); status != http.StatusForbidden {
			t.Fatalf("stale stream = %d", status)
		}
		// A deleted session makes every token of it stale as well.
		other := g.token(gwOtherTeam)
		if status := g.logout(gwSessionID); status != http.StatusNoContent {
			t.Fatalf("logout = %d", status)
		}
		response, body = g.as(other, http.MethodGet, "/ui/v1/teams/4/tasks", nil, "")
		assertEnvelope(t, response, body, http.StatusForbidden, "team_not_accessible")
		if got := len(g.broker.requests()); got != 0 {
			t.Fatalf("stale tokens reached the broker: %v", g.broker.subjects())
		}
		if got := len(journal.seen()); got != 0 {
			t.Fatalf("stale token reached journal: %d", got)
		}
	})
}
