package test

import (
	"log/slog"
	"net/http"
	"testing"
)

// auth: Auth remains gateway-local.
func TestV0048AuthRemainsGatewayLocal(t *testing.T) {
	t.Parallel()

	t.Run("Authenticated request is proxied", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		response, _ := g.as(token, http.MethodGet, "/ui/v1/teams/3/executors", map[string]string{"Cookie": "flowai_session=" + gwSessionID}, "")
		if response.StatusCode != http.StatusOK {
			t.Fatalf("proxy = %d", response.StatusCode)
		}
		requests := g.broker.requests()
		if len(requests) != 1 {
			t.Fatalf("subjects = %v", g.broker.subjects())
		}
		assertContext(t, requests[0], gwTeam, gwOperator, "Alpha-Team")
		assertNoCredential(t, requests, token, gwSessionID, "Bearer", "Authorization", "flowai_session")
	})

	t.Run("Auth audit is enabled", func(t *testing.T) {
		sink := &syncBuffer{}
		g := newOIDCGateway(t, "id_token", teamsArray, slog.New(slog.NewJSONHandler(sink, nil)))
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-alpha"}}, nil)
		session, _ := g.login(t)
		g.issueFor(t, session, gwTeam)
		g.logout(session)
		records := g.authAudit(t, sink)
		events := map[any]bool{}
		for _, record := range records {
			events[record["event"]] = true
		}
		if !events["login"] || !events["token_issued"] || !events["logout"] {
			t.Fatalf("auth audit events = %v, want login, token_issued and logout", events)
		}
		for _, request := range g.broker.requests() {
			if request.Subject != "team-registry.service.get.pub" {
				t.Fatalf("auth sent %s to the broker", request.Subject)
			}
		}
		assertNoCredential(t, g.broker.requests(), "operator-subject-aadmin", g.provider.issuer(), "oidc-team-alpha")
	})
}
