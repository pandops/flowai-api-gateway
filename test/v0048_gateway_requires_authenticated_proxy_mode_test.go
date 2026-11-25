package test

import (
	"net/http"
	"testing"
)

// api-gateway: Gateway requires authenticated proxy mode.
func TestV0048GatewayRequiresAuthenticatedProxyMode(t *testing.T) {
	t.Parallel()

	t.Run("Authenticated proxy request", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		response, _ := g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks", nil, "")
		requests := g.broker.requests()
		if response.StatusCode != http.StatusOK || len(requests) != 1 || requests[0].Subject != "task-manager.ui.list-tasks.pub" {
			t.Fatalf("authenticated request = %d %v", response.StatusCode, g.broker.subjects())
		}
		assertContext(t, requests[0], gwTeam, gwOperator, "Alpha-Team")
	})

	t.Run("Missing bearer token", func(t *testing.T) {
		journal := newFakeJournal(t)
		g := newGateway(t, withJournal(journal))
		for _, call := range []struct{ method, path string }{
			{http.MethodGet, "/ui/v1/teams/3/tasks"},
			{http.MethodPost, "/ui/v1/teams/3/tasks/1010/controls/cancel"},
			{http.MethodPut, "/ui/v1/flows/12"},
			{http.MethodDelete, "/ui/v1/teams/3/executors/7"},
			{http.MethodGet, "/ui/v1/models"},
			{http.MethodGet, "/ui/v1/echo"},
		} {
			for _, headers := range []map[string]string{
				{"X-FlowAI-Team-ID": "3", "Cookie": "flowai_session=" + gwSessionID},
				{"Authorization": "Bearer not-a-token"},
				{"Authorization": "Basic Zm9vOmJhcg=="},
			} {
				response, body := g.do(call.method, call.path, headers, "")
				assertEnvelope(t, response, body, http.StatusUnauthorized, "invalid_working_token")
			}
		}
		if status, _ := dialRejected(t, g.streamURL("/ui/v1/teams/3/stream"), http.Header{"Cookie": {"flowai_session=" + gwSessionID}}); status != http.StatusUnauthorized {
			t.Fatalf("stream without bearer = %d", status)
		}
		if got := len(g.broker.requests()); got != 0 {
			t.Fatalf("unauthenticated requests reached the broker: %v", g.broker.subjects())
		}
		if got := len(journal.seen()); got != 0 {
			t.Fatalf("unauthenticated upgrade reached journal: %d", got)
		}
	})
}
