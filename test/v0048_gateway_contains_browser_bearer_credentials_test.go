package test

import (
	"net/http"
	"testing"
)

// api-gateway: Gateway contains browser bearer credentials.
func TestV0048GatewayContainsBrowserBearerCredentials(t *testing.T) {
	t.Parallel()

	t.Run("Valid browser bearer is consumed", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		g.as(token, http.MethodPost, "/ui/v1/teams/3/tasks/1010/controls/cancel", map[string]string{
			"Cookie":              "flowai_session=" + gwSessionID + "; refresh=refresh-canary",
			"Proxy-Authorization": "Basic proxy-canary",
			"X-Refresh-Token":     "refresh-canary",
		}, `{"reason":"operator"}`)
		requests := g.broker.requests()
		if len(requests) != 1 {
			t.Fatalf("requests = %v", g.broker.subjects())
		}
		assertContext(t, requests[0], gwTeam, gwOperator, "Alpha-Team")
		assertNoCredential(t, requests, token, "Bearer", gwSessionID, "refresh-canary", "proxy-canary")
	})
}
