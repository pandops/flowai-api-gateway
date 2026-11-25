package test

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/gorilla/websocket"
)

// api-gateway: Gateway establishes trusted canonical-team context.
func TestV0048GatewayEstablishesTrustedCanonicalTeamContext(t *testing.T) {
	t.Parallel()

	t.Run("Browser spoofs authenticated context headers", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		response, _ := g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks", map[string]string{
			"X-FlowAI-Operator-ID": "99",
			"X-FlowAI-Team-ID":     "4",
			"X-FlowAI-Team-Name":   "Forged",
			"X-FlowAI-Request-ID":  "1",
			"team":                 "admin",
			"operator_id":          "99",
			"request_id":           "1",
			"team_name":            "Forged",
			"Cookie":               "flowai_session=forged",
		}, "")
		requests := g.broker.requests()
		if response.StatusCode != 200 || len(requests) != 1 {
			t.Fatalf("spoofed = %d %v", response.StatusCode, g.broker.subjects())
		}
		id := assertContext(t, requests[0], gwTeam, gwOperator, "Alpha-Team")
		if id == 1 {
			t.Fatal("browser request ID reached the owner")
		}
		// team_name is sent only when the token carries a canonical name.
		g.sessions.add("session-unnamed", 43, map[int64]string{5: ""})
		g.sessions.mu.Lock()
		g.sessions.sessions[memHash("session-unnamed")].teams[5] = nil
		g.sessions.mu.Unlock()
		unnamed := g.tokenFor("session-unnamed", 5)
		g.as(unnamed, http.MethodGet, "/ui/v1/teams/5/tasks", map[string]string{"X-FlowAI-Team-Name": "Forged"}, "")
		assertContext(t, g.broker.requests()[1], 5, 43, "")
	})

	t.Run("Authenticated WebSocket subscription is created", func(t *testing.T) {
		journal := newFakeJournal(t)
		g := newGateway(t, withJournal(journal))
		token := g.token(gwTeam)
		g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks", nil, "")
		socket, _, err := websocket.DefaultDialer.Dial(g.streamURL("/ui/v1/teams/3/stream"), http.Header{"Authorization": {"Bearer " + token}, "X-FlowAI-Request-ID": {"1"}})
		if err != nil {
			t.Fatal(err)
		}
		readFrames(t, socket, 2)
		socket.Close()
		rest := g.broker.requests()[0].Header
		stream := journal.seen()[0].headers
		if stream.Get("X-FlowAI-Team-ID") != rest["team"] || stream.Get("X-FlowAI-Operator-ID") != rest["operator_id"] || stream.Get("X-FlowAI-Team-Name") != rest["team_name"] {
			t.Fatalf("stream context %v differs from broker context %v", stream, rest)
		}
		if id, err := strconv.ParseInt(stream.Get("X-FlowAI-Request-ID"), 10, 64); err != nil || id <= 1 || stream.Get("X-FlowAI-Request-ID") == rest["request_id"] {
			t.Fatalf("stream request id = %q", stream.Get("X-FlowAI-Request-ID"))
		}
		if stream.Get("Authorization") != "Bearer "+gwJournalSA {
			t.Fatalf("stream is not authenticated by the service bearer: %q", stream.Get("Authorization"))
		}
	})
}
