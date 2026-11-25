package test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/broker"
)

// api-gateway: Gateway remains business-logic-free.
func TestV0048GatewayRemainsBusinessLogicFree(t *testing.T) {
	t.Parallel()

	t.Run("Authenticated service reply returns", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		// Odd spacing, key order and unknown fields must survive byte for byte.
		success := "{ \"z\":1,\"a\":{\"nested\":[3,2,1]},  \"platform_field\":null }"
		g.broker.on("task-manager.ui.get-task.pub", func(broker.Request) broker.Reply {
			return reply(207, success, map[string]string{"ETag": `"task-1010-r9"`, "Retry-After": "3", "Location": "/ui/v1/teams/3/tasks/1010", "Cache-Control": "no-store"})
		})
		response, body := g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks/1010?view=full", nil, "")
		if response.StatusCode != 207 || body != success {
			t.Fatalf("reply = %d %q", response.StatusCode, body)
		}
		for name, want := range map[string]string{"ETag": `"task-1010-r9"`, "Retry-After": "3", "Location": "/ui/v1/teams/3/tasks/1010", "Cache-Control": "no-store", "Content-Type": "application/json"} {
			if response.Header.Get(name) != want {
				t.Fatalf("%s = %q, want %q", name, response.Header.Get(name), want)
			}
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(body), &decoded); err != nil || len(decoded) != 3 {
			t.Fatalf("Gateway added fields: %s", body)
		}
		// An ownership denial is returned the same way.
		const denial = `{"code":"not_found","message":"not visible","request_id":5}`
		g.broker.on("task-manager.ui.get-task.pub", func(broker.Request) broker.Reply { return reply(404, denial, nil) })
		response, body = g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks/1010", nil, "")
		if response.StatusCode != 404 || body != denial {
			t.Fatalf("denial = %d %s", response.StatusCode, body)
		}
		// The Gateway neither caches nor repeats: two reads are two requests.
		g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks/1010", nil, "")
		if got := len(g.broker.requests()); got != 3 {
			t.Fatalf("requests = %d, want 3", got)
		}
		// A reply without a status is not invented into a success.
		g.broker.on("task-manager.ui.get-task.pub", func(broker.Request) broker.Reply {
			return broker.Reply{Header: map[string]string{}, Body: []byte(`{"ok":true}`)}
		})
		response, body = g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks/1010", nil, "")
		assertEnvelope(t, response, body, http.StatusServiceUnavailable, "service_unavailable")
	})
}
