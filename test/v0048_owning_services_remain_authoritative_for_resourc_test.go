package test

import (
	"net/http"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/broker"
)

// api-gateway: Owning services remain authoritative for resource ownership.
func TestV0048OwningServicesRemainAuthoritativeForResourceOwnership(t *testing.T) {
	t.Parallel()
	const denial = `{"code":"not_found","message":"resource is not visible","request_id":81}`

	t.Run("Authenticated team requests another team's resource", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		calls := []struct{ method, path, subject string }{
			{http.MethodGet, "/ui/v1/teams/3/tasks/2020", "task-manager.ui.get-task.pub"},
			{http.MethodGet, "/ui/v1/teams/3/executors/8", "executor-registry.ui.get.pub"},
			{http.MethodGet, "/ui/v1/teams/3/launch-parameters/6", "env-registry.ui.get.pub"},
			{http.MethodGet, "/ui/v1/teams/3/launch-parameters/6/secrets/9/versions", "env-registry.ui.list-secret-versions.pub"},
			{http.MethodGet, "/ui/v1/sources/31", "source-controller.ui.sources-get.pub"},
			{http.MethodGet, "/ui/v1/flows/41", "flow-registry.ui.flow-get.pub"},
			{http.MethodGet, "/ui/v1/models/foreign-model", "model-registry.ui.model-get.pub"},
			{http.MethodGet, "/ui/v1/teams/3/tasks/2020/logs", "journal.ui.task-logs.pub"},
			{http.MethodGet, "/ui/v1/teams/3/audit/51", "audit.ui.get.pub"},
		}
		for _, call := range calls {
			g.broker.on(call.subject, func(broker.Request) broker.Reply {
				return reply(404, denial, map[string]string{"X-Owner-Detail": "dropped"})
			})
		}
		for index, call := range calls {
			response, body := g.as(token, call.method, call.path, nil, "")
			if response.StatusCode != http.StatusNotFound || body != denial {
				t.Fatalf("%s = %d %s, want the owner's denial unchanged", call.path, response.StatusCode, body)
			}
			requests := g.broker.requests()
			if len(requests) != index+1 || requests[index].Subject != call.subject {
				t.Fatalf("%s subjects = %v", call.path, g.broker.subjects())
			}
			// The Gateway decides nothing itself: the verified team goes to the owner.
			assertContext(t, requests[index], gwTeam, gwOperator, "Alpha-Team")
		}
	})

	t.Run("Path names another team", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		g.broker.on("task-manager.ui.get-task.pub", func(broker.Request) broker.Reply { return reply(404, denial, nil) })
		response, body := g.as(token, http.MethodGet, "/ui/v1/teams/4/tasks/1010", nil, "")
		if response.StatusCode != http.StatusNotFound || body != denial {
			t.Fatalf("foreign path = %d %s", response.StatusCode, body)
		}
		requests := g.broker.requests()
		if len(requests) != 1 {
			t.Fatalf("requests = %d", len(requests))
		}
		assertContext(t, requests[0], gwTeam, gwOperator, "Alpha-Team")
		params, _, _ := decodeUI(t, requests[0])
		if params["team_id"] == nil || params["team_id"].(interface{ String() string }).String() != "4" {
			t.Fatalf("path team must reach the owner unchanged for its own check: %v", params)
		}
	})
}
