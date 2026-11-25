package test

import (
	"encoding/json"
	"net/http"
	"testing"
)

// api-gateway: Gateway accepts only integer identifiers.
func TestV0048GatewayAcceptsOnlyIntegerIdentifiers(t *testing.T) {
	t.Parallel()
	g := newGateway(t, nil)
	token := g.token(gwTeam)
	rejected := func(t *testing.T, method, path, body string) {
		t.Helper()
		before := len(g.broker.requests())
		response, text := g.as(token, method, path, nil, body)
		assertEnvelope(t, response, text, http.StatusBadRequest, "invalid_request")
		if got := len(g.broker.requests()); got != before {
			t.Fatalf("%s %s published %d requests", method, path, got-before)
		}
	}

	t.Run("Non-integer task identifier is rejected", func(t *testing.T) {
		for _, id := range []string{"abc", "0", "-1", "1.5", "+7", "007", "9223372036854775808", "1e3", "%20"} {
			rejected(t, http.MethodGet, "/ui/v1/teams/3/tasks/"+id, "")
		}
		// Every other path and query identifier follows the same rule.
		for _, path := range []string{
			"/ui/v1/teams/abc/tasks",
			"/ui/v1/teams/0/audit",
			"/ui/v1/teams/3/audit/x",
			"/ui/v1/teams/3/tasks/1010/controls/c-1/events",
			"/ui/v1/teams/3/launch-parameters/env-a",
			"/ui/v1/teams/3/launch-parameters/5/secrets/s-1",
			"/ui/v1/sources/source-1",
			"/ui/v1/flows/flow-1",
			"/ui/v1/flow-llm-settings/-2",
			"/ui/v1/teams/3/tasks?flow_id=abc",
			"/ui/v1/teams/3/tasks?source_id=0",
			"/ui/v1/teams/3/tasks/1010/events?after_frame_id=-5",
		} {
			rejected(t, http.MethodGet, path, "")
		}
		// Body identifiers are JSON numbers; strings, fractions and zero are refused.
		for _, body := range []string{`{"flow_id":"12"}`, `{"source_ids":[9,"x"]}`, `{"environment_id":1.5}`, `{"binding":{"source_id":0}}`, `not-json`} {
			rejected(t, http.MethodPost, "/ui/v1/flows", body)
		}
	})

	t.Run("UUID identifier is rejected", func(t *testing.T) {
		rejected(t, http.MethodDelete, "/ui/v1/teams/3/executors/3f2c9a1e-8d4b-4c11-9a7e-2b6f0d5c1a90", "")
		rejected(t, http.MethodPost, "/ui/v1/teams/3/executors", `{"executor_id":"3f2c9a1e-8d4b-4c11-9a7e-2b6f0d5c1a90","execution_tag":"openhands","executor_type":"executor_docker_openhands"}`)
	})

	t.Run("Integer identifier is forwarded within the selected team", func(t *testing.T) {
		before := len(g.broker.requests())
		response, _ := g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks/1010", nil, "")
		requests := g.broker.requests()[before:]
		if response.StatusCode != 200 || len(requests) != 1 || requests[0].Subject != "task-manager.ui.get-task.pub" {
			t.Fatalf("get-task = %d %v", response.StatusCode, requests)
		}
		assertContext(t, requests[0], gwTeam, gwOperator, "Alpha-Team")
		params, _, _ := decodeUI(t, requests[0])
		if params["team_id"] != json.Number("3") || params["task_id"] != json.Number("1010") || len(params) != 2 {
			t.Fatalf("params = %v, want team_id 3 and task_id 1010 as JSON numbers", params)
		}
		// Names, tags, external IDs and cursors are not identifiers.
		before = len(g.broker.requests())
		response, _ = g.as(token, http.MethodGet, "/ui/v1/models/minimax-demo", nil, "")
		if response.StatusCode != 200 {
			t.Fatalf("model by name = %d", response.StatusCode)
		}
		response, _ = g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks?cursor=opaque.v1-abc&search=X-1&status=queued", nil, "")
		if response.StatusCode != 200 {
			t.Fatalf("task list = %d", response.StatusCode)
		}
		requests = g.broker.requests()[before:]
		model, _, _ := decodeUI(t, requests[0])
		list, _, _ := decodeUI(t, requests[1])
		if model["name"] != "minimax-demo" || list["cursor"] != "opaque.v1-abc" || list["search"] != "X-1" || list["status"] != "queued" {
			t.Fatalf("model %v list %v", model, list)
		}
		response, _ = g.as(token, http.MethodPost, "/ui/v1/flows", nil, `{"name":"Review","execution_tag":"openhands","source_ids":[9,10],"external_id":"PROJ-1"}`)
		if response.StatusCode != 200 {
			t.Fatalf("flow create with integer body ids = %d", response.StatusCode)
		}
	})
}
