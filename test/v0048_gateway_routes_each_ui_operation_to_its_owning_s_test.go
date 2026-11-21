package test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/broker"
)

// api-gateway: Gateway routes each UI operation to its owning service over the
// broker. One Gateway per scenario; each scenario checks the exact subjects.
func TestV0048GatewayRoutesEachUIOperationToItsOwningService(t *testing.T) {
	t.Parallel()

	t.Run("Operator reads team audit", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		g.broker.on("audit.ui.list.pub", func(broker.Request) broker.Reply {
			return reply(200, `{"items":[],"next_cursor":null}`, nil)
		})
		response, body := g.as(token, http.MethodGet, "/ui/v1/teams/3/audit?limit=25", nil, "")
		if response.StatusCode != http.StatusOK || body != `{"items":[],"next_cursor":null}` {
			t.Fatalf("audit = %d %s", response.StatusCode, body)
		}
		if got := g.broker.subjects(); strings.Join(got, ",") != "audit.ui.list.pub" {
			t.Fatalf("subjects = %v, want exactly audit.ui.list.pub", got)
		}
		request := g.broker.requests()[0]
		assertContext(t, request, gwTeam, gwOperator, "Alpha-Team")
		params, _, hasBody := decodeUI(t, request)
		if params["team_id"] != json.Number("3") || params["limit"] != json.Number("25") || hasBody {
			t.Fatalf("params = %v hasBody %v", params, hasBody)
		}
	})

	t.Run("Operator opens the Executor inventory", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		records := `{"items":[{"executor_id":7,"execution_tag":"openhands","executor_type":"executor_docker_openhands","reported_ip":"192.0.2.7","ip_reported_at":"2026-11-07T10:00:00.000Z"}],"next_cursor":null}`
		states := `{"items":[{"executor_id":7,"connection_state":"connected","claims":1,"available":2,"reported_ip":"192.0.2.7"}]}`
		g.broker.on("executor-registry.ui.list.pub", func(broker.Request) broker.Reply { return reply(200, records, nil) })
		g.broker.on("journal.ui.executor-states.pub", func(broker.Request) broker.Reply { return reply(200, states, nil) })
		first, firstBody := g.as(token, http.MethodGet, "/ui/v1/teams/3/executors", nil, "")
		second, secondBody := g.as(token, http.MethodGet, "/ui/v1/teams/3/executor-states", nil, "")
		if first.StatusCode != 200 || firstBody != records || second.StatusCode != 200 || secondBody != states {
			t.Fatalf("inventory = %d %s / %d %s", first.StatusCode, firstBody, second.StatusCode, secondBody)
		}
		if got := strings.Join(g.broker.subjects(), ","); got != "executor-registry.ui.list.pub,journal.ui.executor-states.pub" {
			t.Fatalf("subjects = %s", got)
		}
	})

	t.Run("Operator cancels a task", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		g.broker.on("task-manager.ui.cancel.pub", func(broker.Request) broker.Reply {
			return reply(202, `{"control_id":5,"state":"requested"}`, map[string]string{"Location": "/ui/v1/teams/3/tasks/1010/controls/5/events", "X-Internal": "dropped"})
		})
		response, body := g.as(token, http.MethodPost, "/ui/v1/teams/3/tasks/1010/controls/cancel", nil, `{"reason":"operator"}`)
		if response.StatusCode != http.StatusAccepted || body != `{"control_id":5,"state":"requested"}` || response.Header.Get("Location") != "/ui/v1/teams/3/tasks/1010/controls/5/events" {
			t.Fatalf("cancel = %d %s %v", response.StatusCode, body, response.Header)
		}
		if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("X-Internal") != "" {
			t.Fatalf("headers = %v", response.Header)
		}
		requests := g.broker.requests()
		if len(requests) != 1 || requests[0].Subject != "task-manager.ui.cancel.pub" {
			t.Fatalf("requests = %v", g.broker.subjects())
		}
		params, forwarded, hasBody := decodeUI(t, requests[0])
		if params["team_id"] != json.Number("3") || params["task_id"] != json.Number("1010") || !hasBody || string(forwarded) != `{"reason":"operator"}` {
			t.Fatalf("params %v body %s", params, forwarded)
		}
	})

	t.Run("Operator saves a Flow with retry settings", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		flow := `{"name":"Review","execution_tag":"openhands","models":["review-model"],"retry_count":3,"retry_wait_seconds":60,"pending_limit_seconds":600,"release_delay_seconds":30}`
		g.broker.on("flow-registry.ui.flow-replace.pub", func(broker.Request) broker.Reply {
			return reply(200, `{"flow_id":12,"revision":4}`, map[string]string{"ETag": `"flow-12-r4"`})
		})
		response, body := g.as(token, http.MethodPut, "/ui/v1/flows/12", map[string]string{"If-Match": `"flow-12-r3"`}, flow)
		if response.StatusCode != 200 || body != `{"flow_id":12,"revision":4}` || response.Header.Get("ETag") != `"flow-12-r4"` {
			t.Fatalf("save = %d %s etag %q", response.StatusCode, body, response.Header.Get("ETag"))
		}
		requests := g.broker.requests()
		if len(requests) != 1 || requests[0].Subject != "flow-registry.ui.flow-replace.pub" || requests[0].Header["If-Match"] != `"flow-12-r3"` {
			t.Fatalf("requests = %+v", requests)
		}
		params, forwarded, _ := decodeUI(t, requests[0])
		if params["flow_id"] != json.Number("12") || string(forwarded) != flow {
			t.Fatalf("params %v body %s", params, forwarded)
		}
	})

	t.Run("Unknown UI route", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		for _, call := range []struct{ method, path string }{
			{http.MethodGet, "/ui/v1/echo"},
			{http.MethodGet, "/ui/v1/teams/3/unknown"},
			{http.MethodDelete, "/ui/v1/teams/3/tasks/1010"},
			{http.MethodPost, "/ui/v1/teams/3/audit"},
			{http.MethodPatch, "/ui/v1/flows/12"},
			{http.MethodGet, "/ui/v1/teams"},
		} {
			response, body := g.as(token, call.method, call.path, nil, "")
			assertEnvelope(t, response, body, http.StatusNotFound, "not_found")
		}
		if got := len(g.broker.requests()); got != 0 {
			t.Fatalf("unknown routes published %d requests: %v", got, g.broker.subjects())
		}
	})

	t.Run("Operator rotates a Source key", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		g.broker.on("source-controller.ui.sources-rotate-key.pub", func(broker.Request) broker.Reply {
			return reply(200, `{"source_id":9,"api_key":"one-time-source-key"}`, map[string]string{"ETag": `"source-9-r2"`, "Cache-Control": "no-store"})
		})
		response, body := g.as(token, http.MethodPost, "/ui/v1/sources/9/rotate-key", map[string]string{"If-Match": `"source-9-r1"`}, "")
		if response.StatusCode != 200 || body != `{"source_id":9,"api_key":"one-time-source-key"}` || response.Header.Get("ETag") != `"source-9-r2"` || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("rotate = %d %s %v", response.StatusCode, body, response.Header)
		}
		if got := strings.Join(g.broker.subjects(), ","); got != "source-controller.ui.sources-rotate-key.pub" {
			t.Fatalf("subjects = %s", got)
		}
		params, _, _ := decodeUI(t, g.broker.requests()[0])
		if params["id"] != json.Number("9") {
			t.Fatalf("params = %v", params)
		}
	})

	t.Run("Operator previews a Flow", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		g.broker.on("flow-registry.ui.flow-preview.pub", func(broker.Request) broker.Reply {
			return reply(200, `{"prompt":"Work X-1"}`, nil)
		})
		preview := `{"prompt_template":"Work {{external_id}}","external_id":"X-1"}`
		response, body := g.as(token, http.MethodPost, "/ui/v1/flows/preview", nil, preview)
		if response.StatusCode != 200 || body != `{"prompt":"Work X-1"}` {
			t.Fatalf("preview = %d %s", response.StatusCode, body)
		}
		if got := strings.Join(g.broker.subjects(), ","); got != "flow-registry.ui.flow-preview.pub" {
			t.Fatalf("subjects = %s", got)
		}
		_, forwarded, _ := decodeUI(t, g.broker.requests()[0])
		if string(forwarded) != preview {
			t.Fatalf("body = %s", forwarded)
		}
	})

	t.Run("Operator revokes a launch-parameter secret", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		g.broker.on("env-registry.ui.revoke-secret.pub", func(broker.Request) broker.Reply { return reply(204, "", nil) })
		response, body := g.as(token, http.MethodDelete, "/ui/v1/teams/3/launch-parameters/5/secrets/8", nil, "")
		if response.StatusCode != http.StatusNoContent || body != "" {
			t.Fatalf("revoke = %d %q", response.StatusCode, body)
		}
		if got := strings.Join(g.broker.subjects(), ","); got != "env-registry.ui.revoke-secret.pub" {
			t.Fatalf("subjects = %s, want only env-registry.ui.revoke-secret.pub", got)
		}
		params, _, _ := decodeUI(t, g.broker.requests()[0])
		if params["team_id"] != json.Number("3") || params["environment_id"] != json.Number("5") || params["secret_id"] != json.Number("8") || len(params) != 3 {
			t.Fatalf("params = %v", params)
		}
	})

	t.Run("Every route of the table reaches its owner's operation", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		for _, call := range uiRouteTable {
			before := len(g.broker.requests())
			body := ""
			if call.method != http.MethodGet && call.method != http.MethodDelete {
				body = `{}`
			}
			response, text := g.as(token, call.method, call.path, nil, body)
			requests := g.broker.requests()
			if response.StatusCode != 200 || len(requests) != before+1 || requests[before].Subject != call.subject {
				t.Fatalf("%s %s = %d %s, subject %v want %s", call.method, call.path, response.StatusCode, text, requests[before:], call.subject)
			}
			assertContext(t, requests[before], gwTeam, gwOperator, "Alpha-Team")
			for _, token := range strings.Split(call.subject, ".")[2:3] {
				if strings.ContainsAny(token, "._") || strings.ToLower(token) != token {
					t.Fatalf("operation token %q is not lowercase words joined by -", token)
				}
			}
		}
	})
}

// uiRouteTable is the route table of the api-gateway delta spec with one
// concrete path per route.
var uiRouteTable = []struct{ method, path, subject string }{
	{"GET", "/ui/v1/teams/3/tasks", "task-manager.ui.list-tasks.pub"},
	{"GET", "/ui/v1/teams/3/tasks/1010", "task-manager.ui.get-task.pub"},
	{"GET", "/ui/v1/teams/3/tasks/1010/attempts", "task-manager.ui.list-attempts.pub"},
	{"GET", "/ui/v1/teams/3/executors/7/tasks", "task-manager.ui.list-executor-tasks.pub"},
	{"GET", "/ui/v1/teams/3/archived-tasks", "task-manager.ui.list-archive.pub"},
	{"GET", "/ui/v1/teams/3/archived-tasks/1010", "task-manager.ui.get-archived-task.pub"},
	{"POST", "/ui/v1/teams/3/tasks/1010/controls/cancel", "task-manager.ui.cancel.pub"},
	{"GET", "/ui/v1/teams/3/tasks/1010/events", "journal.ui.task-events.pub"},
	{"GET", "/ui/v1/teams/3/tasks/1010/logs", "journal.ui.task-logs.pub"},
	{"GET", "/ui/v1/teams/3/tasks/1010/controls/5/events", "journal.ui.control-events.pub"},
	{"GET", "/ui/v1/teams/3/executors/7/events", "journal.ui.executor-events.pub"},
	{"GET", "/ui/v1/teams/3/executor-states", "journal.ui.executor-states.pub"},
	{"GET", "/ui/v1/teams/3/dashboard?period=week", "journal.ui.dashboard.pub"},
	{"GET", "/ui/v1/teams/3/audit", "audit.ui.list.pub"},
	{"GET", "/ui/v1/teams/3/audit/77", "audit.ui.get.pub"},
	{"GET", "/ui/v1/sources", "source-controller.ui.sources-list.pub"},
	{"POST", "/ui/v1/sources", "source-controller.ui.sources-create.pub"},
	{"GET", "/ui/v1/sources/9", "source-controller.ui.sources-get.pub"},
	{"GET", "/ui/v1/sources/9/settings", "source-controller.ui.sources-settings-get.pub"},
	{"PUT", "/ui/v1/sources/9/settings", "source-controller.ui.sources-settings-put.pub"},
	{"POST", "/ui/v1/sources/9/rotate-key", "source-controller.ui.sources-rotate-key.pub"},
	{"POST", "/ui/v1/sources/9/disable", "source-controller.ui.sources-disable.pub"},
	{"POST", "/ui/v1/sources/9/unblock-polling", "source-controller.ui.sources-unblock-polling.pub"},
	{"PATCH", "/ui/v1/sources/9/implementation", "source-controller.ui.sources-update-implementation.pub"},
	{"GET", "/ui/v1/flows", "flow-registry.ui.flows-list.pub"},
	{"POST", "/ui/v1/flows", "flow-registry.ui.flow-create.pub"},
	{"GET", "/ui/v1/flows/12", "flow-registry.ui.flow-get.pub"},
	{"PUT", "/ui/v1/flows/12", "flow-registry.ui.flow-replace.pub"},
	{"POST", "/ui/v1/flows/preview", "flow-registry.ui.flow-preview.pub"},
	{"GET", "/ui/v1/flow-llm-settings", "flow-registry.ui.llm-settings-list.pub"},
	{"GET", "/ui/v1/flow-llm-settings/12", "flow-registry.ui.llm-settings-get.pub"},
	{"PUT", "/ui/v1/flow-llm-settings/12", "flow-registry.ui.llm-settings-replace.pub"},
	{"GET", "/ui/v1/models", "model-registry.ui.models-list.pub"},
	{"POST", "/ui/v1/models", "model-registry.ui.model-create.pub"},
	{"GET", "/ui/v1/models/minimax-demo", "model-registry.ui.model-get.pub"},
	{"PUT", "/ui/v1/models/minimax-demo", "model-registry.ui.model-update.pub"},
	{"POST", "/ui/v1/models/minimax-demo/archive", "model-registry.ui.model-archive.pub"},
	{"POST", "/ui/v1/models/minimax-demo/unarchive", "model-registry.ui.model-unarchive.pub"},
	{"GET", "/ui/v1/teams/3/tasks/1010/launch-parameters", "env-registry.ui.task-parameters.pub"},
	{"GET", "/ui/v1/teams/3/launch-parameters", "env-registry.ui.list.pub"},
	{"POST", "/ui/v1/teams/3/launch-parameters", "env-registry.ui.create.pub"},
	{"GET", "/ui/v1/teams/3/launch-parameters/5", "env-registry.ui.get.pub"},
	{"PUT", "/ui/v1/teams/3/launch-parameters/5", "env-registry.ui.replace.pub"},
	{"DELETE", "/ui/v1/teams/3/launch-parameters/5", "env-registry.ui.delete.pub"},
	{"GET", "/ui/v1/teams/3/launch-parameters/5/revisions", "env-registry.ui.list-revisions.pub"},
	{"POST", "/ui/v1/teams/3/launch-parameters/5/secrets", "env-registry.ui.create-secret.pub"},
	{"PUT", "/ui/v1/teams/3/launch-parameters/5/secrets/8", "env-registry.ui.replace-secret.pub"},
	{"DELETE", "/ui/v1/teams/3/launch-parameters/5/secrets/8", "env-registry.ui.revoke-secret.pub"},
	{"GET", "/ui/v1/teams/3/launch-parameters/5/secrets/8/versions", "env-registry.ui.list-secret-versions.pub"},
	{"GET", "/ui/v1/teams/3/executors", "executor-registry.ui.list.pub"},
	{"POST", "/ui/v1/teams/3/executors", "executor-registry.ui.create.pub"},
	{"GET", "/ui/v1/teams/3/executors/7", "executor-registry.ui.get.pub"},
	{"POST", "/ui/v1/teams/3/executors/7/token", "executor-registry.ui.reissue.pub"},
	{"DELETE", "/ui/v1/teams/3/executors/7", "executor-registry.ui.delete.pub"},
	{"GET", "/ui/v1/execution-tags", "executor-registry.ui.list-execution-tags.pub"},
}
