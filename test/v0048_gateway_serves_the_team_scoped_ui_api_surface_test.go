package test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/broker"
	"github.com/pandops/flowai-api-gateway/internal/httpapi"
)

// api-gateway: Gateway serves the team-scoped UI API surface. Filters,
// validation and ownership belong to the owners; the Gateway forwards the
// selected team and the exact query values and returns the owner's answer.
func TestV0048GatewayServesTheTeamScopedUIAPISurface(t *testing.T) {
	t.Parallel()

	t.Run("UI requests one task-history day", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		day := `{"items":[{"task_id":1010,"ingested_at":"2026-08-15T09:00:00.000Z"}],"next_cursor":null}`
		g.broker.on("task-manager.ui.list-tasks.pub", func(broker.Request) broker.Reply { return reply(200, day, nil) })
		response, body := g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks?date=2026-08-15&limit=10", nil, "")
		if response.StatusCode != 200 || body != day {
			t.Fatalf("day = %d %s", response.StatusCode, body)
		}
		params, _, _ := decodeUI(t, g.broker.requests()[0])
		if params["date"] != "2026-08-15" || params["limit"] != json.Number("10") || params["team_id"] != json.Number("3") {
			t.Fatalf("params = %v", params)
		}
		if _, ok := params["time_zone"]; ok {
			t.Fatalf("Gateway invented a time_zone: %v", params)
		}
		// An explicit zone is forwarded only as given.
		g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks?date=2026-08-15&time_zone=Europe%2FBerlin", nil, "")
		params, _, _ = decodeUI(t, g.broker.requests()[1])
		if params["time_zone"] != "Europe/Berlin" {
			t.Fatalf("time_zone = %v", params["time_zone"])
		}
		g.as(token, http.MethodGet, "/ui/v1/teams/3/dashboard?period=week&time_zone=UTC", nil, "")
		dashboard := g.broker.requests()[2]
		params, _, _ = decodeUI(t, dashboard)
		if dashboard.Subject != "journal.ui.dashboard.pub" || params["time_zone"] != "UTC" || params["period"] != "week" {
			t.Fatalf("dashboard %s params %v", dashboard.Subject, params)
		}
	})

	t.Run("Journal has no responder", func(t *testing.T) {
		g := newGateway(t, func(d *httpapi.Dependencies) {
			d.Broker = brokerWithoutJournal{Requester: d.Broker}
		})
		token := g.token(gwTeam)
		response, body := g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks/1010/logs", nil, "")
		assertEnvelope(t, response, body, http.StatusServiceUnavailable, "service_unavailable")
	})

	t.Run("UI changes selected team", func(t *testing.T) {
		g := newGateway(t, nil)
		alpha := g.token(gwTeam)
		beta := g.token(gwOtherTeam)
		g.as(alpha, http.MethodGet, "/ui/v1/teams/3/tasks", nil, "")
		g.as(beta, http.MethodGet, "/ui/v1/teams/4/tasks", nil, "")
		g.as(alpha, http.MethodGet, "/ui/v1/flows", nil, "")
		requests := g.broker.requests()
		if len(requests) != 3 {
			t.Fatalf("requests = %v", g.broker.subjects())
		}
		assertContext(t, requests[0], gwTeam, gwOperator, "Alpha-Team")
		assertContext(t, requests[1], gwOtherTeam, gwOperator, "Beta-Team")
		assertContext(t, requests[2], gwTeam, gwOperator, "Alpha-Team")
		if requests[0].Header["request_id"] == requests[1].Header["request_id"] || requests[1].Header["request_id"] == requests[2].Header["request_id"] {
			t.Fatal("request IDs repeat across requests")
		}
	})

	t.Run("UI requests an unsupported page size", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		const invalid = `{"code":"invalid_request","message":"limit must be 10, 25, 50 or 100","request_id":17}`
		g.broker.on("audit.ui.list.pub", func(request broker.Request) broker.Reply { return reply(400, invalid, nil) })
		for _, limit := range []string{"7", "1000", "ten"} {
			response, body := g.as(token, http.MethodGet, "/ui/v1/teams/3/audit?limit="+limit, nil, "")
			if response.StatusCode != http.StatusBadRequest || body != invalid {
				t.Fatalf("limit=%s = %d %s, want the owner's validation error unchanged", limit, response.StatusCode, body)
			}
		}
		requests := g.broker.requests()
		first, _, _ := decodeUI(t, requests[0])
		third, _, _ := decodeUI(t, requests[2])
		if first["limit"] != json.Number("7") || third["limit"] != "ten" {
			t.Fatalf("limit forwarded as %v / %v; integers as JSON numbers, other text unchanged for the owner", first["limit"], third["limit"])
		}
	})

	t.Run("UI names a resource outside the selected team", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		const missing = `{"code":"not_found","message":"not found","request_id":23}`
		subjects := map[string]string{
			"/ui/v1/teams/3/tasks/999":                                "task-manager.ui.get-task.pub",
			"/ui/v1/teams/3/executors/999":                            "executor-registry.ui.get.pub",
			"/ui/v1/teams/3/launch-parameters/999":                    "env-registry.ui.get.pub",
			"/ui/v1/teams/3/launch-parameters/5/revisions":            "env-registry.ui.list-revisions.pub",
			"/ui/v1/teams/3/tasks/1010/controls/999/events":           "journal.ui.control-events.pub",
			"/ui/v1/teams/3/tasks/999/logs":                           "journal.ui.task-logs.pub",
			"/ui/v1/teams/3/audit/999":                                "audit.ui.get.pub",
			"/ui/v1/teams/3/launch-parameters/5/secrets/999/versions": "env-registry.ui.list-secret-versions.pub",
		}
		for _, subject := range subjects {
			g.broker.on(subject, func(broker.Request) broker.Reply { return reply(404, missing, nil) })
		}
		for path, subject := range subjects {
			before := len(g.broker.requests())
			response, body := g.as(token, http.MethodGet, path, nil, "")
			requests := g.broker.requests()[before:]
			if response.StatusCode != 404 || body != missing || len(requests) != 1 || requests[0].Subject != subject {
				t.Fatalf("%s = %d %s %v", path, response.StatusCode, body, requests)
			}
		}
	})
}

type brokerWithoutJournal struct {
	broker.Requester
}

func (b brokerWithoutJournal) Request(ctx context.Context, request broker.Request) (broker.Reply, error) {
	if request.Subject == "journal.ui.task-logs.pub" {
		return broker.Reply{}, broker.ErrNoResponders
	}
	return b.Requester.Request(ctx, request)
}
