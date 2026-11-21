package test

import (
	"net/http"
	"testing"
)

const sourceKeyCanary = "fsk_live_source_key_0048"

// api-gateway: Gateway proxies team source and flow administration.
func TestV0048GatewayProxiesTeamSourceAndFlowAdministration(t *testing.T) {
	t.Parallel()

	t.Run("Operator creates a source", func(t *testing.T) {
		sink := &syncBuffer{}
		g := newGateway(t, withLogSink(sink))
		token := g.token(gwTeam)
		oneTime := `{"source_id":31,"name":"GitLab","api_key":"` + sourceKeyCanary + `"}`
		proxyCase{method: http.MethodPost, path: "/ui/v1/sources", body: `{"name":"GitLab","implementation":"gitlab"}`, subject: "source-controller.ui.sources-create.pub", status: http.StatusCreated, reply: oneTime, replyHeaders: map[string]string{"Cache-Control": "no-store", "ETag": `"source-1"`, "Location": "/ui/v1/sources/31"}}.run(t, g, token)
		proxyCase{method: http.MethodPost, path: "/ui/v1/sources/31/rotate-key", ifMatch: `"source-1"`, subject: "source-controller.ui.sources-rotate-key.pub", status: http.StatusOK, reply: oneTime, replyHeaders: map[string]string{"Cache-Control": "no-store", "ETag": `"source-2"`}}.run(t, g, token)
		assertNotRetained(t, g, token, "/ui/v1/sources/31", "source-controller.ui.sources-get.pub", sourceKeyCanary)
		assertNoCredential(t, g.broker.requests()[2:], sourceKeyCanary)
		assertLogClean(t, sink, "source-controller.ui.sources-create.pub", sourceKeyCanary, token)
	})

	t.Run("Browser forges a team or source key", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		proxyCase{method: http.MethodGet, path: "/ui/v1/sources", subject: "source-controller.ui.sources-list.pub", status: 200, reply: `{"items":[]}`}.run(t, g, token)
		proxyCase{method: http.MethodPost, path: "/ui/v1/sources/31/disable", ifMatch: `"source-2"`, subject: "source-controller.ui.sources-disable.pub", status: 200, reply: `{"source_id":31,"status":"disabled"}`}.run(t, g, token)
		// A Source identifier is an integer like every other identifier.
		response, body := g.as(token, http.MethodGet, "/ui/v1/sources/gitlab-main", nil, "")
		assertEnvelope(t, response, body, http.StatusBadRequest, "invalid_request")
		if len(g.broker.requests()) != 2 {
			t.Fatalf("non-integer source id reached the broker: %v", g.broker.subjects())
		}
	})

	t.Run("Operator saves a standalone Source", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		settings := `{"poll_interval_seconds":60,"base_url":"https://gitlab.example"}`
		proxyCase{method: http.MethodPut, path: "/ui/v1/sources/31/settings", ifMatch: `"source-2"`, body: settings, subject: "source-controller.ui.sources-settings-put.pub", status: 200, reply: `{"source_id":31,"settings":{"poll_interval_seconds":60}}`, replyHeaders: map[string]string{"ETag": `"source-3"`, "Cache-Control": "no-store"}}.run(t, g, token)
		proxyCase{method: http.MethodPut, path: "/ui/v1/sources/31/settings", ifMatch: `"source-2"`, body: settings, subject: "source-controller.ui.sources-settings-put.pub", status: http.StatusPreconditionFailed, reply: `{"code":"precondition_failed","message":"stale","request_id":3}`}.run(t, g, token)
		proxyCase{method: http.MethodGet, path: "/ui/v1/sources/31/settings", subject: "source-controller.ui.sources-settings-get.pub", status: 200, reply: `{"source_id":31}`, replyHeaders: map[string]string{"ETag": `"source-3"`}}.run(t, g, token)
	})
}
