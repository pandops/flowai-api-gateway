package test

import (
	"net/http"
	"testing"
)

const providerKeyCanary = "sk-provider-canary-0048"

// api-gateway: Gateway proxies team model administration.
func TestV0048GatewayProxiesTeamModelAdministration(t *testing.T) {
	t.Parallel()

	t.Run("Operator creates a team model", func(t *testing.T) {
		sink := &syncBuffer{}
		g := newGateway(t, withLogSink(sink))
		token := g.token(gwTeam)
		created := `{"name":"minimax-demo","provider":"minimax","provider_model":"MiniMax-M2.5","credential_configured":true,"status":"active"}`
		proxyCase{method: http.MethodPost, path: "/ui/v1/models", body: `{"name":"minimax-demo","provider":"minimax","provider_model":"MiniMax-M2.5","api_key":"` + providerKeyCanary + `"}`, subject: "model-registry.ui.model-create.pub", status: http.StatusCreated, reply: created, replyHeaders: map[string]string{"ETag": `"model-1"`, "Cache-Control": "no-store", "Location": "/ui/v1/models/minimax-demo"}}.run(t, g, token)
		assertNotRetained(t, g, token, "/ui/v1/models/minimax-demo", "model-registry.ui.model-get.pub", providerKeyCanary)
		assertNotRetained(t, g, token, "/ui/v1/models", "model-registry.ui.models-list.pub", providerKeyCanary)
		assertLogClean(t, sink, "model-registry.ui.model-create.pub", providerKeyCanary, token)
	})

	t.Run("Browser forges team identity", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		for _, c := range []proxyCase{
			{method: http.MethodGet, path: "/ui/v1/models", subject: "model-registry.ui.models-list.pub", status: 200, reply: `{"items":[]}`},
			{method: http.MethodGet, path: "/ui/v1/models/minimax-demo", subject: "model-registry.ui.model-get.pub", status: 200, reply: `{"name":"minimax-demo"}`, replyHeaders: map[string]string{"ETag": `"model-2"`}},
			{method: http.MethodGet, path: "/ui/v1/execution-tags", subject: "executor-registry.ui.list-execution-tags.pub", status: 200, reply: `{"items":["gpu"]}`},
		} {
			request := c.run(t, g, token)
			params, _, _ := decodeUI(t, request)
			if _, ok := params["team_id"]; ok {
				t.Fatalf("%s params carry a team the path did not name: %v", c.subject, params)
			}
		}
	})

	t.Run("Operator changes flow LLM settings", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		request := proxyCase{method: http.MethodPut, path: "/ui/v1/flow-llm-settings/41", ifMatch: `"flow-llm-3"`, body: `{"models":["minimax-demo"],"max_budget_usd":"5.00"}`, subject: "flow-registry.ui.llm-settings-replace.pub", status: 200, reply: `{"flow_id":41,"models":["minimax-demo"]}`, replyHeaders: map[string]string{"ETag": `"flow-llm-4"`}}.run(t, g, token)
		if params, _, _ := decodeUI(t, request); params["flow_id"].(interface{ String() string }).String() != "41" {
			t.Fatalf("params = %v", params)
		}
		proxyCase{method: http.MethodPut, path: "/ui/v1/flow-llm-settings/41", ifMatch: `"flow-llm-3"`, body: `{"models":[]}`, subject: "flow-registry.ui.llm-settings-replace.pub", status: http.StatusPreconditionFailed, reply: `{"code":"precondition_failed","message":"stale","request_id":9}`}.run(t, g, token)
	})

	t.Run("Operator archives an active or paused model", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		for _, outcome := range []struct {
			status int
			reply  string
		}{
			{http.StatusNoContent, ""},
			{http.StatusConflict, `{"code":"model_last_in_flow","message":"used by flow 41","request_id":5}`},
			{http.StatusConflict, `{"code":"model_operation_in_progress","message":"busy","request_id":6}`},
			{http.StatusPreconditionFailed, `{"code":"precondition_failed","message":"stale","request_id":7}`},
			{http.StatusServiceUnavailable, `{"code":"service_unavailable","message":"LiteLLM is unavailable","request_id":8}`},
		} {
			proxyCase{method: http.MethodPost, path: "/ui/v1/models/minimax-demo/archive", ifMatch: `"model-2"`, subject: "model-registry.ui.model-archive.pub", status: outcome.status, reply: outcome.reply}.run(t, g, token)
		}
	})

	t.Run("Operator creates a flow with executor tag and model", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		body := `{"name":"MiniMax Demo","executor_tag":"gpu","models":["minimax-demo"],"source_id":31}`
		proxyCase{method: http.MethodPost, path: "/ui/v1/flows", body: body, subject: "flow-registry.ui.flow-create.pub", status: http.StatusCreated, reply: `{"flow_id":41,"name":"MiniMax Demo"}`, replyHeaders: map[string]string{"ETag": `"flow-1"`, "Location": "/ui/v1/flows/41"}}.run(t, g, token)
		proxyCase{method: http.MethodPost, path: "/ui/v1/flows", body: `{"name":"","models":[]}`, subject: "flow-registry.ui.flow-create.pub", status: http.StatusBadRequest, reply: `{"code":"invalid_request","message":"executor_tag is required","request_id":10}`}.run(t, g, token)
		proxyCase{method: http.MethodPost, path: "/ui/v1/flows", body: body, subject: "flow-registry.ui.flow-create.pub", status: http.StatusConflict, reply: `{"code":"flow_name_taken","message":"exists","request_id":11}`}.run(t, g, token)
	})

	t.Run("Operator unarchives a model", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		for _, outcome := range []struct {
			status int
			reply  string
		}{
			{http.StatusNoContent, ""},
			{http.StatusConflict, `{"code":"model_operation_in_progress","message":"busy","request_id":6}`},
			{http.StatusPreconditionFailed, `{"code":"precondition_failed","message":"stale","request_id":7}`},
			{http.StatusServiceUnavailable, `{"code":"service_unavailable","message":"LiteLLM is unavailable","request_id":8}`},
		} {
			proxyCase{method: http.MethodPost, path: "/ui/v1/models/minimax-demo/unarchive", ifMatch: `"model-3"`, subject: "model-registry.ui.model-unarchive.pub", status: outcome.status, reply: outcome.reply}.run(t, g, token)
		}
	})
}
