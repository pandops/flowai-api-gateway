package test

import (
	"net/http"
	"testing"
)

// api-gateway: Gateway proxies source recovery actions.
func TestV0048GatewayProxiesSourceRecoveryActions(t *testing.T) {
	t.Parallel()

	t.Run("Operator unblocks or updates a source", func(t *testing.T) {
		sink := &syncBuffer{}
		g := newGateway(t, withLogSink(sink))
		token := g.token(gwTeam)
		proxyCase{method: http.MethodPost, path: "/ui/v1/sources/31/unblock-polling", ifMatch: `"source-4"`, subject: "source-controller.ui.sources-unblock-polling.pub", status: 200, reply: `{"source_id":31,"polling":"active"}`, replyHeaders: map[string]string{"ETag": `"source-5"`}}.run(t, g, token)
		proxyCase{method: http.MethodPost, path: "/ui/v1/sources/31/unblock-polling", ifMatch: `"source-4"`, subject: "source-controller.ui.sources-unblock-polling.pub", status: http.StatusConflict, reply: `{"code":"source_not_blocked","message":"not blocked","request_id":4}`}.run(t, g, token)
		proxyCase{method: http.MethodPatch, path: "/ui/v1/sources/31/implementation", ifMatch: `"source-5"`, body: `{"implementation":"gitlab-v2"}`, subject: "source-controller.ui.sources-update-implementation.pub", status: 200, reply: `{"source_id":31,"api_key":"` + sourceKeyCanary + `"}`, replyHeaders: map[string]string{"ETag": `"source-6"`, "Cache-Control": "no-store"}}.run(t, g, token)
		assertNotRetained(t, g, token, "/ui/v1/sources/31", "source-controller.ui.sources-get.pub", sourceKeyCanary)
		assertLogClean(t, sink, "source-controller.ui.sources-update-implementation.pub", sourceKeyCanary, token)
	})
}
