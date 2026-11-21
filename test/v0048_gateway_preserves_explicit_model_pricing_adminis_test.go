package test

import (
	"net/http"
	"testing"
)

// api-gateway: Gateway preserves explicit model pricing administration.
func TestV0048GatewayPreservesExplicitModelPricingAdministration(t *testing.T) {
	t.Parallel()

	t.Run("Operator edits model prices through Gateway", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		body := `{"provider_model":"MiniMax-M2.5","pricing":{"input_usd_per_million_tokens":"0.30","output_usd_per_million_tokens":"1.20"}}`
		confirmed := `{"name":"minimax-demo","pricing":{"input_usd_per_million_tokens":"0.30","output_usd_per_million_tokens":"1.20"},"pricing_status":"confirmed"}`
		proxyCase{method: http.MethodPut, path: "/ui/v1/models/minimax-demo", ifMatch: `"model-7"`, body: body, subject: "model-registry.ui.model-update.pub", status: 200, reply: confirmed, replyHeaders: map[string]string{"ETag": `"model-8"`, "Cache-Control": "no-store"}}.run(t, g, token)
		for _, outcome := range []struct {
			status int
			reply  string
		}{
			{http.StatusBadRequest, `{"code":"invalid_request","message":"pricing pair is incomplete","request_id":2}`},
			{http.StatusNotFound, `{"code":"not_found","message":"not found","request_id":3}`},
			{http.StatusConflict, `{"code":"model_operation_in_progress","message":"busy","request_id":4}`},
			{http.StatusPreconditionFailed, `{"code":"precondition_failed","message":"price changed","request_id":5}`},
			{http.StatusServiceUnavailable, `{"code":"service_unavailable","message":"pricing readback is uncertain","request_id":6}`},
		} {
			proxyCase{method: http.MethodPut, path: "/ui/v1/models/minimax-demo", ifMatch: `"model-7"`, body: body, subject: "model-registry.ui.model-update.pub", status: outcome.status, reply: outcome.reply}.run(t, g, token)
		}
		proxyCase{method: http.MethodGet, path: "/ui/v1/models/minimax-demo", subject: "model-registry.ui.model-get.pub", status: 200, reply: confirmed, replyHeaders: map[string]string{"ETag": `"model-8"`}}.run(t, g, token)
	})
}
