package test

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// api-gateway: Gateway exposes versioned auth and mapping APIs.
func TestV0048GatewayExposesVersionedAuthAndMappingAPIs(t *testing.T) {
	t.Parallel()

	t.Run("API error is returned", func(t *testing.T) {
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-alpha"}}, nil)
		leaks := []string{"goroutine", "panic", ".go:", "Bearer", "provider-secret-detail", "operator-subject-aadmin"}
		check := func(name string, response *http.Response, body string, status int, code string) {
			t.Helper()
			assertEnvelope(t, response, body, status, code)
			for _, leak := range leaks {
				if strings.Contains(body, leak) {
					t.Fatalf("%s: error body leaks %q: %s", name, leak, body)
				}
			}
		}
		read := func(response *http.Response) string {
			data, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			return string(data)
		}
		both := g.loginWith(t, func(query url.Values) { query.Set("error", "access_denied") }, nil)
		check("code and error", both, read(both), http.StatusBadRequest, "invalid_request")
		denied := g.loginWith(t, func(query url.Values) {
			query.Del("code")
			query.Set("error", "access_denied")
			query.Set("error_description", "provider-secret-detail")
		}, nil)
		check("provider error", denied, read(denied), http.StatusUnauthorized, "invalid_oidc_identity")
		response, body := g.do(http.MethodPost, "/auth/v1/token", map[string]string{"Content-Type": "application/json"}, `{"team_id":3}`)
		check("no session", response, body, http.StatusUnauthorized, "invalid_session")
		response, body = g.do(http.MethodGet, "/auth/v1/teams", map[string]string{"Cookie": "flowai_session=unknown"}, "")
		check("unknown session", response, body, http.StatusUnauthorized, "invalid_session")
		session, _ := g.login(t)
		response, body = g.issue(session, `{"team_id":"3"}`)
		check("string team", response, body, http.StatusBadRequest, "invalid_request")
		response, body = g.issue(session, `{"team_id":4}`)
		check("foreign team", response, body, http.StatusForbidden, "team_not_accessible")
		userinfo := newOIDCGateway(t, "userinfo", teamsArray, nil)
		userinfo.provider.setUserinfoStatus(http.StatusBadGateway)
		outage := userinfo.loginWith(t, nil, nil)
		check("OIDC outage", outage, read(outage), http.StatusBadGateway, "oidc_provider_unavailable")

		provider := newAdminProvider(t, "admin-a")
		admin := newAdminGateway(t, provider, time.Hour, time.Second)
		response, body = admin.post(t, "", mappingBody(gwOIDCIss, "oidc-team-alpha", 3))
		check("no admin token", response, body, http.StatusUnauthorized, "invalid_admin_token")
		token := provider.token(t, nil)
		admin.post(t, token, mappingBody(gwOIDCIss, "oidc-team-alpha", 3))
		response, body = admin.post(t, token, mappingBody(gwOIDCIss, "oidc-team-alpha", 4))
		check("conflict", response, body, http.StatusConflict, "mapping_conflict")
		response, body = admin.post(t, token, mappingBody(gwOIDCIss, "oidc-team-zeta", 99))
		check("absent team", response, body, http.StatusNotFound, "canonical_team_not_found")
	})
}
