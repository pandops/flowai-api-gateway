package test

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// api-gateway: Gateway authenticates mapping administrators without provider
// coupling.
func TestV0048GatewayAuthenticatesMappingAdministratorsWithoutProviderCoupling(t *testing.T) {
	t.Parallel()
	body := mappingBody(gwOIDCIss, "oidc-team-alpha", 3)

	t.Run("Operator token calls mapping administration", func(t *testing.T) {
		provider := newAdminProvider(t, "admin-a", "admin-b")
		admin := newAdminGateway(t, provider, time.Hour, time.Second)
		operator := newGateway(t, nil).token(gwTeam)
		response, text := admin.post(t, operator, body)
		assertEnvelope(t, response, text, http.StatusUnauthorized, "invalid_admin_token")
		// Every invalid admin JWT is 401 before any mapping or broker access.
		for name, change := range map[string]func(*adminClaims){
			"wrong issuer":           func(c *adminClaims) { c.issuer = "https://forged.example" },
			"wrong audience":         func(c *adminClaims) { c.audience = "flowai-api-gateway" },
			"algorithm not allowed":  func(c *adminClaims) { c.alg = "RS512" },
			"wrong signing key":      func(c *adminClaims) { c.signWith = "admin-b" },
			"unknown kid, known key": func(c *adminClaims) { c.kid, c.signWith = "admin-unknown", "admin-a" },
			"missing iat":            func(c *adminClaims) { c.iat = nil },
			"expired":                func(c *adminClaims) { c.exp = time.Now().Add(-time.Hour).Unix() },
			"malformed role claim":   func(c *adminClaims) { c.roles = adminRoleV48 },
		} {
			response, text := admin.post(t, provider.token(t, change), body)
			if response.StatusCode != http.StatusUnauthorized || !strings.Contains(text, `"invalid_admin_token"`) {
				t.Fatalf("%s = %d %s, want 401 invalid_admin_token", name, response.StatusCode, text)
			}
			assertEnvelope(t, response, text, http.StatusUnauthorized, "invalid_admin_token")
		}
		for _, roles := range [][]string{{}, {"flowai-operator", "flowai-system-admin-x"}, {"flowai-system-admin-extra"}} {
			response, text = admin.post(t, provider.token(t, func(c *adminClaims) { c.roles = roles }), body)
			assertEnvelope(t, response, text, http.StatusForbidden, "insufficient_admin_role")
		}
		if len(admin.broker.requests()) != 0 || admin.mappings.snapshot() != "" {
			t.Fatalf("rejected callers reached broker %v or store %q", admin.broker.subjects(), admin.mappings.snapshot())
		}
		// A rotated key published by the provider is accepted.
		provider.set([]string{"admin-a", "admin-b"}, 0, 0)
		if response, text := admin.post(t, provider.token(t, func(c *adminClaims) { c.kid = "admin-b" }), body); response.StatusCode != http.StatusCreated {
			t.Fatalf("rotated key = %d %s", response.StatusCode, text)
		}
	})

	t.Run("Admin signing key cannot be refreshed", func(t *testing.T) {
		for _, outage := range []struct {
			status int
			delay  time.Duration
		}{{http.StatusInternalServerError, 0}, {0, 2 * time.Second}} {
			provider := newAdminProvider(t, "admin-a", "admin-b")
			admin := newAdminGateway(t, provider, time.Hour, 500*time.Millisecond)
			provider.set(nil, outage.status, outage.delay)
			response, text := admin.post(t, provider.token(t, func(c *adminClaims) { c.kid = "admin-b" }), body)
			assertEnvelope(t, response, text, http.StatusBadGateway, "admin_identity_provider_unavailable")
			if len(admin.broker.requests()) != 0 || admin.mappings.snapshot() != "" {
				t.Fatalf("JWKS outage reached broker %v or store %q", admin.broker.subjects(), admin.mappings.snapshot())
			}
		}
	})

	t.Run("External administrator role is assigned or removed", func(t *testing.T) {
		provider := newAdminProvider(t, "admin-a")
		admin := newAdminGateway(t, provider, 10*time.Minute, time.Second)
		withoutRole := provider.token(t, func(c *adminClaims) { c.roles = []string{} })
		response, text := admin.post(t, withoutRole, body)
		assertEnvelope(t, response, text, http.StatusForbidden, "insufficient_admin_role")
		assigned := provider.token(t, nil)
		if response, text := admin.post(t, assigned, body); response.StatusCode != http.StatusCreated {
			t.Fatalf("token after assignment = %d %s", response.StatusCode, text)
		}
		removed := provider.token(t, func(c *adminClaims) { c.roles = []string{"flowai-operator"} })
		response, text = admin.post(t, removed, mappingBody(gwOIDCIss, "oidc-team-beta", 4))
		assertEnvelope(t, response, text, http.StatusForbidden, "insufficient_admin_role")
		stale := provider.token(t, func(c *adminClaims) { c.iat = time.Now().Add(-11 * time.Minute).Unix() })
		response, text = admin.post(t, stale, mappingBody(gwOIDCIss, "oidc-team-beta", 4))
		assertEnvelope(t, response, text, http.StatusUnauthorized, "invalid_admin_token")
		if admin.mappings.snapshot() != "oidc-team-alpha->3" {
			t.Fatalf("mappings = %s", admin.mappings.snapshot())
		}
	})
}
