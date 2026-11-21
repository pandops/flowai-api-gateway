package test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/httpapi"
	"github.com/pandops/flowai-api-gateway/internal/oidc"
	"github.com/pandops/flowai-api-gateway/internal/sessioncrypto"
	"github.com/pandops/flowai-api-gateway/internal/store"
)

func newFlow(t *testing.T, provider *oidcProvider, redirectURI, source string, adapter oidc.TeamClaimAdapter, scopes []string) *oidc.Flow {
	t.Helper()
	flow, err := oidc.NewFlow(context.Background(), oidc.FlowConfig{Issuer: provider.issuer(), ClientID: providerClientID, RedirectURI: redirectURI, Scopes: scopes, Timeout: 5 * time.Second, StateTTL: 10 * time.Minute, ClockSkew: 30 * time.Second, TokenMaxAge: 10 * time.Minute, ClaimSource: source, TeamClaims: adapter})
	if err != nil {
		t.Fatal(err)
	}
	return flow
}

// authorizeAt drives the provider's authorize endpoint for a Gateway
// authorization URL and returns the callback's code and state.
func authorizeAt(t *testing.T, location string) (string, string) {
	t.Helper()
	response, err := noRedirect.Get(location)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d", response.StatusCode)
	}
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return callback.Query().Get("code"), callback.Query().Get("state")
}

// v0007.45: login is a 302 to the discovered authorization endpoint with the
// client, code flow, openid, state, nonce and S256 PKCE, which the provider
// accepts.
func TestV0007_45_LoginStartsThroughDiscoveryAndPKCE(t *testing.T) {
	t.Parallel()
	provider := newOIDCProvider(t)
	flow := newFlow(t, provider, "https://gateway.example/auth/v1/callback", "id_token", oidc.TeamClaimAdapter{Kind: oidc.StringArray, ClaimPointer: "/teams"}, nil)
	gateway := httptest.NewServer(httpapi.NewWithDependencies(httpapi.Dependencies{Login: flow}))
	t.Cleanup(gateway.Close)
	response, err := noRedirect.Get(gateway.URL + "/auth/v1/login")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusFound {
		t.Fatalf("login = %d", response.StatusCode)
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	if location.Scheme+"://"+location.Host+location.Path != provider.issuer()+"/authorize" {
		t.Fatalf("authorization endpoint = %s", location)
	}
	if query.Get("client_id") != providerClientID || query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || query.Get("redirect_uri") != "https://gateway.example/auth/v1/callback" {
		t.Fatalf("query = %v", query)
	}
	if !strings.Contains(" "+query.Get("scope")+" ", " openid ") || query.Get("state") == "" || query.Get("nonce") == "" || len(query.Get("code_challenge")) != 43 {
		t.Fatalf("query = %v", query)
	}
	code, state := authorizeAt(t, location.String())
	if code == "" || state != query.Get("state") {
		t.Fatalf("provider callback code %q state %q", code, state)
	}
}

// v0007.16: the object_array UserInfo adapter keeps only normalized,
// de-duplicated IDs (ignoring display fields) and the explicit scopes keep
// their order after openid.
func TestV0007_16_ObjectArrayUserInfoNormalizesIDsAndScopes(t *testing.T) {
	t.Parallel()
	provider := newOIDCProvider(t)
	provider.setClaims(nil, map[string]any{"teams": []any{
		map[string]any{"id": "oidc-team-alpha", "name": "Alpha", "alias": "forged"},
		map[string]any{"id": "oidc-team-alpha", "name": "Duplicate"},
		map[string]any{"id": "oidc-team-beta", "name": "Beta"},
	}})
	flow := newFlow(t, provider, "https://gateway.example/auth/v1/callback", "userinfo", oidc.TeamClaimAdapter{Kind: oidc.ObjectArray, ClaimPointer: "/teams", IDField: "id", NameField: "name"}, []string{"membership.read", "profile", "membership.read"})
	location, err := flow.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(location)
	if got := strings.Split(parsed.Query().Get("scope"), " "); !reflect.DeepEqual(got, []string{"openid", "membership.read", "profile"}) {
		t.Fatalf("scope = %q", got)
	}
	code, state := authorizeAt(t, location)
	identity, err := flow.Complete(context.Background(), code, state)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(identity.OIDCTeamIDs, []string{"oidc-team-alpha", "oidc-team-beta"}) || identity.Subject != "operator-subject-aadmin" {
		t.Fatalf("identity = %+v", identity)
	}
}

type refusingSessions struct{ httpapi.SessionCreator }

func (refusingSessions) Create(context.Context, store.SessionInput) error {
	return errors.New("failed callback must not create a session")
}

// v0007.23: with the UserInfo claim source the teams come from UserInfo,
// not the ID token; a malformed UserInfo claim is an invalid identity and an
// unavailable UserInfo is a provider outage.
func TestV0007_23_UserInfoClaimSourceWithoutIDTokenFallback(t *testing.T) {
	t.Parallel()
	provider := newOIDCProvider(t)
	provider.setClaims(map[string]any{"teams": []any{"id-token-only"}}, map[string]any{"teams": []any{"oidc-team-alpha", "oidc-team-beta"}})
	adapter := oidc.TeamClaimAdapter{Kind: oidc.StringArray, ClaimPointer: "/teams"}
	flow := newFlow(t, provider, "https://gateway.example/auth/v1/callback", "userinfo", adapter, nil)
	location, _ := flow.Start(context.Background())
	code, state := authorizeAt(t, location)
	identity, err := flow.Complete(context.Background(), code, state)
	if err != nil || !reflect.DeepEqual(identity.OIDCTeamIDs, []string{"oidc-team-alpha", "oidc-team-beta"}) {
		t.Fatalf("identity = %+v, %v", identity, err)
	}
	cipher, err := sessioncrypto.New([]byte(strings.Repeat("7", 32)))
	if err != nil {
		t.Fatal(err)
	}
	gateway := httptest.NewServer(httpapi.NewWithDependencies(httpapi.Dependencies{Login: flow, OIDC: flow, Sessions: refusingSessions{}, SessionEncryptor: cipher}))
	t.Cleanup(gateway.Close)
	callback := func() (int, string) {
		t.Helper()
		location, _ := flow.Start(context.Background())
		code, state := authorizeAt(t, location)
		response, err := noRedirect.Get(gateway.URL + "/auth/v1/callback?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.Header.Get("Set-Cookie") != "" {
			t.Fatal("failed callback set a session cookie")
		}
		var envelope struct{ Code, Message, RequestID string }
		_ = json.Unmarshal(body, &envelope)
		return response.StatusCode, envelope.Code
	}
	// A UserInfo document without the team claim fails closed instead of
	// reusing the ID token's claim.
	provider.setClaims(map[string]any{"teams": []any{"id-token-only"}}, map[string]any{})
	if status, code := callback(); status != http.StatusUnauthorized || code != "invalid_oidc_identity" {
		t.Fatalf("UserInfo without teams = %d %s", status, code)
	}
	provider.setClaims(map[string]any{"teams": []any{"id-token-only"}}, map[string]any{"teams": "not-an-array"})
	if status, code := callback(); status != http.StatusUnauthorized || code != "invalid_oidc_identity" {
		t.Fatalf("malformed UserInfo teams = %d %s", status, code)
	}
	provider.setUserinfoStatus(http.StatusServiceUnavailable)
	if status, code := callback(); status != http.StatusBadGateway || code != "oidc_provider_unavailable" {
		t.Fatalf("UserInfo unavailable = %d %s", status, code)
	}
}
