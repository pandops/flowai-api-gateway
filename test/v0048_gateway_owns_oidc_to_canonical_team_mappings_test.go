package test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/httpapi"
	"github.com/pandops/flowai-api-gateway/internal/teamregistry"
	"github.com/gorilla/websocket"
)

// api-gateway: Gateway owns OIDC-to-canonical-team mappings.
func TestV0048GatewayOwnsOIDCToCanonicalTeamMappings(t *testing.T) {
	t.Parallel()

	t.Run("User belongs to several mapped OIDC teams", func(t *testing.T) {
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-alpha", "oidc-team-beta"}}, nil)
		session, _ := g.login(t)
		if _, teams := g.teams(t, session); fmt.Sprint(teamIDsOf(teams)) != "[3 4]" {
			t.Fatalf("teams = %v", teams)
		}
		for _, team := range []int64{gwTeam, gwOtherTeam} {
			status, claims := g.issueFor(t, session, team)
			if status != http.StatusOK || fmt.Sprint(claims["team_id"]) != fmt.Sprint(team) {
				t.Fatalf("token for %d = %d %v", team, status, claims)
			}
		}
	})

	t.Run("Browser selects an unresolved team", func(t *testing.T) {
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-alpha"}}, nil)
		session, _ := g.login(t)
		response, body := g.issue(session, `{"team_id":4}`)
		assertEnvelope(t, response, body, http.StatusForbidden, "team_not_accessible")
		if strings.Contains(body, "access_token") || g.sessions.recordedTokens() != 0 {
			t.Fatal("a working token was issued for an unresolved team")
		}
	})

	t.Run("Administrator registers an external team mapping", func(t *testing.T) {
		provider := newAdminProvider(t, "admin-a")
		g := newAdminGateway(t, provider, time.Hour, time.Second)
		response, body := g.post(t, provider.token(t, nil), mappingBody(gwOIDCIss, "oidc-team-alpha", 3))
		if response.StatusCode != http.StatusCreated || !strings.Contains(body, `"team_id":3`) || !strings.Contains(body, `"team_name":"Alpha-Team"`) {
			t.Fatalf("register = %d %s", response.StatusCode, body)
		}
		if g.mappings.snapshot() != "oidc-team-alpha->3" {
			t.Fatalf("mappings = %s", g.mappings.snapshot())
		}
		requests := g.broker.requests()
		if len(requests) != 1 || requests[0].Subject != teamregistry.Subject || requests[0].Header["team"] != teamregistry.AdminTeam {
			t.Fatalf("broker requests = %v", g.broker.subjects())
		}
		if strings.TrimSpace(string(requests[0].Body)) != `{"params":{"team_id":3}}` {
			t.Fatalf("team point read body = %s", requests[0].Body)
		}
		assertNoCredential(t, requests, "oidc-team-alpha", gwOIDCIss, "admin-subject")
	})

	t.Run("Administrator supplies another issuer", func(t *testing.T) {
		provider := newAdminProvider(t, "admin-a")
		g := newAdminGateway(t, provider, time.Hour, time.Second)
		token := provider.token(t, nil)
		for _, body := range []string{
			mappingBody("https://other.example", "oidc-team-alpha", 3),
			mappingBody(gwOIDCIss, "oidc-team-alpha", "team-a"),
			mappingBody(gwOIDCIss, "oidc-team-alpha", 0),
			mappingBody(gwOIDCIss, "oidc-team-alpha", "3"),
			mappingBody(gwOIDCIss, "oidc-team-alpha", 1.5),
		} {
			response, text := g.post(t, token, body)
			assertEnvelope(t, response, text, http.StatusBadRequest, "invalid_request")
		}
		if len(g.broker.requests()) != 0 || g.mappings.snapshot() != "" {
			t.Fatalf("invalid registrations reached broker %v or store %q", g.broker.subjects(), g.mappings.snapshot())
		}
	})

	t.Run("Mapping references an unavailable canonical team", func(t *testing.T) {
		provider := newAdminProvider(t, "admin-a")
		g := newAdminGateway(t, provider, time.Hour, time.Second)
		token := provider.token(t, nil)
		response, body := g.post(t, token, mappingBody(gwOIDCIss, "oidc-team-zeta", 77))
		assertEnvelope(t, response, body, http.StatusNotFound, "canonical_team_not_found")
		if g.mappings.snapshot() != "" {
			t.Fatalf("absent team stored a mapping: %s", g.mappings.snapshot())
		}
	})

	t.Run("Mapping or access references an archived canonical team", func(t *testing.T) {
		archivedAt := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
		archived := map[int64]*time.Time{gwTeam: &archivedAt}
		provider := newAdminProvider(t, "admin-a")
		admin := newAdminGateway(t, provider, time.Hour, time.Second)
		admin.broker.on(teamregistry.Subject, teamRegistryResponder(gwTeamNames, archived))
		response, body := admin.post(t, provider.token(t, nil), mappingBody(gwOIDCIss, "oidc-team-alpha", 3))
		if response.StatusCode != http.StatusCreated || !strings.Contains(body, `"archived_at":"2026-11-01T10:00:00`) {
			t.Fatalf("archived registration = %d %s", response.StatusCode, body)
		}

		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.broker.on(teamregistry.Subject, teamRegistryResponder(gwTeamNames, archived))
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-alpha"}}, nil)
		session, _ := g.login(t)
		_, teams := g.teams(t, session)
		if len(teams) != 1 || teams[0]["archived_at"] == nil {
			t.Fatalf("archived team listing = %v", teams)
		}
		if status, _ := g.issueFor(t, session, gwTeam); status != http.StatusOK {
			t.Fatalf("archived team token = %d", status)
		}

		var fake *fakeBroker
		journal := newFakeJournal(t)
		access := newGateway(t, func(d *httpapi.Dependencies) {
			withTeamRegistry(t, &fake)(d)
			withJournal(journal)(d)
		})
		fake.on(teamregistry.Subject, teamRegistryResponder(gwTeamNames, archived))
		token := access.token(gwTeam)
		rest, _ := access.as(token, http.MethodGet, "/ui/v1/teams/3/tasks", nil, "")
		if rest.StatusCode != http.StatusOK || len(access.broker.uiRequests()) != 1 {
			t.Fatalf("archived team REST read = %d", rest.StatusCode)
		}
		protocol := "flowai.bearer." + base64.RawURLEncoding.EncodeToString([]byte(token))
		socket, _, err := (&websocket.Dialer{Subprotocols: []string{protocol}}).Dial(access.streamURL("/ui/v1/teams/3/stream"), nil)
		if err != nil {
			t.Fatalf("archived team stream: %v", err)
		}
		defer socket.Close()
		if frames := readFrames(t, socket, 2); !strings.Contains(frames[0], `"team_id":3`) {
			t.Fatalf("archived team frames = %v", frames)
		}
	})

	t.Run("Concurrent mapping requests conflict", func(t *testing.T) {
		provider := newAdminProvider(t, "admin-a")
		g := newAdminGateway(t, provider, time.Hour, time.Second)
		token := provider.token(t, nil)
		var wait sync.WaitGroup
		statuses := make([]int, 8)
		bodies := make([]string, 8)
		for index := range statuses {
			wait.Add(1)
			go func() {
				defer wait.Done()
				team := 3
				if index%2 == 1 {
					team = 4 // conflicts: same OIDC team, another canonical team
				}
				response, body := g.post(t, token, mappingBody(gwOIDCIss, "oidc-team-alpha", team))
				statuses[index], bodies[index] = response.StatusCode, body
			}()
		}
		wait.Wait()
		created, same, conflicts := 0, 0, 0
		winner := g.mappings.snapshot()
		for index, status := range statuses {
			switch status {
			case http.StatusCreated:
				created++
			case http.StatusOK:
				same++
			case http.StatusConflict:
				conflicts++
				if !strings.Contains(bodies[index], `"mapping_conflict"`) {
					t.Fatalf("conflict body = %s", bodies[index])
				}
			default:
				t.Fatalf("status %d %s", status, bodies[index])
			}
		}
		if created != 1 || same+conflicts != 7 || conflicts < 4 || (winner != "oidc-team-alpha->3" && winner != "oidc-team-alpha->4") {
			t.Fatalf("created=%d same=%d conflicts=%d winner=%s", created, same, conflicts, winner)
		}
	})
}
