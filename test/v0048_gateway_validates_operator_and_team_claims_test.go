package test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/httpapi"
	"github.com/pandops/flowai-api-gateway/internal/teamregistry"
	"github.com/gorilla/websocket"
)

// assertRejected checks one bad token on REST and on the stream upgrade:
// the stable error and nothing sent to the broker or journal.
func assertRejected(t *testing.T, g *gw, journal *fakeJournal, token string, status int, code string) {
	t.Helper()
	response, body := g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks", nil, "")
	assertEnvelope(t, response, body, status, code)
	upgrade, text := dialRejected(t, g.streamURL("/ui/v1/teams/3/stream"), http.Header{"Authorization": {"Bearer " + token}})
	if upgrade != status || !strings.Contains(text, `"`+code+`"`) {
		t.Fatalf("stream upgrade = %d %s, want %d %s", upgrade, text, status, code)
	}
	if got := len(g.broker.uiRequests()); got != 0 {
		t.Fatalf("rejected token reached the broker: %v", g.broker.subjects())
	}
	if got := len(journal.seen()); got != 0 {
		t.Fatalf("rejected token reached journal: %d", got)
	}
}

// auth: Gateway validates operator and team claims.
func TestV0048GatewayValidatesOperatorAndTeamClaims(t *testing.T) {
	t.Parallel()

	t.Run("Token team assignment is stale", func(t *testing.T) {
		journal := newFakeJournal(t)
		g := newGateway(t, withJournal(journal))
		token := g.token(gwTeam)
		g.sessions.revokeTeam(gwSessionID, gwTeam)
		assertRejected(t, g, journal, token, http.StatusForbidden, "team_not_accessible")
		// After logout the session's still-unexpired token opens no stream.
		g.sessions.add("second-session", gwOperator, map[int64]string{gwTeam: "Alpha-Team"})
		loggedOut := g.tokenFor("second-session", gwTeam)
		if g.logout("second-session") != http.StatusNoContent {
			t.Fatal("logout failed")
		}
		assertRejected(t, g, journal, loggedOut, http.StatusForbidden, "team_not_accessible")
	})

	t.Run("Token has wrong audience or is expired", func(t *testing.T) {
		journal := newFakeJournal(t)
		g := newGateway(t, func(d *httpapi.Dependencies) {
			withJournal(journal)(d)
			d.WorkingTokens = gwSigner(t, 2*time.Second)
		})
		token := g.token(gwTeam)
		assertRejected(t, g, journal, resign(t, token, func(c map[string]any) { c["aud"] = "flowai-journal" }), http.StatusUnauthorized, "invalid_working_token")
		assertRejected(t, g, journal, resign(t, token, func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }), http.StatusUnauthorized, "invalid_working_token")
		for name, change := range map[string]func(map[string]any){
			"string operator": func(c map[string]any) { c["operator_id"] = "42" },
			"string team":     func(c map[string]any) { c["team_id"] = "3" },
			"zero team":       func(c map[string]any) { c["team_id"] = 0 },
			"sub mismatch":    func(c map[string]any) { c["sub"] = "operator-subject-aadmin" },
			"two teams":       func(c map[string]any) { c["team_id"] = []int{3, 4} },
		} {
			t.Logf("claim set %s", name)
			assertRejected(t, g, journal, resign(t, token, change), http.StatusUnauthorized, "invalid_working_token")
		}
		// An open stream closes with 4401 working_token_expired at exp.
		protocol := "flowai.bearer." + base64.RawURLEncoding.EncodeToString([]byte(token))
		socket, _, err := (&websocket.Dialer{Subprotocols: []string{protocol}}).Dial(g.streamURL("/ui/v1/teams/3/stream"), nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		defer socket.Close()
		readFrames(t, socket, 2)
		_ = socket.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _, err = socket.ReadMessage()
		var closed *websocket.CloseError
		if !errors.As(err, &closed) || closed.Code != 4401 || closed.Text != "working_token_expired" {
			t.Fatalf("stream end = %v, want close 4401 working_token_expired", err)
		}
		// Reconnecting with the expired token is a new, failing validation.
		if status, _ := dialRejected(t, g.streamURL("/ui/v1/teams/3/stream"), http.Header{"Authorization": {"Bearer " + token}}); status != http.StatusUnauthorized {
			t.Fatalf("reconnect with expired token = %d", status)
		}
		// A renewed token reconnects with a complete new upgrade validation.
		renewed := g.token(gwTeam)
		renewedProtocol := "flowai.bearer." + base64.RawURLEncoding.EncodeToString([]byte(renewed))
		again, _, err := (&websocket.Dialer{Subprotocols: []string{renewedProtocol}}).Dial(g.streamURL("/ui/v1/teams/3/stream"), nil)
		if err != nil {
			t.Fatalf("reconnect with a renewed token: %v", err)
		}
		readFrames(t, again, 2)
		again.Close()
	})

	t.Run("Token signature context is invalid", func(t *testing.T) {
		journal := newFakeJournal(t)
		g := newGateway(t, withJournal(journal))
		token := g.token(gwTeam)
		parts := strings.Split(token, ".")
		header := func(fields map[string]any) string {
			data, _ := json.Marshal(fields)
			return base64.RawURLEncoding.EncodeToString(data) + "." + parts[1] + "." + parts[2]
		}
		for _, bad := range []string{
			resign(t, token, func(c map[string]any) { c["iss"] = "https://forged.example" }),
			header(map[string]any{"alg": "HS256", "typ": "JWT", "kid": gwKeyID}),
			header(map[string]any{"alg": "none", "typ": "JWT", "kid": gwKeyID}),
			header(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "unknown-kid"}),
			parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2])),
		} {
			assertRejected(t, g, journal, bad, http.StatusUnauthorized, "invalid_working_token")
		}
	})

	t.Run("Token team is archived", func(t *testing.T) {
		archivedAt := time.Date(2026, 11, 2, 8, 0, 0, 0, time.UTC)
		var fake *fakeBroker
		journal := newFakeJournal(t)
		g := newGateway(t, func(d *httpapi.Dependencies) {
			withTeamRegistry(t, &fake)(d)
			withJournal(journal)(d)
		})
		fake.on(teamregistry.Subject, teamRegistryResponder(gwTeamNames, map[int64]*time.Time{gwTeam: &archivedAt}))
		token := g.token(gwTeam)
		if response, _ := g.as(token, http.MethodGet, "/ui/v1/teams/3/tasks", nil, ""); response.StatusCode != http.StatusOK {
			t.Fatalf("archived team read = %d", response.StatusCode)
		}
		protocol := "flowai.bearer." + base64.RawURLEncoding.EncodeToString([]byte(token))
		socket, _, err := (&websocket.Dialer{Subprotocols: []string{protocol}}).Dial(g.streamURL("/ui/v1/teams/3/stream"), nil)
		if err != nil {
			t.Fatalf("archived team stream: %v", err)
		}
		defer socket.Close()
		if frames := readFrames(t, socket, 2); !strings.Contains(frames[0], `"team_id":3`) {
			t.Fatalf("archived team frames = %v", frames)
		}
		if claims := claimsOf(t, token); claims["team_id"] != json.Number("3") {
			t.Fatalf("archived team token claims = %v", claims)
		}
	})
}
