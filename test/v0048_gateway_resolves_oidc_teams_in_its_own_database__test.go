package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func teamIDsOf(teams []map[string]any) []string {
	var ids []string
	for _, team := range teams {
		ids = append(ids, fmt.Sprint(team["team_id"]))
	}
	return ids
}

// issueFor issues a working token on an OIDC session and returns its claims.
func (g *oidcGateway) issueFor(t *testing.T, session string, teamID int64) (int, map[string]any) {
	t.Helper()
	response, body := g.issue(session, fmt.Sprintf(`{"team_id":%d}`, teamID))
	if response.StatusCode != http.StatusOK {
		return response.StatusCode, nil
	}
	var decoded struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, claimsOf(t, decoded.AccessToken)
}

// auth: Gateway resolves OIDC teams in its own database before issuing
// operator-team bearer tokens.
func TestV0048GatewayResolvesOIDCTeamsInItsOwnDatabase(t *testing.T) {
	t.Parallel()

	t.Run("Operator logs in with OIDC teams", func(t *testing.T) {
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-beta", "oidc-team-alpha"}}, nil)
		session, _ := g.login(t)
		for range 2 {
			status, teams := g.teams(t, session)
			if status != http.StatusOK || fmt.Sprint(teamIDsOf(teams)) != "[3 4]" || teams[0]["team_name"] != "Alpha-Team" || teams[1]["team_name"] != "Beta-Team" {
				t.Fatalf("teams = %d %v, want the deterministic resolved list", status, teams)
			}
		}
		status, claims := g.issueFor(t, session, gwOtherTeam)
		if status != http.StatusOK || claims["team_id"] != json.Number("4") || claims["operator_id"] != json.Number("42") || claims["sub"] != "42" {
			t.Fatalf("token = %d %v", status, claims)
		}
		if status, _ := g.issueFor(t, session, 5); status != http.StatusForbidden {
			t.Fatalf("token for an unlisted team = %d", status)
		}
	})

	t.Run("First login assigns an operator identifier and later logins reuse it", func(t *testing.T) {
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-alpha"}}, nil)
		first, _ := g.login(t)
		second, _ := g.login(t)
		g.setSubject("operator-subject-hopr")
		other, _ := g.login(t)
		created := g.sessions.createdSessions()
		if len(created) != 3 || created[0].OperatorID != 42 || created[1].OperatorID != 42 || created[2].OperatorID != 43 {
			t.Fatalf("operator ids = %+v", created)
		}
		if created[2].Subject != "operator-subject-hopr" || created[0].Issuer != g.provider.issuer() {
			t.Fatalf("iss/sub are not kept as external text: %+v", created[2])
		}
		for session, want := range map[string]string{first: "42", second: "42", other: "43"} {
			_, claims := g.issueFor(t, session, gwTeam)
			if claims == nil || claims["operator_id"] != json.Number(want) || claims["sub"] != want {
				t.Fatalf("token claims = %v, want operator %s", claims, want)
			}
		}
		if want := []string{g.provider.issuer() + "\x00operator-subject-aadmin", g.provider.issuer() + "\x00operator-subject-aadmin", g.provider.issuer() + "\x00operator-subject-hopr"}; fmt.Sprint(g.operators.calls) != fmt.Sprint(want) {
			t.Fatalf("operator lookups = %q", g.operators.calls)
		}
	})

	t.Run("OIDC teams resolve to no teams", func(t *testing.T) {
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.provider.setClaims(map[string]any{"groups": []any{}}, nil)
		session, response := g.login(t)
		if response.StatusCode != http.StatusFound || session == "" {
			t.Fatalf("empty membership login = %d", response.StatusCode)
		}
		if status, teams := g.teams(t, session); status != http.StatusOK || len(teams) != 0 {
			t.Fatalf("teams = %d %v", status, teams)
		}
		if status, _ := g.issueFor(t, session, gwTeam); status != http.StatusForbidden {
			t.Fatalf("token without teams = %d", status)
		}
		if g.sessions.recordedTokens() != 0 {
			t.Fatal("a working token was recorded")
		}
	})

	t.Run("Only some OIDC teams are mapped", func(t *testing.T) {
		g := newOIDCGateway(t, "id_token", teamsArray, nil)
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-unknown", "oidc-team-alpha"}}, nil)
		session, _ := g.login(t)
		status, teams := g.teams(t, session)
		if status != http.StatusOK || fmt.Sprint(teamIDsOf(teams)) != "[3]" {
			t.Fatalf("teams = %d %v", status, teams)
		}
		if status, _ := g.issueFor(t, session, gwTeam); status != http.StatusOK {
			t.Fatalf("token for the mapped team = %d", status)
		}
		if _, ok := g.sessions.mappings["oidc-team-unknown"]; ok || len(g.sessions.mappings) != 2 {
			t.Fatalf("unknown OIDC team was auto-created: %v", g.sessions.mappings)
		}
	})
}
