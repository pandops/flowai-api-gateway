//go:build integration

package test

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/pandops/flowai-api-gateway/internal/migrations"
	"github.com/pandops/flowai-api-gateway/internal/oidc"
)

var twoTeams = map[int64]string{3: "Alpha-Team", 4: "Beta-Team"}

func verifiedClaims(t *testing.T, key *rsa.PrivateKey, token string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("working token is not a compact JWT")
	}
	decode := func(part string) map[string]any {
		data, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err := json.Unmarshal(data, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		t.Fatalf("working token signature: %v", err)
	}
	return decode(parts[0]), decode(parts[1])
}

func countRows(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(query).Scan(&count); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return count
}

func expectRows(t *testing.T, db *sql.DB, query string, want ...string) {
	t.Helper()
	if got := pgRows(t, db, query); !reflect.DeepEqual(got, want) && (len(got) != 0 || len(want) != 0) {
		t.Fatalf("%s = %q, want %q", query, got, want)
	}
}

// v0007.45: the OIDC callback creates an encrypted server session with the
// mapped access rows; working tokens are signed one-team tokens recorded per
// jti; a provider group removal revokes the team at the next issue.
func TestV0007_45_CallbackCompletesIntoEncryptedServerSession(t *testing.T) {
	db := pgMigrated(t)
	provider := newOIDCProvider(t)
	provider.setClaims(map[string]any{"teams": []any{"oidc-team-alpha", "oidc-team-beta"}}, nil)
	registry := newCanonicalRegistry(t, twoTeams)
	stack := newGatewayStack(t, db, provider, registry, stackOptions{membershipMaxAge: 0})
	for _, pair := range []struct {
		oidc string
		team int64
	}{{"oidc-team-alpha", 3}, {"oidc-team-beta", 4}} {
		if status := stack.registerMapping(pair.oidc, pair.team); status != http.StatusCreated {
			t.Fatalf("mapping %v = %d", pair, status)
		}
	}
	if status := stack.registerMapping("oidc-team-alpha", 3); status != http.StatusOK {
		t.Fatalf("identical retry = %d", status)
	}
	callback := browserLogin(t, stack.server.URL)
	_ = callback.Body.Close()
	setCookie := callback.Header.Get("Set-Cookie")
	for _, part := range []string{"flowai_session=", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(setCookie, part) {
			t.Fatalf("Set-Cookie %q lacks %q", setCookie, part)
		}
	}
	if callback.StatusCode != http.StatusFound || callback.Header.Get("Location") != stack.server.URL+"/after-login" {
		t.Fatalf("callback = %d %s", callback.StatusCode, callback.Header.Get("Location"))
	}
	session := callback.Cookies()[0].Value
	status, teams := stack.teams(session)
	if status != http.StatusOK || teams != `{"teams":[{"archived_at":null,"team_id":3,"team_name":"Alpha-Team"},{"archived_at":null,"team_id":4,"team_name":"Beta-Team"}]}` {
		t.Fatalf("teams = %d %s", status, teams)
	}
	if got := registry.seen(); !reflect.DeepEqual(got, []int64{3, 4, 3, 3, 4}) {
		t.Fatalf("canonical requests = %v", got)
	}
	var jtis []any
	for _, team := range []int64{3, 4} {
		status, body := stack.issue(session, team)
		if status != http.StatusOK || body["token_type"] != "Bearer" || body["expires_in"] != float64(300) {
			t.Fatalf("issue %d = %d %v", team, status, body)
		}
		header, claims := verifiedClaims(t, stack.key, body["access_token"].(string))
		if header["alg"] != "RS256" || header["kid"] != "flowai-working-e2e-1" {
			t.Fatalf("header = %v", header)
		}
		if claims["iss"] != "https://gateway.flowai.invalid" || claims["aud"] != "flowai-state-registry" || claims["team_id"] != float64(team) || claims["operator_id"] != float64(1) || claims["sub"] != "1" {
			t.Fatalf("claims = %v", claims)
		}
		jtis = append(jtis, claims["jti"])
	}
	if jtis[0] == jtis[1] {
		t.Fatal("tokens share a jti")
	}
	expectRows(t, db, `SELECT issuer||' '||oidc_team_id||' '||team_id FROM api_gateway.oidc_team_mappings ORDER BY oidc_team_id`, provider.issuer()+" oidc-team-alpha 3", provider.issuer()+" oidc-team-beta 4")
	expectRows(t, db, `SELECT oidc_team_id FROM api_gateway.membership_observations ORDER BY oidc_team_id`, "oidc-team-alpha", "oidc-team-beta")
	expectRows(t, db, `SELECT team_id FROM api_gateway.derived_operator_team_access ORDER BY team_id`, "3", "4")
	var size int
	var plaintext bool
	var storedHash []byte
	if err := db.QueryRow(`SELECT octet_length(encrypted_provider_state), position('access_token'::bytea IN encrypted_provider_state) > 0, session_id_hash FROM api_gateway.oidc_sessions`).Scan(&size, &plaintext, &storedHash); err != nil {
		t.Fatal(err)
	}
	cookieHash := sha256.Sum256([]byte(session))
	if size <= 32 || plaintext || hex.EncodeToString(storedHash) != hex.EncodeToString(cookieHash[:]) || countRows(t, db, `SELECT count(*) FROM api_gateway.oidc_sessions`) != 1 {
		t.Fatalf("session row: size %d plaintext %v", size, plaintext)
	}
	if countRows(t, db, `SELECT count(*) FROM api_gateway.working_token_records`) != 2 || countRows(t, db, `SELECT count(DISTINCT jti_hash) FROM api_gateway.working_token_records`) != 2 {
		t.Fatal("working token records are not two distinct rows")
	}

	provider.setClaims(map[string]any{"teams": []any{"oidc-team-alpha"}}, nil)
	status, body := stack.issue(session, 4)
	if status != http.StatusForbidden || body["code"] != "team_not_accessible" {
		t.Fatalf("revoked team = %d %v", status, body)
	}
	expectRows(t, db, `SELECT oidc_team_id FROM api_gateway.membership_observations ORDER BY oidc_team_id`, "oidc-team-alpha")
	expectRows(t, db, `SELECT team_id FROM api_gateway.derived_operator_team_access ORDER BY team_id`, "3")
	if countRows(t, db, `SELECT count(*) FROM api_gateway.working_token_records`) != 2 {
		t.Fatal("revoked issue recorded a token")
	}
}

// v0007.23: with the UserInfo claim source the observed memberships are the
// UserInfo ones, and with no mapping the session has zero teams.
func TestV0007_23_UserInfoMembershipObservationsWithoutIDTokenTeams(t *testing.T) {
	db := pgMigrated(t)
	provider := newOIDCProvider(t)
	provider.setClaims(map[string]any{"teams": []any{"id-token-only"}}, map[string]any{"teams": []any{"oidc-team-alpha", "oidc-team-beta"}})
	stack := newGatewayStack(t, db, provider, newCanonicalRegistry(t, twoTeams), stackOptions{claimSource: "userinfo", membershipMaxAge: 5 * time.Minute})
	session, _ := stack.login()
	if status, teams := stack.teams(session); status != http.StatusOK || teams != `{"teams":[]}` {
		t.Fatalf("teams = %d %s", status, teams)
	}
	expectRows(t, db, `SELECT oidc_team_id FROM api_gateway.membership_observations ORDER BY oidc_team_id`, "oidc-team-alpha", "oidc-team-beta")
}

// v0007.16: an object_array UserInfo login with explicit scopes persists only
// the normalized, de-duplicated team IDs.
func TestV0007_16_ObjectArrayUserInfoEndToEnd(t *testing.T) {
	db := pgMigrated(t)
	provider := newOIDCProvider(t)
	provider.setClaims(nil, map[string]any{"teams": []any{
		map[string]any{"id": "oidc-team-alpha", "name": "Alpha", "alias": "forged"},
		map[string]any{"id": "oidc-team-alpha", "name": "Duplicate"},
		map[string]any{"id": "oidc-team-beta", "name": "Beta"},
	}})
	stack := newGatewayStack(t, db, provider, newCanonicalRegistry(t, twoTeams), stackOptions{claimSource: "userinfo", adapter: oidc.TeamClaimAdapter{Kind: oidc.ObjectArray, ClaimPointer: "/teams", IDField: "id", NameField: "name"}, scopes: []string{"membership.read", "profile", "membership.read"}, membershipMaxAge: 5 * time.Minute})
	stack.login()
	if scope := provider.lastAuthorization().Get("scope"); scope != "openid membership.read profile" {
		t.Fatalf("scope = %q", scope)
	}
	expectRows(t, db, `SELECT oidc_team_id FROM api_gateway.membership_observations ORDER BY oidc_team_id`, "oidc-team-alpha", "oidc-team-beta")
}

// v0007.1 v0007.3 v0007.24: every issued token is one working_token_records
// row keyed by the hash of its own jti, with expiry after issue.
func TestV0007_1_WorkingTokenRecordsHaveDistinctJTIHashes(t *testing.T) {
	db := pgMigrated(t)
	provider := newOIDCProvider(t)
	provider.setClaims(map[string]any{"teams": []any{"oidc-team-alpha", "oidc-team-beta"}}, nil)
	stack := newGatewayStack(t, db, provider, newCanonicalRegistry(t, twoTeams), stackOptions{membershipMaxAge: 5 * time.Minute})
	stack.registerMapping("oidc-team-alpha", 3)
	stack.registerMapping("oidc-team-beta", 4)
	session, _ := stack.login()
	var want []string
	for _, team := range []int64{3, 3, 4} {
		_, claims := verifiedClaims(t, stack.key, stack.token(session, team))
		hash := sha256.Sum256([]byte(claims["jti"].(string)))
		want = append(want, hex.EncodeToString(hash[:])+" "+strconv.FormatInt(team, 10))
	}
	sort.Strings(want)
	expectRows(t, db, `SELECT encode(jti_hash,'hex')||' '||team_id FROM api_gateway.working_token_records ORDER BY 1`, want...)
	if countRows(t, db, `SELECT count(DISTINCT jti_hash) FROM api_gateway.working_token_records WHERE expires_at > issued_at`) != 3 {
		t.Fatal("token records are not three distinct, forward-dated rows")
	}
}

// v0007.4: logout deletes the persisted session and everything hanging off
// it; the session can no longer issue and its earlier token is stale.
func TestV0007_4_LogoutDeletesPersistedSession(t *testing.T) {
	db := pgMigrated(t)
	provider := newOIDCProvider(t)
	provider.setClaims(map[string]any{"teams": []any{"oidc-team-alpha"}}, nil)
	stack := newGatewayStack(t, db, provider, newCanonicalRegistry(t, twoTeams), stackOptions{membershipMaxAge: 5 * time.Minute})
	stack.registerMapping("oidc-team-alpha", 3)
	session, _ := stack.login()
	token := stack.token(session, 3)
	status, headers, _ := stack.request(http.MethodDelete, "/auth/v1/session", map[string]string{"Cookie": "flowai_session=" + session}, "")
	if status != http.StatusNoContent || !strings.Contains(headers.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatalf("logout = %d %q", status, headers.Get("Set-Cookie"))
	}
	for _, table := range []string{"oidc_sessions", "membership_observations", "derived_operator_team_access", "working_token_records"} {
		if count := countRows(t, db, `SELECT count(*) FROM api_gateway.`+table); count != 0 {
			t.Fatalf("%s rows after logout = %d", table, count)
		}
	}
	if status, body := stack.issue(session, 3); status != http.StatusUnauthorized || body["code"] != "invalid_session" {
		t.Fatalf("issue after logout = %d %v", status, body)
	}
	if status, _, body := stack.request(http.MethodGet, "/ui/v1/echo", map[string]string{"Authorization": "Bearer " + token}, ""); status != http.StatusForbidden || !strings.Contains(body, "team_not_accessible") {
		t.Fatalf("stale token = %d %s", status, body)
	}
}

// v0007.21: Gateway migrates with a separate migrator role, serves with a
// DML-only runtime role, and its persisted session survives a restart.
func TestV0007_21_RuntimeAndMigrationRolesAcrossRestart(t *testing.T) {
	suffix := pgToken(4)
	runtimeRole, migratorRole := "agw_runtime_"+suffix, "agw_migrator_"+suffix
	runtimePassword, migratorPassword := pgToken(12), pgToken(12)
	cluster := pgOpen(t, pgShared.dsn("flowai", pgShared.password, "postgres"))
	t.Cleanup(func() {
		for _, role := range []string{runtimeRole, migratorRole} {
			if _, err := cluster.Exec(`DROP ROLE IF EXISTS ` + role); err != nil {
				t.Errorf("drop role %s: %v", role, err)
			}
		}
	})
	superDSN, database := pgDatabase(t)
	super := pgOpen(t, superDSN)
	ctx := context.Background()
	if err := migrations.ApplyUp(ctx, super); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, runtimeRole, runtimePassword),
		fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, migratorRole, migratorPassword),
		fmt.Sprintf(`GRANT CONNECT ON DATABASE "%s" TO %s, %s`, database, runtimeRole, migratorRole),
		fmt.Sprintf(`GRANT CREATE ON DATABASE "%s" TO %s`, database, migratorRole),
		fmt.Sprintf(`GRANT USAGE ON SCHEMA api_gateway TO %s, %s`, runtimeRole, migratorRole),
		fmt.Sprintf(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA api_gateway TO %s`, runtimeRole),
		fmt.Sprintf(`GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA api_gateway TO %s`, migratorRole),
		fmt.Sprintf(`GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA api_gateway TO %s, %s`, runtimeRole, migratorRole),
	} {
		if _, err := super.Exec(statement); err != nil {
			t.Fatalf("role setup: %v", err)
		}
	}
	migrate := func() {
		t.Helper()
		migrator, err := sql.Open("pgx", pgShared.dsn(migratorRole, migratorPassword, database))
		if err != nil {
			t.Fatal(err)
		}
		defer migrator.Close()
		if err := migrations.ApplyUp(ctx, migrator); err != nil {
			t.Fatalf("migrate with migrator role: %v", err)
		}
	}
	migrate()
	runtime, err := sql.Open("pgx", pgShared.dsn(runtimeRole, runtimePassword, database))
	if err != nil {
		t.Fatal(err)
	}
	var pgErr *pgconn.PgError
	if _, err := runtime.Exec(`CREATE TABLE api_gateway.runtime_migration_forbidden(id int)`); !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("precondition: runtime role must not have DDL, got %v", err)
	}
	provider := newOIDCProvider(t)
	provider.setClaims(map[string]any{"teams": []any{"oidc-team-alpha"}}, nil)
	registry := newCanonicalRegistry(t, map[int64]string{7: "Isolation-Team"})
	stack := newGatewayStack(t, runtime, provider, registry, stackOptions{membershipMaxAge: 5 * time.Minute})
	if status := stack.registerMapping("oidc-team-alpha", 7); status != http.StatusCreated {
		t.Fatalf("mapping with runtime role = %d", status)
	}
	session, _ := stack.login()
	const want = `{"teams":[{"archived_at":null,"team_id":7,"team_name":"Isolation-Team"}]}`
	if status, teams := stack.teams(session); status != http.StatusOK || teams != want {
		t.Fatalf("teams = %d %s", status, teams)
	}
	if count := countRows(t, runtime, `SELECT count(*) FROM api_gateway.oidc_sessions`); count != 1 {
		t.Fatalf("runtime sessions = %d", count)
	}
	stack.close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}

	migrate()
	restarted := pgOpen(t, pgShared.dsn(runtimeRole, runtimePassword, database))
	again := newGatewayStack(t, restarted, provider, registry, stackOptions{membershipMaxAge: 5 * time.Minute})
	if status, teams := again.teams(session); status != http.StatusOK || teams != want {
		t.Fatalf("teams after restart = %d %s", status, teams)
	}
	again.token(session, 7)
}

// v0034.15: self-preference revisions are atomic on a real PostgreSQL lock,
// shared by the operator's team tokens and by two Gateway instances, and
// survive a restart.
func TestV0034_15_AtomicRevisionsAcrossTeamsAndGatewayInstances(t *testing.T) {
	dsn, _ := pgDatabase(t)
	super := pgOpen(t, dsn)
	if err := migrations.ApplyUp(context.Background(), super); err != nil {
		t.Fatal(err)
	}
	provider := newOIDCProvider(t)
	provider.setClaims(map[string]any{"teams": []any{"oidc-team-alpha", "oidc-team-beta"}}, nil)
	registry := newCanonicalRegistry(t, twoTeams)
	options := stackOptions{membershipMaxAge: 5 * time.Minute}
	primary := newGatewayStack(t, pgOpen(t, dsn), provider, registry, options)
	peer := newGatewayStack(t, pgOpen(t, dsn), provider, registry, options)
	primary.registerMapping("oidc-team-alpha", 3)
	primary.registerMapping("oidc-team-beta", 4)
	session, _ := primary.login()
	tokens := []string{primary.token(session, 3), primary.token(session, 4)}
	_, alpha := verifiedClaims(t, primary.key, tokens[0])
	_, beta := verifiedClaims(t, primary.key, tokens[1])
	if alpha["operator_id"] != beta["operator_id"] || alpha["team_id"] != float64(3) || beta["team_id"] != float64(4) {
		t.Fatalf("team tokens = %v / %v", alpha, beta)
	}
	read := func(stack *gatewayStack, token string) string {
		t.Helper()
		status, headers, body := stack.request(http.MethodGet, "/ui/v1/operator/settings", map[string]string{"Authorization": "Bearer " + token}, "")
		if status != http.StatusOK || headers.Get("Cache-Control") != "no-store" {
			t.Fatalf("read = %d %v %s", status, headers, body)
		}
		return strings.TrimSpace(body) + " " + headers.Get("ETag")
	}
	save := func(stack *gatewayStack, token, zone, etag string) (int, string, string) {
		status, headers, body := stack.request(http.MethodPut, "/ui/v1/operator/settings", map[string]string{"Authorization": "Bearer " + token, "If-Match": etag, "Content-Type": "application/json"}, `{"time_zone":"`+zone+`"}`)
		return status, headers.Get("ETag"), strings.TrimSpace(body)
	}
	initial := `{"time_zone":null} "op-0"`
	for _, got := range []string{read(primary, tokens[0]), read(peer, tokens[1]), read(primary, tokens[1])} {
		if got != initial {
			t.Fatalf("initial = %s", got)
		}
	}
	watcher := pgOpen(t, dsn)
	race := func(zones []string, etag, kind string, raceTokens []string) []int {
		t.Helper()
		tx, err := super.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range []string{`SET LOCAL statement_timeout='5s'`, `SET LOCAL lock_timeout='5s'`, `LOCK TABLE api_gateway.operator_preferences IN SHARE MODE`} {
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
		}
		var holder int
		if err := tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&holder); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		statuses := make([]int, 2)
		var wait sync.WaitGroup
		for index, zone := range zones {
			wait.Add(1)
			go func() {
				defer wait.Done()
				instance := primary
				if index == 1 {
					instance = peer
				}
				statuses[index], _, _ = save(instance, raceTokens[index], zone, etag)
			}()
		}
		prefix := map[string]string{"insert": "INSERT INTO api_gateway.operator_preferences%", "update": "UPDATE api_gateway.operator_preferences%"}[kind]
		blocked, deadline := 0, time.Now().Add(10*time.Second)
		for blocked != 2 && time.Now().Before(deadline) {
			if err := watcher.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>$1 AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE $2`, holder, prefix).Scan(&blocked); err != nil {
				t.Error(err)
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if err := tx.Rollback(); err != nil {
			t.Error(err)
		}
		wait.Wait()
		if blocked != 2 {
			t.Fatalf("%s arrivals blocked on the lock = %d, want 2", kind, blocked)
		}
		sort.Ints(statuses)
		return statuses
	}
	expectStatuses := func(got []int, want ...int) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("race statuses = %v, want %v", got, want)
		}
	}
	expectStatuses(race([]string{"Europe/Moscow", "America/New_York"}, `"op-1"`, "update", tokens), 412, 412)
	expectStatuses(race([]string{"Europe/Moscow", "America/New_York"}, `"op-1"`, "update", []string{tokens[0], tokens[0]}), 412, 412)
	if read(primary, tokens[0]) != initial || read(peer, tokens[1]) != initial {
		t.Fatal("stale updates changed the unset preference")
	}
	expectStatuses(race([]string{"Europe/Moscow", "America/New_York"}, `"op-0"`, "insert", tokens), 200, 412)
	saved := read(primary, tokens[0])
	if saved != `{"time_zone":"Europe/Moscow"} "op-1"` && saved != `{"time_zone":"America/New_York"} "op-1"` {
		t.Fatalf("insert winner = %s", saved)
	}
	if read(peer, tokens[1]) != saved {
		t.Fatal("peer instance does not see the saved preference")
	}
	expectStatuses(race([]string{"Asia/Kolkata", "Pacific/Apia"}, `"op-0"`, "insert", []string{tokens[0], tokens[0]}), 412, 412)
	zone := strings.TrimSuffix(strings.TrimPrefix(strings.Fields(saved)[0], `{"time_zone":"`), `"}`)
	if status, etag, _ := save(primary, tokens[0], zone, `"op-1"`); status != http.StatusOK || etag != `"op-1"` {
		t.Fatalf("noop = %d %s", status, etag)
	}
	if status, etag, _ := save(peer, tokens[1], zone, `"op-1"`); status != http.StatusOK || etag != `"op-1"` {
		t.Fatalf("other-team noop = %d %s", status, etag)
	}
	expectStatuses(race([]string{"Asia/Kolkata", "Pacific/Apia"}, `"op-0"`, "insert", tokens), 412, 412)
	if read(primary, tokens[0]) != saved || read(peer, tokens[1]) != saved {
		t.Fatal("stale inserts changed the saved preference")
	}
	expectStatuses(race([]string{"Asia/Kolkata", "Pacific/Apia"}, `"op-1"`, "update", tokens), 200, 412)
	current := read(primary, tokens[0])
	if !strings.HasSuffix(current, `"op-2"`) || read(peer, tokens[1]) != current {
		t.Fatalf("update winner = %s", current)
	}
	primary.close()
	restarted := newGatewayStack(t, pgOpen(t, dsn), provider, registry, options)
	if read(restarted, tokens[0]) != current || read(restarted, tokens[1]) != current {
		t.Fatal("restart lost the preference")
	}
	status, etag, body := save(peer, tokens[1], "UTC", `"op-2"`)
	if status != http.StatusOK || etag != `"op-3"` || body != `{"time_zone":"UTC"}` {
		t.Fatalf("save after restart = %d %s %s", status, etag, body)
	}
	if read(restarted, tokens[0]) != read(peer, tokens[1]) {
		t.Fatal("instances disagree")
	}
}
