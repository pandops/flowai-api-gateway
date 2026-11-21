package httpapi

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/store"
)

// v0041Preferences has store.OperatorPreferences' conditional-write
// semantics: revision 0 inserts only an absent row, a matching revision
// updates, an identical value keeps the revision, anything else is stale.
type v0041Preferences struct {
	mu          sync.Mutex
	rows        map[int64]store.OperatorPreference
	unavailable bool
	saves       int
}

func (p *v0041Preferences) Read(_ context.Context, operatorID int64) (store.OperatorPreference, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.unavailable {
		return store.OperatorPreference{}, errors.New("relation does not exist")
	}
	return p.rows[operatorID], nil
}

func (p *v0041Preferences) Save(_ context.Context, operatorID int64, zone string, revision int64) (store.OperatorPreference, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.saves++
	if p.unavailable {
		return store.OperatorPreference{}, errors.New("relation does not exist")
	}
	if p.rows == nil {
		p.rows = map[int64]store.OperatorPreference{}
	}
	current, exists := p.rows[operatorID]
	if (revision == 0 && exists) || (revision != 0 && (!exists || current.Revision != revision)) {
		return store.OperatorPreference{}, store.ErrPreferenceStale
	}
	next := store.OperatorPreference{TimeZone: &zone, Revision: 1}
	if exists {
		next.Revision = current.Revision
		if *current.TimeZone != zone {
			next.Revision++
		}
	}
	p.rows[operatorID] = next
	return next, nil
}

func (p *v0041Preferences) setUnavailable(value bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.unavailable = value
}

const (
	v0041OtherSessionID  = "session-other-operator"
	v0041OtherOperatorID = int64(43)
)

func newV0041SettingsGateway(t *testing.T) (*v0041Gateway, *v0041Preferences) {
	t.Helper()
	preferences := &v0041Preferences{}
	gateway := newV0041Gateway(t, func(d *Dependencies) { d.OperatorPreferences = preferences })
	t.Cleanup(func() {
		if got := gateway.broker.count(); got != 0 {
			t.Errorf("operator settings sent %d broker requests", got)
		}
	})
	gateway.sessions.add(v0041OtherSessionID, v0041OtherOperatorID, map[int64]string{3: "Alpha Team"})
	return gateway, preferences
}

type v0041Setting struct {
	status int
	zone   *string
	etag   string
	body   string
}

func (s v0041Setting) String() string {
	zone := "null"
	if s.zone != nil {
		zone = *s.zone
	}
	return fmt.Sprintf("%d %s %s", s.status, zone, s.etag)
}

func (g *v0041Gateway) readSetting(token string, extra map[string]string) v0041Setting {
	g.t.Helper()
	headers := map[string]string{}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	for name, value := range extra {
		headers[name] = value
	}
	response, body := g.do(http.MethodGet, "/ui/v1/operator/settings", headers, "")
	if response.Header.Get("Cache-Control") != "no-store" {
		g.t.Fatalf("Cache-Control = %q", response.Header.Get("Cache-Control"))
	}
	setting := v0041Setting{status: response.StatusCode, etag: response.Header.Get("ETag"), body: body}
	if response.StatusCode == http.StatusOK {
		var decoded struct {
			TimeZone *string `json:"time_zone"`
		}
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			g.t.Fatal(err)
		}
		setting.zone = decoded.TimeZone
	}
	return setting
}

func (g *v0041Gateway) saveSetting(token, etag, contentType, body string) (int, string, string) {
	g.t.Helper()
	headers := map[string]string{"If-Match": etag, "Content-Type": contentType}
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	response, text := g.do(http.MethodPut, "/ui/v1/operator/settings", headers, body)
	return response.StatusCode, response.Header.Get("ETag"), text
}

func (g *v0041Gateway) saveZone(token, zone, etag string) (int, string, string) {
	g.t.Helper()
	return g.saveSetting(token, etag, "application/json", `{"time_zone":"`+zone+`"}`)
}

func v0041Same(a, b v0041Setting) bool { return a.String() == b.String() }

// v0041Resign returns a correctly signed working token with changed claims.
func v0041Resign(t *testing.T, token string, change func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(token, ".")
	claims := v0041Claims(t, token)
	change(claims)
	payload, _ := json.Marshal(claims)
	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, v0041PrivateKey(t), crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func v0041InvalidTokens(t *testing.T, token string) map[string]string {
	t.Helper()
	now := time.Now().Unix()
	parts := strings.Split(token, ".")
	signature := v0041Base64(t, parts[2])
	signature[0] ^= 1
	return map[string]string{
		"expired": v0041Resign(t, token, func(c map[string]any) { c["iat"], c["exp"] = now-120, now-60 }),
		"forged":  parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(signature),
	}
}

func v0041AssertInvalid(t *testing.T, status int, body string) {
	t.Helper()
	v0041Envelope(t, status, body, http.StatusUnauthorized, "invalid_working_token")
	if strings.Contains(body, "time_zone") {
		t.Fatalf("invalid identity leaked settings: %s", body)
	}
}

// v0034.15: personal preferences are keyed by the verified operator, ignore
// forged identity, refuse invalid tokens without leaking the zone, and outlive
// the session that wrote them.
func TestV0034_15_PersonalPreferencesIsolateOperatorsAndSurviveSessionDeletion(t *testing.T) {
	t.Parallel()
	gateway, _ := newV0041SettingsGateway(t)
	first := gateway.token(3)
	second := gateway.tokenFor(v0041OtherSessionID, 3)
	if v0041Claims(t, first)["operator_id"] == v0041Claims(t, second)["operator_id"] {
		t.Fatal("operators are not distinct")
	}
	initial := "200 null \"op-0\""
	for _, token := range []string{first, second} {
		if got := gateway.readSetting(token, nil).String(); got != initial {
			t.Fatalf("initial = %s", got)
		}
	}
	rejectInvalid := func() {
		t.Helper()
		beforeFirst, beforeSecond := gateway.readSetting(first, nil), gateway.readSetting(second, nil)
		for name, token := range v0041InvalidTokens(t, first) {
			read := gateway.readSetting(token, nil)
			v0041AssertInvalid(t, read.status, read.body)
			for _, revision := range []string{`"op-0"`, `"op-1"`} {
				var wait sync.WaitGroup
				for _, zone := range []string{"Asia/Kolkata", "Pacific/Apia"} {
					wait.Add(1)
					go func() {
						defer wait.Done()
						status, _, body := gateway.saveZone(token, zone, revision)
						if status != http.StatusUnauthorized || !strings.Contains(body, "invalid_working_token") || strings.Contains(body, "time_zone") {
							t.Errorf("%s save = %d %s", name, status, body)
						}
					}()
				}
				wait.Wait()
			}
			if !v0041Same(gateway.readSetting(first, nil), beforeFirst) || !v0041Same(gateway.readSetting(second, nil), beforeSecond) {
				t.Fatalf("%s identity changed a preference", name)
			}
		}
	}
	rejectInvalid()
	if status, _, body := gateway.saveZone(first, "UTC", `"op-0"`); status != http.StatusOK {
		t.Fatalf("first save = %d %s", status, body)
	}
	if got := gateway.readSetting(second, nil).String(); got != initial {
		t.Fatalf("other operator saw the save: %s", got)
	}
	if status, _, _ := gateway.saveZone(second, "Europe/Moscow", `"op-0"`); status != http.StatusOK {
		t.Fatalf("second save = %d", status)
	}
	secondSaved := gateway.readSetting(second, nil)
	if status, etag, _ := gateway.saveZone(second, "Europe/Moscow", secondSaved.etag); status != http.StatusOK || etag != secondSaved.etag {
		t.Fatalf("noop = %d %s", status, etag)
	}
	if status, etag, _ := gateway.saveZone(second, "Asia/Kolkata", secondSaved.etag); status != http.StatusOK || etag != `"op-2"` {
		t.Fatalf("change = %d %s", status, etag)
	}
	firstState, secondState := gateway.readSetting(first, nil), gateway.readSetting(second, nil)
	if firstState.String() != "200 UTC \"op-1\"" || secondState.String() != "200 Asia/Kolkata \"op-2\"" {
		t.Fatalf("states = %s / %s", firstState, secondState)
	}
	rejectInvalid()
	if got := gateway.readSetting(first, map[string]string{"X-FlowAI-Operator-ID": "43", "X-Operator-ID": "43"}); !v0041Same(got, firstState) {
		t.Fatalf("forged operator header read %s", got)
	}
	status, _, _ := gateway.saveSetting(first, firstState.etag, "application/json", `{"time_zone":"Pacific/Apia","operator_id":43}`)
	if status != http.StatusBadRequest || !v0041Same(gateway.readSetting(first, nil), firstState) || !v0041Same(gateway.readSetting(second, nil), secondState) {
		t.Fatalf("selecting another operator = %d", status)
	}
	if logout := gateway.logout(v0041SessionID); logout.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d", logout.StatusCode)
	}
	revoked := gateway.readSetting(first, nil)
	v0041Envelope(t, revoked.status, revoked.body, http.StatusForbidden, "team_not_accessible")
	if status, _, _ := gateway.saveZone(first, "Asia/Kolkata", firstState.etag); status != http.StatusForbidden {
		t.Fatalf("revoked save = %d", status)
	}
	if !v0041Same(gateway.readSetting(second, nil), secondState) {
		t.Fatal("other operator changed")
	}
	gateway.sessions.add("session-alpha-new", v0041OperatorID, map[int64]string{3: "Alpha Team", 4: "Beta Team"})
	for _, team := range []int64{3, 4} {
		if got := gateway.readSetting(gateway.tokenFor("session-alpha-new", team), nil); !v0041Same(got, firstState) {
			t.Fatalf("new session %d read %s, want %s", team, got, firstState)
		}
	}
}

// v0034.15 (Gateway validation part): the self preference is one operator row
// across teams, every malformed write is rejected without change, and the
// route needs a bearer.
func TestV0034_15_DurableSelfPreferenceValidation(t *testing.T) {
	t.Parallel()
	gateway, preferences := newV0041SettingsGateway(t)
	alpha, beta := gateway.token(3), gateway.token(4)
	if v0041Claims(t, alpha)["operator_id"] != v0041Claims(t, beta)["operator_id"] {
		t.Fatal("team tokens have different operators")
	}
	if a, b := gateway.readSetting(alpha, nil), gateway.readSetting(beta, nil); a.String() != `200 null "op-0"` || !v0041Same(a, b) || strings.TrimSpace(a.body) != `{"time_zone":null}` {
		t.Fatalf("initial = %s / %s (%s)", a, b, a.body)
	}
	if status, _, _ := gateway.saveZone(alpha, "Europe/Moscow", `"op-0"`); status != http.StatusOK {
		t.Fatalf("save = %d", status)
	}
	if status, _, _ := gateway.saveZone(beta, "America/New_York", `"op-0"`); status != http.StatusPreconditionFailed {
		t.Fatalf("stale insert from other team = %d", status)
	}
	if status, _, _ := gateway.saveZone(alpha, "Asia/Kolkata", `"op-1"`); status != http.StatusOK {
		t.Fatalf("update = %d", status)
	}
	current := gateway.readSetting(alpha, nil)
	if current.String() != `200 Asia/Kolkata "op-2"` || !v0041Same(gateway.readSetting(beta, nil), current) {
		t.Fatalf("current = %s", current)
	}
	savesBefore := preferences.saves
	for _, body := range []string{`{}`, `{"time_zone":null}`, `{"time_zone":3}`, `{"time_zone":""}`, `{"time_zone":"Local"}`, `{"time_zone":"+03:00"}`, `{"time_zone":"../Europe/Moscow"}`, `{"time_zone":"/etc/passwd"}`, `{"time_zone":"Missing/Zone"}`, `{"time_zone":"UTC","operator_id":"forged"}`, `{"time_zone":"UTC","time_zone":"Europe/Moscow"}`, `{"time_zone":"UTC","unknown":true}`} {
		if status, _, text := gateway.saveSetting(alpha, current.etag, "application/json", body); status != http.StatusBadRequest {
			t.Fatalf("%s = %d %s", body, status, text)
		}
	}
	for _, etag := range []string{"", "op-2", `"op-two"`, `"op--1"`, "*"} {
		if status, _, _ := gateway.saveZone(alpha, "UTC", etag); status != http.StatusBadRequest {
			t.Fatalf("If-Match %q = %d", etag, status)
		}
	}
	if status, _, _ := gateway.saveSetting(alpha, current.etag, "application/json", `{"time_zone":"`+strings.Repeat("x", 4096)+`"}`); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized = %d", status)
	}
	if status, _, _ := gateway.saveSetting(alpha, current.etag, "text/plain", `{"time_zone":"UTC"}`); status != http.StatusUnsupportedMediaType {
		t.Fatalf("wrong media type = %d", status)
	}
	missing := gateway.readSetting("", nil)
	v0041Envelope(t, missing.status, missing.body, http.StatusUnauthorized, "invalid_working_token")
	if status, _, _ := gateway.saveZone("", "UTC", current.etag); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated save = %d", status)
	}
	if preferences.saves != savesBefore || !v0041Same(gateway.readSetting(alpha, nil), current) {
		t.Fatalf("rejected writes reached the store: %d", preferences.saves-savesBefore)
	}
	gateway.restart()
	if !v0041Same(gateway.readSetting(beta, nil), current) {
		t.Fatal("restart lost the preference")
	}
	status, etag, body := gateway.saveZone(beta, "UTC", current.etag)
	if status != http.StatusOK || etag != `"op-3"` || strings.TrimSpace(body) != `{"time_zone":"UTC"}` {
		t.Fatalf("other-team save = %d %s %s", status, etag, body)
	}
}

// v0034.11 (Gateway part): no bearer means no settings, and a zone saved in
// one session is what a fresh session of the same operator reads.
func TestV0034_11_SavedZoneSurvivesFreshSession(t *testing.T) {
	t.Parallel()
	gateway, _ := newV0041SettingsGateway(t)
	missing := gateway.readSetting("", map[string]string{"Cookie": "flowai_session=" + v0041SessionID})
	v0041Envelope(t, missing.status, missing.body, http.StatusUnauthorized, "invalid_working_token")
	token := gateway.token(3)
	initial := gateway.readSetting(token, nil)
	if status, _, _ := gateway.saveZone(token, "Europe/Moscow", initial.etag); status != http.StatusOK {
		t.Fatalf("save = %d", status)
	}
	if logout := gateway.logout(v0041SessionID); logout.StatusCode != http.StatusNoContent {
		t.Fatalf("logout = %d", logout.StatusCode)
	}
	gateway.sessions.add("session-second-login", v0041OperatorID, map[int64]string{3: "Alpha Team"})
	if got := gateway.readSetting(gateway.tokenFor("session-second-login", 3), nil); got.zone == nil || *got.zone != "Europe/Moscow" {
		t.Fatalf("fresh session read %s", got)
	}
}

// v0034.15: every Gateway-visible Stage 0 operator_preference cell
// (identity x record x transition). Browser-only transitions (focus, lost
// write response) belong to Web UI; the real-lock race to the integration case.
func TestV0034_15_PersonalPreferenceLifecycleCells(t *testing.T) {
	t.Parallel()
	identities := []string{"same_operator_same_team", "same_operator_other_team", "other_operator", "expired", "forged"}
	transitions := []string{"read", "save", "noop", "concurrent_insert", "concurrent_update", "restart", "logout_login", "unavailable"}
	for _, identity := range identities {
		for _, record := range []string{"unset", "saved"} {
			for _, transition := range transitions {
				t.Run(identity+"/"+record+"/"+transition, func(t *testing.T) {
					t.Parallel()
					v0041LifecycleCell(t, identity, record, transition)
				})
			}
		}
	}
}

func v0041LifecycleCell(t *testing.T, identity, record, transition string) {
	gateway, preferences := newV0041SettingsGateway(t)
	callerSession, controlSession, callerOperator := v0041SessionID, v0041OtherSessionID, v0041OperatorID
	if identity == "other_operator" {
		callerSession, controlSession, callerOperator = v0041OtherSessionID, v0041SessionID, v0041OtherOperatorID
	}
	team := int64(3)
	if identity == "same_operator_other_team" {
		team = 4
	}
	token, control := gateway.tokenFor(callerSession, team), gateway.tokenFor(controlSession, 3)
	bad := identity == "expired" || identity == "forged"
	active := token
	if bad {
		active = v0041InvalidTokens(t, token)[identity]
	}
	if status, _, _ := gateway.saveZone(control, "Pacific/Apia", `"op-0"`); status != http.StatusOK {
		t.Fatalf("control save = %d", status)
	}
	sentinel := gateway.readSetting(control, nil)
	if record == "saved" {
		if status, _, _ := gateway.saveZone(token, "UTC", `"op-0"`); status != http.StatusOK {
			t.Fatalf("seed = %d", status)
		}
	}
	expected := gateway.readSetting(token, nil)
	want := `200 null "op-0"`
	if record == "saved" {
		want = `200 UTC "op-1"`
	}
	if expected.String() != want {
		t.Fatalf("start = %s, want %s", expected, want)
	}
	statusFor := func(good int) int {
		if bad {
			return http.StatusUnauthorized
		}
		return good
	}
	nextEtag := `"op-1"`
	if record == "saved" {
		nextEtag = `"op-2"`
	}
	switch transition {
	case "read":
		if got := gateway.readSetting(active, nil); got.status != statusFor(http.StatusOK) {
			t.Fatalf("read = %d", got.status)
		} else if bad {
			v0041AssertInvalid(t, got.status, got.body)
		}
	case "save":
		status, _, body := gateway.saveZone(active, "Asia/Kolkata", expected.etag)
		if status != statusFor(http.StatusOK) {
			t.Fatalf("save = %d %s", status, body)
		}
		if bad {
			v0041AssertInvalid(t, status, body)
		} else {
			expected = gateway.readSetting(token, nil)
			if expected.zone == nil || *expected.zone != "Asia/Kolkata" || expected.etag != nextEtag {
				t.Fatalf("after save = %s", expected)
			}
		}
	case "noop":
		if record == "saved" {
			status, etag, _ := gateway.saveZone(active, "UTC", expected.etag)
			if status != statusFor(http.StatusOK) || (!bad && etag != expected.etag) {
				t.Fatalf("noop = %d %s", status, etag)
			}
		}
		if got := gateway.readSetting(active, nil); got.status != statusFor(http.StatusOK) {
			t.Fatalf("noop read = %d", got.status)
		}
	case "concurrent_insert", "concurrent_update":
		revision := `"op-0"`
		if transition == "concurrent_update" {
			revision = expected.etag
			if revision == `"op-0"` {
				revision = `"op-1"`
			}
		}
		statuses := make([]int, 2)
		var wait sync.WaitGroup
		for index, zone := range []string{"Asia/Kolkata", "Pacific/Apia"} {
			wait.Add(1)
			go func() {
				defer wait.Done()
				statuses[index], _, _ = gateway.saveZone(active, zone, revision)
			}()
		}
		wait.Wait()
		sort.Ints(statuses)
		canWrite := (transition == "concurrent_insert") == (record == "unset")
		wantStatuses := []int{http.StatusPreconditionFailed, http.StatusPreconditionFailed}
		if bad {
			wantStatuses = []int{http.StatusUnauthorized, http.StatusUnauthorized}
		} else if canWrite {
			wantStatuses = []int{http.StatusOK, http.StatusPreconditionFailed}
		}
		if fmt.Sprint(statuses) != fmt.Sprint(wantStatuses) {
			t.Fatalf("race statuses = %v, want %v", statuses, wantStatuses)
		}
		if !bad && canWrite {
			expected = gateway.readSetting(token, nil)
			if expected.zone == nil || (*expected.zone != "Asia/Kolkata" && *expected.zone != "Pacific/Apia") || expected.etag != nextEtag {
				t.Fatalf("race winner = %s", expected)
			}
		}
	case "restart":
		gateway.restart()
		if got := gateway.readSetting(active, nil); got.status != statusFor(http.StatusOK) {
			t.Fatalf("restart read = %d", got.status)
		}
	case "logout_login":
		if logout := gateway.logout(callerSession); logout.StatusCode != http.StatusNoContent {
			t.Fatalf("logout = %d", logout.StatusCode)
		}
		if got := gateway.readSetting(active, nil); got.status != statusFor(http.StatusForbidden) {
			t.Fatalf("after logout = %d", got.status)
		}
		gateway.sessions.add("session-renewed", callerOperator, map[int64]string{3: "Alpha Team", 4: "Beta Team"})
		if got := gateway.readSetting(gateway.tokenFor("session-renewed", team), nil); !v0041Same(got, expected) {
			t.Fatalf("renewed read %s, want %s", got, expected)
		}
		if !v0041Same(gateway.readSetting(control, nil), sentinel) {
			t.Fatal("control operator changed")
		}
		return
	case "unavailable":
		preferences.setUnavailable(true)
		got := gateway.readSetting(active, nil)
		code := "operator_settings_unavailable"
		if bad {
			code = "invalid_working_token"
		}
		v0041Envelope(t, got.status, got.body, statusFor(http.StatusServiceUnavailable), code)
		preferences.setUnavailable(false)
	}
	if got := gateway.readSetting(token, nil); !v0041Same(got, expected) {
		t.Fatalf("caller ended at %s, want %s", got, expected)
	}
	if !v0041Same(gateway.readSetting(control, nil), sentinel) {
		t.Fatal("control operator changed")
	}
}
