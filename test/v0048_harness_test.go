package test

// Shared in-process fixtures for the v0048 API Gateway unit tests: a fake
// broker at the Gateway's messaging boundary (broker.Requester), in-memory
// session and operator stores with the persisted stores' semantics, a real
// RS256 working-token signer, a fake journal stream edge and a fake admin
// JWKS provider. No FlowAI service and no NATS server is started.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/adminauth"
	"github.com/pandops/flowai-api-gateway/internal/broker"
	"github.com/pandops/flowai-api-gateway/internal/httpapi"
	"github.com/pandops/flowai-api-gateway/internal/jwtverify"
	"github.com/pandops/flowai-api-gateway/internal/store"
	"github.com/pandops/flowai-api-gateway/internal/teamregistry"
	"github.com/pandops/flowai-api-gateway/internal/workingtoken"
	"github.com/gorilla/websocket"
)

const (
	gwIssuer    = "https://gateway.flowai.invalid"
	gwAudience  = "flowai-api-gateway"
	gwKeyID     = "flowai-working-v0048-1"
	gwSessionID = "session-operator-42"
	gwOperator  = int64(42)
	gwTeam      = int64(3)
	gwOtherTeam = int64(4)
	gwOIDCIss   = "https://oidc.flowai.invalid"
	gwJournalSA = "journal-service-bearer-canary"
)

var (
	gwKeyOnce       sync.Once
	gwKey           *rsa.PrivateKey
	gwDecimal       = regexp.MustCompile(`^[1-9][0-9]*$`)
	gwTeamNames     = map[int64]string{gwTeam: "Alpha-Team", gwOtherTeam: "Beta-Team"}
	gwContextHeader = map[string]bool{"team": true, "operator_id": true, "request_id": true, "team_name": true, "If-Match": true}
)

func gwPrivateKey() *rsa.PrivateKey {
	gwKeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		gwKey = key
	})
	return gwKey
}

func gwSigner(t *testing.T, ttl time.Duration) *workingtoken.Signer {
	t.Helper()
	data, err := x509.MarshalPKCS8PrivateKey(gwPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	signer, err := workingtoken.New(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}), gwKeyID, gwIssuer, gwAudience, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// ---- fake broker -----------------------------------------------------------

// fakeBroker records every request the Gateway sends. A responder per subject
// answers; subjects without one get 200 {"ok":true}.
type fakeBroker struct {
	mu         sync.Mutex
	sent       []broker.Request
	responders map[string]func(broker.Request) broker.Reply
}

func newFakeBroker() *fakeBroker {
	return &fakeBroker{responders: map[string]func(broker.Request) broker.Reply{}}
}

func (b *fakeBroker) Request(ctx context.Context, request broker.Request) (broker.Reply, error) {
	b.mu.Lock()
	copied := broker.Request{Subject: request.Subject, Header: map[string]string{}, Body: append([]byte(nil), request.Body...)}
	for name, value := range request.Header {
		copied.Header[name] = value
	}
	b.sent = append(b.sent, copied)
	respond := b.responders[request.Subject]
	b.mu.Unlock()
	if respond == nil {
		return reply(200, `{"ok":true}`, nil), nil
	}
	return respond(copied), nil
}

func (b *fakeBroker) on(subject string, respond func(broker.Request) broker.Reply) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.responders[subject] = respond
}

func (b *fakeBroker) requests() []broker.Request {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]broker.Request(nil), b.sent...)
}

// uiRequests are the requests on `ui` subjects (the team-registry point read
// of token issue is excluded).
func (b *fakeBroker) uiRequests() []broker.Request {
	var result []broker.Request
	for _, request := range b.requests() {
		if strings.Contains(request.Subject, ".ui.") {
			result = append(result, request)
		}
	}
	return result
}

func (b *fakeBroker) subjects() []string {
	var result []string
	for _, request := range b.requests() {
		result = append(result, request.Subject)
	}
	return result
}

func reply(status int, body string, headers map[string]string) broker.Reply {
	header := map[string]string{"status": strconv.Itoa(status)}
	for name, value := range headers {
		header[name] = value
	}
	return broker.Reply{Header: header, Body: []byte(body)}
}

// teamRegistryResponder answers team-registry.service.get.pub like
// team-registry: 200 for a known team, 404 canonical_team_not_found otherwise.
func teamRegistryResponder(teams map[int64]string, archived map[int64]*time.Time) func(broker.Request) broker.Reply {
	return func(request broker.Request) broker.Reply {
		var envelope struct {
			Params struct {
				TeamID int64 `json:"team_id"`
			} `json:"params"`
		}
		if err := json.Unmarshal(request.Body, &envelope); err != nil {
			return reply(400, `{"code":"invalid_request","message":"bad","request_id":1}`, nil)
		}
		name, ok := teams[envelope.Params.TeamID]
		if !ok {
			return reply(404, `{"code":"canonical_team_not_found","message":"no team","request_id":1}`, nil)
		}
		var archivedAt any
		if at := archived[envelope.Params.TeamID]; at != nil {
			archivedAt = at.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		body, _ := json.Marshal(map[string]any{"team_id": envelope.Params.TeamID, "team_name": name, "default_image": "ghcr.io/flowai/runtime@sha256:" + strings.Repeat("a", 64), "ingested_at": "2026-11-01T00:00:00.000Z", "archived_at": archivedAt})
		return reply(200, string(body), nil)
	}
}

// decodeUI decodes the request body envelope {"params":{...},"body":...}.
func decodeUI(t *testing.T, request broker.Request) (map[string]any, json.RawMessage, bool) {
	t.Helper()
	var envelope map[string]json.RawMessage
	decoder := json.NewDecoder(strings.NewReader(string(request.Body)))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatalf("%s body %q is not a JSON object: %v", request.Subject, request.Body, err)
	}
	for key := range envelope {
		if key != "params" && key != "body" {
			t.Fatalf("%s envelope has unexpected key %q", request.Subject, key)
		}
	}
	params := map[string]any{}
	if raw, ok := envelope["params"]; ok {
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if err := decoder.Decode(&params); err != nil {
			t.Fatalf("%s params: %v", request.Subject, err)
		}
	} else {
		t.Fatalf("%s envelope lacks params", request.Subject)
	}
	body, hasBody := envelope["body"]
	return params, body, hasBody
}

// assertContext checks the verified context headers of one ui request and
// that nothing else (no browser header, credential or cookie) was sent.
func assertContext(t *testing.T, request broker.Request, team int64, operator int64, teamName string) int64 {
	t.Helper()
	header := request.Header
	if header["team"] != strconv.FormatInt(team, 10) {
		t.Fatalf("%s team header = %q, want %d", request.Subject, header["team"], team)
	}
	if header["operator_id"] != strconv.FormatInt(operator, 10) {
		t.Fatalf("%s operator_id = %q, want %d", request.Subject, header["operator_id"], operator)
	}
	requestID, err := strconv.ParseInt(header["request_id"], 10, 64)
	if err != nil || requestID <= 0 || !gwDecimal.MatchString(header["request_id"]) {
		t.Fatalf("%s request_id = %q", request.Subject, header["request_id"])
	}
	if teamName == "" {
		if _, ok := header["team_name"]; ok {
			t.Fatalf("%s carries team_name without a canonical name", request.Subject)
		}
	} else if header["team_name"] != teamName {
		t.Fatalf("%s team_name = %q, want %q", request.Subject, header["team_name"], teamName)
	}
	for name := range header {
		if !gwContextHeader[name] {
			t.Fatalf("%s carries unexpected header %q=%q", request.Subject, name, header[name])
		}
	}
	return requestID
}

// assertNoCredential fails when any header or body byte of any request
// contains one of the canaries.
func assertNoCredential(t *testing.T, requests []broker.Request, canaries ...string) {
	t.Helper()
	for _, request := range requests {
		for _, canary := range canaries {
			if strings.Contains(string(request.Body), canary) {
				t.Fatalf("%s body carries %q", request.Subject, canary)
			}
			for name, value := range request.Header {
				if strings.Contains(value, canary) || strings.Contains(name, canary) {
					t.Fatalf("%s header %s carries %q", request.Subject, name, canary)
				}
			}
		}
	}
}

// ---- in-memory sessions and operators --------------------------------------

type memSession struct {
	operatorID int64
	teams      map[int64]*string
}

type memToken struct {
	sessionHash [32]byte
	operatorID  int64
	teamID      int64
	expiresAt   time.Time
}

// memSessions mirrors store.SessionStore: a token is usable only while its
// record, its session and that session's team access all exist.
type memSessions struct {
	mu       sync.Mutex
	sessions map[[32]byte]*memSession
	tokens   map[string]memToken
	created  []store.SessionInput
	recorded int
	// mappings derive team access from observed OIDC team IDs on Create,
	// like the persisted store's oidc_team_mappings join.
	mappings map[string]int64
}

func newMemSessions() *memSessions {
	return &memSessions{sessions: map[[32]byte]*memSession{}, tokens: map[string]memToken{}}
}

func memHash(sessionID string) [32]byte { return sha256.Sum256([]byte(sessionID)) }

func (s *memSessions) add(sessionID string, operatorID int64, teams map[int64]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	access := map[int64]*string{}
	for id, name := range teams {
		name := name
		access[id] = &name
	}
	s.sessions[memHash(sessionID)] = &memSession{operatorID: operatorID, teams: access}
}

func (s *memSessions) revokeTeam(sessionID string, teamID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions[memHash(sessionID)].teams, teamID)
}

func (s *memSessions) Create(_ context.Context, input store.SessionInput) error {
	s.mu.Lock()
	s.created = append(s.created, input)
	teams := map[int64]string{}
	for _, oidcTeamID := range input.OIDCTeamIDs {
		if teamID, ok := s.mappings[oidcTeamID]; ok {
			teams[teamID] = gwTeamNames[teamID]
		}
	}
	s.mu.Unlock()
	s.add(input.SessionID, input.OperatorID, teams)
	return nil
}

func (s *memSessions) createdSessions() []store.SessionInput {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]store.SessionInput(nil), s.created...)
}

func (s *memSessions) AccessibleTeams(_ context.Context, sessionID string, _ time.Time) ([]store.AccessibleTeam, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[memHash(sessionID)]
	if !ok {
		return nil, store.ErrSessionNotFound
	}
	teams := []store.AccessibleTeam{}
	for id, name := range session.teams {
		teams = append(teams, store.AccessibleTeam{TeamID: id, TeamName: name})
	}
	sort.Slice(teams, func(i, j int) bool { return *teams[i].TeamName < *teams[j].TeamName })
	return teams, nil
}

func (s *memSessions) Delete(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := memHash(sessionID)
	if _, ok := s.sessions[hash]; !ok {
		return store.ErrSessionNotFound
	}
	delete(s.sessions, hash)
	for jti, token := range s.tokens {
		if token.sessionHash == hash {
			delete(s.tokens, jti)
		}
	}
	return nil
}

func (s *memSessions) TokenContext(_ context.Context, sessionID string, teamID int64, _ time.Time) (store.TokenContext, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := memHash(sessionID)
	session, ok := s.sessions[hash]
	if !ok {
		return store.TokenContext{}, store.ErrSessionNotFound
	}
	name, ok := session.teams[teamID]
	if !ok {
		return store.TokenContext{}, store.ErrTeamNotAccessible
	}
	return store.TokenContext{SessionHash: hash, OperatorID: session.operatorID, TeamID: teamID, TeamName: name}, nil
}

func (s *memSessions) RecordToken(_ context.Context, context store.TokenContext, jti string, _, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[jti] = memToken{sessionHash: context.SessionHash, operatorID: context.OperatorID, teamID: context.TeamID, expiresAt: expiresAt}
	s.recorded++
	return nil
}

func (s *memSessions) recordedTokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recorded
}

func (s *memSessions) ValidateTokenAccess(_ context.Context, operatorID, teamID int64, jti string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.tokens[jti]
	if !ok || token.operatorID != operatorID || token.teamID != teamID || !token.expiresAt.After(now) {
		return store.ErrTeamNotAccessible
	}
	session, ok := s.sessions[token.sessionHash]
	if !ok {
		return store.ErrTeamNotAccessible
	}
	if _, ok := session.teams[teamID]; !ok {
		return store.ErrTeamNotAccessible
	}
	return nil
}

// memOperators has store.Operators' semantics: one integer per (issuer, sub),
// assigned from an increasing sequence on first sight.
type memOperators struct {
	mu    sync.Mutex
	next  int64
	ids   map[string]int64
	calls []string
}

func newMemOperators(first int64) *memOperators {
	return &memOperators{next: first, ids: map[string]int64{}}
}

func (o *memOperators) OperatorID(_ context.Context, issuer, subject string) (int64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	key := issuer + "\x00" + subject
	o.calls = append(o.calls, key)
	if id, ok := o.ids[key]; ok {
		return id, nil
	}
	id := o.next
	o.next++
	o.ids[key] = id
	return id, nil
}

// ---- gateway ---------------------------------------------------------------

type gw struct {
	t        *testing.T
	server   *httptest.Server
	sessions *memSessions
	broker   *fakeBroker
	deps     httpapi.Dependencies
}

// newGateway serves the real handler: operator 42 holds a session with access
// to teams 3 ("Alpha-Team") and 4 ("Beta-Team"); every /ui/v1 operation and
// the team point read go to the fake broker.
func newGateway(t *testing.T, configure func(*httpapi.Dependencies)) *gw {
	t.Helper()
	sessions := newMemSessions()
	sessions.add(gwSessionID, gwOperator, gwTeamNames)
	fake := newFakeBroker()
	dependencies := httpapi.Dependencies{Sessions: sessions, WorkingTokens: gwSigner(t, 5*time.Minute), Broker: fake, RPCTimeout: 300 * time.Millisecond}
	if configure != nil {
		configure(&dependencies)
	}
	server := httptest.NewServer(httpapi.NewWithDependencies(dependencies))
	t.Cleanup(server.Close)
	return &gw{t: t, server: server, sessions: sessions, broker: fake, deps: dependencies}
}

// withTeamRegistry wires the team point read over the fake broker through the
// real team-registry client.
func withTeamRegistry(t *testing.T, fake **fakeBroker) func(*httpapi.Dependencies) {
	return func(d *httpapi.Dependencies) {
		b := d.Broker.(*fakeBroker)
		*fake = b
		// team-registry knows teams 3 and 4; a test may replace the responder.
		b.on(teamregistry.Subject, teamRegistryResponder(gwTeamNames, nil))
		client, err := teamregistry.New(b)
		if err != nil {
			t.Fatal(err)
		}
		d.Teams = client
		d.Presentation = &memPresentation{}
	}
}

type memPresentation struct {
	mu      sync.Mutex
	updates []string
}

func (p *memPresentation) RefreshPresentation(_ context.Context, teamID int64, teamName string, archivedAt *time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.updates = append(p.updates, fmt.Sprintf("%d|%s|%v", teamID, teamName, archivedAt != nil))
	return nil
}

func (g *gw) issue(sessionID string, body string) (*http.Response, string) {
	g.t.Helper()
	return g.do(http.MethodPost, "/auth/v1/token", map[string]string{"Content-Type": "application/json", "Cookie": "flowai_session=" + sessionID}, body)
}

func (g *gw) tokenFor(sessionID string, teamID int64) string {
	g.t.Helper()
	response, body := g.issue(sessionID, fmt.Sprintf(`{"team_id":%d}`, teamID))
	var decoded struct {
		AccessToken string `json:"access_token"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &decoded) != nil || decoded.AccessToken == "" {
		g.t.Fatalf("issue %s/%d = %d %s", sessionID, teamID, response.StatusCode, body)
	}
	return decoded.AccessToken
}

func (g *gw) token(teamID int64) string { return g.tokenFor(gwSessionID, teamID) }

func (g *gw) do(method, path string, headers map[string]string, body string) (*http.Response, string) {
	g.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, g.server.URL+path, reader)
	if err != nil {
		g.t.Fatal(err)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		g.t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response, string(data)
}

// as sends an authenticated request with token and optional extra headers.
func (g *gw) as(token, method, path string, extra map[string]string, body string) (*http.Response, string) {
	g.t.Helper()
	headers := map[string]string{"Authorization": "Bearer " + token}
	if body != "" {
		headers["Content-Type"] = "application/json"
	}
	for name, value := range extra {
		headers[name] = value
	}
	return g.do(method, path, headers, body)
}

func (g *gw) logout(sessionID string) int {
	g.t.Helper()
	response, _ := g.do(http.MethodDelete, "/auth/v1/session", map[string]string{"Cookie": "flowai_session=" + sessionID}, "")
	return response.StatusCode
}

// assertEnvelope checks the stable error envelope with an integer request_id.
func assertEnvelope(t *testing.T, response *http.Response, body string, wantStatus int, wantCode string) int64 {
	t.Helper()
	if response.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d; body %s", response.StatusCode, wantStatus, body)
	}
	var envelope struct {
		Code      string          `json:"code"`
		Message   string          `json:"message"`
		RequestID json.RawMessage `json:"request_id"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("error body %q: %v", body, err)
	}
	if envelope.Code != wantCode || envelope.Message == "" {
		t.Fatalf("envelope = %s, want code %s", body, wantCode)
	}
	id, err := strconv.ParseInt(string(envelope.RequestID), 10, 64)
	if err != nil || id <= 0 {
		t.Fatalf("request_id %s is not a positive JSON integer", envelope.RequestID)
	}
	return id
}

func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("token is not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	var claims map[string]any
	if err := decoder.Decode(&claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// resign signs changed claims with the Gateway key (a validly signed token
// with an unusable claim set).
func resign(t *testing.T, token string, change func(map[string]any)) string {
	t.Helper()
	claims := claimsOf(t, token)
	change(claims)
	header, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": gwKeyID})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, gwPrivateKey(), crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// ---- fake journal stream edge ----------------------------------------------

type journalUpgrade struct {
	path    string
	query   string
	headers http.Header
}

// fakeJournal serves GET /v1/teams/{team_id}/stream like journal's edge: it
// requires the Gateway service bearer, sends two frames named after the
// verified team and echoes every browser frame back.
type fakeJournal struct {
	server   *httptest.Server
	mu       sync.Mutex
	upgrades []journalUpgrade
}

func newFakeJournal(t *testing.T) *fakeJournal {
	t.Helper()
	journal := &fakeJournal{}
	upgrader := websocket.Upgrader{}
	journal.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		journal.mu.Lock()
		journal.upgrades = append(journal.upgrades, journalUpgrade{path: r.URL.Path, query: r.URL.RawQuery, headers: r.Header.Clone()})
		journal.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+gwJournalSA {
			http.Error(w, `{"code":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		team := r.Header.Get("X-FlowAI-Team-ID")
		for index, kind := range []string{"replay", "live"} {
			if err := conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(`{"frame_id":%d,"team_id":%s,"kind":"%s"}`, 5121+index, team, kind))); err != nil {
				return
			}
		}
		for {
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if string(payload) == "close-please" {
				_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "journal_closed"))
				return
			}
			if err := conn.WriteMessage(messageType, append([]byte("echo:"), payload...)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(journal.server.Close)
	return journal
}

func (j *fakeJournal) seen() []journalUpgrade {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]journalUpgrade(nil), j.upgrades...)
}

func withJournal(journal *fakeJournal) func(*httpapi.Dependencies) {
	return func(d *httpapi.Dependencies) {
		d.JournalURL, d.JournalToken = journal.server.URL, gwJournalSA
	}
}

func (g *gw) streamURL(path string) string {
	return "ws" + strings.TrimPrefix(g.server.URL, "http") + path
}

// dialRejected dials an upgrade that must fail and returns the HTTP status
// and body.
func dialRejected(t *testing.T, url string, header http.Header) (int, string) {
	t.Helper()
	conn, response, err := websocket.DefaultDialer.Dial(url, header)
	if err == nil {
		conn.Close()
		t.Fatal("upgrade unexpectedly succeeded")
	}
	if !errors.Is(err, websocket.ErrBadHandshake) || response == nil {
		t.Fatalf("dial error = %v", err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(data)
}

func readFrames(t *testing.T, conn *websocket.Conn, count int) []string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var frames []string
	for range count {
		_, payload, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		frames = append(frames, string(payload))
	}
	_ = conn.SetReadDeadline(time.Time{})
	return frames
}

// ---- fake admin JWKS provider ----------------------------------------------

const (
	adminAudienceV48 = "flowai-api-gateway-admin"
	adminRoleV48     = "flowai-system-admin"
)

type adminProvider struct {
	server    *httptest.Server
	mu        sync.Mutex
	keys      map[string]*rsa.PrivateKey
	published []string
	status    int
	delay     time.Duration
}

func newAdminProvider(t *testing.T, kids ...string) *adminProvider {
	t.Helper()
	provider := &adminProvider{keys: map[string]*rsa.PrivateKey{}}
	for _, kid := range kids {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		provider.keys[kid] = key
	}
	provider.published = kids[:1]
	provider.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		provider.mu.Lock()
		status, delay, published := provider.status, provider.delay, append([]string(nil), provider.published...)
		provider.mu.Unlock()
		time.Sleep(delay)
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		var keys []any
		for _, kid := range published {
			key := provider.keys[kid]
			keys = append(keys, map[string]any{"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	}))
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *adminProvider) set(published []string, status int, delay time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if published != nil {
		p.published = published
	}
	p.status, p.delay = status, delay
}

type adminClaims struct {
	kid, signWith string
	iat           any
	roles         any
	audience      string
	issuer        string
	alg           string
	exp           int64
}

func (p *adminProvider) token(t *testing.T, change func(*adminClaims)) string {
	t.Helper()
	spec := adminClaims{kid: "admin-a", iat: time.Now().Unix(), roles: []string{adminRoleV48}, audience: adminAudienceV48, issuer: p.server.URL, alg: "RS256", exp: time.Now().Unix() + 60}
	if change != nil {
		change(&spec)
	}
	if spec.signWith == "" {
		spec.signWith = spec.kid
	}
	header, _ := json.Marshal(map[string]any{"alg": spec.alg, "typ": "JWT", "kid": spec.kid})
	claims := map[string]any{"iss": spec.issuer, "aud": spec.audience, "sub": "admin-subject", "exp": spec.exp, "realm_access": map[string]any{"roles": spec.roles}}
	if spec.iat != nil {
		claims["iat"] = spec.iat
	}
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	var signature []byte
	var err error
	if spec.alg == "RS512" {
		digest := sha512.Sum512([]byte(input))
		signature, err = rsa.SignPKCS1v15(rand.Reader, p.keys[spec.signWith], crypto.SHA512, digest[:])
	} else {
		digest := sha256.Sum256([]byte(input))
		signature, err = rsa.SignPKCS1v15(rand.Reader, p.keys[spec.signWith], crypto.SHA256, digest[:])
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// memMappings has store.MappingStore's one-to-one registration semantics.
type memMappings struct {
	mu   sync.Mutex
	rows map[string]store.Mapping
}

func (m *memMappings) Register(_ context.Context, mapping store.Mapping) (store.Mapping, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[string]store.Mapping{}
	}
	if existing, ok := m.rows[mapping.OIDCTeamID]; ok {
		if existing.TeamID != mapping.TeamID {
			return store.Mapping{}, false, store.ErrMappingConflict
		}
		return existing, false, nil
	}
	for _, existing := range m.rows {
		if existing.TeamID == mapping.TeamID {
			return store.Mapping{}, false, store.ErrMappingConflict
		}
	}
	m.rows[mapping.OIDCTeamID] = mapping
	return mapping, true, nil
}

func (m *memMappings) snapshot() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rows []string
	for _, row := range m.rows {
		rows = append(rows, fmt.Sprintf("%s->%d", row.OIDCTeamID, row.TeamID))
	}
	sort.Strings(rows)
	return strings.Join(rows, ",")
}

type adminGateway struct {
	server   *httptest.Server
	broker   *fakeBroker
	mappings *memMappings
}

// newAdminGateway serves mapping registration with real admin JWT trust and
// the real team-registry client over a fake broker that knows teams 3 and 4.
func newAdminGateway(t *testing.T, provider *adminProvider, maxAge time.Duration, timeout time.Duration) *adminGateway {
	t.Helper()
	verifier, err := jwtverify.New(jwtverify.Config{Issuer: provider.server.URL, Audience: adminAudienceV48, JWKSURL: provider.server.URL + "/jwks", Algorithms: []string{"RS256"}, ClockSkew: 30 * time.Second, TokenMaxAge: maxAge, HTTPTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := adminauth.New(verifier, "/realm_access/roles", adminRoleV48)
	if err != nil {
		t.Fatal(err)
	}
	fake := newFakeBroker()
	fake.on(teamregistry.Subject, teamRegistryResponder(gwTeamNames, nil))
	client, err := teamregistry.New(fake)
	if err != nil {
		t.Fatal(err)
	}
	mappings := &memMappings{}
	server := httptest.NewServer(httpapi.NewWithDependencies(httpapi.Dependencies{ConfiguredIssuer: gwOIDCIss, AdminAuth: authenticator, Mappings: mappings, Teams: client, Broker: fake, RPCTimeout: 300 * time.Millisecond}))
	t.Cleanup(server.Close)
	return &adminGateway{server: server, broker: fake, mappings: mappings}
}

func (g *adminGateway) post(t *testing.T, token string, body string) (*http.Response, string) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, g.server.URL+"/admin/v1/oidc-team-mappings", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response, string(data)
}

func mappingBody(issuer, oidcTeamID string, teamID any) string {
	body, _ := json.Marshal(map[string]any{"issuer": issuer, "oidc_team_id": oidcTeamID, "team_id": teamID})
	return string(body)
}
