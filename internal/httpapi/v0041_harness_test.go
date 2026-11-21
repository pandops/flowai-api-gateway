package httpapi

// Shared in-process fixtures for the v0041 Gateway survivors of the deleted
// Playwright suites: a real RS256 working-token signer, an in-memory session
// store with the persisted store's access semantics, and an httptest State
// broker that records every request it receives.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/broker"
	"github.com/pandops/flowai-api-gateway/internal/store"
	"github.com/pandops/flowai-api-gateway/internal/workingtoken"
)

const (
	v0041Issuer   = "https://gateway.flowai.invalid"
	v0041Audience = "flowai-state-registry"
	v0041KeyID    = "flowai-working-e2e-1"
)

var (
	v0041KeyOnce sync.Once
	v0041Key     *rsa.PrivateKey
)

func v0041PrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	v0041KeyOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		v0041Key = key
	})
	return v0041Key
}

func v0041Signer(t *testing.T, ttl time.Duration) *workingtoken.Signer {
	t.Helper()
	data, err := x509.MarshalPKCS8PrivateKey(v0041PrivateKey(t))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := workingtoken.New(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}), v0041KeyID, v0041Issuer, v0041Audience, ttl)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

type v0041Session struct {
	operatorID int64
	teams      map[int64]*string
}

type v0041Token struct {
	sessionHash [32]byte
	operatorID  int64
	teamID      int64
	expiresAt   time.Time
}

// v0041Sessions mirrors store.SessionStore: a token is usable only while its
// record, its session and that session's team access all still exist.
type v0041Sessions struct {
	mu       sync.Mutex
	sessions map[[32]byte]*v0041Session
	tokens   map[string]v0041Token
	recorded int
}

func newV0041Sessions() *v0041Sessions {
	return &v0041Sessions{sessions: map[[32]byte]*v0041Session{}, tokens: map[string]v0041Token{}}
}

func v0041Hash(sessionID string) [32]byte { return sha256.Sum256([]byte(sessionID)) }

func (s *v0041Sessions) add(sessionID string, operatorID int64, teams map[int64]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	access := map[int64]*string{}
	for id, name := range teams {
		name := name
		access[id] = &name
	}
	s.sessions[v0041Hash(sessionID)] = &v0041Session{operatorID: operatorID, teams: access}
}

func (s *v0041Sessions) revokeTeam(sessionID string, teamID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions[v0041Hash(sessionID)].teams, teamID)
}

func (s *v0041Sessions) recordedTokens() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recorded
}

func (s *v0041Sessions) Create(_ context.Context, input store.SessionInput) error {
	s.add(input.SessionID, input.OperatorID, nil)
	return nil
}

func (s *v0041Sessions) AccessibleTeams(_ context.Context, sessionID string, _ time.Time) ([]store.AccessibleTeam, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[v0041Hash(sessionID)]
	if !ok {
		return nil, store.ErrSessionNotFound
	}
	teams := []store.AccessibleTeam{}
	for id, name := range session.teams {
		teams = append(teams, store.AccessibleTeam{TeamID: id, TeamName: name})
	}
	return teams, nil
}

func (s *v0041Sessions) Delete(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := v0041Hash(sessionID)
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

func (s *v0041Sessions) TokenContext(_ context.Context, sessionID string, teamID int64, _ time.Time) (store.TokenContext, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hash := v0041Hash(sessionID)
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

func (s *v0041Sessions) RecordToken(_ context.Context, context store.TokenContext, jti string, _, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[jti] = v0041Token{sessionHash: context.SessionHash, operatorID: context.OperatorID, teamID: context.TeamID, expiresAt: expiresAt}
	s.recorded++
	return nil
}

func (s *v0041Sessions) ValidateTokenAccess(_ context.Context, operatorID, teamID int64, jti string, now time.Time) error {
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

// v0041Broker records every broker request and answers 200 {"ok":true}.
type v0041Broker struct {
	mu       sync.Mutex
	requests []broker.Request
}

func (b *v0041Broker) Request(_ context.Context, request broker.Request) (broker.Reply, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.requests = append(b.requests, request)
	return broker.Reply{Header: map[string]string{"status": "200"}, Body: []byte(`{"ok":true}`)}, nil
}

func (b *v0041Broker) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.requests)
}

type v0041Gateway struct {
	t        *testing.T
	server   *httptest.Server
	sessions *v0041Sessions
	broker   *v0041Broker
	signer   *workingtoken.Signer
	deps     Dependencies
}

// restart serves a fresh handler instance over the same dependencies.
func (g *v0041Gateway) restart() {
	g.t.Helper()
	g.server.Close()
	g.server = httptest.NewServer(NewWithDependencies(g.deps))
	g.t.Cleanup(g.server.Close)
}

// tokenFor issues a working token for any session held by the fake store.
func (g *v0041Gateway) tokenFor(sessionID string, teamID int64) string {
	g.t.Helper()
	response := g.issueResponse(sessionID, teamID)
	body := v0041ReadBody(g.t, response)
	var decoded struct {
		AccessToken string `json:"access_token"`
	}
	if response.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &decoded) != nil || decoded.AccessToken == "" {
		g.t.Fatalf("issue %s/%d = %d %s", sessionID, teamID, response.StatusCode, body)
	}
	return decoded.AccessToken
}

const (
	v0041SessionID  = "session-alpha-operator"
	v0041OperatorID = int64(42)
)

// newV0041Gateway serves the real handler with one session that can access
// team 3 ("Alpha Team") and team 4 ("Beta Team").
func newV0041Gateway(t *testing.T, configure func(*Dependencies)) *v0041Gateway {
	t.Helper()
	sessions := newV0041Sessions()
	sessions.add(v0041SessionID, v0041OperatorID, map[int64]string{3: "Alpha Team", 4: "Beta Team"})
	fake := &v0041Broker{}
	signer := v0041Signer(t, 5*time.Minute)
	dependencies := Dependencies{Sessions: sessions, WorkingTokens: signer, Broker: fake, RPCTimeout: time.Second}
	if configure != nil {
		configure(&dependencies)
	}
	server := httptest.NewServer(NewWithDependencies(dependencies))
	t.Cleanup(server.Close)
	return &v0041Gateway{t: t, server: server, sessions: sessions, broker: fake, signer: signer, deps: dependencies}
}

func (g *v0041Gateway) issueResponse(sessionID string, teamID int64) *http.Response {
	g.t.Helper()
	request, err := http.NewRequest(http.MethodPost, g.server.URL+"/auth/v1/token", strings.NewReader(`{"team_id":`+strconv.FormatInt(teamID, 10)+`}`))
	if err != nil {
		g.t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Cookie", "flowai_session="+sessionID)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		g.t.Fatal(err)
	}
	return response
}

func (g *v0041Gateway) token(teamID int64) string {
	g.t.Helper()
	response := g.issueResponse(v0041SessionID, teamID)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		g.t.Fatalf("issue token status = %d", response.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil || body.AccessToken == "" {
		g.t.Fatalf("token body: %v", err)
	}
	return body.AccessToken
}

func (g *v0041Gateway) logout(sessionID string) *http.Response {
	g.t.Helper()
	request, _ := http.NewRequest(http.MethodDelete, g.server.URL+"/auth/v1/session", nil)
	request.Header.Set("Cookie", "flowai_session="+sessionID)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		g.t.Fatal(err)
	}
	_ = response.Body.Close()
	return response
}

func (g *v0041Gateway) do(method, path string, headers map[string]string, body string) (*http.Response, string) {
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

// v0041Envelope asserts the stable Gateway error envelope.
func v0041Envelope(t *testing.T, status int, body string, wantStatus int, wantCode string) {
	t.Helper()
	if status != wantStatus {
		t.Fatalf("status = %d, want %d; body %s", status, wantStatus, body)
	}
	var envelope struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID int64  `json:"request_id"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("error body %q: %v", body, err)
	}
	if envelope.Code != wantCode || envelope.Message == "" || envelope.RequestID <= 0 {
		t.Fatalf("envelope = %+v, want code %s", envelope, wantCode)
	}
}

func v0041Claims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWT")
	}
	var claims map[string]any
	if err := json.Unmarshal(v0041Base64(t, parts[1]), &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func v0041Base64(t *testing.T, part string) []byte {
	t.Helper()
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func v0041ReadBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
