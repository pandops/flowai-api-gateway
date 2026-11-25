// Package httpapi defines the API Gateway HTTP surface.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/adminauth"
	"github.com/pandops/flowai-api-gateway/internal/broker"
	"github.com/pandops/flowai-api-gateway/internal/jwtverify"
	"github.com/pandops/flowai-api-gateway/internal/oidc"
	"github.com/pandops/flowai-api-gateway/internal/store"
	"github.com/pandops/flowai-api-gateway/internal/teamregistry"
	"github.com/pandops/flowai-api-gateway/internal/workingtoken"
	"github.com/gorilla/websocket"
)

type errorResponse struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID int64  `json:"request_id"`
}

func New() http.Handler {
	return NewWithDependencies(Dependencies{})
}

type AdminAuthenticator interface {
	Authenticate(context.Context, string) (string, error)
}
type LoginStarter interface {
	Start(context.Context) (string, error)
}
type OIDCCompleter interface {
	Complete(context.Context, string, string) (oidc.Identity, error)
}
type SessionCreator interface {
	Create(context.Context, store.SessionInput) error
	AccessibleTeams(context.Context, string, time.Time) ([]store.AccessibleTeam, error)
	Delete(context.Context, string) error
	TokenContext(context.Context, string, int64, time.Time) (store.TokenContext, error)
	RecordToken(context.Context, store.TokenContext, string, time.Time, time.Time) error
	ValidateTokenAccess(context.Context, int64, int64, string, time.Time) error
}

// OperatorRegistry assigns the canonical integer operator_id of a verified
// (issuer, subject) pair.
type OperatorRegistry interface {
	OperatorID(context.Context, string, string) (int64, error)
}
type WorkingTokenSigner interface {
	Sign(int64, int64, *string) (workingtoken.Token, error)
	Verify(string, time.Time) (workingtoken.Claims, error)
}
type SessionEncryptor interface {
	Encrypt([]byte, []byte) ([]byte, error)
	Decrypt([]byte, []byte) ([]byte, error)
}
type RefreshableSessionStore interface {
	MembershipState(context.Context, string, time.Time) (store.MembershipState, error)
	ReplaceMembership(context.Context, string, []byte, []string, time.Time) error
}
type MembershipRefresher interface {
	Refresh(context.Context, []byte, string) ([]string, []byte, error)
}
type MappingRegistrar interface {
	Register(context.Context, store.Mapping) (store.Mapping, bool, error)
}
type MappingPresentationUpdater interface {
	RefreshPresentation(context.Context, int64, string, *time.Time) error
}

// CanonicalTeamReader is the team-registry.service.get point read. The string
// is the `team` header: the decimal team_id, or "admin".
type CanonicalTeamReader interface {
	GetTeam(context.Context, int64, string, int64) (teamregistry.Team, error)
}

type Dependencies struct {
	OperatorPreferences OperatorPreferenceStore
	ConfiguredIssuer    string
	AdminAuth           AdminAuthenticator
	Mappings            MappingRegistrar
	Presentation        MappingPresentationUpdater
	Teams               CanonicalTeamReader
	Login               LoginStarter
	OIDC                OIDCCompleter
	Sessions            SessionCreator
	SessionEncryptor    SessionEncryptor
	SessionTTL          time.Duration
	MembershipMaxAge    time.Duration
	Membership          MembershipRefresher
	WebUIURL            string
	WorkingTokens       WorkingTokenSigner
	Operators           OperatorRegistry
	// Broker carries every /ui/v1 operation to its owning service.
	Broker broker.Requester
	// RPCTimeout bounds every broker request (default 5 s).
	RPCTimeout time.Duration
	// JournalURL is journal's HTTP edge; JournalToken the Gateway's service
	// bearer token for it.
	JournalURL   string
	JournalToken string
	// AuthAudit receives the Gateway's own authentication audit; nil disables
	// it. It never goes to the broker.
	AuthAudit *slog.Logger
	// Logger receives the Gateway's request log; nil uses slog.Default().
	Logger *slog.Logger
}

type authenticatedContext struct {
	Claims workingtoken.Claims
}

func NewWithDependencies(dependencies Dependencies) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		// The Gateway is ready only while its own broker connection is up.
		if readiness, ok := dependencies.Broker.(interface{ Ready() bool }); ok && !readiness.Ready() {
			writeError(w, http.StatusServiceUnavailable, "broker_unavailable", "message broker is unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /auth/v1/login", func(w http.ResponseWriter, r *http.Request) { startLogin(w, r, dependencies.Login) })
	mux.HandleFunc("GET /auth/v1/callback", func(w http.ResponseWriter, r *http.Request) { callback(w, r, dependencies) })
	mux.HandleFunc("GET /auth/v1/teams", func(w http.ResponseWriter, r *http.Request) { listTeams(w, r, dependencies) })
	mux.HandleFunc("POST /auth/v1/token", func(w http.ResponseWriter, r *http.Request) { issueToken(w, r, dependencies) })
	mux.HandleFunc("DELETE /auth/v1/session", func(w http.ResponseWriter, r *http.Request) { logout(w, r, dependencies) })
	mux.HandleFunc("POST /admin/v1/oidc-team-mappings", func(w http.ResponseWriter, r *http.Request) { registerMapping(w, r, dependencies) })
	mux.HandleFunc("GET /ui/v1/operator/settings", func(w http.ResponseWriter, r *http.Request) { operatorSettings(w, r, dependencies) })
	mux.HandleFunc("PUT /ui/v1/operator/settings", func(w http.ResponseWriter, r *http.Request) { operatorSettings(w, r, dependencies) })
	mux.HandleFunc("/ui/", func(w http.ResponseWriter, r *http.Request) {
		if websocket.IsWebSocketUpgrade(r) {
			proxyWebSocket(w, r, dependencies)
			return
		}
		proxyREST(w, r, dependencies)
	})
	return mux
}

const browserBearerProtocolPrefix = "flowai.bearer."

func websocketBearer(r *http.Request) (string, string) {
	const bearerPrefix = "Bearer "
	if authorization := r.Header.Get("Authorization"); strings.HasPrefix(authorization, bearerPrefix) {
		return strings.TrimSpace(strings.TrimPrefix(authorization, bearerPrefix)), ""
	}
	for _, protocol := range websocket.Subprotocols(r) {
		if !strings.HasPrefix(protocol, browserBearerProtocolPrefix) {
			continue
		}
		encoded := strings.TrimPrefix(protocol, browserBearerProtocolPrefix)
		token, err := base64.RawURLEncoding.DecodeString(encoded)
		if err == nil && len(token) > 0 {
			return string(token), protocol
		}
	}
	return "", ""
}

func copyWebSocket(ctx context.Context, source, destination *websocket.Conn, writeMu *sync.Mutex, result chan<- error) {
	for {
		messageType, payload, err := source.ReadMessage()
		if err != nil {
			result <- err
			return
		}
		if writeMu != nil {
			writeMu.Lock()
		}
		err = destination.WriteMessage(messageType, payload)
		if writeMu != nil {
			writeMu.Unlock()
		}
		if err != nil {
			result <- err
			return
		}
		select {
		case <-ctx.Done():
			result <- ctx.Err()
			return
		default:
		}
	}
}

func authenticateWorkingToken(w http.ResponseWriter, r *http.Request, dependencies Dependencies, token string) (authenticatedContext, bool) {
	if token == "" || dependencies.WorkingTokens == nil || dependencies.Sessions == nil {
		writeError(w, http.StatusUnauthorized, "invalid_working_token", "working token is invalid")
		return authenticatedContext{}, false
	}
	claims, err := dependencies.WorkingTokens.Verify(token, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_working_token", "working token is invalid")
		return authenticatedContext{}, false
	}
	if err := dependencies.Sessions.ValidateTokenAccess(r.Context(), claims.OperatorID, claims.TeamID, claims.JTI, time.Now().UTC()); err != nil {
		writeError(w, http.StatusForbidden, "team_not_accessible", "team is not accessible")
		return authenticatedContext{}, false
	}
	return authenticatedContext{Claims: claims}, true
}

func logout(w http.ResponseWriter, r *http.Request, dependencies Dependencies) {
	cookie, err := r.Cookie("flowai_session")
	if err != nil || cookie.Value == "" || dependencies.Sessions == nil {
		invalidSession(w, r)
		return
	}
	if err := dependencies.Sessions.Delete(r.Context(), cookie.Value); errors.Is(err, store.ErrSessionNotFound) {
		invalidSession(w, r)
		return
	} else if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "session persistence is unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "flowai_session", Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	dependencies.authAudit(r.Context(), "logout")
	w.WriteHeader(http.StatusNoContent)
}

func issueToken(w http.ResponseWriter, r *http.Request, dependencies Dependencies) {
	cookie, err := r.Cookie("flowai_session")
	if err != nil || cookie.Value == "" || dependencies.Sessions == nil || dependencies.WorkingTokens == nil {
		invalidSession(w, r)
		return
	}
	var input struct {
		TeamID int64 `json:"team_id"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF || input.TeamID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "token request is invalid")
		return
	}
	if !refreshMembership(w, r, cookie.Value, dependencies) {
		return
	}
	tokenContext, err := dependencies.Sessions.TokenContext(r.Context(), cookie.Value, input.TeamID, time.Now().UTC())
	if errors.Is(err, store.ErrSessionNotFound) {
		invalidSession(w, r)
		return
	}
	if errors.Is(err, store.ErrTeamNotAccessible) {
		writeError(w, http.StatusForbidden, "team_not_accessible", "team is not accessible")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "session persistence is unavailable")
		return
	}
	if dependencies.Teams != nil && dependencies.Presentation != nil {
		canonical, err := dependencies.readTeam(r.Context(), tokenContext.TeamID, strconv.FormatInt(tokenContext.TeamID, 10), newRequestID())
		if err != nil {
			writeTeamReadError(w, err, newRequestID())
			return
		}
		if err := dependencies.Presentation.RefreshPresentation(r.Context(), canonical.TeamID, canonical.TeamName, canonical.ArchivedAt); err != nil {
			writeError(w, http.StatusServiceUnavailable, "service_unavailable", "team presentation persistence is unavailable")
			return
		}
		tokenContext.TeamName = &canonical.TeamName
	}
	token, err := dependencies.WorkingTokens.Sign(tokenContext.OperatorID, tokenContext.TeamID, tokenContext.TeamName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid_session", "working token could not be issued")
		return
	}
	if err := dependencies.Sessions.RecordToken(r.Context(), tokenContext, token.JTI, token.IssuedAt, token.ExpiresAt); err != nil {
		writeError(w, http.StatusInternalServerError, "invalid_session", "working token could not be recorded")
		return
	}
	dependencies.authAudit(r.Context(), "token_issued", "operator_id", tokenContext.OperatorID, "team_id", tokenContext.TeamID)
	writeJSON(w, http.StatusOK, map[string]any{"access_token": token.AccessToken, "token_type": "Bearer", "expires_in": token.ExpiresIn})
}

func refreshMembership(w http.ResponseWriter, r *http.Request, sessionID string, dependencies Dependencies) bool {
	refreshable, ok := dependencies.Sessions.(RefreshableSessionStore)
	if !ok || dependencies.Membership == nil || dependencies.SessionEncryptor == nil {
		return true
	}
	now := time.Now().UTC()
	state, err := refreshable.MembershipState(r.Context(), sessionID, now)
	if errors.Is(err, store.ErrSessionNotFound) {
		invalidSession(w, r)
		return false
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "session persistence is unavailable")
		return false
	}
	if dependencies.MembershipMaxAge > 0 && now.Sub(state.ObservedAt) <= dependencies.MembershipMaxAge {
		return true
	}
	plaintext, err := dependencies.SessionEncryptor.Decrypt(state.EncryptedProviderState, []byte(sessionID))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_session", "browser session is invalid")
		return false
	}
	teamIDs, providerState, err := dependencies.Membership.Refresh(r.Context(), plaintext, state.Subject)
	if err != nil {
		writeError(w, http.StatusBadGateway, "oidc_provider_unavailable", "OIDC provider is unavailable")
		return false
	}
	encrypted, err := dependencies.SessionEncryptor.Encrypt(providerState, []byte(sessionID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid_session", "session could not be refreshed")
		return false
	}
	if err := refreshable.ReplaceMembership(r.Context(), sessionID, encrypted, teamIDs, now); err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "session persistence is unavailable")
		return false
	}
	return true
}

func startLogin(w http.ResponseWriter, r *http.Request, login LoginStarter) {
	if login == nil {
		notImplemented(w, r)
		return
	}
	location, err := login.Start(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, "oidc_provider_unavailable", "OIDC provider is unavailable")
		return
	}
	http.Redirect(w, r, location, http.StatusFound)
}

func registerMapping(w http.ResponseWriter, r *http.Request, dependencies Dependencies) {
	if dependencies.AdminAuth == nil || dependencies.Mappings == nil || dependencies.Teams == nil {
		invalidAdminToken(w, r)
		return
	}
	_, err := dependencies.AdminAuth.Authenticate(r.Context(), r.Header.Get("Authorization"))
	if err != nil {
		switch {
		case errors.Is(err, adminauth.ErrProviderUnavailable):
			writeError(w, http.StatusBadGateway, "admin_identity_provider_unavailable", "administrator identity provider is unavailable")
		case errors.Is(err, adminauth.ErrInsufficientRole):
			writeError(w, http.StatusForbidden, "insufficient_admin_role", "administrator role is required")
		default:
			writeError(w, http.StatusUnauthorized, "invalid_admin_token", "administrator token is invalid")
		}
		return
	}
	var input struct {
		Issuer     string `json:"issuer"`
		OIDCTeamID string `json:"oidc_team_id"`
		TeamID     int64  `json:"team_id"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF || input.Issuer == "" || input.OIDCTeamID == "" || input.TeamID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "mapping request is invalid")
		return
	}
	if input.Issuer != dependencies.ConfiguredIssuer {
		writeError(w, http.StatusBadRequest, "invalid_request", "issuer is not configured")
		return
	}
	requestID := newRequestID()
	team, err := dependencies.readTeam(r.Context(), input.TeamID, teamregistry.AdminTeam, requestID)
	if err != nil {
		writeTeamReadError(w, err, requestID)
		return
	}
	mapping, created, err := dependencies.Mappings.Register(r.Context(), store.Mapping{Issuer: input.Issuer, OIDCTeamID: input.OIDCTeamID, TeamID: team.TeamID, TeamName: &team.TeamName, ArchivedAt: team.ArchivedAt})
	if err != nil {
		if errors.Is(err, store.ErrMappingConflict) {
			writeErrorWithID(w, http.StatusConflict, "mapping_conflict", "mapping conflicts with an existing mapping", requestID)
		} else {
			writeErrorWithID(w, http.StatusServiceUnavailable, "service_unavailable", "mapping persistence is unavailable", requestID)
		}
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"issuer": mapping.Issuer, "oidc_team_id": mapping.OIDCTeamID, "team_id": mapping.TeamID, "team_name": mapping.TeamName, "archived_at": mapping.ArchivedAt})
}

func callback(w http.ResponseWriter, r *http.Request, dependencies Dependencies) {
	query := r.URL.Query()
	hasCode := query.Get("code") != ""
	hasError := query.Get("error") != ""
	if query.Get("state") == "" || hasCode == hasError {
		writeError(w, http.StatusBadRequest, "invalid_request", "callback must contain exactly one result")
		return
	}
	if hasError || dependencies.OIDC == nil || dependencies.Sessions == nil || dependencies.SessionEncryptor == nil {
		writeError(w, http.StatusUnauthorized, "invalid_oidc_identity", "OIDC identity is invalid")
		return
	}
	identity, err := dependencies.OIDC.Complete(r.Context(), query.Get("code"), query.Get("state"))
	if err != nil {
		if errors.Is(err, oidc.ErrProviderUnavailable) || errors.Is(err, jwtverify.ErrJWKSUnavailable) {
			writeError(w, http.StatusBadGateway, "oidc_provider_unavailable", "OIDC provider is unavailable")
		} else {
			writeError(w, http.StatusUnauthorized, "invalid_oidc_identity", "OIDC identity is invalid")
		}
		return
	}
	sessionID, err := randomOpaqueToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid_session", "session could not be created")
		return
	}
	encrypted, err := dependencies.SessionEncryptor.Encrypt(identity.ProviderState, []byte(sessionID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invalid_session", "session could not be created")
		return
	}
	if dependencies.Operators == nil {
		writeError(w, http.StatusInternalServerError, "invalid_session", "session could not be created")
		return
	}
	operatorID, err := dependencies.Operators.OperatorID(r.Context(), identity.Issuer, identity.Subject)
	if err != nil || operatorID <= 0 {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "operator persistence is unavailable")
		return
	}
	now := time.Now().UTC()
	ttl := dependencies.SessionTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	if err := dependencies.Sessions.Create(r.Context(), store.SessionInput{SessionID: sessionID, OperatorID: operatorID, Issuer: identity.Issuer, Subject: identity.Subject, EncryptedProviderState: encrypted, OIDCTeamIDs: identity.OIDCTeamIDs, ObservedAt: now, ExpiresAt: now.Add(ttl)}); err != nil {
		writeError(w, http.StatusInternalServerError, "invalid_session", "session could not be created")
		return
	}
	dependencies.authAudit(r.Context(), "login", "operator_id", operatorID)
	http.SetCookie(w, &http.Cookie{Name: "flowai_session", Value: sessionID, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds())})
	location := dependencies.WebUIURL
	if location == "" {
		location = "/"
	}
	http.Redirect(w, r, location, http.StatusFound)
}

func listTeams(w http.ResponseWriter, r *http.Request, dependencies Dependencies) {
	cookie, err := r.Cookie("flowai_session")
	if err != nil || cookie.Value == "" || dependencies.Sessions == nil {
		invalidSession(w, r)
		return
	}
	teams, err := dependencies.Sessions.AccessibleTeams(r.Context(), cookie.Value, time.Now().UTC())
	if errors.Is(err, store.ErrSessionNotFound) {
		invalidSession(w, r)
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", "session persistence is unavailable")
		return
	}
	result := make([]map[string]any, 0, len(teams))
	for _, team := range teams {
		if dependencies.Teams != nil && dependencies.Presentation != nil {
			canonical, err := dependencies.readTeam(r.Context(), team.TeamID, strconv.FormatInt(team.TeamID, 10), newRequestID())
			if err != nil {
				writeTeamReadError(w, err, newRequestID())
				return
			}
			if err := dependencies.Presentation.RefreshPresentation(r.Context(), canonical.TeamID, canonical.TeamName, canonical.ArchivedAt); err != nil {
				writeError(w, http.StatusServiceUnavailable, "service_unavailable", "team presentation persistence is unavailable")
				return
			}
			team.TeamName, team.ArchivedAt = &canonical.TeamName, canonical.ArchivedAt
		}
		result = append(result, map[string]any{"team_id": team.TeamID, "team_name": team.TeamName, "archived_at": team.ArchivedAt})
	}
	writeJSON(w, http.StatusOK, map[string]any{"teams": result})
}

func invalidSession(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusUnauthorized, "invalid_session", "browser session is invalid")
}

func invalidAdminToken(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusUnauthorized, "invalid_admin_token", "administrator token is invalid")
}

func notImplemented(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"code":    "not_implemented",
		"message": "v0007 behavior has not been implemented",
	})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeErrorWithID(w, status, code, message, newRequestID())
}

func writeErrorWithID(w http.ResponseWriter, status int, code, message string, requestID int64) {
	writeJSON(w, status, errorResponse{Code: code, Message: message, RequestID: requestID})
}

// newRequestID returns a random positive 63-bit request identifier.
func newRequestID() int64 {
	for {
		var value [8]byte
		if _, err := rand.Read(value[:]); err != nil {
			panic("secure random source unavailable")
		}
		if id := int64(binary.BigEndian.Uint64(value[:]) >> 1); id > 0 {
			return id
		}
	}
}

// readTeam is the team-registry point read, bounded by the RPC timeout.
func (d Dependencies) readTeam(ctx context.Context, teamID int64, teamHeader string, requestID int64) (teamregistry.Team, error) {
	ctx, cancel := context.WithTimeout(ctx, d.rpcTimeout())
	defer cancel()
	return d.Teams.GetTeam(ctx, teamID, teamHeader, requestID)
}

func writeTeamReadError(w http.ResponseWriter, err error, requestID int64) {
	switch {
	case errors.Is(err, teamregistry.ErrTeamNotFound):
		writeErrorWithID(w, http.StatusNotFound, "canonical_team_not_found", "canonical team was not found", requestID)
	case errors.Is(err, broker.ErrUnavailable):
		writeErrorWithID(w, http.StatusServiceUnavailable, "broker_unavailable", "message broker is unavailable", requestID)
	default:
		writeErrorWithID(w, http.StatusServiceUnavailable, "service_unavailable", "team-registry is unavailable", requestID)
	}
}

// authAudit writes one Gateway authentication audit record. It never carries
// a session, token or provider credential.
func (d Dependencies) authAudit(ctx context.Context, event string, attributes ...any) {
	if d.AuthAudit == nil {
		return
	}
	d.AuthAudit.InfoContext(ctx, "auth_audit", append([]any{"event", event}, attributes...)...)
}

func (d Dependencies) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

func randomOpaqueToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
