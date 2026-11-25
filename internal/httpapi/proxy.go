package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pandops/flowai-api-gateway/internal/broker"
	"github.com/pandops/flowai-api-gateway/internal/uiroutes"
	"github.com/pandops/flowai-api-gateway/internal/workingtoken"
	"github.com/gorilla/websocket"
)

// maxBodyBytes bounds a forwarded REST request body.
const maxBodyBytes = 1 << 20

const defaultRPCTimeout = 5 * time.Second

// replyHeaders are the owner reply headers the Gateway copies to the browser.
var replyHeaders = []string{"ETag", "Location", "Retry-After", "Cache-Control"}

var decimalIdentifier = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

// parseIdentifier accepts a positive int64 written without sign or leading
// zeros.
func parseIdentifier(raw string) (int64, bool) {
	if !decimalIdentifier.MatchString(raw) {
		return 0, false
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	return value, err == nil && value > 0
}

// isIdentifierName reports whether a path, query or body field names a
// FlowAI identifier. external_id is the Source's external text, not one.
func isIdentifierName(name string) bool {
	if name == "external_id" || name == "external_ids" {
		return false
	}
	return name == "id" || strings.HasSuffix(name, "_id") || strings.HasSuffix(name, "_ids")
}

// buildParams types the route's path and query parameters: identifiers as
// JSON numbers, limit as an integer when it is one, archived as a boolean
// when it is one, and every other value as the string the browser sent.
func buildParams(route uiroutes.Route, path map[string]string, query url.Values) (map[string]any, bool) {
	params := map[string]any{}
	for name, raw := range path {
		if name == "name" {
			params[name] = raw
			continue
		}
		value, ok := parseIdentifier(raw)
		if !ok {
			return nil, false
		}
		params[name] = value
	}
	for name, values := range query {
		if _, taken := params[name]; taken || len(values) == 0 {
			continue
		}
		raw := values[0]
		switch {
		case isIdentifierName(name):
			value, ok := parseIdentifier(raw)
			if !ok {
				return nil, false
			}
			params[name] = value
		case name == "limit":
			if value, err := strconv.ParseInt(raw, 10, 64); err == nil {
				params[name] = value
			} else {
				params[name] = raw
			}
		case name == "archived" && (raw == "true" || raw == "false"):
			params[name] = raw == "true"
		default:
			params[name] = raw
		}
	}
	return params, true
}

// bodyIdentifiersValid checks that every identifier field of a JSON body is a
// positive int64 JSON number (an array of them for a *_ids field).
func bodyIdentifiersValid(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for name, field := range typed {
			if isIdentifierName(name) && field != nil {
				if strings.HasSuffix(name, "_ids") {
					items, ok := field.([]any)
					if !ok {
						return false
					}
					for _, item := range items {
						if !jsonIdentifier(item) {
							return false
						}
					}
					continue
				}
				if !jsonIdentifier(field) {
					return false
				}
				continue
			}
			if !bodyIdentifiersValid(field) {
				return false
			}
		}
	case []any:
		for _, item := range typed {
			if !bodyIdentifiersValid(item) {
				return false
			}
		}
	}
	return true
}

func jsonIdentifier(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	_, valid := parseIdentifier(number.String())
	return valid
}

func proxyREST(w http.ResponseWriter, r *http.Request, dependencies Dependencies) {
	const bearerPrefix = "Bearer "
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, bearerPrefix) {
		writeError(w, http.StatusUnauthorized, "invalid_working_token", "working token is invalid")
		return
	}
	auth, ok := authenticateWorkingToken(w, r, dependencies, strings.TrimSpace(strings.TrimPrefix(authorization, bearerPrefix)))
	if !ok {
		return
	}
	requestID := newRequestID()
	route, pathParams, found := uiroutes.Lookup(r.Method, r.URL.EscapedPath())
	if !found {
		// A path shaped like a routed operation but with a malformed
		// identifier is refused as such; any other path is unknown.
		if shape, shapeParams, shaped := uiroutes.Shape(r.URL.EscapedPath()); shaped {
			if _, valid := buildParams(shape, shapeParams, r.URL.Query()); !valid {
				writeErrorWithID(w, http.StatusBadRequest, "invalid_request", "identifiers must be positive integers", requestID)
				return
			}
		}
		writeErrorWithID(w, http.StatusNotFound, "not_found", "route is not part of the UI API", requestID)
		return
	}
	params, valid := buildParams(route, pathParams, r.URL.Query())
	if !valid {
		writeErrorWithID(w, http.StatusBadRequest, "invalid_request", "identifiers must be positive integers", requestID)
		return
	}
	envelope := map[string]any{"params": params}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeErrorWithID(w, http.StatusBadRequest, "invalid_request", "request body could not be read", requestID)
		return
	}
	if len(raw) > maxBodyBytes {
		writeErrorWithID(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds 1 MiB", requestID)
		return
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil || decoder.Decode(&struct{}{}) != io.EOF || !bodyIdentifiersValid(decoded) {
			writeErrorWithID(w, http.StatusBadRequest, "invalid_request", "request body must be JSON with integer identifiers", requestID)
			return
		}
		envelope["body"] = json.RawMessage(raw)
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		writeErrorWithID(w, http.StatusBadRequest, "invalid_request", "request could not be encoded", requestID)
		return
	}
	header := contextHeaders(auth.Claims, requestID)
	if ifMatch := r.Header.Get("If-Match"); ifMatch != "" {
		header["If-Match"] = ifMatch
	}
	subject := route.Subject()
	logger := dependencies.logger()
	if dependencies.Broker == nil {
		writeErrorWithID(w, http.StatusServiceUnavailable, "broker_unavailable", "message broker is unavailable", requestID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), dependencies.rpcTimeout())
	defer cancel()
	started := time.Now()
	reply, err := dependencies.Broker.Request(ctx, broker.Request{Subject: subject, Header: header, Body: payload})
	if err != nil {
		code := "service_unavailable"
		if errors.Is(err, broker.ErrUnavailable) {
			code = "broker_unavailable"
		}
		logger.Warn("ui request failed", "subject", subject, "method", r.Method, "request_id", requestID, "team_id", auth.Claims.TeamID, "operator_id", auth.Claims.OperatorID, "error_code", code, "duration_ms", time.Since(started).Milliseconds())
		message := "owning service did not answer"
		if code == "broker_unavailable" {
			message = "message broker is unavailable"
		}
		writeErrorWithID(w, http.StatusServiceUnavailable, code, message, requestID)
		return
	}
	status, err := strconv.Atoi(reply.Header["status"])
	if err != nil || status < 200 || status > 599 {
		logger.Warn("ui reply is malformed", "subject", subject, "request_id", requestID)
		writeErrorWithID(w, http.StatusServiceUnavailable, "service_unavailable", "owning service replied without a status", requestID)
		return
	}
	logger.Info("ui request", "subject", subject, "method", r.Method, "request_id", requestID, "team_id", auth.Claims.TeamID, "operator_id", auth.Claims.OperatorID, "status", status, "duration_ms", time.Since(started).Milliseconds())
	for _, name := range replyHeaders {
		if value := reply.Header[name]; value != "" {
			w.Header().Set(name, value)
		}
	}
	if len(reply.Body) > 0 || status != http.StatusNoContent {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_, _ = w.Write(reply.Body)
}

// contextHeaders is the verified context of one ui request.
func contextHeaders(claims workingtoken.Claims, requestID int64) map[string]string {
	header := map[string]string{
		"team":        strconv.FormatInt(claims.TeamID, 10),
		"operator_id": strconv.FormatInt(claims.OperatorID, 10),
		"request_id":  strconv.FormatInt(requestID, 10),
	}
	if claims.TeamName != nil && *claims.TeamName != "" {
		header["team_name"] = *claims.TeamName
	}
	return header
}

func (d Dependencies) rpcTimeout() time.Duration {
	if d.RPCTimeout > 0 {
		return d.RPCTimeout
	}
	return defaultRPCTimeout
}

// ---- team stream -----------------------------------------------------------

var streamPath = regexp.MustCompile(`^/ui/v1/teams/([^/]+)/stream$`)

const tokenExpiredClose = 4401

func proxyWebSocket(w http.ResponseWriter, r *http.Request, dependencies Dependencies) {
	token, protocol := websocketBearer(r)
	auth, ok := authenticateWorkingToken(w, r, dependencies, token)
	if !ok {
		return
	}
	requestID := newRequestID()
	match := streamPath.FindStringSubmatch(r.URL.EscapedPath())
	if r.Method != http.MethodGet || match == nil {
		writeErrorWithID(w, http.StatusNotFound, "not_found", "route is not part of the UI API", requestID)
		return
	}
	teamID, valid := parseIdentifier(match[1])
	query := url.Values{}
	if valid {
		if cursor, present := r.URL.Query()["after_frame_id"]; present {
			if _, cursorValid := parseIdentifier(cursor[0]); !cursorValid {
				valid = false
			} else {
				query.Set("after_frame_id", cursor[0])
			}
		}
	}
	if !valid {
		writeErrorWithID(w, http.StatusBadRequest, "invalid_request", "identifiers must be positive integers", requestID)
		return
	}
	if dependencies.JournalURL == "" {
		writeErrorWithID(w, http.StatusServiceUnavailable, "service_unavailable", "team stream is unavailable", requestID)
		return
	}
	target, err := url.Parse(strings.TrimRight(dependencies.JournalURL, "/") + "/v1/teams/" + strconv.FormatInt(teamID, 10) + "/stream")
	if err != nil {
		writeErrorWithID(w, http.StatusServiceUnavailable, "service_unavailable", "team stream is unavailable", requestID)
		return
	}
	switch target.Scheme {
	case "https":
		target.Scheme = "wss"
	default:
		target.Scheme = "ws"
	}
	target.RawQuery = query.Encode()
	upstreamHeader := http.Header{}
	upstreamHeader.Set("Authorization", "Bearer "+dependencies.JournalToken)
	for name, value := range contextHeaders(auth.Claims, requestID) {
		switch name {
		case "team":
			upstreamHeader.Set("X-FlowAI-Team-ID", value)
		case "operator_id":
			upstreamHeader.Set("X-FlowAI-Operator-ID", value)
		case "request_id":
			upstreamHeader.Set("X-FlowAI-Request-ID", value)
		case "team_name":
			upstreamHeader.Set("X-FlowAI-Team-Name", value)
		}
	}
	dialer := websocket.Dialer{HandshakeTimeout: dependencies.rpcTimeout()}
	upstream, response, err := dialer.DialContext(r.Context(), target.String(), upstreamHeader)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	logger := dependencies.logger()
	if err != nil {
		logger.Warn("team stream unavailable", "team_id", teamID, "request_id", requestID)
		writeErrorWithID(w, http.StatusServiceUnavailable, "service_unavailable", "team stream is unavailable", requestID)
		return
	}
	defer upstream.Close()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var responseHeader http.Header
	if protocol != "" {
		responseHeader = http.Header{"Sec-WebSocket-Protocol": {protocol}}
	}
	browser, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		return
	}
	defer browser.Close()
	logger.Info("team stream opened", "team_id", teamID, "operator_id", auth.Claims.OperatorID, "request_id", requestID)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var browserWrite sync.Mutex
	result := make(chan error, 2)
	go copyWebSocket(ctx, upstream, browser, &browserWrite, result)
	go copyWebSocket(ctx, browser, upstream, nil, result)
	expiry := time.NewTimer(time.Until(time.Unix(auth.Claims.ExpiresAt, 0)))
	defer expiry.Stop()
	select {
	case err := <-result:
		var closeErr *websocket.CloseError
		code, text := websocket.CloseNormalClosure, ""
		if errors.As(err, &closeErr) && closeErr.Code != websocket.CloseNoStatusReceived && closeErr.Code != websocket.CloseAbnormalClosure && closeErr.Code != websocket.CloseTLSHandshake {
			code, text = closeErr.Code, closeErr.Text
		}
		browserWrite.Lock()
		_ = browser.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, text), time.Now().Add(time.Second))
		browserWrite.Unlock()
	case <-expiry.C:
		browserWrite.Lock()
		_ = browser.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(tokenExpiredClose, "working_token_expired"), time.Now().Add(time.Second))
		browserWrite.Unlock()
	case <-ctx.Done():
	}
}
