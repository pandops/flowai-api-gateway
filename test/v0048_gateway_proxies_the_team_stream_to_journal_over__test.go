package test

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// api-gateway: Gateway proxies the team stream to journal over HTTP.
func TestV0048GatewayProxiesTheTeamStreamToJournal(t *testing.T) {
	t.Parallel()

	t.Run("Browser opens the team stream", func(t *testing.T) {
		journal := newFakeJournal(t)
		g := newGateway(t, withJournal(journal))
		token := g.token(gwTeam)
		protocol := "flowai.bearer." + base64.RawURLEncoding.EncodeToString([]byte(token))
		dialer := websocket.Dialer{Subprotocols: []string{protocol}, HandshakeTimeout: 2 * time.Second}
		socket, response, err := dialer.Dial(g.streamURL("/ui/v1/teams/3/stream?after_frame_id=5120"), nil)
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		defer socket.Close()
		if response.Header.Get("Sec-WebSocket-Protocol") != protocol {
			t.Fatalf("subprotocol = %q", response.Header.Get("Sec-WebSocket-Protocol"))
		}
		frames := readFrames(t, socket, 2)
		if frames[0] != `{"frame_id":5121,"team_id":3,"kind":"replay"}` || frames[1] != `{"frame_id":5122,"team_id":3,"kind":"live"}` {
			t.Fatalf("frames = %v, want journal's frames unchanged and in order", frames)
		}
		if err := socket.WriteMessage(websocket.TextMessage, []byte(`{"ping":1}`)); err != nil {
			t.Fatal(err)
		}
		if echoed := readFrames(t, socket, 1); echoed[0] != `echo:{"ping":1}` {
			t.Fatalf("browser frame did not reach journal unchanged: %v", echoed)
		}
		seen := journal.seen()
		if len(seen) != 1 || seen[0].path != "/v1/teams/3/stream" || seen[0].query != "after_frame_id=5120" {
			t.Fatalf("journal upgrades = %+v", seen)
		}
		headers := seen[0].headers
		if headers.Get("Authorization") != "Bearer "+gwJournalSA || headers.Get("X-FlowAI-Team-ID") != "3" || headers.Get("X-FlowAI-Operator-ID") != "42" || headers.Get("X-FlowAI-Team-Name") != "Alpha-Team" {
			t.Fatalf("journal context = %v", headers)
		}
		if id, err := strconv.ParseInt(headers.Get("X-FlowAI-Request-ID"), 10, 64); err != nil || id <= 0 {
			t.Fatalf("request id = %q", headers.Get("X-FlowAI-Request-ID"))
		}
		if got := len(g.broker.uiRequests()); got != 0 {
			t.Fatalf("the stream used the broker: %d requests", got)
		}
		// journal closing the established stream closes the browser stream.
		if err := socket.WriteMessage(websocket.TextMessage, []byte("close-please")); err != nil {
			t.Fatal(err)
		}
		_ = socket.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, _, err = socket.ReadMessage()
		var closeErr *websocket.CloseError
		var netErr net.Error
		if err == nil || (errors.As(err, &netErr) && netErr.Timeout()) {
			t.Fatalf("browser stream stayed open after journal closed it: %v", err)
		}
		_ = closeErr
		// A non-integer or non-positive resume cursor is refused before journal.
		for _, cursor := range []string{"abc", "0", "-3", "1.5"} {
			status, body := dialRejected(t, g.streamURL("/ui/v1/teams/3/stream?after_frame_id="+cursor), http.Header{"Authorization": {"Bearer " + token}})
			if status != http.StatusBadRequest || !strings.Contains(body, `"invalid_request"`) {
				t.Fatalf("after_frame_id=%s = %d %s", cursor, status, body)
			}
		}
		status, body := dialRejected(t, g.streamURL("/ui/v1/teams/team-a/stream"), http.Header{"Authorization": {"Bearer " + token}})
		if status != http.StatusBadRequest || !strings.Contains(body, `"invalid_request"`) {
			t.Fatalf("non-integer stream team = %d %s", status, body)
		}
		if got := len(journal.seen()); got != 1 {
			t.Fatalf("rejected upgrades dialed journal: %d", got)
		}
		// A missing or corrupted bearer is refused before journal.
		if status, _ := dialRejected(t, g.streamURL("/ui/v1/teams/3/stream"), nil); status != http.StatusUnauthorized {
			t.Fatalf("missing bearer = %d", status)
		}
		corrupted := token[:len(token)-4] + "AAAA"
		if status, _ := dialRejected(t, g.streamURL("/ui/v1/teams/3/stream"), http.Header{"Authorization": {"Bearer " + corrupted}}); status != http.StatusUnauthorized {
			t.Fatalf("bad signature = %d", status)
		}
		if got := len(journal.seen()); got != 1 {
			t.Fatalf("unauthenticated upgrades dialed journal: %d", got)
		}
	})

	t.Run("Browser forges stream context", func(t *testing.T) {
		journal := newFakeJournal(t)
		g := newGateway(t, withJournal(journal))
		token := g.token(gwTeam)
		socket, _, err := websocket.DefaultDialer.Dial(g.streamURL("/ui/v1/teams/3/stream"), http.Header{
			"Authorization":        {"Bearer " + token},
			"Cookie":               {"flowai_session=" + gwSessionID},
			"X-Flowai-Team-Id":     {"4"},
			"X-Flowai-Operator-Id": {"99"},
			"X-Flowai-Team-Name":   {"Forged Beta"},
			"X-Flowai-Request-Id":  {"1"},
			"X-Flowai-Service":     {"forged-service-bearer"},
		})
		if err != nil {
			t.Fatalf("upgrade: %v", err)
		}
		frames := readFrames(t, socket, 2)
		socket.Close()
		if !strings.Contains(frames[0], `"team_id":3`) {
			t.Fatalf("frames = %v", frames)
		}
		headers := journal.seen()[0].headers
		if headers.Get("Authorization") != "Bearer "+gwJournalSA || len(headers.Values("Authorization")) != 1 {
			t.Fatalf("journal authorization = %v", headers.Values("Authorization"))
		}
		if headers.Get("X-FlowAI-Team-ID") != "3" || len(headers.Values("X-FlowAI-Team-ID")) != 1 || headers.Get("X-FlowAI-Operator-ID") != "42" || headers.Get("X-FlowAI-Team-Name") != "Alpha-Team" || headers.Get("X-FlowAI-Request-ID") == "1" {
			t.Fatalf("journal context = %v", headers)
		}
		for name := range headers {
			if strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "X-Flowai-Service") || strings.EqualFold(name, "Origin") {
				t.Fatalf("journal received browser header %s", name)
			}
			if strings.Contains(strings.Join(headers.Values(name), ","), "flowai.bearer") || strings.Contains(strings.Join(headers.Values(name), ","), token) {
				t.Fatalf("journal received the browser bearer in %s", name)
			}
		}
		// The service bearer token never reaches the browser.
		protocol := "flowai.bearer." + base64.RawURLEncoding.EncodeToString([]byte(token))
		dialer := websocket.Dialer{Subprotocols: []string{protocol}}
		second, response, err := dialer.Dial(g.streamURL("/ui/v1/teams/3/stream"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer second.Close()
		for name, values := range response.Header {
			if strings.Contains(strings.Join(values, ","), gwJournalSA) {
				t.Fatalf("browser received the service bearer in %s", name)
			}
		}
		for _, frame := range readFrames(t, second, 2) {
			if strings.Contains(frame, gwJournalSA) {
				t.Fatal("browser frame carries the service bearer")
			}
		}
		// The bearer subprotocol is consumed: journal's dial carries no
		// browser subprotocol and no part of the browser token.
		subprotocolDial := journal.seen()[len(journal.seen())-1].headers
		if values := subprotocolDial.Values("Sec-Websocket-Protocol"); len(values) != 0 {
			t.Fatalf("journal received subprotocols %v", values)
		}
		for name, values := range subprotocolDial {
			if joined := strings.Join(values, ","); strings.Contains(joined, "flowai.bearer") || strings.Contains(joined, token) || strings.Contains(joined, base64.RawURLEncoding.EncodeToString([]byte(token))) {
				t.Fatalf("journal received the browser bearer in %s", name)
			}
		}
	})
}
