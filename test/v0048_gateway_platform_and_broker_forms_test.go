package test

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
)

// service-platform and message-broker rows in their api-gateway form.
func TestV0048GatewayPlatformAndBrokerForms(t *testing.T) {
	t.Parallel()

	t.Run("Concurrent team streams", func(t *testing.T) {
		journal := newFakeJournal(t)
		g := newGateway(t, withJournal(journal))
		tokens := map[int64]string{gwTeam: g.token(gwTeam), gwOtherTeam: g.token(gwOtherTeam)}
		frames := map[int64][]string{}
		var mu sync.Mutex
		var wait sync.WaitGroup
		for team, token := range tokens {
			wait.Add(1)
			go func() {
				defer wait.Done()
				protocol := "flowai.bearer." + base64.RawURLEncoding.EncodeToString([]byte(token))
				socket, _, err := (&websocket.Dialer{Subprotocols: []string{protocol}}).Dial(g.streamURL(fmt.Sprintf("/ui/v1/teams/%d/stream", team)), nil)
				if err != nil {
					t.Errorf("team %d stream: %v", team, err)
					return
				}
				defer socket.Close()
				got := readFrames(t, socket, 2)
				mu.Lock()
				frames[team] = got
				mu.Unlock()
			}()
		}
		wait.Wait()
		for team, got := range frames {
			for _, frame := range got {
				if !strings.Contains(frame, fmt.Sprintf(`"team_id":%d,`, team)) {
					t.Fatalf("team %d stream carries %s", team, frame)
				}
			}
		}
		seen := map[string]bool{}
		for _, upgrade := range journal.seen() {
			seen[upgrade.headers.Get("X-FlowAI-Team-ID")+"@"+upgrade.path] = true
		}
		if len(frames) != 2 || !seen["3@/v1/teams/3/stream"] || !seen["4@/v1/teams/4/stream"] {
			t.Fatalf("journal upgrades = %v, frames %v", seen, frames)
		}
	})

	t.Run("Secret write passes through the broker without storage", func(t *testing.T) {
		sink := &syncBuffer{}
		g := newGateway(t, withLogSink(sink))
		token := g.token(gwTeam)
		const value = "launch-secret-value-canary"
		proxyCase{method: http.MethodPut, path: "/ui/v1/teams/3/launch-parameters/5/secrets/8", ifMatch: `"secret-8-v1"`, body: `{"value":"` + value + `"}`, subject: "env-registry.ui.replace-secret.pub", status: 200, reply: `{"secret_id":8,"key":"API_TOKEN","version":2}`, replyHeaders: map[string]string{"ETag": `"secret-8-v2"`}}.run(t, g, token)
		assertNotRetained(t, g, token, "/ui/v1/teams/3/launch-parameters/5", "env-registry.ui.get.pub", value)
		assertLogClean(t, sink, "env-registry.ui.replace-secret.pub", value, token)
	})

	t.Run("One-time Executor JWT crosses the broker only in a reply", func(t *testing.T) {
		sink := &syncBuffer{}
		g := newGateway(t, withLogSink(sink))
		token := g.token(gwTeam)
		const executorJWT = "eyJhbGciOiJFZDI1NTE5In0.executor-jwt-canary.sig"
		created := `{"executor_id":7,"team_id":3,"execution_tag":"GPU","executor_type":"executor_docker_openhands","token":"` + executorJWT + `"}`
		proxyCase{method: http.MethodPost, path: "/ui/v1/teams/3/executors", body: `{"execution_tag":"GPU","executor_type":"executor_docker_openhands"}`, subject: "executor-registry.ui.create.pub", status: http.StatusCreated, reply: created, replyHeaders: map[string]string{"Cache-Control": "no-store", "Location": "/ui/v1/teams/3/executors/7"}}.run(t, g, token)
		proxyCase{method: http.MethodPost, path: "/ui/v1/teams/3/executors/7/token", subject: "executor-registry.ui.reissue.pub", status: 200, reply: `{"executor_id":7,"token":"` + executorJWT + `"}`, replyHeaders: map[string]string{"Cache-Control": "no-store"}}.run(t, g, token)
		assertNoCredential(t, g.broker.requests(), executorJWT)
		assertNotRetained(t, g, token, "/ui/v1/teams/3/executors/7", "executor-registry.ui.get.pub", executorJWT)
		assertLogClean(t, sink, "executor-registry.ui.create.pub", executorJWT, token)
	})
}
