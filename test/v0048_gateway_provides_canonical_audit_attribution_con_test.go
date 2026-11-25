package test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/broker"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) records(t *testing.T) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("auth log line %q: %v", line, err)
		}
		records = append(records, record)
	}
	return records
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func assertNoAuditSubject(t *testing.T, requests []broker.Request) {
	t.Helper()
	for _, request := range requests {
		if strings.Contains(request.Subject, ".audit.") {
			t.Fatalf("Gateway published audit subject %s", request.Subject)
		}
	}
}

// api-gateway: Gateway provides canonical audit attribution context.
func TestV0048GatewayProvidesCanonicalAuditAttributionContext(t *testing.T) {
	t.Parallel()

	t.Run("Authenticated operator creates a control request", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		g.broker.on("task-manager.ui.cancel.pub", func(broker.Request) broker.Reply {
			return reply(202, `{"control_id":61,"task_id":1010,"action":"cancel"}`, nil)
		})
		response, body := g.as(token, http.MethodPost, "/ui/v1/teams/3/tasks/1010/controls/cancel", map[string]string{"X-FlowAI-Team-Name": "Forged"}, `{"action":"cancel"}`)
		if response.StatusCode != http.StatusAccepted || body != `{"control_id":61,"task_id":1010,"action":"cancel"}` {
			t.Fatalf("control = %d %s", response.StatusCode, body)
		}
		requests := g.broker.requests()
		if len(requests) != 1 || requests[0].Subject != "task-manager.ui.cancel.pub" {
			t.Fatalf("subjects = %v", g.broker.subjects())
		}
		assertContext(t, requests[0], gwTeam, gwOperator, "Alpha-Team")
		assertNoAuditSubject(t, requests)
	})

	t.Run("Operator logs in", func(t *testing.T) {
		sink := &syncBuffer{}
		g := newOIDCGateway(t, "id_token", teamsArray, slog.New(slog.NewJSONHandler(sink, nil)))
		g.provider.setClaims(map[string]any{"groups": []any{"oidc-team-alpha"}}, nil)
		session, _ := g.login(t)
		status, _ := g.issueFor(t, session, gwTeam)
		if status != http.StatusOK {
			t.Fatalf("token = %d", status)
		}
		records := g.authAudit(t, sink)
		if len(records) == 0 {
			t.Fatal("login wrote no authentication audit")
		}
		assertNoAuditSubject(t, g.broker.requests())
		if strings.Contains(sink.String(), session) {
			t.Fatal("auth audit carries the session identifier")
		}
	})
}

// authAudit returns the auth-audit records of the sink: each carries the
// canonical integer operator_id (except logout) and no credential.
func (g *oidcGateway) authAudit(t *testing.T, sink *syncBuffer) []map[string]any {
	t.Helper()
	var audit []map[string]any
	for _, record := range sink.records(t) {
		if record["msg"] != "auth_audit" {
			continue
		}
		// A logout knows only its session; every other record names the operator.
		if id, ok := record["operator_id"]; (ok && id != float64(42)) || (!ok && record["event"] != "logout") {
			t.Fatalf("auth audit record %v lacks canonical operator_id 42", record)
		}
		audit = append(audit, record)
	}
	text := sink.String()
	for _, secret := range []string{"access_token", "refresh_token", "Bearer ", "eyJ"} {
		if strings.Contains(text, secret) {
			t.Fatalf("auth log carries %q", secret)
		}
	}
	return audit
}
