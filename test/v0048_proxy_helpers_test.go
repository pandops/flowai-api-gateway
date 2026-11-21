package test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/broker"
	"github.com/pandops/flowai-api-gateway/internal/httpapi"
)

// forged are browser headers that must never reach an owner or replace the
// verified context.
var forged = map[string]string{
	"X-FlowAI-Team-ID":     "4",
	"X-FlowAI-Operator-ID": "99",
	"X-FlowAI-Team-Name":   "Forged Beta",
	"X-FlowAI-Request-ID":  "1",
	"team":                 "4",
	"operator_id":          "99",
	"X-FlowAI-Source-Key":  "fsk_forged_source_key",
	"Cookie":               "flowai_session=" + gwSessionID,
}

// proxyCase is one owner exchange: the Gateway must deliver exactly one
// request on subject with the verified context and return the owner's reply.
type proxyCase struct {
	method, path, body, ifMatch string
	subject                     string
	status                      int
	reply                       string
	replyHeaders                map[string]string
}

// run sends c through g with token and the forged headers, and checks the
// owner's reply reaches the browser unchanged (ETag, Cache-Control, Location,
// Retry-After kept, everything else dropped) and the request carries only the
// verified context, the If-Match precondition and the unchanged body.
func (c proxyCase) run(t *testing.T, g *gw, token string) broker.Request {
	t.Helper()
	g.broker.on(c.subject, func(broker.Request) broker.Reply {
		headers := map[string]string{"X-Owner-Internal": "dropped"}
		for name, value := range c.replyHeaders {
			headers[name] = value
		}
		return reply(c.status, c.reply, headers)
	})
	extra := map[string]string{}
	for name, value := range forged {
		extra[name] = value
	}
	if c.ifMatch != "" {
		extra["If-Match"] = c.ifMatch
	}
	before := len(g.broker.requests())
	response, body := g.as(token, c.method, c.path, extra, c.body)
	if response.StatusCode != c.status || body != c.reply {
		t.Fatalf("%s %s = %d %s, want %d %s", c.method, c.path, response.StatusCode, body, c.status, c.reply)
	}
	for name, value := range c.replyHeaders {
		if response.Header.Get(name) != value {
			t.Fatalf("%s %s reply %s = %q, want %q", c.method, c.path, name, response.Header.Get(name), value)
		}
	}
	if response.Header.Get("X-Owner-Internal") != "" {
		t.Fatalf("%s %s copied an owner header outside the allowlist", c.method, c.path)
	}
	requests := g.broker.requests()[before:]
	if len(requests) != 1 || requests[0].Subject != c.subject {
		subjects := []string{}
		for _, request := range requests {
			subjects = append(subjects, request.Subject)
		}
		t.Fatalf("%s %s subjects = %v, want exactly one %s (no retry, no other service)", c.method, c.path, subjects, c.subject)
	}
	request := requests[0]
	assertContext(t, request, gwTeam, gwOperator, "Alpha-Team")
	if c.ifMatch != request.Header["If-Match"] {
		t.Fatalf("%s If-Match = %q, want %q", c.subject, request.Header["If-Match"], c.ifMatch)
	}
	_, forwarded, hasBody := decodeUI(t, request)
	if c.body == "" {
		if hasBody {
			t.Fatalf("%s carries a body the browser did not send: %s", c.subject, forwarded)
		}
	} else if !jsonEqual(t, string(forwarded), c.body) {
		t.Fatalf("%s body = %s, want %s unchanged", c.subject, forwarded, c.body)
	}
	assertNoCredential(t, []broker.Request{request}, token, "Bearer", "fsk_forged_source_key", "Forged Beta", "flowai_session")
	return request
}

func jsonEqual(t *testing.T, left, right string) bool {
	t.Helper()
	var a, b any
	if json.Unmarshal([]byte(left), &a) != nil || json.Unmarshal([]byte(right), &b) != nil {
		return false
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// assertNoCaching checks that a credential seen in an owner reply is not
// retained: a second identical read reaches the owner again and the Gateway
// holds no copy anywhere observable.
func assertNotRetained(t *testing.T, g *gw, token, path, subject, secret string) {
	t.Helper()
	g.broker.on(subject, func(broker.Request) broker.Reply { return reply(200, `{"ok":true}`, nil) })
	before := len(g.broker.requests())
	_, body := g.as(token, http.MethodGet, path, nil, "")
	if strings.Contains(body, secret) || len(g.broker.requests()) != before+1 {
		t.Fatalf("Gateway served %s from a cache: %s", path, body)
	}
}

// withLogSink sends the Gateway's request log to sink.
func withLogSink(sink *syncBuffer) func(*httpapi.Dependencies) {
	return func(d *httpapi.Dependencies) {
		d.Logger = slog.New(slog.NewJSONHandler(sink, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
}

// assertLogClean checks that the Gateway logged the exchange on subject (so
// the logger is wired) and that no secret appears in any record.
func assertLogClean(t *testing.T, sink *syncBuffer, subject string, secrets ...string) {
	t.Helper()
	text := sink.String()
	if !strings.Contains(text, subject) {
		t.Fatalf("the Gateway logged no record of %s: %q", subject, text)
	}
	for _, secret := range secrets {
		if strings.Contains(text, secret) {
			t.Fatalf("the Gateway log carries a credential %q", secret)
		}
	}
}
