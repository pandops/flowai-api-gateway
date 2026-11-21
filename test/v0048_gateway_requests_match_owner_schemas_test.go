package test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/teamregistry"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ownerSchema loads an owner's request or reply schema by its rule-17 name
// svc/<owner>/schemas/<class>.<operation>.<kind>.schema.json and compiles
// it, optionally at a JSON pointer fragment.
func ownerSchema(t *testing.T, owner, class, operation, kind, fragment string) *jsonschema.Schema {
	t.Helper()
	fixture := os.Getenv("FLOWAI_CONTRACT_FIXTURE_DIR")
	if !filepath.IsAbs(fixture) {
		t.Fatal("FLOWAI_CONTRACT_FIXTURE_DIR must point to the absolute path of the staged publisher schemas")
	}
	root := filepath.Join(fixture, "svc", owner, "schemas")
	path := filepath.Join(root, class+"."+operation+"."+kind+".schema.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("%s publishes no %s schema for %s.%s: %v", owner, kind, class, operation, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.UseLoader(jsonschema.SchemeURLLoader{"file": jsonschema.FileLoader{}, "https": ownerSchemaLoader{root: filepath.Dir(filepath.Dir(root))}})
	schema, err := compiler.Compile(path + fragment)
	if err != nil {
		t.Fatalf("compile %s%s: %v", path, fragment, err)
	}
	return schema
}

// ownerSchemaLoader resolves the owners' schema $id URLs
// https://flowai.local/schemas/<owner>/<file> to svc/<owner>/schemas/<file>,
// so a $ref between an owner's files loads the owner's own copy.
type ownerSchemaLoader struct{ root string }

func (l ownerSchemaLoader) Load(url string) (any, error) {
	const prefix = "https://flowai.local/schemas/"
	if !strings.HasPrefix(url, prefix) {
		return nil, fmt.Errorf("schema %s is outside the FlowAI owners", url)
	}
	owner, file, ok := strings.Cut(strings.TrimPrefix(url, prefix), "/")
	if !ok || strings.Contains(file, "..") {
		return nil, fmt.Errorf("schema URL %s names no owner file", url)
	}
	data, err := os.Open(filepath.Join(l.root, owner, "schemas", filepath.FromSlash(file)))
	if err != nil {
		return nil, err
	}
	defer data.Close()
	return jsonschema.UnmarshalJSON(data)
}

func validateJSON(t *testing.T, schema *jsonschema.Schema, data []byte, what string) {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("%s is not JSON: %v", what, err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("%s does not match the owner's schema: %v\n%s", what, err, data)
	}
}

// bodyless are the POST operations whose owners accept no request body; the
// browser sends none, so the contract check sends none either.
var bodyless = map[string]bool{
	"source-controller.ui.sources-rotate-key.pub":      true,
	"source-controller.ui.sources-disable.pub":         true,
	"source-controller.ui.sources-unblock-polling.pub": true,
	"model-registry.ui.model-archive.pub":              true,
	"model-registry.ui.model-unarchive.pub":            true,
	"executor-registry.ui.reissue.pub":                 true,
}

// Rule 9 contract: every request the Gateway publishes matches its owner's
// request schema, and the replies the Gateway decodes match the owner's reply
// schema. The browser body is forwarded verbatim, so its shape is the
// browser's contract; the Gateway owns the envelope, its params and whether
// a body is present.
func TestV0048GatewayRequestsMatchOwnerSchemas(t *testing.T) {
	t.Parallel()

	t.Run("Every ui request matches the owner's request schema", func(t *testing.T) {
		g := newGateway(t, nil)
		token := g.token(gwTeam)
		for _, call := range uiRouteTable {
			subject := strings.TrimSuffix(call.subject, ".pub")
			owner, operation, _ := strings.Cut(subject, ".ui.")
			body := ""
			if call.method != http.MethodGet && call.method != http.MethodDelete && !bodyless[call.subject] {
				body = `{}`
			}
			before := len(g.broker.requests())
			g.as(token, call.method, call.path, nil, body)
			requests := g.broker.requests()[before:]
			if len(requests) != 1 {
				t.Fatalf("%s %s sent %d requests", call.method, call.path, len(requests))
			}
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(requests[0].Body, &envelope); err != nil {
				t.Fatalf("%s envelope: %v", call.subject, err)
			}
			validateJSON(t, ownerSchema(t, owner, "ui", operation, "request", "#/properties/params"), envelope["params"], call.subject+" params")
			if _, hasBody := envelope["body"]; hasBody != (body != "") {
				t.Fatalf("%s body present = %v, want %v", call.subject, hasBody, body != "")
			}
		}
	})

	t.Run("Team point read matches team-registry's schemas", func(t *testing.T) {
		var fake *fakeBroker
		g := newGateway(t, withTeamRegistry(t, &fake))
		g.token(gwTeam)
		var seen bool
		for _, request := range fake.requests() {
			if request.Subject != teamregistry.Subject {
				continue
			}
			seen = true
			validateJSON(t, ownerSchema(t, "team-registry", "service", "get", "request", ""), request.Body, "team point read")
			reply := teamRegistryResponder(gwTeamNames, nil)(request)
			validateJSON(t, ownerSchema(t, "team-registry", "service", "get", "reply", ""), reply.Body, "team-registry fake reply")
		}
		if !seen {
			t.Fatal("token issue made no team point read")
		}
	})
}
