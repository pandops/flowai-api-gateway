// Package uiroutes is API Gateway's explicit /ui/v1 route table: each route
// names the owning service and the `ui` operation token of its capability.
package uiroutes

import (
	"net/url"
	"strings"
)

// Prefix is the team-scoped Web UI REST surface the table serves.
const Prefix = "/ui/v1/"

// Route maps one method and path pattern to <Owner>.ui.<Operation>.pub.
// Pattern segments in braces are path parameters, named as in the REST API.
type Route struct {
	Method    string
	Pattern   string
	Owner     string
	Operation string
}

// Subject is the request subject API Gateway publishes for the route.
func (r Route) Subject() string { return r.Owner + ".ui." + r.Operation + ".pub" }

// Table is the complete route table (api-gateway delta spec). Routes absent
// from it are 404 not_found with no broker request.
var Table = []Route{
	// task-manager
	{"GET", "teams/{team_id}/tasks", "task-manager", "list-tasks"},
	{"GET", "teams/{team_id}/tasks/{task_id}", "task-manager", "get-task"},
	{"GET", "teams/{team_id}/tasks/{task_id}/attempts", "task-manager", "list-attempts"},
	{"GET", "teams/{team_id}/executors/{executor_id}/tasks", "task-manager", "list-executor-tasks"},
	{"GET", "teams/{team_id}/archived-tasks", "task-manager", "list-archive"},
	{"GET", "teams/{team_id}/archived-tasks/{task_id}", "task-manager", "get-archived-task"},
	{"POST", "teams/{team_id}/tasks/{task_id}/controls/cancel", "task-manager", "cancel"},
	// journal
	{"GET", "teams/{team_id}/tasks/{task_id}/events", "journal", "task-events"},
	{"GET", "teams/{team_id}/tasks/{task_id}/logs", "journal", "task-logs"},
	{"GET", "teams/{team_id}/tasks/{task_id}/controls/{control_id}/events", "journal", "control-events"},
	{"GET", "teams/{team_id}/executors/{executor_id}/events", "journal", "executor-events"},
	{"GET", "teams/{team_id}/executor-states", "journal", "executor-states"},
	{"GET", "teams/{team_id}/dashboard", "journal", "dashboard"},
	// audit
	{"GET", "teams/{team_id}/audit", "audit", "list"},
	{"GET", "teams/{team_id}/audit/{audit_id}", "audit", "get"},
	// source-controller
	{"GET", "sources", "source-controller", "sources-list"},
	{"POST", "sources", "source-controller", "sources-create"},
	{"GET", "sources/{id}", "source-controller", "sources-get"},
	{"GET", "sources/{id}/settings", "source-controller", "sources-settings-get"},
	{"PUT", "sources/{id}/settings", "source-controller", "sources-settings-put"},
	{"POST", "sources/{id}/rotate-key", "source-controller", "sources-rotate-key"},
	{"POST", "sources/{id}/disable", "source-controller", "sources-disable"},
	{"POST", "sources/{id}/unblock-polling", "source-controller", "sources-unblock-polling"},
	{"PATCH", "sources/{id}/implementation", "source-controller", "sources-update-implementation"},
	// flow-registry
	{"GET", "flows", "flow-registry", "flows-list"},
	{"POST", "flows", "flow-registry", "flow-create"},
	{"POST", "flows/preview", "flow-registry", "flow-preview"},
	{"GET", "flows/{flow_id}", "flow-registry", "flow-get"},
	{"PUT", "flows/{flow_id}", "flow-registry", "flow-replace"},
	{"GET", "flow-llm-settings", "flow-registry", "llm-settings-list"},
	{"GET", "flow-llm-settings/{flow_id}", "flow-registry", "llm-settings-get"},
	{"PUT", "flow-llm-settings/{flow_id}", "flow-registry", "llm-settings-replace"},
	// model-registry
	{"GET", "models", "model-registry", "models-list"},
	{"POST", "models", "model-registry", "model-create"},
	{"GET", "models/{name}", "model-registry", "model-get"},
	{"PUT", "models/{name}", "model-registry", "model-update"},
	{"POST", "models/{name}/archive", "model-registry", "model-archive"},
	{"POST", "models/{name}/unarchive", "model-registry", "model-unarchive"},
	// env-registry
	{"GET", "teams/{team_id}/tasks/{task_id}/launch-parameters", "env-registry", "task-parameters"},
	{"GET", "teams/{team_id}/launch-parameters", "env-registry", "list"},
	{"POST", "teams/{team_id}/launch-parameters", "env-registry", "create"},
	{"GET", "teams/{team_id}/launch-parameters/{environment_id}", "env-registry", "get"},
	{"PUT", "teams/{team_id}/launch-parameters/{environment_id}", "env-registry", "replace"},
	{"DELETE", "teams/{team_id}/launch-parameters/{environment_id}", "env-registry", "delete"},
	{"GET", "teams/{team_id}/launch-parameters/{environment_id}/revisions", "env-registry", "list-revisions"},
	{"POST", "teams/{team_id}/launch-parameters/{environment_id}/secrets", "env-registry", "create-secret"},
	{"PUT", "teams/{team_id}/launch-parameters/{environment_id}/secrets/{secret_id}", "env-registry", "replace-secret"},
	{"DELETE", "teams/{team_id}/launch-parameters/{environment_id}/secrets/{secret_id}", "env-registry", "revoke-secret"},
	{"GET", "teams/{team_id}/launch-parameters/{environment_id}/secrets/{secret_id}/versions", "env-registry", "list-secret-versions"},
	// executor-registry
	{"GET", "teams/{team_id}/executors", "executor-registry", "list"},
	{"POST", "teams/{team_id}/executors", "executor-registry", "create"},
	{"GET", "teams/{team_id}/executors/{executor_id}", "executor-registry", "get"},
	{"POST", "teams/{team_id}/executors/{executor_id}/token", "executor-registry", "reissue"},
	{"DELETE", "teams/{team_id}/executors/{executor_id}", "executor-registry", "delete"},
	{"GET", "execution-tags", "executor-registry", "list-execution-tags"},
}

// Lookup finds the route for method and the full escaped request path and
// returns its path parameters by REST name, still unvalidated. A literal
// segment wins over a parameter, so POST flows/preview is the preview route.
func Lookup(method, path string) (Route, map[string]string, bool) {
	return lookup(method, path)
}

// Shape finds a route of any method whose pattern matches path, so the
// Gateway can refuse a malformed identifier even when the method is not
// routed. An empty method matches every route.
func Shape(path string) (Route, map[string]string, bool) {
	return lookup("", path)
}

func lookup(method, path string) (Route, map[string]string, bool) {
	if !strings.HasPrefix(path, Prefix) {
		return Route{}, nil, false
	}
	segments := strings.Split(strings.TrimPrefix(path, Prefix), "/")
	var best Route
	var bestParams map[string]string
	bestLiterals := -1
	for _, route := range Table {
		if method != "" && route.Method != method {
			continue
		}
		pattern := strings.Split(route.Pattern, "/")
		if len(pattern) != len(segments) {
			continue
		}
		params := map[string]string{}
		literals := 0
		matched := true
		for index, part := range pattern {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
				value, err := url.PathUnescape(segments[index])
				if err != nil || segments[index] == "" {
					matched = false
					break
				}
				name := part[1 : len(part)-1]
				if name != "name" {
					// Identifiers are checked on their raw text: an escape
					// is never a valid decimal identifier.
					value = segments[index]
				}
				params[name] = value
				continue
			}
			if part != segments[index] {
				matched = false
				break
			}
			literals++
		}
		if matched && literals > bestLiterals {
			best, bestParams, bestLiterals = route, params, literals
		}
	}
	return best, bestParams, bestLiterals >= 0
}
