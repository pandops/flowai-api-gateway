package test

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/migrations"
)

// api-gateway: Gateway isolates its persistence from every other service.
// The migrations the Gateway applies are its whole database surface; they may
// create and change objects only in its own schema api_gateway.
func TestV0048GatewayIsolatesItsPersistenceFromEveryOtherService(t *testing.T) {
	t.Parallel()

	t.Run("Services share one PostgreSQL instance", func(t *testing.T) {
		files, err := fs.Glob(migrations.Files(), "sql/*.sql")
		if err != nil || len(files) < 3 {
			t.Fatalf("migration files = %v (%v)", files, err)
		}
		qualified := regexp.MustCompile(`(?i)\b(?:CREATE|ALTER|DROP|INSERT\s+INTO|DELETE\s+FROM|UPDATE|REFERENCES|TABLE|SEQUENCE|SCHEMA(?:\s+IF\s+NOT\s+EXISTS)?)\s+([a-z_][a-z0-9_]*)\.`)
		forbidden := regexp.MustCompile(`(?i)\b(GRANT|REVOKE|ALTER\s+ROLE|CREATE\s+ROLE|search_path|public\.|state_registry|task_manager_schema|journal_schema|audit_schema|team_registry_schema)\b`)
		for _, name := range files {
			data, err := fs.ReadFile(migrations.Files(), name)
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			for _, match := range qualified.FindAllStringSubmatch(text, -1) {
				if match[1] != "api_gateway" {
					t.Fatalf("%s touches schema %q: %s", name, match[1], match[0])
				}
			}
			if hit := forbidden.FindString(text); hit != "" {
				t.Fatalf("%s reaches outside the Gateway schema: %q", name, hit)
			}
			// The deployment role has no CREATE on the database, so
			// CREATE SCHEMA IF NOT EXISTS fails there even for an existing
			// schema; the schema is created only after a pg_namespace check.
			if strings.Contains(text, "CREATE SCHEMA IF NOT EXISTS") {
				t.Fatalf("%s runs CREATE SCHEMA IF NOT EXISTS", name)
			}
			if strings.Contains(text, "CREATE SCHEMA") && !strings.Contains(text, "pg_namespace") {
				t.Fatalf("%s creates a schema without checking pg_namespace", name)
			}
		}
	})
}
