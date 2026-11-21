//go:build integration

package test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/migrations"
)

// api-gateway: Gateway isolates its persistence from every other service —
// on real PostgreSQL with the deployment's role shape: the role and its
// schema api_gateway are pre-created, the role has no CREATE on the database
// and no right on schema public, so the Gateway must migrate inside its own
// schema without trying to create it.
func TestV0048GatewayIsolatesItsPersistenceOnPostgreSQL(t *testing.T) {
	t.Run("Services share one PostgreSQL instance", func(t *testing.T) {
		role, password := "api_gateway_"+pgToken(4), pgToken(12)
		cluster := pgOpen(t, pgShared.dsn("flowai", pgShared.password, "postgres"))
		superDSN, database := pgDatabase(t)
		super := pgOpen(t, superDSN)
		t.Cleanup(func() {
			// The role owns api_gateway in the test database, which is
			// dropped later; release its objects and grants first.
			if _, err := super.Exec(`DROP OWNED BY ` + role); err != nil {
				t.Errorf("drop objects of %s: %v", role, err)
			}
			if _, err := cluster.Exec(`DROP ROLE IF EXISTS ` + role); err != nil {
				t.Errorf("drop role %s: %v", role, err)
			}
		})
		for _, statement := range []string{
			fmt.Sprintf(`CREATE ROLE %s LOGIN PASSWORD '%s'`, role, password),
			fmt.Sprintf(`REVOKE ALL ON DATABASE "%s" FROM PUBLIC`, database),
			fmt.Sprintf(`GRANT CONNECT ON DATABASE "%s" TO %s`, database, role),
			`REVOKE ALL ON SCHEMA public FROM PUBLIC`,
			fmt.Sprintf(`CREATE SCHEMA api_gateway AUTHORIZATION %s`, role),
			// Another service's schema on the same instance.
			`CREATE SCHEMA task_manager_schema`,
			`CREATE TABLE task_manager_schema.tasks (task_id bigint PRIMARY KEY)`,
		} {
			if _, err := super.Exec(statement); err != nil {
				t.Fatalf("deployment setup %q: %v", statement, err)
			}
		}
		gateway, err := sql.Open("pgx", pgShared.dsn(role, password, database))
		if err != nil {
			t.Fatal(err)
		}
		defer gateway.Close()
		ctx := context.Background()
		for attempt := 1; attempt <= 2; attempt++ {
			if err := migrations.ApplyUp(ctx, gateway); err != nil {
				t.Fatalf("migration %d with the deployment role: %v", attempt, err)
			}
		}
		expectRows(t, super, `SELECT DISTINCT schemaname FROM pg_tables WHERE tableowner = '`+role+`' ORDER BY 1`, "api_gateway")
		if count := countRows(t, super, `SELECT count(*) FROM pg_tables WHERE schemaname = 'api_gateway' AND tablename = 'goose_db_version'`); count != 1 {
			t.Fatalf("migration history is not in api_gateway: %d", count)
		}
		if _, err := gateway.Exec(`SELECT task_id FROM task_manager_schema.tasks`); err == nil {
			t.Fatal("the Gateway role reads another service's schema")
		}
	})
}
