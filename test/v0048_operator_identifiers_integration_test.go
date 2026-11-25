//go:build integration

package test

import (
	"context"
	"sync"
	"testing"

	"github.com/pandops/flowai-api-gateway/internal/store"
)

// auth: First login assigns an operator identifier and later logins reuse it
// — on real PostgreSQL: one global sequence in api_gateway, one stored
// integer per (iss, sub) even under concurrent first logins, and integer
// identifier columns throughout the Gateway schema.
func TestV0048OperatorIdentifiersOnPostgreSQL(t *testing.T) {
	t.Parallel()

	t.Run("First login assigns an operator identifier and later logins reuse it", func(t *testing.T) {
		db := pgMigrated(t)
		operators, err := store.NewOperators(db)
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		const issuer = "https://oidc.flowai.invalid"
		results := make([]int64, 16)
		errs := make([]error, 16)
		var wait sync.WaitGroup
		for index := range results {
			wait.Add(1)
			go func() {
				defer wait.Done()
				results[index], errs[index] = operators.OperatorID(ctx, issuer, "operator-subject-aadmin")
			}()
		}
		wait.Wait()
		for index, err := range errs {
			if err != nil || results[index] <= 0 || results[index] != results[0] {
				t.Fatalf("concurrent first logins = %v / %v", results, errs)
			}
		}
		again, err := operators.OperatorID(ctx, issuer, "operator-subject-aadmin")
		if err != nil || again != results[0] {
			t.Fatalf("later login = %d %v, want %d", again, err, results[0])
		}
		other, err := operators.OperatorID(ctx, issuer, "operator-subject-hopr")
		if err != nil || other <= 0 || other == results[0] {
			t.Fatalf("another sub = %d %v", other, err)
		}
		elsewhere, err := operators.OperatorID(ctx, "https://other-issuer.invalid", "operator-subject-aadmin")
		if err != nil || elsewhere == results[0] || elsewhere == other {
			t.Fatalf("same sub at another issuer = %d %v", elsewhere, err)
		}
		expectRows(t, db, `SELECT issuer || '|' || subject FROM api_gateway.operators ORDER BY operator_id`,
			issuer+"|operator-subject-aadmin", issuer+"|operator-subject-hopr", "https://other-issuer.invalid|operator-subject-aadmin")
		if count := countRows(t, db, `SELECT count(*) FROM pg_sequences WHERE schemaname = 'api_gateway' AND sequencename = 'operator_id_seq'`); count != 1 {
			t.Fatalf("operator sequence count = %d", count)
		}
	})

	t.Run("Gateway identifier columns are 64-bit integers", func(t *testing.T) {
		db := pgMigrated(t)
		rows := pgRows(t, db, `SELECT table_name || '.' || column_name || ':' || data_type FROM information_schema.columns
			WHERE table_schema = 'api_gateway' AND column_name IN ('operator_id','team_id','request_id','audit_id') ORDER BY 1`)
		if len(rows) == 0 {
			t.Fatal("no identifier columns found")
		}
		for _, row := range rows {
			if want := ":bigint"; len(row) < len(want) || row[len(row)-len(want):] != want {
				t.Fatalf("identifier column %s is not bigint (all: %v)", row, rows)
			}
		}
		// Every session row refers to an assigned operator.
		if count := countRows(t, db, `SELECT count(*) FROM information_schema.referential_constraints r
			JOIN information_schema.key_column_usage k ON k.constraint_name = r.constraint_name AND k.constraint_schema = r.constraint_schema
			JOIN information_schema.constraint_column_usage u ON u.constraint_name = r.constraint_name AND u.constraint_schema = r.constraint_schema
			WHERE r.constraint_schema = 'api_gateway' AND k.table_name = 'oidc_sessions' AND k.column_name = 'operator_id' AND u.table_name = 'operators'`); count != 1 {
			t.Fatalf("oidc_sessions.operator_id -> operators foreign keys = %d", count)
		}
	})
}
