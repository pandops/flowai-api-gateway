//go:build integration

package test

// One PostgreSQL container per package run backs the Gateway integration
// cases:
// TestMain owns it, every case gets its own randomly named database that is
// dropped and verified absent in t.Cleanup.

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/pandops/flowai-api-gateway/internal/migrations"
)

const (
	pgImage        = "docker.io/library/postgres@sha256:a85daf0dbd5e79586e850e3fe4b21b796799828ad015ce2166aeb98cc24da61c"
	pgLabel        = "flowai.api-gateway.test"
	pgReadyTimeout = 60 * time.Second
)

type pgFixture struct {
	binary, container, password string
	port                        int
}

var pgShared *pgFixture

func TestMain(m *testing.M) {
	probe, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	binary, err := pgContainerBinary(probe)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "container runtime detection failed: %v\n", err)
		os.Exit(1)
	}
	start, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	fixture, err := pgStart(start, binary)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "postgres fixture start failed: %v\n", err)
		os.Exit(1)
	}
	pgShared = fixture
	code := m.Run()
	stop, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := pgRun(stop, fixture.binary, "rm", "--force", fixture.container); err != nil {
		fmt.Fprintf(os.Stderr, "container teardown: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	cancel()
	os.Exit(code)
}

func pgContainerBinary(ctx context.Context) (string, error) {
	for _, candidate := range []string{"docker", "podman"} {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		info, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = exec.CommandContext(info, path, "info").Run()
		cancel()
		if err == nil {
			return path, nil
		}
	}
	return "", errors.New("no usable docker or podman CLI found")
}

func pgStart(ctx context.Context, binary string) (*pgFixture, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	f := &pgFixture{binary: binary, container: "flowai-agw-" + pgToken(12), password: pgToken(24), port: port}
	if ledger := os.Getenv("FLOWAI_RESOURCE_LEDGER"); ledger != "" {
		existing, err := exec.CommandContext(ctx, binary, "ps", "-aq", "--filter", "name=^"+f.container+"$").Output()
		if err != nil || strings.TrimSpace(string(existing)) != "" {
			return nil, errors.New("PostgreSQL fixture container identity is not fresh")
		}
		record, _ := json.Marshal(map[string]string{"kind": "containers", "selector": "name=^" + f.container + "$"})
		file, err := os.OpenFile(ledger, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		_, writeErr := file.Write(append(record, '\n'))
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return nil, err
		}
	}
	if err := pgRun(ctx, binary, "run", "--detach", "--rm", "--name", f.container, "--label", pgLabel,
		"--publish", fmt.Sprintf("127.0.0.1:%d:5432", port), "--tmpfs", "/var/lib/postgresql/data:rw",
		"--env", "POSTGRES_USER=flowai", "--env", "POSTGRES_PASSWORD="+f.password, "--env", "POSTGRES_DB=postgres", pgImage); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(pgReadyTimeout)
	for time.Now().Before(deadline) {
		db, err := sql.Open("pgx", f.dsn("flowai", f.password, "postgres"))
		if err == nil {
			ping, cancel := context.WithTimeout(ctx, 2*time.Second)
			err = db.PingContext(ping)
			cancel()
			_ = db.Close()
			if err == nil {
				return f, nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	stop, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return nil, errors.Join(errors.New("postgres not ready"), pgRun(stop, binary, "rm", "--force", f.container))
}

func pgRun(ctx context.Context, binary string, argv ...string) error {
	output, err := exec.CommandContext(ctx, binary, argv...).CombinedOutput()
	if err != nil {
		text := string(output)
		if pgShared != nil {
			text = strings.ReplaceAll(text, pgShared.password, "<redacted>")
		}
		return fmt.Errorf("%s %s: %w: %s", binary, argv[0], err, text)
	}
	return nil
}

func pgToken(size int) string {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", value)
}

func (f *pgFixture) dsn(user, password, database string) string {
	return (&url.URL{Scheme: "postgres", User: url.UserPassword(user, password), Host: fmt.Sprintf("127.0.0.1:%d", f.port), Path: "/" + database, RawQuery: "sslmode=disable"}).String()
}

// pgDatabase creates one owned database, returns its superuser DSN and drops
// it (verifying absence) when the case ends.
func pgDatabase(t *testing.T) (string, string) {
	t.Helper()
	if pgShared == nil {
		t.Fatal("postgres fixture unavailable")
	}
	name := "agw_" + pgToken(12)
	admin, err := sql.Open("pgx", pgShared.dsn("flowai", pgShared.password, "postgres"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := admin.ExecContext(ctx, `CREATE DATABASE "`+name+`"`); err != nil {
		_ = admin.Close()
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		defer admin.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1 AND pid<>pg_backend_pid()`, name); err != nil {
			t.Errorf("terminate %s sessions: %v", name, err)
		}
		if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS "`+name+`"`); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
		var exists bool
		if err := admin.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil || exists {
			t.Errorf("owned database %s remains (err %v)", name, err)
		}
	})
	return pgShared.dsn("flowai", pgShared.password, name), name
}

func pgOpen(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// pgMigrated returns a superuser connection to a fresh migrated database.
func pgMigrated(t *testing.T) *sql.DB {
	t.Helper()
	dsn, _ := pgDatabase(t)
	db := pgOpen(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := migrations.ApplyUp(ctx, db); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return db
}

func pgRows(t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		result = append(result, value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}
