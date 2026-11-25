package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// v0041ClearEnvironment blanks every API Gateway variable for one test.
func v0041ClearEnvironment(t *testing.T) {
	t.Helper()
	for _, entry := range os.Environ() {
		if name, _, _ := strings.Cut(entry, "="); strings.HasPrefix(name, "API_GATEWAY_") {
			t.Setenv(name, "")
		}
	}
}

// v0007.34: partial or symmetric administrator trust blocks startup, and the
// refusal carries no credential material.
func TestV0007_34_InvalidAdministratorTrustBlocksStartup(t *testing.T) {
	const canary = "trust-canary-secret"
	for _, tt := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"partial", map[string]string{"API_GATEWAY_ADMIN_ISSUER": "https://issuer.invalid"}, "admin issuer, audience, JWKS URL, role pointer, and NATS URL must be configured together"},
		{"symmetric", map[string]string{
			"API_GATEWAY_ADMIN_ISSUER":             "https://issuer.invalid",
			"API_GATEWAY_ADMIN_AUDIENCE":           "admin",
			"API_GATEWAY_ADMIN_JWKS_URL":           "https://issuer.invalid/jwks",
			"API_GATEWAY_ADMIN_ROLE_CLAIM_POINTER": "/roles",
			"API_GATEWAY_NATS_URL":                 "nats://nats.invalid:4222",
			"API_GATEWAY_ADMIN_ALGORITHMS":         "HS256",
		}, "API_GATEWAY_ADMIN_ALGORITHMS must contain only"},
		{"mixed symmetric", map[string]string{
			"API_GATEWAY_ADMIN_ISSUER":             "https://issuer.invalid",
			"API_GATEWAY_ADMIN_AUDIENCE":           "admin",
			"API_GATEWAY_ADMIN_JWKS_URL":           "https://issuer.invalid/jwks",
			"API_GATEWAY_ADMIN_ROLE_CLAIM_POINTER": "/roles",
			"API_GATEWAY_NATS_URL":                 "nats://nats.invalid:4222",
			"API_GATEWAY_ADMIN_ALGORITHMS":         "RS256,HS256",
		}, "API_GATEWAY_ADMIN_ALGORITHMS must contain only"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v0041ClearEnvironment(t)
			t.Setenv("API_GATEWAY_POSTGRES_URL", "postgres://gateway:password="+canary+"@db.invalid/gateway?sslmode=verify-full&sslrootcert=/run/flowai/stand-ca/ca.pem")
			for name, value := range tt.env {
				t.Setenv(name, value)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want %q", err, tt.want)
			}
			for _, leak := range []string{"token=", "password=", canary} {
				if strings.Contains(err.Error(), leak) {
					t.Fatalf("Load() error leaks %q: %v", leak, err)
				}
			}
		})
	}
	t.Run("complete asymmetric", func(t *testing.T) {
		v0041ClearEnvironment(t)
		for name, value := range map[string]string{
			"API_GATEWAY_ADMIN_ISSUER":             "https://issuer.invalid",
			"API_GATEWAY_ADMIN_AUDIENCE":           "admin",
			"API_GATEWAY_ADMIN_JWKS_URL":           "https://issuer.invalid/jwks",
			"API_GATEWAY_ADMIN_ROLE_CLAIM_POINTER": "/roles",
			"API_GATEWAY_NATS_URL":                 "nats://nats.invalid:4222",
			"API_GATEWAY_ADMIN_ALGORITHMS":         "RS256,RS512",
		} {
			t.Setenv(name, value)
		}
		cfg, err := Load()
		if err != nil || !reflect.DeepEqual(cfg.AdminAlgorithms, []string{"RS256", "RS512"}) {
			t.Fatalf("Load() = %v, %v", cfg.AdminAlgorithms, err)
		}
	})
}

// v0007.16: additional scopes are split on commas and trimmed in order; the
// OIDC flow then prepends openid and removes duplicates.
func TestV0007_16_AdditionalScopesAreParsedInOrder(t *testing.T) {
	v0041ClearEnvironment(t)
	t.Setenv("API_GATEWAY_OIDC_ADDITIONAL_SCOPES", " membership.read,profile,membership.read ")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"membership.read", "profile", "membership.read"}; !reflect.DeepEqual(cfg.OIDCAdditionalScopes, want) {
		t.Fatalf("scopes = %q, want %q", cfg.OIDCAdditionalScopes, want)
	}
}

// v0007.21: migrations run with the separate migration URL while the runtime
// keeps its own URL; without one, both use the runtime URL.
func TestV0007_21_MigrationURLIsSeparateFromRuntimeURL(t *testing.T) {
	v0041ClearEnvironment(t)
	t.Setenv("API_GATEWAY_POSTGRES_URL", "postgres://api_gateway_runtime@db.invalid/postgres?sslmode=verify-full&sslrootcert=/run/flowai/stand-ca/ca.pem")
	t.Setenv("API_GATEWAY_MIGRATION_POSTGRES_URL", "postgres://api_gateway_migrator@db.invalid/postgres?sslmode=verify-full&sslrootcert=/run/flowai/stand-ca/ca.pem")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PostgresURL != "postgres://api_gateway_runtime@db.invalid/postgres?sslmode=verify-full&sslrootcert=/run/flowai/stand-ca/ca.pem" || cfg.MigrationPostgresURL != "postgres://api_gateway_migrator@db.invalid/postgres?sslmode=verify-full&sslrootcert=/run/flowai/stand-ca/ca.pem" {
		t.Fatalf("runtime %q migration %q", cfg.PostgresURL, cfg.MigrationPostgresURL)
	}
	t.Setenv("API_GATEWAY_MIGRATION_POSTGRES_URL", "")
	cfg, err = Load()
	if err != nil || cfg.MigrationPostgresURL != cfg.PostgresURL {
		t.Fatalf("default migration URL %q (%v)", cfg.MigrationPostgresURL, err)
	}
}

// v0048: the broker and journal edges are configured from the environment
// with the deployment's names; rpc_timeout defaults to 5s and must be a
// positive duration; the inbox prefix defaults to _INBOX.api-gateway; the
// journal service bearer never appears in a config error.
func TestV0048_BrokerAndJournalSettings(t *testing.T) {
	v0041ClearEnvironment(t)
	const canary = "journal-bearer-canary"
	t.Setenv("API_GATEWAY_NATS_URL", "tls://nats:4222")
	t.Setenv("API_GATEWAY_NATS_CA_FILE", "/run/flowai/stand-ca/ca.pem")
	t.Setenv("API_GATEWAY_NATS_CREDENTIALS_FILE", "/run/flowai/nats/user.creds")
	t.Setenv("API_GATEWAY_JOURNAL_URL", "http://journal:8080")
	t.Setenv("API_GATEWAY_JOURNAL_TOKEN", canary)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NATSURL != "tls://nats:4222" || cfg.NATSCAFile != "/run/flowai/stand-ca/ca.pem" || cfg.NATSCredentialsFile != "/run/flowai/nats/user.creds" || cfg.NATSInboxPrefix != "_INBOX.api-gateway" || cfg.JournalURL != "http://journal:8080" || cfg.JournalToken != canary || cfg.RPCTimeout.String() != "5s" {
		t.Fatalf("config = %q %q %q %q %q timeout %s", cfg.NATSURL, cfg.NATSCAFile, cfg.NATSCredentialsFile, cfg.NATSInboxPrefix, cfg.JournalURL, cfg.RPCTimeout)
	}
	t.Setenv("API_GATEWAY_NATS_INBOX_PREFIX", "_INBOX.api-gateway-2")
	t.Setenv("API_GATEWAY_RPC_TIMEOUT", "750ms")
	if cfg, err := Load(); err != nil || cfg.RPCTimeout.String() != "750ms" || cfg.NATSInboxPrefix != "_INBOX.api-gateway-2" {
		t.Fatalf("overrides = %v %q %v", cfg.RPCTimeout, cfg.NATSInboxPrefix, err)
	}
	for _, bad := range []string{"0s", "-1s", "soon"} {
		t.Setenv("API_GATEWAY_RPC_TIMEOUT", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "API_GATEWAY_RPC_TIMEOUT") || strings.Contains(err.Error(), canary) {
			t.Fatalf("rpc timeout %q: %v", bad, err)
		}
	}
	t.Setenv("API_GATEWAY_RPC_TIMEOUT", "")
	t.Setenv("API_GATEWAY_JOURNAL_TOKEN", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "API_GATEWAY_JOURNAL_URL and API_GATEWAY_JOURNAL_TOKEN must be configured together") {
		t.Fatalf("journal URL without token = %v", err)
	}
	t.Setenv("API_GATEWAY_JOURNAL_URL", "")
	t.Setenv("API_GATEWAY_JOURNAL_TOKEN", canary)
	if _, err := Load(); err == nil || strings.Contains(err.Error(), canary) {
		t.Fatalf("journal token without URL = %v", err)
	}
}

// service-platform "Startup lacks production trust" (api-gateway form): a
// PostgreSQL URL without verified TLS fails startup, and the error carries no
// password.
func TestV0048_StartupLacksProductionTrust(t *testing.T) {
	const canary = "pg-password-canary"
	const trusted = "postgres://api_gateway:" + canary + "@postgres:5432/flowai?sslmode=verify-full&sslrootcert=/run/flowai/stand-ca/ca.pem"
	for name, env := range map[string]map[string]string{
		"TLS disabled":        {"API_GATEWAY_POSTGRES_URL": "postgres://api_gateway:" + canary + "@postgres:5432/flowai?sslmode=disable"},
		"TLS unverified":      {"API_GATEWAY_POSTGRES_URL": "postgres://api_gateway:" + canary + "@postgres:5432/flowai?sslmode=require&sslrootcert=/run/flowai/stand-ca/ca.pem"},
		"no sslmode":          {"API_GATEWAY_POSTGRES_URL": "postgres://api_gateway:" + canary + "@postgres:5432/flowai"},
		"no CA":               {"API_GATEWAY_POSTGRES_URL": "postgres://api_gateway:" + canary + "@postgres:5432/flowai?sslmode=verify-full"},
		"migration plaintext": {"API_GATEWAY_POSTGRES_URL": trusted, "API_GATEWAY_MIGRATION_POSTGRES_URL": "postgres://api_gateway:" + canary + "@postgres:5432/flowai?sslmode=disable"},
	} {
		t.Run(name, func(t *testing.T) {
			v0041ClearEnvironment(t)
			for key, value := range env {
				t.Setenv(key, value)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "sslmode=verify-full") || strings.Contains(err.Error(), canary) {
				t.Fatalf("Load() = %v, want a verified-TLS error without the password", err)
			}
		})
	}
	v0041ClearEnvironment(t)
	t.Setenv("API_GATEWAY_POSTGRES_URL", trusted)
	if cfg, err := Load(); err != nil || cfg.MigrationPostgresURL != trusted {
		t.Fatalf("trusted URL = %v (%q)", err, cfg.MigrationPostgresURL)
	}
}
