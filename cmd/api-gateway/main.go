// Command api-gateway runs the Web UI authentication and proxy boundary.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	_ "time/tzdata" // Ship the build's IANA database in the scratch image.

	"github.com/pandops/flowai-api-gateway/internal/adminauth"
	"github.com/pandops/flowai-api-gateway/internal/broker"
	"github.com/pandops/flowai-api-gateway/internal/config"
	"github.com/pandops/flowai-api-gateway/internal/httpapi"
	"github.com/pandops/flowai-api-gateway/internal/jwtverify"
	"github.com/pandops/flowai-api-gateway/internal/migrations"
	"github.com/pandops/flowai-api-gateway/internal/oidc"
	"github.com/pandops/flowai-api-gateway/internal/sessioncrypto"
	"github.com/pandops/flowai-api-gateway/internal/store"
	"github.com/pandops/flowai-api-gateway/internal/teamregistry"
	"github.com/pandops/flowai-api-gateway/internal/workingtoken"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "api-gateway failed:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "api-gateway")
	dependencies := httpapi.Dependencies{
		RPCTimeout:   cfg.RPCTimeout,
		JournalURL:   cfg.JournalURL,
		JournalToken: cfg.JournalToken,
		Logger:       logger,
		AuthAudit:    logger,
	}
	var teams *teamregistry.Client
	if cfg.NATSURL != "" {
		requester, err := broker.Connect(broker.Config{URL: cfg.NATSURL, CAFile: cfg.NATSCAFile, CredentialsFile: cfg.NATSCredentialsFile, InboxPrefix: cfg.NATSInboxPrefix}, logger)
		if err != nil {
			return fmt.Errorf("connect to the message broker: %w", err)
		}
		defer requester.Close()
		dependencies.Broker = requester
		teams, err = teamregistry.New(requester)
		if err != nil {
			return err
		}
		dependencies.Teams = teams
	}
	var database *sql.DB
	if cfg.OIDCIssuer != "" {
		database, err = sql.Open("pgx", cfg.PostgresURL)
		if err != nil {
			return fmt.Errorf("open Gateway database: %w", err)
		}
		defer database.Close()
		migrationDatabase, err := sql.Open("pgx", cfg.MigrationPostgresURL)
		if err != nil {
			return fmt.Errorf("open Gateway migration database: %w", err)
		}
		defer migrationDatabase.Close()
		migrationCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := migrations.ApplyUp(migrationCtx, migrationDatabase); err != nil {
			return fmt.Errorf("migrate Gateway database: %w", err)
		}
		sessions, err := store.NewSessionStore(database)
		if err != nil {
			return err
		}
		cipher, err := sessioncrypto.New(cfg.SessionKey)
		if err != nil {
			return err
		}
		flow, err := oidc.NewFlow(context.Background(), oidc.FlowConfig{Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, RedirectURI: cfg.OIDCRedirectURI, Scopes: cfg.OIDCAdditionalScopes, Timeout: cfg.OIDCEndpointTimeout, StateTTL: 10 * time.Minute, ClockSkew: 30 * time.Second, TokenMaxAge: 10 * time.Minute, ClaimSource: cfg.OIDCTeamClaimSource, TeamClaims: oidc.TeamClaimAdapter{Kind: oidc.AdapterKind(cfg.OIDCTeamClaimAdapter), ClaimPointer: cfg.OIDCTeamClaimPointer, IDField: cfg.OIDCTeamClaimIDField, NameField: cfg.OIDCTeamClaimNameField}})
		if err != nil {
			return fmt.Errorf("initialize OIDC: %w", err)
		}
		dependencies.Login = flow
		dependencies.OIDC = flow
		dependencies.Membership = flow
		dependencies.MembershipMaxAge = cfg.MembershipMaxAge
		dependencies.Sessions = sessions
		operators, err := store.NewOperators(database)
		if err != nil {
			return err
		}
		dependencies.Operators = operators
		mappingStore, err := store.NewMappingStore(database)
		if err != nil {
			return err
		}
		dependencies.Presentation = mappingStore
		preferences, err := store.NewOperatorPreferences(database)
		if err != nil {
			return err
		}
		dependencies.OperatorPreferences = preferences
		dependencies.SessionEncryptor = cipher
		dependencies.SessionTTL = cfg.SessionTTL
		dependencies.WebUIURL = cfg.WebUIURL
		workingTokens, err := workingtoken.New(cfg.WorkingTokenPrivateKeyPEM, cfg.WorkingTokenKeyID, cfg.WorkingTokenIssuer, cfg.WorkingTokenAudience, cfg.WorkingTokenTTL)
		if err != nil {
			return fmt.Errorf("initialize working-token signer: %w", err)
		}
		dependencies.WorkingTokens = workingTokens
		if cfg.AdminIssuer != "" {
			adminVerifier, err := jwtverify.New(jwtverify.Config{Issuer: cfg.AdminIssuer, Audience: cfg.AdminAudience, JWKSURL: cfg.AdminJWKSURL, Algorithms: cfg.AdminAlgorithms, ClockSkew: cfg.AdminClockSkew, TokenMaxAge: cfg.AdminTokenMaxAge, HTTPTimeout: cfg.AdminJWKSTimeout})
			if err != nil {
				return fmt.Errorf("initialize admin JWT trust: %w", err)
			}
			adminAuthenticator, err := adminauth.New(adminVerifier, cfg.AdminRolePointer, "flowai-system-admin")
			if err != nil {
				return fmt.Errorf("initialize admin authorization: %w", err)
			}
			dependencies.ConfiguredIssuer = cfg.OIDCIssuer
			dependencies.AdminAuth = adminAuthenticator
			dependencies.Mappings = mappingStore
		}
	}
	server := &http.Server{Addr: cfg.BindAddress(), Handler: httpapi.NewWithDependencies(dependencies), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() {
		logger.Info("api-gateway listening", "bind", cfg.BindAddress())
		errCh <- server.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}
