package broker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

// Config is the Gateway's broker connection. URL, CAFile and
// CredentialsFile are required: the Gateway never connects without its own
// credentials or without verifying the server against the stand CA.
type Config struct {
	URL             string
	CAFile          string
	CredentialsFile string
	// InboxPrefix is the only inbox the Gateway user may subscribe to.
	InboxPrefix string
	// ReconnectWait is the pause between connection attempts.
	ReconnectWait time.Duration
}

// NATS is the core request/reply adapter over one NATS connection.
type NATS struct {
	conn *nats.Conn
}

// Connect validates cfg and starts connecting. It returns at once even when
// the broker is unreachable; the connection keeps retrying and Ready reports
// its state.
func Connect(cfg Config, logger *slog.Logger) (*NATS, error) {
	if logger == nil {
		logger = slog.Default()
	}
	parsed, err := url.Parse(cfg.URL)
	if cfg.URL == "" || err != nil || parsed.Scheme != "tls" || parsed.Host == "" {
		return nil, errors.New("broker: a tls:// NATS URL is required")
	}
	if cfg.CAFile == "" {
		return nil, errors.New("broker: the NATS CA file is required")
	}
	if cfg.CredentialsFile == "" {
		return nil, errors.New("broker: the NATS credentials file is required")
	}
	if cfg.InboxPrefix == "" {
		return nil, errors.New("broker: the NATS inbox prefix is required")
	}
	for name, path := range map[string]string{"CA": cfg.CAFile, "credentials": cfg.CredentialsFile} {
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return nil, fmt.Errorf("broker: the NATS %s file is not readable", name)
		}
	}
	wait := cfg.ReconnectWait
	if wait <= 0 {
		wait = 2 * time.Second
	}
	conn, err := nats.Connect(cfg.URL,
		nats.Name("api-gateway"),
		nats.RootCAs(cfg.CAFile),
		nats.UserCredentials(cfg.CredentialsFile),
		nats.CustomInboxPrefix(cfg.InboxPrefix),
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(wait),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				logger.Warn("broker disconnected", "error", err.Error())
			}
		}),
		nats.ReconnectHandler(func(*nats.Conn) { logger.Info("broker reconnected") }),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			logger.Warn("broker error", "error", err.Error())
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("broker: connect: %w", err)
	}
	return &NATS{conn: conn}, nil
}

// Request sends one request and maps transport outcomes to ErrNoResponders,
// ErrTimeout and ErrUnavailable.
func (n *NATS) Request(ctx context.Context, request Request) (Reply, error) {
	if n == nil || n.conn == nil || !n.conn.IsConnected() {
		return Reply{}, ErrUnavailable
	}
	message := nats.NewMsg(request.Subject)
	for name, value := range request.Header {
		message.Header.Set(name, value)
	}
	message.Data = request.Body
	answer, err := n.conn.RequestMsgWithContext(ctx, message)
	switch {
	case err == nil:
	case errors.Is(err, nats.ErrNoResponders):
		return Reply{}, ErrNoResponders
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout), errors.Is(err, context.Canceled):
		return Reply{}, ErrTimeout
	default:
		return Reply{}, ErrUnavailable
	}
	reply := Reply{Header: map[string]string{}, Body: answer.Data}
	for name, values := range answer.Header {
		if len(values) > 0 {
			reply.Header[name] = values[0]
		}
	}
	return reply, nil
}

// Ready reports whether the broker connection is up.
func (n *NATS) Ready() bool { return n != nil && n.conn != nil && n.conn.IsConnected() }

// Close closes the connection.
func (n *NATS) Close() {
	if n != nil && n.conn != nil {
		n.conn.Close()
	}
}
