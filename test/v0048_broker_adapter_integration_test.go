//go:build integration

package test

// The Gateway's NATS adapter against a real NATS server used only as
// transport: operator mode with a Gateway user whose permissions mirror the
// deployment (publish ui and team point-read subjects, subscribe only
// _INBOX.api-gateway.>), TLS with a test CA.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/pandops/flowai-api-gateway/internal/broker"
)

const natsImage = "docker.io/library/nats@sha256:a7d440bf0240e664ed74fc17c70d616e6ff4bb9890dc26f7276589daedd1e196"

type natsFixture struct {
	container, url, caFile, gatewayCreds, responderCreds, anonymousURL string
	port                                                               int
}

func writePEM(t *testing.T, path, kind string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

// natsTLS writes a test CA and a server certificate for 127.0.0.1.
func natsTLS(t *testing.T, dir string) string {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agw test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "nats"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(serverKey)
	writePEM(t, filepath.Join(dir, "ca.pem"), "CERTIFICATE", caDER)
	writePEM(t, filepath.Join(dir, "server.pem"), "CERTIFICATE", serverDER)
	writePEM(t, filepath.Join(dir, "server-key.pem"), "EC PRIVATE KEY", keyDER)
	return filepath.Join(dir, "ca.pem")
}

func natsUser(t *testing.T, account nkeys.KeyPair, path string, configure func(*jwt.UserClaims)) {
	t.Helper()
	user, _ := nkeys.CreateUser()
	public, _ := user.PublicKey()
	claims := jwt.NewUserClaims(public)
	if configure != nil {
		configure(claims)
	}
	token, err := claims.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := user.Seed()
	creds, err := jwt.FormatUserConfig(token, seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatal(err)
	}
}

// startNATS starts one owned NATS container and removes it (verified) at the
// end of the case.
func startNATS(t *testing.T) *natsFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	caFile := natsTLS(t, dir)
	operator, _ := nkeys.CreateOperator()
	operatorPublic, _ := operator.PublicKey()
	operatorJWT, err := jwt.NewOperatorClaims(operatorPublic).Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	account, _ := nkeys.CreateAccount()
	accountPublic, _ := account.PublicKey()
	accountJWT, err := jwt.NewAccountClaims(accountPublic).Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	f := &natsFixture{container: "flowai-agw-nats-" + pgToken(8), caFile: caFile, gatewayCreds: filepath.Join(dir, "gateway.creds"), responderCreds: filepath.Join(dir, "responder.creds")}
	natsUser(t, account, f.gatewayCreds, func(c *jwt.UserClaims) {
		c.Pub.Allow.Add("*.ui.*.pub", "team-registry.service.get.pub")
		c.Sub.Allow.Add("_INBOX.api-gateway.>")
	})
	natsUser(t, account, f.responderCreds, func(c *jwt.UserClaims) { c.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second} })
	config := fmt.Sprintf("port: 4222\noperator: %s\nresolver: MEMORY\nresolver_preload: {\n  %s: %s\n}\ntls {\n  cert_file: /etc/agw-nats/server.pem\n  key_file: /etc/agw-nats/server-key.pem\n}\n", operatorJWT, accountPublic, accountJWT)
	if err := os.WriteFile(filepath.Join(dir, "nats.conf"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.port = listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	f.url = fmt.Sprintf("tls://127.0.0.1:%d", f.port)
	if ledger := os.Getenv("FLOWAI_RESOURCE_LEDGER"); ledger != "" {
		record, _ := json.Marshal(map[string]string{"kind": "containers", "selector": "name=^" + f.container + "$"})
		file, err := os.OpenFile(ledger, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write(append(record, '\n'))
		if err := errors.Join(writeErr, file.Close()); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := pgRun(ctx, pgShared.binary, "run", "--detach", "--name", f.container, "--label", pgLabel,
		"--publish", fmt.Sprintf("127.0.0.1:%d:4222", f.port), "--volume", dir+":/etc/agw-nats:ro",
		natsImage, "nats-server", "-c", "/etc/agw-nats/nats.conf"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := pgRun(ctx, pgShared.binary, "rm", "--force", f.container); err != nil {
			t.Errorf("remove NATS container: %v", err)
		}
	})
	f.waitReady(t)
	return f
}

func (f *natsFixture) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := nats.Connect(f.url, nats.UserCredentials(f.responderCreds), nats.RootCAs(f.caFile), nats.Timeout(time.Second))
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("NATS fixture not ready")
}

// responder answers subject on the fixture as an owning service would.
func (f *natsFixture) responder(t *testing.T, subject string, answer func(*nats.Msg) *nats.Msg) *nats.Conn {
	t.Helper()
	conn, err := nats.Connect(f.url, nats.UserCredentials(f.responderCreds), nats.RootCAs(f.caFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	if _, err := conn.Subscribe(subject, func(message *nats.Msg) {
		if reply := answer(message); reply != nil {
			reply.Subject = message.Reply
			_ = conn.PublishMsg(reply)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	return conn
}

func (f *natsFixture) gateway(t *testing.T) *broker.NATS {
	t.Helper()
	adapter, err := broker.Connect(broker.Config{URL: f.url, CAFile: f.caFile, CredentialsFile: f.gatewayCreds, InboxPrefix: "_INBOX.api-gateway", ReconnectWait: 200 * time.Millisecond}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(adapter.Close)
	waitFor(t, 10*time.Second, adapter.Ready, "adapter ready")
	return adapter
}

func waitFor(t *testing.T, limit time.Duration, condition func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func call(adapter *broker.NATS, subject string, header map[string]string, body string, timeout time.Duration) (broker.Reply, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return adapter.Request(ctx, broker.Request{Subject: subject, Header: header, Body: []byte(body)})
}

// message-broker (api-gateway form): the adapter carries rule-9 headers both
// ways, maps transport outcomes, follows the connection state and refuses to
// start without credentials or trust.
func TestV0048GatewayBrokerAdapterOnNATS(t *testing.T) {
	t.Run("Owner replies with an error", func(t *testing.T) {
		f := startNATS(t)
		var seen *nats.Msg
		f.responder(t, "flow-registry.ui.flow-replace.pub", func(message *nats.Msg) *nats.Msg {
			seen = message
			reply := nats.NewMsg("")
			reply.Header.Set("status", "412")
			reply.Header.Set("ETag", `"flow-12-r5"`)
			reply.Header.Set("Location", "/ui/v1/flows/12")
			reply.Header.Set("Retry-After", "3")
			reply.Header.Set("Cache-Control", "no-store")
			reply.Data = []byte(`{"code":"precondition_failed","message":"stale","request_id":77}`)
			return reply
		})
		adapter := f.gateway(t)
		header := map[string]string{"team": "3", "operator_id": "42", "request_id": "77", "team_name": "Alpha-Team", "If-Match": `"flow-12-r4"`}
		reply, err := call(adapter, "flow-registry.ui.flow-replace.pub", header, `{"params":{"flow_id":12},"body":{"name":"x"}}`, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		for name, want := range map[string]string{"status": "412", "ETag": `"flow-12-r5"`, "Location": "/ui/v1/flows/12", "Retry-After": "3", "Cache-Control": "no-store"} {
			if reply.Header[name] != want {
				t.Fatalf("reply header %s = %q, want %q (all %v)", name, reply.Header[name], want, reply.Header)
			}
		}
		if string(reply.Body) != `{"code":"precondition_failed","message":"stale","request_id":77}` {
			t.Fatalf("reply body = %s", reply.Body)
		}
		for name, want := range header {
			if seen.Header.Get(name) != want {
				t.Fatalf("request header %s = %q, want %q", name, seen.Header.Get(name), want)
			}
		}
		if string(seen.Data) != `{"params":{"flow_id":12},"body":{"name":"x"}}` || !strings.HasPrefix(seen.Reply, "_INBOX.api-gateway.") {
			t.Fatalf("request = %s via %s", seen.Data, seen.Reply)
		}
	})

}
