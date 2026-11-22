package capsuleprotocol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// One client keeps its authenticated connection between calls (P-09): a
// delivery's health check, contract check and event take one mTLS handshake,
// not three. A connection idle past ClientIdleTimeout is closed first.
func TestAClientKeepsItsConnectionBetweenCalls(t *testing.T) {
	h, g := credentialPair(t, "a", "0123456789abcdef")
	_, dial := serverFixture(t, h, g, nil)
	var dials atomic.Int32
	c, err := NewClient(h, func(ctx context.Context) (net.Conn, error) { dials.Add(1); return dial(ctx) })
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err = c.Health(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"one", "two"} {
		if _, err = c.Send(t.Context(), event(id)); err != nil {
			t.Fatal(err)
		}
	}
	if n := dials.Load(); n != 1 {
		t.Fatal("connections for five calls:", n)
	}
	c.CloseIdleConnections()
	if err = c.Health(t.Context()); err != nil || dials.Load() != 2 {
		t.Fatal("a closed connection was reused", dials.Load(), err)
	}
}

// A kept connection does not outlive its server's certificate: each response
// is checked against the certificate's validity, which TLS checks only at the
// handshake.
func TestAKeptConnectionEndsWithItsServersCertificate(t *testing.T) {
	now := time.Now()
	valid := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	expired := &x509.Certificate{NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}
	if !currentPeer(&tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{valid, valid}}}, now) {
		t.Fatal("a valid peer refused")
	}
	for _, state := range []*tls.ConnectionState{nil, {}, {VerifiedChains: [][]*x509.Certificate{{valid, expired}}}} {
		if currentPeer(state, now) {
			t.Fatal("an unverified or expired peer accepted", state)
		}
	}
}
