package authoritylog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// replicaLink starts a replica's server on 127.0.0.1 and returns its
// address and a function that makes a primary's client of it, as another
// process of the primary would.
func replicaLink(t *testing.T) (string, func() *Client) {
	t.Helper()
	dir := t.TempDir()
	primaryCrt, primaryKey := writeSide(t, dir, RolePrimary, testRestore)
	replicaCrt, replicaKey := writeSide(t, dir, RoleReplica, testRestore)
	serverTLS, err := TLSFiles{Certificate: replicaCrt, Key: replicaKey, PeerCertificate: primaryCrt, RestoreAuthority: testRestore, KeyAuthority: testKeys}.ServerTLS()
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := TLSFiles{Certificate: primaryCrt, Key: primaryKey, PeerCertificate: replicaCrt, RestoreAuthority: testRestore, KeyAuthority: testKeys}.ClientTLS()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{Replica: &fixedReplica{}, Config: serverTLS}).Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	address := listener.Addr().String()
	return address, func() *Client {
		c, err := NewClient(address, clientTLS)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
}

// idle opens n TCP connections to address from source, a loopback address
// of its own, that never start a handshake: an unauthenticated peer that
// holds them open.
func idle(t *testing.T, address, source string, n int) []net.Conn {
	t.Helper()
	var conns []net.Conn
	for range n {
		d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}, Timeout: 2 * time.Second}
		c, err := d.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	t.Cleanup(func() {
		for _, c := range conns {
			c.Close()
		}
	})
	// Let the server accept them before the primary dials.
	time.Sleep(200 * time.Millisecond)
	return conns
}

// synced makes one exchange of c within a few seconds.
func synced(t *testing.T, c *Client) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := c.Sync(ctx, Request{RestoreAuthority: testRestore, KeyAuthority: testKeys, Epoch: 1})
	return err
}

// L-17: connections from one address that never authenticate take a few
// handshake slots only, so the primary, from another address, still links.
func TestOneSourceCannotStarveTheReplicaListener(t *testing.T) {
	address, client := replicaLink(t)
	idle(t, address, "127.0.0.2", 2*maxConnections)
	if err := synced(t, client()); err != nil {
		t.Fatal("the primary could not link past one source's idle connections:", err)
	}
}

// L-17: many sources, each under its cap, fill the handshake slots that any
// address may take. The primary's established connection keeps its slot,
// and a new process of the primary, from the address it authenticated from
// before, takes a slot kept for it.
func TestManySourcesCannotStarveTheKnownPrimary(t *testing.T) {
	address, client := replicaLink(t)
	established := client()
	if err := synced(t, established); err != nil {
		t.Fatal(err)
	}
	// Four per source, the cap of each.
	for i := range 2 * maxConnections / 4 {
		idle(t, address, fmt.Sprintf("127.0.1.%d", i+1), 4)
	}
	if err := synced(t, established); err != nil {
		t.Fatal("the established connection lost its slot:", err)
	}
	if err := synced(t, client()); err != nil {
		t.Fatal("a new connection of the known primary found no slot:", err)
	}
}

// L-17: a connection that does not complete its handshake is closed after a
// few seconds (3), not the ten it held before.
func TestAnUnauthenticatedConnectionIsClosedSoon(t *testing.T) {
	address, _ := replicaLink(t)
	c := idle(t, address, "127.0.0.3", 1)[0]
	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, err := c.Read(make([]byte, 1))
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() || !errors.Is(err, io.EOF) && err == nil {
		t.Fatal("the connection stayed open:", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("closed after %s", elapsed)
	}
	// A handshake that starts but stalls is closed as soon.
	raw, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	start = time.Now()
	if _, err = raw.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x40}); err != nil { // a TLS record header, then nothing
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err = io.ReadAll(raw); errors.As(err, &timeout) && timeout.Timeout() {
		t.Fatal("a stalled handshake stayed open")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("a stalled handshake closed after %s", elapsed)
	}
}
