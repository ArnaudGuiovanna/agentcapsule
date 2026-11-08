package capsuleprotocol

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestSignedBootIdentityCannotBeRebound(t *testing.T) {
	identity := Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}
	host, guest, err := NewBootCredentials(identity, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []Credentials{host, guest, *host.Platform, *guest.Platform} {
		for _, mutate := range []func(*Identity){
			func(i *Identity) { i.Incarnation++ },
			func(i *Identity) { i.Incarnation = 0 },
			func(i *Identity) { i.Generation++ },
			func(i *Identity) { i.AgentID = "b" },
			func(i *Identity) { i.FenceOnly = true },
		} {
			bad := c
			mutate(&bad.Identity)
			if _, err := bad.TLS(false); !errors.Is(err, ErrIdentity) {
				t.Fatal("signed identity rebound", err)
			}
		}
	}
}

func TestValidityIncludesBothAuthoritiesAndRejectsForeignMaterial(t *testing.T) {
	id := Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}
	h, _, err := NewBootCredentials(id, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	_, short, err := NewCredentials(id, 20*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, platform, err := newCredentials(id, 10*time.Minute, "platform")
	if err != nil {
		t.Fatal(err)
	}
	h.Platform = &platform
	_, after, err := h.Validity()
	_, want, _ := platform.Validity()
	if err != nil || !after.Equal(want) {
		t.Fatal("reverse-channel expiry ignored:", after, want, err)
	}
	bad := h
	bad.CA = short.CA
	if _, _, err = bad.Validity(); !errors.Is(err, ErrIdentity) {
		t.Fatal("foreign authority treated as expiry:", err)
	}
	bad = h
	bad.Certificate = []byte("invalid")
	if _, _, err = bad.Validity(); err == nil {
		t.Fatal("malformed record accepted")
	}
	platform.Identity.Generation++
	if _, _, err = h.Validity(); !errors.Is(err, ErrIdentity) {
		t.Fatal("foreign platform generation accepted:", err)
	}
}

func TestRetainedTLSConnectionCannotOutliveCertificate(t *testing.T) {
	for _, channel := range []string{"control", "platform"} {
		t.Run(channel, func(t *testing.T) {
			client, server, err := newCredentials(Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}, time.Hour, channel)
			if err != nil {
				t.Fatal(err)
			}
			_, after, err := server.Validity()
			if err != nil {
				t.Fatal(err)
			}
			var now atomic.Int64
			now.Store(time.Now().UnixNano())
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var calls, connections atomic.Int32
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() {
				done <- serveAuthenticated(ctx, l, server, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusOK) }), func() time.Time { return time.Unix(0, now.Load()) })
			}()
			t.Cleanup(func() { cancel(); <-done })
			cfg, err := client.TLS(false)
			if err != nil {
				t.Fatal(err)
			}
			transport := &http.Transport{TLSClientConfig: cfg, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				connections.Add(1)
				return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
			}}
			t.Cleanup(transport.CloseIdleConnections)
			httpClient := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			request := func() int {
				r, err := httpClient.Get("https://" + cfg.ServerName + "/v1/health")
				if err != nil {
					t.Fatal(err)
				}
				defer r.Body.Close()
				if _, err = io.Copy(io.Discard, r.Body); err != nil {
					t.Fatal(err)
				}
				return r.StatusCode
			}
			if got := request(); got != http.StatusOK {
				t.Fatal(got)
			}
			now.Store(after.UnixNano())
			if got := request(); got != http.StatusUnauthorized {
				t.Fatal("expired persistent session admitted:", got)
			}
			if calls.Load() != 1 || connections.Load() != 1 {
				t.Fatal("test did not reuse authenticated connection:", calls.Load(), connections.Load())
			}
		})
	}
}

// These are actual TLS handshakes with signed expired/not-yet-valid material,
// rather than a scheduler clock stub or an assumed transport error.
func TestTLSRejectsExpiredAndFutureCertificatesInBothDirections(t *testing.T) {
	for _, channel := range []string{"control", "platform"} {
		for _, offset := range []time.Duration{-2 * time.Hour, time.Hour} {
			t.Run(channel+"/"+offset.String(), func(t *testing.T) {
				client, server, err := newCredentialsAt(Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"}, time.Hour, channel, time.Now().Add(offset))
				if err != nil {
					t.Fatal(err)
				}
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				var called atomic.Int32
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() {
					done <- ServeAuthenticated(ctx, l, server, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called.Add(1) }))
				}()
				t.Cleanup(func() { cancel(); <-done })
				c, err := NewClient(client, func(ctx context.Context) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
				})
				if err != nil {
					t.Fatal(err)
				}
				err = c.Health(t.Context())
				var invalid x509.CertificateInvalidError
				if !errors.As(err, &invalid) || invalid.Reason != x509.Expired || called.Load() != 0 {
					t.Fatalf("invalid time accepted: calls=%d err=%v", called.Load(), err)
				}
			})
		}
	}
}
