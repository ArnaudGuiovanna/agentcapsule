package authoritylog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"slices"
	"sync"
	"syscall"
	"time"
)

// The link is mutual TLS 1.3 over TCP, with no framework: one request, one
// response, each a JSON object behind a 4-byte length. Each side pins the
// other's self-signed certificate in its configuration. A certificate names
// its role and the identities of the two authorities it serves, which are
// the authorities' existing identities; each side checks them.

// Roles of a certificate.
const (
	RolePrimary = "primary"
	RoleReplica = "replica"
)

// The kinds of a replica's refusal, a closed vocabulary.
const (
	RefusedIdentity    = "identity"
	RefusedOlderEpoch  = "older_epoch"
	RefusedNewerEpoch  = "newer_epoch"
	RefusedGap         = "gap"
	RefusedConflict    = "conflict"
	RefusedPromoted    = "promoted"
	RefusedInvalid     = "invalid"
	RefusedUnavailable = "unavailable"
)

// RefusalKinds lists every refusal kind.
func RefusalKinds() []string {
	return []string{RefusedIdentity, RefusedOlderEpoch, RefusedNewerEpoch, RefusedGap, RefusedConflict, RefusedPromoted, RefusedInvalid, RefusedUnavailable}
}

// ErrRefused is wrapped by every Refusal.
var ErrRefused = errors.New("replica refused the request")

// ErrProtocol marks a malformed exchange or a configuration that cannot work.
var ErrProtocol = errors.New("authority replication protocol error")

// Refusal is a replica's answer that it did not apply a record. Position is
// where the replica stands.
type Refusal struct {
	Kind     string
	Position Position
}

func (r *Refusal) Error() string { return "replica refused: " + r.Kind }
func (r *Refusal) Unwrap() error { return ErrRefused }

// Request names the authorities and the epoch of the stream, and carries
// records in order. Without records, it asks for the replica's position.
type Request struct {
	RestoreAuthority string   `json:"restore_authority"`
	KeyAuthority     string   `json:"key_authority"`
	Epoch            uint64   `json:"epoch"`
	Records          [][]byte `json:"records,omitempty"`
}

// Link carries requests to a replica. The replica itself is a Link, so tests
// run the stream in memory; Client carries it over mutual TLS.
type Link interface {
	Sync(ctx context.Context, r Request) (Position, error)
}

type response struct {
	Refused  string   `json:"refused,omitempty"`
	Position Position `json:"position"`
}

const maxFrame = 2*MaxRecords*MaxRecord + 4096

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return ErrProtocol
	}
	frame := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(frame, uint32(len(b)))
	_, err = w.Write(append(frame, b...))
	return err
}

func readFrame(r io.Reader, v any) error {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > maxFrame {
		return ErrProtocol
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil || d.More() {
		return ErrProtocol
	}
	return nil
}

func identityURIs(role, restoreAuthority, keyAuthority string) []*url.URL {
	return []*url.URL{
		{Scheme: "urn", Opaque: "agentcapsule:authority-role:" + role},
		{Scheme: "urn", Opaque: "agentcapsule:restore-authority:" + restoreAuthority},
		{Scheme: "urn", Opaque: "agentcapsule:key-authority:" + keyAuthority},
	}
}

func serverName(role string) string { return "agentcapsule-authority-" + role }

// GenerateCertificate returns a self-signed Ed25519 certificate and its
// private key, both PEM, for one side of the link.
func GenerateCertificate(role, restoreAuthority, keyAuthority string) (certificate, key []byte, err error) {
	if (role != RolePrimary && role != RoleReplica) || !ValidID(restoreAuthority, "restoreauth_") || !ValidID(keyAuthority, "keyauth_") {
		return nil, nil, ErrProtocol
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().Add(-time.Hour)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: serverName(role)},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{serverName(role)},
		URIs:                  identityURIs(role, restoreAuthority, keyAuthority),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return nil, nil, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, err
	}
	certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	key = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	clear(pkcs8)
	return certificate, key, nil
}

// Fingerprint is the SHA-256 of a PEM certificate's DER, in hex.
func Fingerprint(certificate []byte) (string, error) {
	block, rest := pem.Decode(certificate)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return "", ErrProtocol
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// TLSFiles is one side's configuration: its certificate and key, and the
// pinned certificate of the other side. Both certificates must name the two
// authorities.
type TLSFiles struct {
	Certificate      string
	Key              string
	PeerCertificate  string
	RestoreAuthority string
	KeyAuthority     string
}

func readFile(path string, private bool) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > 64<<10 || st.Mode().Perm()&0022 != 0 {
		return nil, ErrProtocol
	}
	if private && (st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid())) {
		return nil, ErrProtocol
	}
	return io.ReadAll(io.LimitReader(f, 64<<10))
}

func parseCertificate(b []byte, role, restoreAuthority, keyAuthority string) (*x509.Certificate, error) {
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrProtocol
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, ErrProtocol
	}
	want := identityURIs(role, restoreAuthority, keyAuthority)
	if len(c.URIs) != len(want) || c.Subject.CommonName != serverName(role) || !slices.Equal(c.DNSNames, []string{serverName(role)}) {
		return nil, ErrProtocol
	}
	for i := range want {
		if c.URIs[i].String() != want[i].String() {
			return nil, ErrProtocol
		}
	}
	// Self-signed: the pin, not a CA, is what the peer trusts.
	if err = c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
		return nil, ErrProtocol
	}
	return c, nil
}

func (f TLSFiles) config(role, peerRole string) (*tls.Config, error) {
	if !ValidID(f.RestoreAuthority, "restoreauth_") || !ValidID(f.KeyAuthority, "keyauth_") {
		return nil, ErrProtocol
	}
	own, err := readFile(f.Certificate, false)
	if err != nil {
		return nil, err
	}
	if _, err = parseCertificate(own, role, f.RestoreAuthority, f.KeyAuthority); err != nil {
		return nil, err
	}
	key, err := readFile(f.Key, true)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(own, key)
	if err != nil {
		return nil, ErrProtocol
	}
	peerPEM, err := readFile(f.PeerCertificate, false)
	if err != nil {
		return nil, err
	}
	peer, err := parseCertificate(peerPEM, peerRole, f.RestoreAuthority, f.KeyAuthority)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(peer)
	pinned := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, peer.Raw) {
			return ErrProtocol
		}
		return nil
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, VerifyConnection: pinned}
	if role == RoleReplica {
		c.ClientAuth, c.ClientCAs = tls.RequireAndVerifyClientCert, pool
	} else {
		c.RootCAs, c.ServerName = pool, serverName(RoleReplica)
	}
	return c, nil
}

// ClientTLS is the primary's side.
func (f TLSFiles) ClientTLS() (*tls.Config, error) { return f.config(RolePrimary, RoleReplica) }

// ServerTLS is the replica's side.
func (f TLSFiles) ServerTLS() (*tls.Config, error) { return f.config(RoleReplica, RolePrimary) }

// Client is the primary's end of the link. It keeps one connection and
// reconnects after an error. It is safe for concurrent use; requests go one
// at a time.
type Client struct {
	address string
	config  *tls.Config
	mu      chan struct{}
	conn    *tls.Conn
}

// NewClient returns a client of the replica at address (host:port).
func NewClient(address string, config *tls.Config) (*Client, error) {
	if _, _, err := net.SplitHostPort(address); err != nil || config == nil {
		return nil, ErrProtocol
	}
	return &Client{address: address, config: config, mu: make(chan struct{}, 1)}, nil
}

// requestTimeout bounds one exchange when the context has no deadline.
const requestTimeout = 30 * time.Second

// Sync sends one request and waits for the replica's answer.
func (c *Client) Sync(ctx context.Context, r Request) (Position, error) {
	select {
	case c.mu <- struct{}{}:
	case <-ctx.Done():
		return Position{}, ctx.Err()
	}
	defer func() { <-c.mu }()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(requestTimeout)
	}
	if c.conn == nil {
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}, Config: c.config}
		conn, err := dialer.DialContext(ctx, "tcp", c.address)
		if err != nil {
			var netErr net.Error
			if !errors.As(err, &netErr) && ctx.Err() == nil {
				err = errors.Join(ErrProtocol, err) // the handshake failed: certificates
			}
			return Position{}, err
		}
		c.conn = conn.(*tls.Conn)
	}
	conn := c.conn
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	var answer response
	err := conn.SetDeadline(deadline)
	if err == nil {
		err = writeFrame(conn, r)
	}
	if err == nil {
		err = readFrame(conn, &answer)
	}
	if err != nil {
		conn.Close()
		c.conn = nil
		if ctx.Err() != nil {
			return Position{}, errors.Join(ctx.Err(), err)
		}
		return Position{}, err
	}
	if answer.Refused != "" {
		if !slices.Contains(RefusalKinds(), answer.Refused) {
			return Position{}, ErrProtocol
		}
		return answer.Position, &Refusal{Kind: answer.Refused, Position: answer.Position}
	}
	return answer.Position, nil
}

// Close closes the connection, if any.
func (c *Client) Close() error {
	c.mu <- struct{}{}
	defer func() { <-c.mu }()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// Server is the replica's end of the link.
type Server struct {
	Replica Link
	Config  *tls.Config
	// Idle bounds the wait for the next request of a connection.
	Idle time.Duration
	// Observe receives each failed request, for logs and metrics.
	Observe func(error)
}

// maxConnections bounds the primary's concurrent processes.
const maxConnections = 32

// Serve accepts connections until ctx ends or the listener fails.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s.Replica == nil || s.Config == nil || s.Config.ClientAuth != tls.RequireAndVerifyClientCert {
		return ErrProtocol
	}
	idle := s.Idle
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	slots := make(chan struct{}, maxConnections)
	for {
		raw, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case slots <- struct{}{}:
		default:
			raw.Close()
			continue
		}
		wg.Go(func() {
			defer func() { <-slots }()
			s.serve(ctx, tls.Server(raw, s.Config), idle)
		})
	}
}

func (s *Server) observe(err error) {
	if s.Observe != nil && err != nil {
		s.Observe(err)
	}
}

func (s *Server) serve(ctx context.Context, conn *tls.Conn, idle time.Duration) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.HandshakeContext(ctx); err != nil {
		s.observe(fmt.Errorf("%w: handshake", ErrProtocol))
		return
	}
	for {
		var r Request
		conn.SetDeadline(time.Now().Add(idle))
		if err := readFrame(conn, &r); err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.observe(err)
			}
			return
		}
		conn.SetDeadline(time.Now().Add(requestTimeout))
		if len(r.Records) > MaxRecords {
			s.observe(ErrProtocol)
			return
		}
		position, err := s.Replica.Sync(ctx, r)
		answer := response{Position: position}
		if err != nil {
			s.observe(err)
			var refusal *Refusal
			if !errors.As(err, &refusal) {
				refusal = &Refusal{Kind: RefusedUnavailable, Position: position}
			}
			answer.Refused, answer.Position = refusal.Kind, refusal.Position
		}
		if answer.Position.Digest == nil {
			answer.Position.Digest = Origin()
		}
		if err = writeFrame(conn, answer); err != nil {
			return
		}
	}
}
