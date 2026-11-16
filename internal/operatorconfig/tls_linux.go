//go:build linux

package operatorconfig

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"sync/atomic"
	"time"
)

var (
	// ErrTLSFiles: the certificate is not a regular file writable only by its
	// owner, or the key is not a private file (see ReadPrivate), or either
	// does not hold PEM of the right kind.
	ErrTLSFiles = errors.New("TLS files unusable: a certificate writable only by its owner and a private key, regular files with absolute paths")
	// ErrTLSKeyMismatch: the key is not the certificate's.
	ErrTLSKeyMismatch = errors.New("TLS key does not match the certificate")
	// ErrTLSValidity: the certificate has expired or is not valid yet.
	ErrTLSValidity = errors.New("TLS certificate expired or not yet valid")
	// ErrTLSName: the certificate does not cover the name clients use.
	ErrTLSName = errors.New("TLS certificate does not cover the server name")
	// ErrTLSUsage: the certificate's extended key usage excludes this role.
	ErrTLSUsage = errors.New("TLS certificate not issued for this role")
)

// LoadCertificate reads a PEM certificate chain and its private key and
// checks them for a role (x509.ExtKeyUsageServerAuth or ClientAuth) at now.
// The leaf must be valid at now and, when it lists extended key usages,
// include the role. The key never appears in an error.
func LoadCertificate(certificate, key string, usage x509.ExtKeyUsage, now time.Time) (tls.Certificate, error) {
	certPEM, err := ReadProtectedUpTo(certificate, 1<<16)
	if err != nil {
		return tls.Certificate{}, ErrTLSFiles
	}
	keyPEM, err := ReadPrivateUpTo(key, 1<<16)
	if err != nil {
		return tls.Certificate{}, ErrTLSFiles
	}
	defer clear(keyPEM)
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return tls.Certificate{}, ErrTLSFiles
	}
	if _, err = x509.ParseCertificate(block.Bytes); err != nil {
		return tls.Certificate{}, ErrTLSFiles
	}
	if !privateKeyPEM(keyPEM) {
		return tls.Certificate{}, ErrTLSFiles
	}
	// Both parse on their own: a remaining failure is a key of another pair.
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, ErrTLSKeyMismatch
	}
	leaf := pair.Leaf
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return tls.Certificate{}, ErrTLSValidity
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, usage) && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return tls.Certificate{}, ErrTLSUsage
	}
	return pair, nil
}

func privateKeyPEM(b []byte) bool {
	block, _ := pem.Decode(b)
	if block == nil {
		return false
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return true
	}
	_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return err == nil
}

// LoadServerCertificate is LoadCertificate for a server; with a name, the
// certificate must also cover it (a DNS name or an IP address).
func LoadServerCertificate(certificate, key, name string, now time.Time) (tls.Certificate, error) {
	pair, err := LoadCertificate(certificate, key, x509.ExtKeyUsageServerAuth, now)
	if err != nil {
		return pair, err
	}
	if name != "" && pair.Leaf.VerifyHostname(name) != nil {
		return tls.Certificate{}, ErrTLSName
	}
	return pair, nil
}

// ServerCertificate is the certificate a TLS listener presents. Reload reads
// the files again, for a renewal (on SIGHUP), and keeps the certificate in
// service when the new files fail the checks.
type ServerCertificate struct {
	certificate, key, name string
	current                atomic.Pointer[tls.Certificate]
}

// NewServerCertificate loads the files once; see LoadServerCertificate.
func NewServerCertificate(certificate, key, name string) (*ServerCertificate, error) {
	s := &ServerCertificate{certificate: certificate, key: key, name: name}
	return s, s.Reload()
}

// Reload replaces the certificate for new connections.
func (s *ServerCertificate) Reload() error {
	pair, err := LoadServerCertificate(s.certificate, s.key, s.name, time.Now())
	if err != nil {
		return err
	}
	s.current.Store(&pair)
	return nil
}

// NotAfter is the expiry of the certificate in service.
func (s *ServerCertificate) NotAfter() time.Time { return s.current.Load().Leaf.NotAfter }

// TLSConfig serves TLS 1.2 and 1.3 only, with Go's default cipher suites
// (forward-secret AEAD suites for TLS 1.2).
func (s *ServerCertificate) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return s.current.Load(), nil
	}}
}
