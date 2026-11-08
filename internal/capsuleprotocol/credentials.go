// Package capsuleprotocol implements authenticated capsule.v1 control RPCs.
// Its handler belongs in a trusted harness using harnessstore's SQL transaction;
// it does not make arbitrary external application effects transactional.
package capsuleprotocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"
)

const Version = "capsule.v1"
const ControlPort = 5000
const PlatformPort = 5001
const BootConfigPath = "/etc/capsule/boot.json"

var ErrIdentity = errors.New("capsule channel identity mismatch")

type Identity struct {
	Incarnation uint64 `json:"incarnation"`
	AgentID     string `json:"agent_id"`
	Generation  uint64 `json:"generation"`
	VMID        string `json:"vm_id"`
	FenceOnly   bool   `json:"fence_only,omitempty"`
}

func (i Identity) Validate() error {
	if i.AgentID == "" || len(i.AgentID) > 256 || i.Generation == 0 || i.Incarnation == 0 || i.Incarnation > 1<<63-1 {
		return ErrIdentity
	}
	for _, c := range i.AgentID {
		if c < 33 || c > 126 {
			return ErrIdentity
		}
	}
	b, err := hex.DecodeString(i.VMID)
	if err != nil || len(b) != 8 || strings.ToLower(i.VMID) != i.VMID {
		return ErrIdentity
	}
	return nil
}

func (i Identity) serverName() string { return i.VMID + ".control.agentcapsule.invalid" }

// The signed URI binds all identity fields, including restricted mode and the
// storage incarnation. Editing a credentials JSON file cannot rebind a leaf.
func (i Identity) certificateURI() *url.URL {
	b, _ := json.Marshal(i)
	digest := sha256.Sum256(b)
	return &url.URL{Scheme: "urn", Opaque: "agentcapsule:boot:" + hex.EncodeToString(digest[:])}
}

func (i Identity) matchesCertificate(c *x509.Certificate) bool {
	return len(c.URIs) == 1 && c.URIs[0].String() == i.certificateURI().String()
}

// Credentials are boot-scoped secrets. Host receives only the client key; guest
// receives only the server key. Neither receives the ephemeral CA private key.
// Do not log these structs or include them in evidence/backup archives.
type Credentials struct {
	Identity    Identity `json:"identity"`
	CA          []byte   `json:"ca"`
	Certificate []byte   `json:"certificate"`
	PrivateKey  []byte   `json:"private_key"`
	Channel     string   `json:"channel,omitempty"`
	// The reverse channel has a separate authority and the opposite TLS role.
	// Sharing an authority for both directions would let a guest client key
	// authenticate to the control server as though it belonged to the host.
	Platform *Credentials `json:"platform,omitempty"`
}

func NewCredentials(id Identity, lifetime time.Duration) (host, guest Credentials, err error) {
	return newCredentials(id, lifetime, "control")
}

func NewBootCredentials(id Identity, lifetime time.Duration, platform bool) (host, guest Credentials, err error) {
	host, guest, err = NewCredentials(id, lifetime)
	if err != nil {
		return
	}
	if platform && !id.FenceOnly {
		var client, server Credentials
		client, server, err = newCredentials(id, lifetime, "platform")
		if err != nil {
			return
		}
		host.Platform = &server
		guest.Platform = &client
	}
	return
}

func newCredentials(id Identity, lifetime time.Duration, channel string) (host, guest Credentials, err error) {
	return newCredentialsAt(id, lifetime, channel, time.Now())
}

func newCredentialsAt(id Identity, lifetime time.Duration, channel string, now time.Time) (host, guest Credentials, err error) {
	if err = id.Validate(); err != nil {
		return
	}
	if lifetime < time.Minute || lifetime > 30*24*time.Hour {
		return host, guest, errors.New("invalid boot certificate lifetime")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return host, guest, err
	}
	serial := func() *big.Int {
		n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			panic(e)
		}
		return n.Add(n, big.NewInt(1))
	}
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "AgentCapsule " + channel + " boot " + id.VMID},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(lifetime), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, MaxPathLen: 0, MaxPathLenZero: true}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		return host, guest, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	makeLeaf := func(role x509.ExtKeyUsage) (Credentials, error) {
		leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return Credentials{}, e
		}
		leaf := &x509.Certificate{SerialNumber: serial(), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
			URIs:     []*url.URL{id.certificateURI()},
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{role}, DNSNames: []string{id.VMID + "." + channel + ".agentcapsule.invalid"}, BasicConstraintsValid: true}
		b, e := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
		if e != nil {
			return Credentials{}, e
		}
		pk, e := x509.MarshalPKCS8PrivateKey(leafKey)
		if e != nil {
			return Credentials{}, e
		}
		return Credentials{Identity: id, Channel: channel, CA: caPEM, Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})}, nil
	}
	host, err = makeLeaf(x509.ExtKeyUsageClientAuth)
	if err != nil {
		return
	}
	guest, err = makeLeaf(x509.ExtKeyUsageServerAuth)
	return
}

// Validity returns the intersection of the signed leaf/authority windows for
// both boot channels. It never treats malformed or foreign material as expiry.
// The private key is checked but neither returned nor included in errors.
func (c Credentials) Validity() (notBefore, notAfter time.Time, err error) {
	if _, err = c.TLS(false); err != nil {
		return
	}
	parse := func(b []byte) (*x509.Certificate, error) {
		p, rest := pem.Decode(b)
		if p == nil || p.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
			return nil, errors.New("invalid boot certificate record")
		}
		return x509.ParseCertificate(p.Bytes)
	}
	ca, err := parse(c.CA)
	if err != nil {
		return notBefore, notAfter, err
	}
	leaf, err := parse(c.Certificate)
	if err != nil {
		return notBefore, notAfter, err
	}
	channel := c.Channel
	if channel == "" {
		channel = "control"
	}
	if leaf.CheckSignatureFrom(ca) != nil || leaf.VerifyHostname(c.Identity.VMID+"."+channel+".agentcapsule.invalid") != nil {
		return notBefore, notAfter, ErrIdentity
	}
	notBefore, notAfter = leaf.NotBefore, leaf.NotAfter
	include := func(before, after time.Time) {
		if before.After(notBefore) {
			notBefore = before
		}
		if after.Before(notAfter) {
			notAfter = after
		}
	}
	include(ca.NotBefore, ca.NotAfter)
	if c.Platform != nil {
		if channel != "control" || c.Identity.FenceOnly || c.Platform.Identity != c.Identity || c.Platform.Channel != "platform" || c.Platform.Platform != nil {
			return notBefore, notAfter, ErrIdentity
		}
		before, after, e := c.Platform.Validity()
		if e != nil {
			return notBefore, notAfter, e
		}
		include(before, after)
	}
	if !notBefore.Before(notAfter) {
		return notBefore, notAfter, errors.New("empty boot certificate validity window")
	}
	return
}

func (c Credentials) TLS(server bool) (*tls.Config, error) {
	if err := c.Identity.Validate(); err != nil {
		return nil, err
	}
	channel := c.Channel
	if channel == "" {
		channel = "control"
	}
	if channel != "control" && channel != "platform" {
		return nil, ErrIdentity
	}
	cert, err := tls.X509KeyPair(c.Certificate, c.PrivateKey)
	if err != nil {
		return nil, errors.New("invalid boot certificate/key")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || !c.Identity.matchesCertificate(leaf) {
		return nil, ErrIdentity
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CA) {
		return nil, errors.New("invalid boot authority")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, SessionTicketsDisabled: true, NextProtos: []string{"http/1.1"}}
	cfg.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || !c.Identity.matchesCertificate(state.PeerCertificates[0]) {
			return ErrIdentity
		}
		return nil
	}
	if server {
		cfg.ClientCAs = roots
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	} else {
		cfg.RootCAs = roots
		cfg.ServerName = c.Identity.VMID + "." + channel + ".agentcapsule.invalid"
	}
	return cfg, nil
}
