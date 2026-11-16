//go:build linux

package preflight

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/jackc/pgx/v5/pgconn"
)

// renewBefore is how long before expiry a certificate is reported.
const renewBefore = 30 * 24 * time.Hour

// Certificate checks a certificate and its key for a role: readable with the
// right permissions, the key matching, valid now, issued for the role, and
// covering name (a server's) or bearing commonName (a client's) when given.
// A certificate that expires within 30 days is a warning.
func Certificate(h Host, check, certificate, key string, usage x509.ExtKeyUsage, name, commonName string) Result {
	now := h.Now()
	var pair tls.Certificate
	var err error
	if usage == x509.ExtKeyUsageServerAuth {
		pair, err = operatorconfig.LoadServerCertificate(certificate, key, name, now)
	} else {
		pair, err = operatorconfig.LoadCertificate(certificate, key, usage, now)
	}
	switch {
	case errors.Is(err, operatorconfig.ErrTLSFiles):
		return fail(check, certificate+" or its key cannot be used",
			"give absolute paths to regular files (no symlink): the certificate writable only by its owner, the key owned by the service's user (or root) with mode 0600")
	case errors.Is(err, operatorconfig.ErrTLSKeyMismatch):
		return fail(check, "the key is not the key of "+certificate, "install the key issued with this certificate")
	case errors.Is(err, operatorconfig.ErrTLSValidity):
		return fail(check, certificate+" has expired or is not valid yet", "renew the certificate, and check the clock")
	case errors.Is(err, operatorconfig.ErrTLSName):
		return fail(check, certificate+" does not cover "+name, "issue the certificate for "+name)
	case errors.Is(err, operatorconfig.ErrTLSUsage):
		return fail(check, certificate+" is not issued for this role", "issue it with the extended key usage "+usageName(usage))
	case err != nil:
		return fail(check, certificate+" cannot be used", "check the files")
	}
	leaf := pair.Leaf
	if commonName != "" && leaf.Subject.CommonName != commonName {
		return fail(check, fmt.Sprintf("%s names %q, the peer admits %q only", certificate, leaf.Subject.CommonName, commonName),
			"issue the certificate with the common name "+commonName)
	}
	detail := fmt.Sprintf("%s valid until %s", certificate, leaf.NotAfter.UTC().Format(time.DateOnly))
	if name != "" {
		detail += ", covers " + name
	}
	if leaf.NotAfter.Sub(now) < renewBefore {
		return warn(check, detail, "renew it within 30 days; the API reloads its certificate on SIGHUP")
	}
	return ok(check, detail)
}

func usageName(u x509.ExtKeyUsage) string {
	if u == x509.ExtKeyUsageClientAuth {
		return "clientAuth"
	}
	return "serverAuth"
}

// Listen checks that an address a service will listen on is valid and free.
// With loopback, the address must be a loopback IP.
func Listen(check, address string, loopback bool) Result {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fail(check, address+" is not host:port", "write the address as host:port")
	}
	if ip := net.ParseIP(host); loopback && (ip == nil || !ip.IsLoopback()) {
		return fail(check, address+" is not a loopback address", "listen on 127.0.0.1 or ::1")
	}
	l, err := net.Listen("tcp", address)
	if err != nil {
		if errors.Is(err, syscall.EADDRINUSE) {
			return fail(check, address+" is already in use", "stop the process that holds it (the service itself, if it runs), or choose another port")
		}
		return fail(check, address+" cannot be bound: "+errnoText(err), "use an address of this host")
	}
	l.Close()
	return ok(check, address+" is free")
}

// Reachable checks that something answers TCP at address.
func Reachable(ctx context.Context, check, address, fix string) Result {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return warn(check, address+" does not answer", fix)
	}
	c.Close()
	return ok(check, address+" answers")
}

// MutualTLS connects to address with config, completes the handshake, and
// waits briefly for the peer: a peer that refuses the client's certificate
// or name closes the connection, one that admits it keeps it open or speaks
// first (an HTTP/2 server sends its settings). An address that does not
// answer is a warning, since the service may start later; a refusal fails.
func MutualTLS(ctx context.Context, check, address string, config *tls.Config) Result {
	d := net.Dialer{Timeout: 5 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return warn(check, address+" does not answer", "start the service, or check the address")
	}
	defer raw.Close()
	if config.ServerName == "" {
		// The name a client checks by default: the address's host, as gRPC does.
		config = config.Clone()
		config.ServerName, _, _ = net.SplitHostPort(address)
	}
	conn := tls.Client(raw, config)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = conn.HandshakeContext(ctx); err != nil {
		var unknown x509.UnknownAuthorityError
		var name x509.HostnameError
		switch {
		case errors.As(err, &unknown):
			return fail(check, address+" presents a certificate the configured CA did not sign", "configure the CA that signed the service's certificate")
		case errors.As(err, &name):
			return fail(check, address+" presents a certificate for another name", "connect by a name or address the service's certificate covers")
		}
		return fail(check, address+" refused the TLS handshake", "check the client certificate and the CA on both sides")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	one := make([]byte, 1)
	if _, err = conn.Read(one); err != nil {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			return fail(check, address+" closed the connection after the handshake: it refuses this client", "use a client certificate the service admits")
		}
	}
	return ok(check, fmt.Sprintf("%s admits this client over TLS 1.%d", address, conn.ConnectionState().Version-tls.VersionTLS10))
}

// Database checks the connection string for the mode, then connects: over a
// Unix socket, or over TLS, confirmed by the server (pg_stat_ssl). Errors
// from the driver are not printed: they can name users and hosts.
func Database(ctx context.Context, mode operatorconfig.Mode, dsn string) Result {
	const check = "postgresql"
	if dsn == "" {
		return fail(check, "AGENTCAPSULE_DATABASE_URL is empty", "provide the connection string in the service's protected environment")
	}
	policy := operatorconfig.CheckDatabaseURL(dsn)
	if errors.Is(policy, operatorconfig.ErrDatabaseURL) {
		return fail(check, "the connection string does not parse, or names TLS files that cannot be read", "fix AGENTCAPSULE_DATABASE_URL")
	}
	clearText := errors.Is(policy, operatorconfig.ErrDatabaseClearText)
	if clearText && mode == operatorconfig.Production {
		return fail(check, "the connection may use clear text or skip the server's verification",
			"use a Unix socket (host=/run/postgresql), or sslmode=verify-full with sslrootcert set to the CA of the server's certificate")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := pgconn.Connect(ctx, dsn)
	if err != nil {
		return fail(check, "PostgreSQL cannot be reached or refuses this connection", "check that the server runs, the address, pg_hba.conf, and that the server's certificate is signed by sslrootcert and covers the host name")
	}
	defer c.Close(context.Background())
	results, err := c.Exec(ctx, `SELECT current_setting('server_version'),
	    coalesce((SELECT CASE WHEN ssl THEN version END FROM pg_stat_ssl WHERE pid = pg_backend_pid()), '')`).ReadAll()
	if err != nil || len(results) != 1 || len(results[0].Rows) != 1 {
		return fail(check, "PostgreSQL answered the connection but not a query", "check the role's rights")
	}
	server, tlsVersion := string(results[0].Rows[0][0]), string(results[0].Rows[0][1])
	switch {
	case c.Conn().RemoteAddr().Network() == "unix":
		if clearText {
			return warn(check, "PostgreSQL "+server+" over a Unix socket; another host of the connection string may use clear text", "keep every host on a Unix socket or verify-full")
		}
		return ok(check, "PostgreSQL "+server+" over a Unix socket")
	case tlsVersion != "":
		if clearText {
			return warn(check, "PostgreSQL "+server+" over "+tlsVersion+", without verifying the server (development)", "use sslmode=verify-full in production")
		}
		return ok(check, "PostgreSQL "+server+" over "+tlsVersion+", server verified")
	}
	if mode == operatorconfig.Production {
		return fail(check, "PostgreSQL "+server+" over TCP without TLS", "use sslmode=verify-full")
	}
	return warn(check, "PostgreSQL "+server+" over TCP without TLS (development)", "use sslmode=verify-full in production")
}

// Mode reports the mode, and fails on an unknown one.
func Mode() (operatorconfig.Mode, Result) {
	mode, err := operatorconfig.ModeFromEnvironment()
	if err != nil {
		return "", fail("mode", "AGENTCAPSULE_MODE is "+fmt.Sprintf("%q", os.Getenv(operatorconfig.ModeVariable)), "unset it (production) or set it to development")
	}
	if mode == operatorconfig.Development {
		return mode, warn("mode", "development: clear text allowed on loopback and to PostgreSQL", "unset AGENTCAPSULE_MODE in production")
	}
	return mode, ok("mode", "production: TLS or a Unix socket on every hop")
}
