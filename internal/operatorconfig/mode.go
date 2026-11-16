package operatorconfig

import (
	"errors"
	"os"

	"github.com/jackc/pgx/v5/pgconn"
)

// Mode says how strictly a process checks its transport security
// (docs/adr/010-transport-security-and-preflight.md). Production, the
// default, refuses every clear-text hop: the API serves TLS only and
// PostgreSQL is reached over a Unix socket or verified TLS. Development
// allows clear text on loopback and to PostgreSQL, and says so on standard
// error at every start.
type Mode string

const (
	Production  Mode = "production"
	Development Mode = "development"
	// ModeVariable selects the mode; unset means production.
	ModeVariable = "AGENTCAPSULE_MODE"
	// DatabaseVariable holds the PostgreSQL connection string.
	DatabaseVariable = "AGENTCAPSULE_DATABASE_URL"
	// DevelopmentWarning is written on standard error by every process that
	// starts in development mode.
	DevelopmentWarning = "development_mode_clear_text_allowed_never_use_in_production"
)

var ErrMode = errors.New("AGENTCAPSULE_MODE must be empty, production or development")

// ModeFromEnvironment reads AGENTCAPSULE_MODE. Any value other than the two
// modes is refused, so that a typo never weakens production.
func ModeFromEnvironment() (Mode, error) {
	switch os.Getenv(ModeVariable) {
	case "", string(Production):
		return Production, nil
	case string(Development):
		return Development, nil
	}
	return "", ErrMode
}

var (
	// ErrDatabaseClearText: a host the connection string can reach is neither
	// a Unix socket nor reached with sslmode=verify-full.
	ErrDatabaseClearText = errors.New("database connection may use clear text or unverified TLS; use a Unix socket or sslmode=verify-full")
	// ErrDatabaseURL: the connection string does not parse, or names TLS
	// files that cannot be read. The connection string is never quoted.
	ErrDatabaseURL = errors.New("database connection string invalid")
)

// CheckDatabaseURL accepts a connection string only when every host it can
// reach, fallbacks included, is a Unix socket or is reached over TLS that
// verifies the server's certificate and name (sslmode=verify-full, or
// sslrootcert=system). It reads the string as the connection will, with the
// PG* environment variables, so nothing can turn clear text back on.
func CheckDatabaseURL(dsn string) error {
	c, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return ErrDatabaseURL // its text may quote the connection string
	}
	targets := append([]*pgconn.FallbackConfig{{Host: c.Host, Port: c.Port, TLSConfig: c.TLSConfig}}, c.Fallbacks...)
	for _, t := range targets {
		if network, _ := pgconn.NetworkAddress(t.Host, t.Port); network == "unix" {
			continue
		}
		if t.TLSConfig == nil || t.TLSConfig.InsecureSkipVerify || t.TLSConfig.ServerName == "" {
			return ErrDatabaseClearText
		}
	}
	return nil
}

// DatabaseURL returns AGENTCAPSULE_DATABASE_URL once it satisfies the mode,
// or the code a process prints when it does not.
func DatabaseURL(mode Mode) (string, string) {
	dsn := os.Getenv(DatabaseVariable)
	if dsn == "" {
		return "", "database_configuration_required"
	}
	if mode == Development {
		return dsn, ""
	}
	switch CheckDatabaseURL(dsn) {
	case nil:
		return dsn, ""
	case ErrDatabaseClearText:
		return "", "database_tls_required_in_production"
	}
	return "", "database_configuration_invalid"
}
