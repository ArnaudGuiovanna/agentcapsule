//go:build linux

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityclient"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// withoutAuthority is written on standard error by an API that starts in
// development mode without the authority service: production refuses to
// start without it (docs/adr/006-authority-service.md, answer 3(a)).
const withoutAuthority = "development_mode_without_authority_service_never_use_in_production"

// The HTTP server's diagnostics must not serialize request headers or contents.
type fixedLog struct{}

func (fixedLog) Write(p []byte) (int, error) {
	_, err := fmt.Fprintln(os.Stderr, "http_transport_error")
	return len(p), err
}

func run(args []string) int {
	f := flag.NewFlagSet("agentcapsule-api", flag.ContinueOnError)
	listen := f.String("listen", "127.0.0.1:8080", "HTTPS listener; plain HTTP only on loopback in development mode")
	keyPath := f.String("receipt-key-file", "", "private receipt encryption key")
	hostID := f.String("host-id", "", "stable worker host for agent reservations")
	activeTransit := f.String("transit-active-key", "", "active transit key ID pinned in PostgreSQL")
	var transitFiles operatorconfig.KeyFiles
	f.Var(&transitFiles, "transit-key", "repeatable transit key ID=/absolute/private/key-file")
	cert := f.String("tls-cert", "", "TLS certificate chain (PEM), reloaded on SIGHUP")
	tlsKey := f.String("tls-key", "", "TLS private key (PEM, mode 0600), reloaded on SIGHUP")
	tlsName := f.String("tls-server-name", "", "name clients use to reach the API; the certificate must cover it")
	metricsListen := f.String("metrics-listen", "", "loopback address serving Prometheus metrics at /metrics (none when empty)")
	preflightOnly := f.Bool("preflight", false, "check this configuration (TLS files, ports, PostgreSQL, the authority service), print what to fix, then exit")
	var authority authorityFlags
	f.StringVar(&authority.socket, "authority-socket", "", "the authority service's API socket; required in production")
	f.StringVar(&authority.restoreID, "restore-authority-id", "", "pinned identity of the restore authority (restoreauth_…)")
	f.StringVar(&authority.keyID, "key-authority-id", "", "pinned identity of the key authority (keyauth_…)")
	if err := f.Parse(args); err != nil {
		return 2
	}
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	if f.NArg() != 0 || *keyPath == "" || *hostID == "" || (*cert == "") != (*tlsKey == "") || (*tlsName != "" && *cert == "") || !authority.complete() {
		return fail("configuration_required")
	}
	// Production unless AGENTCAPSULE_MODE=development, which says so at
	// every start (docs/adr/010-transport-security-and-preflight.md).
	mode, err := operatorconfig.ModeFromEnvironment()
	if err != nil {
		return fail("mode_invalid")
	}
	if mode == operatorconfig.Development {
		fmt.Fprintln(os.Stderr, operatorconfig.DevelopmentWarning)
	}
	if *preflightOnly {
		return runPreflight(mode, *listen, *metricsListen, *cert, *tlsKey, *tlsName, *keyPath, authority)
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return fail("listen_address_invalid")
	}
	if *cert == "" {
		if mode == operatorconfig.Production {
			return fail("tls_required_in_production")
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fail("tls_required_for_non_loopback_listener")
		}
	}
	if *metricsListen != "" {
		// Metrics are technical, but a scraper reaches them on the host only.
		metricsHost, _, err := net.SplitHostPort(*metricsListen)
		if ip := net.ParseIP(metricsHost); err != nil || ip == nil || !ip.IsLoopback() {
			return fail("metrics_listen_must_be_loopback")
		}
	}
	var served *operatorconfig.ServerCertificate
	if *cert != "" {
		if served, err = operatorconfig.NewServerCertificate(*cert, *tlsKey, *tlsName); err != nil {
			return fail(tlsFailure(err))
		}
	}
	key, err := operatorconfig.ReadPrivate(*keyPath, 32)
	if err != nil {
		return fail("receipt_key_file_invalid")
	}
	dsn, code := operatorconfig.DatabaseURL(mode)
	if code != "" {
		return fail(code)
	}
	// The authority service (docs/adr/006-authority-service.md): the API
	// reaches it on its API socket, pinning both identities. Production
	// requires it; development may run without it, and says so.
	var authorities *authorityclient.API
	switch {
	case authority.socket != "":
		if authorities, err = authority.open(); err != nil {
			return fail("authority_configuration_invalid")
		}
		defer authorities.Close()
	case mode == operatorconfig.Production:
		return fail("authority_required_in_production")
	default:
		fmt.Fprintln(os.Stderr, withoutAuthority)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if authorities != nil {
		// A service that does not answer yet is waited for, and said once;
		// one that holds another installation's authorities is refused.
		waiting := telemetry.NewLogger(os.Stderr, map[string][]string{"event": {"authority_service_waiting"}})
		var once sync.Once
		if _, err = authorities.Wait(ctx, func(error) {
			once.Do(func() { waiting.Event("authority_service_waiting") })
		}); err != nil {
			return fail(authorityFailure(err))
		}
	}
	startup, cancel := context.WithTimeout(ctx, 30*time.Second)
	s, err := controlplane.Open(startup, dsn)
	if err != nil {
		cancel()
		return fail("database_initialization_failed")
	}
	defer s.Close()
	// Only the organization model runs: the legacy owner domain's acp_ tokens
	// are refused (D-01, ADR 001). Delegated tokens are verified with the keys
	// registered in PostgreSQL by agentcapsule-admin configure-delegation.
	s.CloseLegacyOwnerDomain()
	if err = s.Ready(startup); err != nil {
		cancel()
		return fail("database_schema_unavailable")
	}
	cancel()
	accounts, err := controlplane.NewAccounts(s, key)
	if err != nil {
		return fail("receipt_key_invalid")
	}
	check, checkCancel := context.WithTimeout(ctx, 10*time.Second)
	err = accounts.CheckReceiptKey(check)
	checkCancel()
	if err != nil {
		return fail("receipt_key_does_not_match_installation")
	}
	// Each new receipt is encrypted with the daily key of the authority
	// service (ADR 006 §7). The installation's key still reads the receipts
	// written before, and derives the LLM credential and download link keys.
	if authorities != nil && accounts.UseDailyReceiptKeys(authorities.ReceiptKeys()) != nil {
		return fail("api_initialization_failed")
	}
	handler, err := api.NewForHost(s, accounts, *hostID)
	if err == nil && (len(transitFiles) != 0 || *activeTransit != "") {
		keys, e := transitFiles.Read()
		if e != nil {
			return fail("transit_key_file_invalid")
		}
		transit, e := controlplane.NewTransit(s, *activeTransit, keys, 7*24*time.Hour)
		operatorconfig.ClearKeys(keys)
		if e != nil {
			return fail("transit_configuration_invalid")
		}
		check, done := context.WithTimeout(ctx, 10*time.Second)
		e = transit.CheckKeys(check)
		done()
		if e != nil {
			return fail("transit_keys_do_not_match_installation")
		}
		handler, err = api.NewForHostWithTransit(s, accounts, *hostID, transit)
	}
	if err != nil {
		return fail("api_initialization_failed")
	}
	if authorities != nil {
		handler.ReportAuthority(func(ctx context.Context) (string, error) {
			status, err := authorities.Status(ctx)
			return status.Mode, err
		})
		// Every revoking transaction appends its record to the service
		// before it commits, and the pending ones are confirmed once the
		// standby holds them (docs/adr/006-authority-service.md §7).
		s.RecordAccessWith(authorities)
		go handler.ConfirmRevocations(ctx, 5*time.Second)
	}
	// One event per request on standard output: its X-Request-ID, route
	// pattern, status and duration, never an ID from the path or a body.
	registry := telemetry.NewRegistry()
	handler.EnableTelemetry(registry, os.Stdout)
	if *metricsListen != "" {
		metricsListener, err := net.Listen("tcp", *metricsListen)
		if err != nil {
			return fail("metrics_listener_unavailable")
		}
		metrics := &http.Server{Handler: registry.Handler(5 * time.Second), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second,
			ErrorLog: log.New(fixedLog{}, "", 0)}
		go func() { _ = metrics.Serve(metricsListener) }()
		defer metrics.Close()
	}
	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(fixedLog{}, "", 0)}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return fail("listener_unavailable")
	}
	stopped := make(chan error, 1)
	if served != nil {
		server.TLSConfig = served.TLSConfig()
	}
	go func() {
		if served != nil {
			stopped <- server.ServeTLS(listener, "", "")
		} else {
			stopped <- server.Serve(listener)
		}
	}()
	if served != nil {
		// A renewed certificate takes effect on SIGHUP, for new connections;
		// files that fail the checks leave the current one in service.
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-hup:
					if err := served.Reload(); err != nil {
						fmt.Fprintln(os.Stderr, "tls_reload_failed_"+tlsFailure(err))
					} else {
						fmt.Fprintln(os.Stdout, "tls_reloaded")
					}
				}
			}
		}()
	}
	fmt.Fprintln(os.Stdout, "api_started")
	select {
	case err = <-stopped:
		if errors.Is(err, http.ErrServerClosed) {
			return 0
		}
		return fail("api_stopped")
	case <-ctx.Done():
		shutdown, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		if err = server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return fail("api_shutdown_timeout")
		}
		<-stopped
		return 0
	}
}

// authorityFlags reach the authority service's API socket.
type authorityFlags struct {
	socket, restoreID, keyID string
}

// complete reports whether the three flags are given together, or none.
func (a authorityFlags) complete() bool {
	return (a.socket == "") == (a.restoreID == "") && (a.socket == "") == (a.keyID == "")
}

func (a authorityFlags) open() (*authorityclient.API, error) {
	return authorityclient.NewAPI(a.socket, a.restoreID, a.keyID)
}

// authorityFailure names why the API did not reach the authority service.
func authorityFailure(err error) string {
	switch {
	case errors.Is(err, authorityservice.ErrIdentity):
		return "authority_identity_mismatch"
	case errors.Is(err, authorityservice.ErrRole):
		return "authority_socket_role_mismatch"
	case errors.Is(err, authorityservice.ErrProtocol):
		return "authority_protocol_unsupported"
	}
	return "authority_service_unavailable"
}

// tlsFailure names why the TLS files were refused.
func tlsFailure(err error) string {
	switch {
	case errors.Is(err, operatorconfig.ErrTLSKeyMismatch):
		return "tls_key_does_not_match_certificate"
	case errors.Is(err, operatorconfig.ErrTLSValidity):
		return "tls_certificate_expired_or_not_yet_valid"
	case errors.Is(err, operatorconfig.ErrTLSName):
		return "tls_certificate_does_not_cover_server_name"
	case errors.Is(err, operatorconfig.ErrTLSUsage):
		return "tls_certificate_not_for_servers"
	}
	return "tls_files_invalid"
}

// runPreflight checks the API's own configuration and exits 1 when a check
// fails. It changes nothing: each listener is opened and closed at once.
func runPreflight(mode operatorconfig.Mode, listen, metricsListen, cert, key, name, receiptKey string, authority authorityFlags) int {
	_, modeResult := preflight.Mode()
	results := []preflight.Result{modeResult}
	h := preflight.System()
	switch {
	case cert != "":
		results = append(results, preflight.Certificate(h, "api_certificate", cert, key, x509.ExtKeyUsageServerAuth, name, ""))
		if name == "" {
			results = append(results, preflight.Result{Check: "api_server_name", Status: preflight.Warn, Detail: "-tls-server-name not given: the name is not checked",
				Fix: "give the name clients use, so that the API refuses a certificate that does not cover it"})
		}
	case mode == operatorconfig.Production:
		results = append(results, preflight.Result{Check: "api_certificate", Status: preflight.Fail, Detail: "no -tls-cert and -tls-key: production serves HTTPS only",
			Fix: "give the certificate chain and its key"})
	default:
		results = append(results, preflight.Result{Check: "api_certificate", Status: preflight.Warn, Detail: "plain HTTP on loopback (development)",
			Fix: "give -tls-cert and -tls-key in production"})
	}
	results = append(results, preflight.Listen("api_listen", listen, false))
	if metricsListen != "" {
		results = append(results, preflight.Listen("metrics_listen", metricsListen, true))
	}
	if _, err := operatorconfig.ReadPrivate(receiptKey, 32); err != nil {
		results = append(results, preflight.Result{Check: "receipt_key", Status: preflight.Fail, Detail: receiptKey + " is not a private 32-byte file",
			Fix: "the file written by agentcapsule-admin bootstrap, mode 0600, owned by the API's user"})
	} else {
		results = append(results, preflight.Result{Check: "receipt_key", Status: preflight.OK, Detail: receiptKey})
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	results = append(results, authorityCheck(ctx, mode, authority), preflight.Clock(h),
		preflight.Database(ctx, mode, os.Getenv(operatorconfig.DatabaseVariable)))
	if err := preflight.Write(os.Stdout, results); err != nil || preflight.Failed(results) {
		return 1
	}
	return 0
}

// authorityCheck asks the authority service for its status once, as the API
// does at start, and says what to fix.
func authorityCheck(ctx context.Context, mode operatorconfig.Mode, authority authorityFlags) preflight.Result {
	const check = "authority"
	const flags = "give -authority-socket, -restore-authority-id and -key-authority-id (docs/recovery.md, Install the authority service)"
	if authority.socket == "" {
		if mode == operatorconfig.Production {
			return preflight.Result{Check: check, Status: preflight.Fail, Detail: "no -authority-socket: production needs the authority service", Fix: flags}
		}
		return preflight.Result{Check: check, Status: preflight.Warn, Detail: "no authority service (development)", Fix: flags + " in production"}
	}
	client, err := authority.open()
	if err != nil {
		return preflight.Result{Check: check, Status: preflight.Fail, Detail: "the authority flags are invalid",
			Fix: "an absolute socket path of at most 100 bytes, and the identities that the init commands printed"}
	}
	defer client.Close()
	probe, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	status, err := client.Status(probe)
	switch {
	case errors.Is(err, authorityservice.ErrIdentity):
		return preflight.Result{Check: check, Status: preflight.Fail, Detail: "the service on " + authority.socket + " holds other authorities than the pinned ones",
			Fix: "pin the identities of /etc/agentcapsule/authority.json"}
	case errors.Is(err, authorityservice.ErrRole):
		return preflight.Result{Check: check, Status: preflight.Fail, Detail: authority.socket + " is not the service's API socket",
			Fix: "use the service's api_socket"}
	case errors.Is(err, syscall.EACCES):
		return preflight.Result{Check: check, Status: preflight.Fail, Detail: "this account may not open " + authority.socket,
			Fix: "add the API's account to the group agentcapsule-authority-clients (deploy/systemd/agentcapsule-authority.sysusers), then restart the API"}
	case err != nil:
		return preflight.Result{Check: check, Status: preflight.Fail, Detail: "the authority service does not answer on " + authority.socket,
			Fix: "start agentcapsule-authority, and check that its api_uid is this account"}
	}
	switch status.Mode {
	case restoreauthority.ModeDegraded:
		return preflight.Result{Check: check, Status: preflight.Warn, Detail: "the authority service runs in degraded mode, without its standby",
			Fix: "bring the standby back (docs/recovery.md, Degraded mode)"}
	case restoreauthority.ModeWaiting:
		return preflight.Result{Check: check, Status: preflight.Warn, Detail: "the authority service waits for its standby and runs nothing",
			Fix: "start agentcapsule-authority serve on the standby, or check the address and the firewall"}
	case restoreauthority.ModeStandalone:
		return preflight.Result{Check: check, Status: preflight.OK,
			Detail: "the authority service answers with the pinned identities; standalone: no replica, no protection against the host's loss"}
	}
	return preflight.Result{Check: check, Status: preflight.OK, Detail: "the authority service answers with the pinned identities, synchronous with its standby"}
}

func main() { os.Exit(run(os.Args[1:])) }
