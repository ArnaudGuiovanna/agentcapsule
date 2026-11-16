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
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/preflight"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

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
	preflightOnly := f.Bool("preflight", false, "check this configuration (TLS files, ports, PostgreSQL), print what to fix, then exit")
	if err := f.Parse(args); err != nil {
		return 2
	}
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	if f.NArg() != 0 || *keyPath == "" || *hostID == "" || (*cert == "") != (*tlsKey == "") || (*tlsName != "" && *cert == "") {
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
		return runPreflight(mode, *listen, *metricsListen, *cert, *tlsKey, *tlsName, *keyPath)
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
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
func runPreflight(mode operatorconfig.Mode, listen, metricsListen, cert, key, name, receiptKey string) int {
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
	results = append(results, preflight.Clock(h), preflight.Database(ctx, mode, os.Getenv(operatorconfig.DatabaseVariable)))
	if err := preflight.Write(os.Stdout, results); err != nil || preflight.Failed(results) {
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:])) }
