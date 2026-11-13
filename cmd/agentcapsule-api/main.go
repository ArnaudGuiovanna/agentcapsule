//go:build linux

package main

import (
	"context"
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
	"github.com/ArnaudGuiovanna/agentcapsule/internal/delegatedidentity"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The HTTP server's diagnostics must not serialize request headers or contents.
type fixedLog struct{}

func (fixedLog) Write(p []byte) (int, error) {
	_, err := fmt.Fprintln(os.Stderr, "http_transport_error")
	return len(p), err
}

func run() int {
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP loopback listener, or HTTPS listener with certificate")
	keyPath := flag.String("receipt-key-file", "", "private receipt encryption key")
	delegationPath := flag.String("delegated-identity-file", "", "local public Ed25519 trust configuration (does not activate database trust)")
	hostID := flag.String("host-id", "", "stable worker host for agent reservations")
	activeTransit := flag.String("transit-active-key", "", "active transit key ID pinned in PostgreSQL")
	var transitFiles operatorconfig.KeyFiles
	flag.Var(&transitFiles, "transit-key", "repeatable transit key ID=/absolute/private/key-file")
	cert := flag.String("tls-cert", "", "TLS certificate chain")
	tlsKey := flag.String("tls-key", "", "TLS private key")
	metricsListen := flag.String("metrics-listen", "", "loopback address serving Prometheus metrics at /metrics (none when empty)")
	flag.Parse()
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	if flag.NArg() != 0 || *keyPath == "" || *hostID == "" || (*cert == "") != (*tlsKey == "") {
		return fail("configuration_required")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil {
		return fail("listen_address_invalid")
	}
	if *cert == "" {
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
	key, err := operatorconfig.ReadPrivate(*keyPath, 32)
	if err != nil {
		return fail("receipt_key_file_invalid")
	}
	var identityVerifier *delegatedidentity.Verifier
	if *delegationPath != "" {
		cfg, e := operatorconfig.ReadDelegationConfig(*delegationPath)
		if e != nil {
			return fail("delegated_identity_configuration_invalid")
		}
		identityVerifier, e = delegatedidentity.NewVerifier(cfg)
		if e != nil {
			return fail("delegated_identity_configuration_invalid")
		}
	}
	dsn := os.Getenv("AGENTCAPSULE_DATABASE_URL")
	if dsn == "" {
		return fail("database_configuration_required")
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
	handler.SetDelegatedIdentityVerifier(identityVerifier)
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
	go func() {
		if *cert != "" {
			stopped <- server.ServeTLS(listener, *cert, *tlsKey)
		} else {
			stopped <- server.Serve(listener)
		}
	}()
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
func main() { os.Exit(run()) }
