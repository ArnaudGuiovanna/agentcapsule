package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/oidcedge"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

// runOIDCEdge is `agentcapsule-api oidc-edge`: the bundled identity
// provider's public HTTPS listener (S-19, internal/oidcedge). It holds no
// database connection and no platform key; its unit runs it under a dynamic
// account with the certificate and key as systemd credentials.
func runOIDCEdge(args []string) int {
	f := flag.NewFlagSet("agentcapsule-api oidc-edge", flag.ContinueOnError)
	listen := f.String("listen", "", "public HTTPS listener, for example 0.0.0.0:9444")
	upstream := f.String("upstream", "127.0.0.1:9445", "Keycloak's loopback HTTP listener")
	cert := f.String("tls-cert", "", "TLS certificate chain (PEM), reloaded on SIGHUP")
	key := f.String("tls-key", "", "TLS private key (PEM, mode 0600), reloaded on SIGHUP")
	name := f.String("tls-server-name", "", "the identity provider's name; the certificate must cover it")
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *listen == "" || *cert == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "oidc_edge_configuration_invalid")
		return 2
	}
	host, _, err := net.SplitHostPort(*upstream)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		fmt.Fprintln(os.Stderr, "oidc_edge_upstream_not_loopback")
		return 2
	}
	served, err := operatorconfig.NewServerCertificate(*cert, *key, *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, tlsFailure(err))
		return 1
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "oidc_edge_listen_failed")
		return 1
	}
	server := oidcedge.Server(oidcedge.Handler(&url.URL{Scheme: "http", Host: *upstream}))
	server.TLSConfig = served.TLSConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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
	stopped := make(chan error, 1)
	go func() { stopped <- server.ServeTLS(listener, "", "") }()
	fmt.Fprintln(os.Stdout, "oidc_edge_started")
	select {
	case err = <-stopped:
	case <-ctx.Done():
		err = server.Shutdown(context.Background())
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "oidc_edge_failed")
		return 1
	}
	return 0
}
