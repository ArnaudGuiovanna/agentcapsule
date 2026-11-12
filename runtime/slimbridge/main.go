// Command agentcapsule-slim-bridge carries the platform's deliveries between
// agents over SLIM (INT-04, docs/interop.md). It is the only process that holds
// SLIM credentials: one mutual-TLS connection to the node, the shared
// application secret, and a SLIM name per agent it answers for. Agents never
// see SLIM.
//
// The worker talks to it over two local Unix sockets (internal/slimlink):
// "serve this agent's name", "send this delivery to that name", and, from the
// bridge back to the worker, "this delivery arrived for that name". Each
// delivery is one A2A 1.0 message over SLIM (slim-a2a-go); its answer, a task
// with the guest's receipt as artifact, is what the mailbox acknowledges.
//
// SLIM clients do not reconnect after the node restarts, so the bridge probes
// itself through the node and exits after three failures in a row; its
// supervisor (for example systemd with Restart=always) starts a new one. While it is away the
// worker spends no delivery attempt.
//
//	agentcapsule-slim-bridge -config /etc/agentcapsule/slim-bridge.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Failure{Error: code})
}

func decode(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 2*maxBody))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// handler is the bridge's side of the local protocol.
func (b *Bridge) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+healthPath, func(w http.ResponseWriter, _ *http.Request) {
		if !b.healthy.Load() {
			fail(w, http.StatusServiceUnavailable, codeUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(Health{Name: b.cfg.Name})
	})
	mux.HandleFunc("POST "+servePath, func(w http.ResponseWriter, r *http.Request) {
		var in ServeRequest
		if err := decode(r, &in); err != nil {
			fail(w, http.StatusBadRequest, codeInvalid)
			return
		}
		if !b.healthy.Load() {
			fail(w, http.StatusServiceUnavailable, codeUnavailable)
			return
		}
		if err := b.Serve(in.Name); errors.Is(err, errInvalid) {
			fail(w, http.StatusBadRequest, codeInvalid)
			return
		} else if err != nil {
			fail(w, http.StatusServiceUnavailable, codeUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST "+sendPath, func(w http.ResponseWriter, r *http.Request) {
		var in SendRequest
		if err := decode(r, &in); err != nil {
			fail(w, http.StatusBadRequest, codeInvalid)
			return
		}
		receipt, status, code := b.Send(r.Context(), in)
		if status != http.StatusOK {
			fail(w, status, code)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	})
	return mux
}

// run returns the process's exit code: 0 on SIGTERM, 2 for a bad
// configuration, 3 when the node is lost or unreachable.
func run(args []string) int {
	flags := flag.NewFlagSet("agentcapsule-slim-bridge", flag.ContinueOnError)
	path := flags.String("config", "/etc/agentcapsule/slim-bridge.json", "configuration file")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	cfg, secret, err := LoadConfig(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "slim_bridge_configuration_invalid:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	b, err := Connect(cfg, secret)
	if err != nil {
		fmt.Fprintln(os.Stderr, "slim_node_unreachable:", err)
		return 3
	}
	l, err := listen(cfg.Socket, uint32(cfg.WorkerUID))
	if err != nil {
		fmt.Fprintln(os.Stderr, "slim_bridge_socket_unavailable:", err)
		return 2
	}
	server := &http.Server{Handler: b.handler(), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context { return ctx }}
	go func() { _ = server.Serve(l) }()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				b.Release(cfg.Idle())
			}
		}
	}()
	fmt.Println("slim_bridge_started", cfg.Name)
	err = b.Watch(ctx)
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = server.Shutdown(shutdown)
	cancel()
	if errors.Is(err, ErrNodeLost) {
		fmt.Fprintln(os.Stderr, "slim_node_lost")
		return 3
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:])) }
