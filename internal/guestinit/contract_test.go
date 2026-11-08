//go:build linux

package guestinit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// A separate real process supplies intentionally incompatible HTTP responses
// on its inherited Unix listener. Positive peer-credential authentication is
// exercised by the production reference harness and capsuleprotocol local tests.
func TestContractHarnessChild(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if !strings.HasPrefix(mode, "contract-child-") {
		return
	}
	config := os.NewFile(3, "config")
	boot, err := ReadHarnessBoot(config)
	config.Close()
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(4, "control")
	listener, err := net.FileListener(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out := map[string]any{"protocol": capsuleprotocol.Version, "identity": boot.Identity}
		if r.URL.Path == "/v1/health" {
			out["previous_shutdown"] = boot.PreviousShutdown
		} else if mode == "contract-child-legacy" {
			out["code"] = "unknown_operation"
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.Header().Set("X-Capsule-Protocol", capsuleprotocol.Version)
			out["features"] = []capsuleprotocol.ControlFeature{capsuleprotocol.ControlHealth, capsuleprotocol.ControlFences}
			out["limits"] = capsuleprotocol.ControlLimits{MessageBytes: capsuleprotocol.MaxMessageBytes, ContentBytes: capsuleprotocol.MaxContentBytes}
		}
		_ = json.NewEncoder(w).Encode(out)
	})}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	if err = server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(boot.DataDirectory, "terminated"), []byte("stopped"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorRejectsHealthyButIncompatibleHarnessBeforeProxy(t *testing.T) {
	root, err := os.MkdirTemp("", "acp-contract-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err = os.Chmod(root, 0711); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "fixture")
	out, err := os.OpenFile(binary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		in.Close()
		t.Fatal(err)
	}
	_, copied := io.Copy(out, in)
	err = errors.Join(copied, in.Close(), out.Close())
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid, gid = 1000, 1000
	}
	for _, mode := range []string{"legacy", "missing-application-features"} {
		t.Run(mode, func(t *testing.T) {
			data := filepath.Join(root, mode)
			if err := os.Mkdir(data, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(data, int(uid), int(gid)); err != nil {
				t.Fatal(err)
			}
			opts := ProcessOptions{Boot: HarnessBoot{Protocol: capsuleprotocol.Version, PreviousShutdown: capsuleprotocol.ShutdownClean,
				Identity:      capsuleprotocol.Identity{Incarnation: 1, AgentID: "a", Generation: 1, VMID: "0123456789abcdef"},
				DataDirectory: data, SupervisorUID: uint32(os.Geteuid())}, UID: uid, GID: gid,
				SocketPath: filepath.Join(root, mode+".sock"), Entrypoint: []string{binary, "-test.run=^TestContractHarnessChild$", "--", "contract-child-" + mode}}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			process, err := StartHarness(t.Context(), ctx, opts)
			want := capsuleprotocol.ErrUnsupportedProtocol
			if mode == "legacy" {
				want = capsuleprotocol.ErrCapabilitiesUnavailable
			}
			if process != nil || !errors.Is(err, want) {
				if process != nil {
					_ = process.Stop(ctx)
				}
				t.Fatal("healthy incompatible harness exposed a proxy", err)
			}
			if _, err := os.Stat(filepath.Join(data, "terminated")); err != nil {
				t.Fatal("rejected harness was not reaped after termination", err)
			}
		})
	}
}
