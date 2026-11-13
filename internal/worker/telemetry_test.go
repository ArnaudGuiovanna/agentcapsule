//go:build linux

package worker

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/slimlink"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// Why work waits, as metrics and events report it. A pass joins the errors of
// its jobs: an organization's wake budget is named first.
func TestRetryReasons(t *testing.T) {
	away := &net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", syscall.ENOENT)}
	for want, err := range map[string]error{
		"wake_budget":      fmt.Errorf("deliver: %w", controlplane.ErrWakeBudget),
		"slim_unavailable": errors.Join(away),
		"capacity":         fmt.Errorf("start: %w", runtime.ErrCapacity),
		"error":            errors.New("database unavailable"),
	} {
		if got := RetryReason(err); got != want {
			t.Error(want, got)
		}
	}
	if got := RetryReason(&slimlink.BridgeError{Status: 503, Code: slimlink.CodeUnavailable}); got != "slim_unavailable" {
		t.Error("a bridge's refusal", got)
	}
	if got := RetryReason(errors.Join(errors.New("other"), controlplane.ErrWakeBudget)); got != "wake_budget" {
		t.Error("joined", got)
	}
	if got := RetryReason(&net.OpError{Op: "dial", Net: "vsock", Err: syscall.ECONNREFUSED}); got != "error" {
		t.Error("a VM's control channel is not SLIM", got)
	}
}

// The worker's WAL archiving gauges as Prometheus scrapes them, read from a
// real PostgreSQL (REC-03): every gauge is served, and the settings match the
// store's own reading.
func TestArchivingMetrics(t *testing.T) {
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("PostgreSQL required")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	s, err := controlplane.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	want, err := s.WALArchiving(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	registry := telemetry.NewRegistry()
	(&Placements{store: s}).enableArchivingTelemetry(registry)
	rec := httptest.NewRecorder()
	registry.Handler(5*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	values := map[string]float64{}
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if name, value, ok := strings.Cut(line, " "); ok && !strings.HasPrefix(line, "#") {
			if values[name], err = strconv.ParseFloat(value, 64); err != nil {
				t.Fatal(line, err)
			}
		}
	}
	flag := map[bool]float64{false: 0, true: 1}
	if values["agentcapsule_telemetry_collect_errors_total"] != 0 ||
		values["agentcapsule_postgres_wal_archiving_enabled"] != flag[want.Enabled] ||
		values["agentcapsule_postgres_wal_archive_timeout_seconds"] != want.Timeout.Seconds() {
		t.Fatal("archiving metrics", values, want)
	}
	for _, name := range []string{"agentcapsule_postgres_wal_archive_pending", "agentcapsule_postgres_wal_archive_failing"} {
		if v, ok := values[name]; !ok || (v != 0 && v != 1) {
			t.Fatal(name, values)
		}
	}
	// A segment may have been archived between the two readings: the age is
	// only required to be served.
	if v, ok := values["agentcapsule_postgres_wal_archive_age_seconds"]; !ok || v < 0 {
		t.Fatal("no age", values)
	}
}
