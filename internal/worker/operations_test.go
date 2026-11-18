//go:build linux

package worker

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

// The worker's storage pressure (OPS-03): a file system at or past the
// threshold is recorded for the API, served as metrics, and makes a waiting
// provisioning a typed retry; one that cannot be read counts as pressed.
func TestStoragePressureIsRecordedAndServed(t *testing.T) {
	l := newDeadLab(t)
	used := map[string]float64{"/data": 0.80, "/images": 0.79}
	p := &StoragePressure{Data: "/data", Images: "/images", Threshold: 0.80, usedRatio: func(path string) (float64, error) {
		if r, ok := used[path]; ok {
			return r, nil
		}
		return 0, errors.New("unreadable")
	}}
	registry := telemetry.NewRegistry()
	if err := l.w.EnableStoragePressure(&StoragePressure{Threshold: 0.99}, nil); !errors.Is(err, controlplane.ErrInput) {
		t.Fatal("a threshold above 0.95", err)
	}
	if err := l.w.EnableStoragePressure(p, registry); err != nil {
		t.Fatal(err)
	}
	pressure := func() (data, images bool) {
		t.Helper()
		if err := l.w.recordStoragePressure(t.Context(), 5*time.Second); err != nil {
			t.Fatal(err)
		}
		if err := l.db.QueryRow(t.Context(), "SELECT data_pressure,image_pressure FROM worker_hosts WHERE host_id='local'").Scan(&data, &images); err != nil {
			t.Fatal(err)
		}
		return data, images
	}
	if data, images := pressure(); !data || images {
		t.Fatal("recorded", data, images)
	}
	rec := httptest.NewRecorder()
	registry.Handler(5*time.Second).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{`agentcapsule_worker_storage_pressure{filesystem="data"} 1`, `agentcapsule_worker_storage_pressure{filesystem="images"} 0`,
		"agentcapsule_worker_image_disk_used_ratio 0.79"} {
		if !strings.Contains(rec.Body.String(), want+"\n") {
			t.Fatal("metrics lack", want, rec.Body.String())
		}
	}
	if err := p.Refuse("/data"); !errors.Is(err, controlplane.ErrStoragePressure) || RetryReason(fmt.Errorf("provision: %w", err)) != "storage_pressure" {
		t.Fatal("a new volume under pressure", err)
	}
	used["/data"], p.Images = 0.5, "/missing"
	if data, images := pressure(); data || !images {
		t.Fatal("recorded after the change", data, images)
	}
}

// The configuration's storage_pressure: 0.80 by default, 0.5 to 0.95; the
// images are the registry's cache, <root>/releases by default.
func TestStoragePressureConfiguration(t *testing.T) {
	c := ServiceConfig{Version: 1, HostID: "host", Root: "/srv/agentcapsule", BootTimeout: "30s", BootLease: "2m", PollInterval: "1s", AttemptTimeout: "45s"}
	if p := c.Pressure(); p.Threshold != DefaultStoragePressure || p.Data != c.Root || p.Images != c.Root {
		t.Fatal("default", p)
	}
	c.Registry = &ServiceRegistry{}
	if p := c.Pressure(); p.Images != "/srv/agentcapsule/releases" {
		t.Fatal("default cache", p)
	}
	c.Registry.Cache = "/srv/images"
	if p := c.Pressure(); p.Images != "/srv/images" {
		t.Fatal("cache", p)
	}
	for value, ok := range map[float64]bool{0: true, 0.5: true, 0.9: true, 0.95: true, 0.49: false, 0.96: false, 1: false, -1: false} {
		c.StoragePressure = value
		if _, _, _, err := c.Settings(); (err == nil) != ok {
			t.Fatal("storage_pressure", value, err)
		}
	}
}

// An import under storage pressure (OPS-03) downloads nothing: it waits, and
// its last attempt rejects it as storage_pressure.
func TestImportsWaitUnderStoragePressure(t *testing.T) {
	l := newImportLab(t)
	ref := l.publish(t, "pressed", "1.0.0")
	l.importer.Pressure = func(dir string) error {
		if dir != l.cache {
			t.Error("pressure checked on", dir)
		}
		return controlplane.ErrStoragePressure
	}
	pulls := l.reg.Pulls.Load()
	imp := l.request(t, "pressed", ref.String())
	l.importOne(t)
	if v := l.state(t, imp.ID); v.State != "IMPORTING" || v.Attempts != 1 || l.reg.Pulls.Load() != pulls {
		t.Fatal("an import under pressure", v, l.reg.Pulls.Load()-pulls)
	}
	if _, err := l.db.Exec(t.Context(), "UPDATE harness_imports SET attempts=$2,next_attempt_at=clock_timestamp() WHERE id=$1",
		imp.ID, controlplane.MaxImportAttempts-1); err != nil {
		t.Fatal(err)
	}
	l.importOne(t)
	if v := l.state(t, imp.ID); v.State != "REJECTED" || v.ErrorCode != "storage_pressure" {
		t.Fatal("the last attempt under pressure", v)
	}
	l.importer.Pressure = func(string) error { return nil }
	again := l.request(t, "space", ref.String())
	l.importOne(t)
	if v := l.state(t, again.ID); v.State != "READY" {
		t.Fatal("an import once space returned", v)
	}
}

// The dispatch pass purges the audit events older than the retention (TEN-06),
// at most every ten minutes, and never without a retention.
func TestDispatchPassPurgesTheAuditTrail(t *testing.T) {
	l := newDeadLab(t)
	old := func(id string) {
		t.Helper()
		if _, err := l.db.Exec(t.Context(), `INSERT INTO operator_audit(id,created_at,actor,action,target,outcome)
            VALUES($1,clock_timestamp()-interval '40 days','local-uid:0','audit.retention_set','keep_all','done')`, id); err != nil {
			t.Fatal(err)
		}
	}
	exists := func(id string) bool {
		var n int
		if err := l.db.QueryRow(t.Context(), "SELECT count(*) FROM operator_audit WHERE id=$1", id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	old("kept")
	l.pass()
	if !exists("kept") {
		t.Fatal("purged without a retention")
	}
	days := 30
	if _, err := l.s.SetAuditRetention(t.Context(), controlplane.OperatorCommand{Actor: "local-uid:0"}, &days); err != nil {
		t.Fatal(err)
	}
	l.pass()
	if !exists("kept") {
		t.Fatal("purged again within ten minutes")
	}
	l.w.auditPurgedAt.Store(0)
	l.pass()
	if exists("kept") {
		t.Fatal("not purged past the retention")
	}
	var purges int
	if err := l.db.QueryRow(t.Context(), "SELECT count(*) FROM operator_audit WHERE action='audit.purged' AND actor='worker'").Scan(&purges); err != nil || purges != 1 {
		t.Fatal("purge not recorded", purges, err)
	}
}
