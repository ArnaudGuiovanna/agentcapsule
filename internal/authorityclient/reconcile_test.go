//go:build linux && cgo

package authorityclient

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// The reconciliation's operations (ADR 006 §7, wave 7) on the API socket:
// every record, subject and store, read page by page; the announcement of
// an epoch never promoted; import_subjects begins only what the authority
// lacks, and waits the quiet period for a new one.
func TestReconciliationThroughTheAPISocket(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	ctx := t.Context()
	var ids []string
	for i := range restoreauthority.MaxExportPage + 3 {
		id := fmt.Sprintf("arv_%032d", i)
		r := restoreauthority.AccessRecord{ID: id, Kind: authoritylog.AccessAssignment, Organization: "org_1", Objects: [][]string{{"asg_" + strconv.Itoa(i)}}}
		if _, err := catalog.AppendAccess(ctx, r); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if _, err := catalog.BeginRevocation(ctx, "agent/known"); err != nil {
		t.Fatal(err)
	}
	b, err := catalog.Register(ctx, "agent-store", "agent-volume")
	if err != nil {
		t.Fatal(err)
	}
	// The quiet period of a new subject ends a second after the service
	// started, whatever ran in between: served is no later than its start.
	served := time.Now()
	l := serve(t, keys, catalog, caps(time.Second, time.Minute), startedNow)
	api := l.apiClient(t)

	records, err := api.AuthorityRecords(ctx)
	if err != nil || len(records) != len(ids) {
		t.Fatal("the records", len(records), err)
	}
	for i, r := range records {
		if r.ID != ids[i] || !r.OnReplica || r.Epoch != 1 || r.RecordedAt.IsZero() || r.Objects[0][0] != "asg_"+strconv.Itoa(i) {
			t.Fatal("a record", i, r)
		}
	}
	identity, epoch, err := api.AuthorityEpoch(ctx)
	if err != nil || identity != catalog.Identity() || epoch != 1 {
		t.Fatal("the epoch", identity, epoch, err)
	}
	if a, err := api.AuthorityAnnouncement(ctx); err != nil || a.Epoch != 1 || a.Degraded || a.Blanket != "" {
		t.Fatal("epoch 1 announces nothing", a, err)
	}
	stores, err := api.AuthorityStores(ctx)
	if err != nil || len(stores) != 1 || stores[0].ID != b.Store || stores[0].Volume != b.Volume || stores[0].Incarnation != 1 || stores[0].Sealed {
		t.Fatal("the stores", stores, err)
	}
	// A known subject answers at once; a new one waits the quiet period.
	start := time.Now()
	if err = api.ImportSubjects(ctx, []string{"agent/known"}); err != nil || time.Since(start) >= time.Second/2 {
		t.Fatal("a known subject", err, time.Since(start))
	}
	begun, err := api.c.ImportSubjects(ctx, []string{"agent/known", "request/new", "request/new"})
	if err != nil || begun != 1 || time.Since(served) < time.Second {
		t.Fatal("a new subject", begun, err, time.Since(served))
	}
	subjects, err := api.AuthoritySubjects(ctx)
	if err != nil || !slices.Equal(subjects, []string{"agent/known", "request/new"}) {
		t.Fatal("the subjects", subjects, err)
	}
	if err = api.ImportSubjects(ctx, []string{""}); !errors.Is(err, restoreauthority.ErrInput) {
		t.Fatal("an empty subject", err)
	}
	if _, _, err = api.c.ExportAccess(ctx, -1); !errors.Is(err, restoreauthority.ErrInput) {
		t.Fatal("a negative cursor", err)
	}
	if svc.MaxImportSubjects < 500 {
		t.Fatal("the reconciliation imports by 500")
	}
}
