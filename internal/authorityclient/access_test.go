//go:build linux && cgo

package authorityclient

import (
	"errors"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
)

// append_access and on_replica (ADR 006 wave 5) on both sockets: the
// service commits the record and says how far it has gone; a record of the
// same ID and other content is a conflict; an invalid one is refused; an
// unknown ID is not known. The API's client answers in the control plane's
// terms.
func TestAccessRecordsThroughTheService(t *testing.T) {
	keys, catalog := authorities(t, t.TempDir())
	l := serve(t, keys, catalog)
	api := l.apiClient(t)
	ctx := t.Context()
	record := restoreauthority.AccessRecord{ID: "arv_" + strings.Repeat("a", 32), Kind: "team_membership", Organization: "org_1",
		Objects: [][]string{{"team_1", "prn_1"}}}
	got, err := api.AppendAccess(ctx, record)
	if err != nil || !got.Known || !got.OnReplica || got.Degraded || got.Epoch != 1 {
		t.Fatal("standalone", got, err)
	}
	if status, err := api.AccessStatus(ctx, record.ID); err != nil || status != got {
		t.Fatal("on_replica", status, err)
	}
	if status, err := api.AccessStatus(ctx, "arv_"+strings.Repeat("b", 32)); err != nil || status.Known || status.OnReplica {
		t.Fatal("an unknown record", status, err)
	}
	other := record
	other.Objects = [][]string{{"team_2", "prn_1"}}
	if _, err = api.AppendAccess(ctx, other); !errors.Is(err, restoreauthority.ErrConflict) {
		t.Fatal("another record under the same ID", err)
	}
	if _, err = api.AppendAccess(ctx, restoreauthority.AccessRecord{ID: record.ID, Kind: "role", Objects: other.Objects}); !errors.Is(err, restoreauthority.ErrInput) {
		t.Fatal("an unknown kind", err)
	}
	// The worker socket serves them too, for agentcapsule-admin as root.
	worker := l.client(t)
	second := record
	second.ID = "arv_" + strings.Repeat("c", 32)
	if got, err := worker.AppendAccess(ctx, second); err != nil || !got.OnReplica {
		t.Fatal("on the worker socket", got, err)
	}
	receipt, err := api.RecordAccess(ctx, controlplane.AccessRecord{ID: "arv_" + strings.Repeat("d", 32), Kind: "member", Organization: "org_1",
		Objects: [][]string{{"prn_2"}}})
	if err != nil || !receipt.Known || !receipt.OnReplica {
		t.Fatal("the control plane's recorder", receipt, err)
	}
	records, err := catalog.AccessRecords(ctx)
	if err != nil || len(records) != 3 {
		t.Fatal("the catalogue's records", records, err)
	}
}
