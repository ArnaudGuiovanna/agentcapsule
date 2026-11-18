package controlplane

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// recordingAuthority keeps every record, and answers that the replica holds
// it.
type recordingAuthority struct {
	mu      sync.Mutex
	records []AccessRecord
}

func (a *recordingAuthority) RecordAccess(_ context.Context, r AccessRecord) (AccessReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, r)
	return AccessReceipt{Known: true, Epoch: 1, Seq: uint64(len(a.records)), OnReplica: true}, nil
}

func (a *recordingAuthority) AccessProgress(context.Context, string) (AccessReceipt, error) {
	return AccessReceipt{Known: true, OnReplica: true}, nil
}

// A revocation of many objects goes in several records, each within the
// authority's bounds: at most 1000 objects, far below a stream record.
func TestLongRevocationGoesInSeveralRecords(t *testing.T) {
	s, _ := freshStore(t, "manual", 10)
	authority := &recordingAuthority{}
	s.RecordAccessWith(authority)
	tx, err := s.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollback(tx)
	revoked := s.revocations(tx, "")
	many := make([]string, 2500)
	for i := range many {
		many[i] = fmt.Sprintf("s%d", i)
	}
	if err = revoked.add(t.Context(), "service_token", "org_1", objects(many)); err != nil {
		t.Fatal(err)
	}
	large := [][]string{}
	for i := range 40 {
		large = append(large, []string{fmt.Sprintf("%d", i), strings.Repeat("x", 1000)})
	}
	if err = revoked.add(t.Context(), "delegated_token", "org_1", large); err != nil {
		t.Fatal(err)
	}
	var sizes []int
	for _, r := range authority.records {
		sizes = append(sizes, len(r.Objects))
	}
	if fmt.Sprint(sizes) != "[1000 1000 500 16 16 8]" || len(revoked.list) != 6 {
		t.Fatal("records", sizes, len(revoked.list))
	}
	seen := map[string]bool{}
	for _, r := range authority.records[:3] {
		for _, o := range r.Objects {
			seen[o[0]] = true
		}
	}
	if len(seen) != len(many) {
		t.Fatal("objects lost or repeated", len(seen))
	}
}
