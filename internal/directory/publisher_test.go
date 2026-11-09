package directory

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// memoryStore follows the controlplane semantics of agent_directory: a step
// applies only if the record is still where the publisher found it.
type memoryStore struct {
	row      controlplane.DirectoryWork // desired state and Directory view
	state    string
	reason   string
	deferred time.Duration
}

func (m *memoryStore) due() bool {
	return m.row.Revision > m.row.PublishedRevision || m.row.RetiredCID != ""
}

func (m *memoryStore) ClaimDirectoryWork(context.Context, int, time.Duration) ([]controlplane.DirectoryWork, error) {
	if !m.due() {
		return nil, nil
	}
	m.row.Attempt++
	return []controlplane.DirectoryWork{m.row}, nil
}

func (m *memoryStore) current(w controlplane.DirectoryWork) bool {
	return w.PublishedRevision == m.row.PublishedRevision && w.PublishedCID == m.row.PublishedCID && m.row.RetiredCID == ""
}

func (m *memoryStore) RecordDirectoryPublished(_ context.Context, w controlplane.DirectoryWork, cid string) error {
	if !m.current(w) {
		return controlplane.ErrConflict
	}
	if m.row.PublishedCID != cid {
		m.row.RetiredCID = m.row.PublishedCID
	}
	m.row.PublishedCID, m.row.PublishedRevision, m.state, m.reason, m.row.Attempt = cid, w.Revision, "published", "", 0
	return nil
}

func (m *memoryStore) RecordDirectoryUnpublished(_ context.Context, w controlplane.DirectoryWork, reason string) error {
	if !m.current(w) {
		return controlplane.ErrConflict
	}
	m.row.RetiredCID, m.row.PublishedCID, m.row.PublishedRevision, m.reason, m.row.Attempt = m.row.PublishedCID, "", w.Revision, reason, 0
	m.state = "unpublished"
	if reason != "" {
		m.state = "invalid"
	}
	return nil
}

func (m *memoryStore) RecordDirectoryRetired(_ context.Context, _ string, cid string) error {
	if m.row.RetiredCID != cid {
		return controlplane.ErrConflict
	}
	m.row.RetiredCID = ""
	return nil
}

func (m *memoryStore) DeferDirectoryWork(_ context.Context, _ string, delay time.Duration) error {
	m.deferred = delay
	return nil
}

type memoryDirectory struct {
	records    map[string]string // cid -> description
	down       bool
	deleteDown bool
	pushes     int
}

func (d *memoryDirectory) Push(_ context.Context, raw []byte) (string, error) {
	if d.down {
		return "", ErrUnavailable
	}
	d.pushes++
	if string(raw) == "" {
		return "", errors.New("empty")
	}
	var r struct{ Description, Version string }
	_ = json.Unmarshal(raw, &r)
	if r.Description == "refuse me" {
		return "", &InvalidRecordError{Message: "unknown skill"}
	}
	cid := "cid-" + r.Version + "-" + r.Description
	d.records[cid] = r.Description
	return cid, nil
}

func (d *memoryDirectory) Delete(_ context.Context, cid string) error {
	if d.down || d.deleteDown {
		return ErrUnavailable
	}
	delete(d.records, cid)
	return nil
}

func TestPublisherFollowsTheAgentsRevisions(t *testing.T) {
	store := &memoryStore{row: controlplane.DirectoryWork{AgentID: "agt_1", TenantID: "org_1", Revision: 1, Publish: true,
		Description: "first", Skills: []int{10302}, CreatedAt: time.Now()}}
	dir := &memoryDirectory{records: map[string]string{}}
	p := &Publisher{Store: store, Directory: dir}
	run := func() {
		t.Helper()
		if _, err := p.RunOnce(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	only := func(cid string) {
		t.Helper()
		if len(dir.records) != 1 || dir.records[cid] == "" || store.row.PublishedCID != cid || store.due() {
			t.Fatalf("Directory %v, store %+v", dir.records, store.row)
		}
	}

	run() // first publication
	only("cid-1.0.1-first")

	store.row.Revision, store.row.Description = 2, "second" // new description
	run()
	only("cid-1.0.2-second")

	// The Directory is down: nothing is recorded, the work comes back later.
	store.row.Revision, store.row.Description = 3, "third"
	dir.down = true
	run()
	if store.row.PublishedRevision != 2 || store.deferred != 5*time.Second || !store.due() {
		t.Fatal("an outage was recorded as progress", store.row, store.deferred)
	}
	run()
	if store.deferred != 10*time.Second {
		t.Fatal("no backoff", store.deferred)
	}
	dir.down = false
	run()
	only("cid-1.0.3-third")

	// The new record is recorded, but the old one cannot be deleted yet: it is
	// kept as retired and deleted on a later round.
	store.row.Revision, store.row.Description = 4, "fourth"
	dir.deleteDown = true
	run()
	if store.row.PublishedCID != "cid-1.0.4-fourth" || store.row.RetiredCID != "cid-1.0.3-third" || len(dir.records) != 2 {
		t.Fatal("retired record", store.row, dir.records)
	}
	dir.deleteDown = false
	run()
	only("cid-1.0.4-fourth")

	// The schema refuses the new description: the old record is withdrawn too.
	store.row.Revision, store.row.Description = 5, "refuse me"
	run()
	if store.state != "invalid" || store.reason != "unknown skill" || len(dir.records) != 0 || store.row.PublishedCID != "" || store.due() {
		t.Fatal("invalid record", store.state, store.reason, dir.records, store.row)
	}

	store.row.Revision, store.row.Description = 6, "fixed"
	run()
	only("cid-1.0.6-fixed")

	// Hidden (or deleted, or its organization disabled): no record any more.
	store.row.Revision, store.row.Publish = 7, false
	run()
	if store.state != "unpublished" || len(dir.records) != 0 || store.row.PublishedCID != "" || store.due() {
		t.Fatal("unpublished", store.state, dir.records, store.row)
	}
	pushes := dir.pushes
	run()
	if dir.pushes != pushes {
		t.Fatal("work done twice")
	}
}

func TestBackoffIsBounded(t *testing.T) {
	for attempt, want := range map[int64]time.Duration{0: 5 * time.Second, 1: 5 * time.Second, 2: 10 * time.Second, 4: 40 * time.Second, 7: 5 * time.Minute, 60: 5 * time.Minute} {
		if got := backoff(attempt); got != want {
			t.Fatal(attempt, got, want)
		}
	}
}
