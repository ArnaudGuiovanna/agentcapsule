//go:build linux && cgo

package worker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
)

// The operator's garbage collection (OPR-5) removes from the archive root
// what the maintenance worker's own cleanup would: an agent's archives
// beyond the Keep newest of this host, every archive of a deleted agent whose
// key is destroyed, and what interrupted captures and removals left, once
// untouched for an hour. A dry run reports the same and removes nothing. The
// newest archives, a live agent's archive taken on demand, another host's
// records and a capture in progress stay.
func TestGarbageCollectionRemovesWhatRetentionAndThePurgeWould(t *testing.T) {
	l := newArchiveLab(t, "asleep", "asleep")
	ctx := t.Context()
	live, gone := l.agents[0], l.agents[1]
	id := func(n int) string { return fmt.Sprintf("arc_%032x", n) }
	record := func(e controlplane.Enrollment, host, archive string, hours int) {
		t.Helper()
		if _, err := l.db.Exec(ctx, `INSERT INTO volume_archives(archive_id,agent_id,host_id,volume_id,incarnation,started_at,captured_at,size)
            VALUES($1,$2,$3,$4,1,now()-make_interval(hours=>$5)-interval '1 minute',now()-make_interval(hours=>$5),4096)`,
			archive, e.AgentID, host, e.VolumeID, hours); err != nil {
			t.Fatal(err)
		}
	}
	// The live agent: four archives, an hour apart (1 the oldest), and one
	// taken on demand (5), which nothing records; on another host, an older
	// record (6) that this host's retention does not count. The deleted
	// agent: one archive (7).
	for n := 1; n <= 4; n++ {
		l.publish(t, live, id(n))
		record(live, "local", id(n), 5-n)
	}
	l.publish(t, live, id(5))
	record(live, "other-host", id(6), 30)
	l.publish(t, gone, id(7))
	record(gone, "local", id(7), 1)
	l.deleteAgent(t, gone)
	// Leftovers: a capture interrupted two hours ago, one still writing, a
	// removal interrupted.
	root := l.archives.Root()
	for _, name := range []string{".pending-stale", ".pending-writing", ".removed-crash"} {
		if err := os.Mkdir(filepath.Join(root, name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name, "volume.luks"), make([]byte, 100), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	for _, p := range []string{filepath.Join(root, ".pending-stale", "volume.luks"), filepath.Join(root, ".pending-stale")} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	entries := func() []string {
		t.Helper()
		list, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range list {
			names = append(names, e.Name())
		}
		return names
	}
	removed := func(e controlplane.Enrollment, archive string) bool {
		t.Helper()
		return l.records(t, e.AgentID)[archive].RemovedAt != nil
	}
	g := GarbageCollection{Store: l.store, HostID: "local", Archives: l.archives, Keep: 2}
	before := entries()
	dry, err := g.Run(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	a := dry.Archives
	if a == nil || !slices.Equal(a.Retention, []string{id(1), id(2)}) || !slices.Equal(a.Deleted, []string{id(7)}) || a.Leftovers != 2 ||
		a.Bytes < 3*4096+200 || dry.Images != nil || !dry.Found() {
		t.Fatalf("dry run: %+v", a)
	}
	if !slices.Equal(entries(), before) || removed(live, id(1)) || removed(gone, id(7)) {
		t.Fatal("a dry run removed something", entries())
	}
	done, err := g.Run(ctx, false)
	if err != nil || !slices.Equal(done.Archives.Retention, a.Retention) || !slices.Equal(done.Archives.Deleted, a.Deleted) ||
		done.Archives.Leftovers != a.Leftovers || done.Archives.Bytes != a.Bytes {
		t.Fatalf("the run did not do what its dry run said: %+v %v", done.Archives, err)
	}
	if got := entries(); !slices.Equal(got, []string{".pending-writing", id(3), id(4), id(5)}) {
		t.Fatal("left on disk", got)
	}
	for _, n := range []int{1, 2} {
		if !removed(live, id(n)) {
			t.Fatal("retention's removal is not recorded", n)
		}
	}
	if !removed(gone, id(7)) || removed(live, id(3)) || removed(live, id(6)) {
		t.Fatal("records", l.records(t, live.AgentID), l.records(t, gone.AgentID))
	}
	if again, err := g.Run(ctx, false); err != nil || again.Found() {
		t.Fatalf("a second run found more: %+v %v", again.Archives, err)
	}
}

// The garbage collection evicts the cached packages that no agent of the
// host can boot, as the worker's hourly eviction does, and the leftovers of
// downloads interrupted an hour ago or more. It keeps approved releases,
// packages an agent may boot, imports in progress and a download that is
// still writing. A dry run removes nothing.
func TestGarbageCollectionEvictsOnlyImagesNoAgentCanBoot(t *testing.T) {
	l := newImportLab(t)
	ctx := t.Context()
	released := map[string]controlplane.HarnessImport{}
	digests := map[string]string{}
	for _, name := range []string{"approved", "unused", "booting"} {
		ref := l.publish(t, name, "1.0.0")
		imp := l.request(t, "import-"+name, ref.String())
		l.importOne(t)
		released[name] = l.state(t, imp.ID)
		digests[name] = ref.Digest
	}
	for _, name := range []string{"unused", "booting"} {
		if _, err := l.accounts.DeprecateHarnessRelease(ctx, l.platform, released[name].ReleaseID, "deprecate-"+name); err != nil {
			t.Fatal(err)
		}
	}
	staging := filepath.Join(l.cache, ".staging")
	for _, name := range []string{"crashed", "writing"} {
		if err := os.MkdirAll(filepath.Join(staging, name, "pkg"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(staging, name, "pkg", "harness.ext4"), make([]byte, 1000), 0o444); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	for _, p := range []string{"crashed/pkg/harness.ext4", "crashed/pkg", "crashed"} {
		if err := os.Chtimes(filepath.Join(staging, p), old, old); err != nil {
			t.Fatal(err)
		}
	}
	booting := filepath.Join(l.importer.PackageDir(digests["booting"]), harnesspkg.RootfsFile)
	g := GarbageCollection{Store: l.store, HostID: "local", ImageCache: l.cache,
		InUse: func(context.Context) (map[string]bool, error) { return map[string]bool{booting: true}, nil }}
	cached := func(name string) bool {
		_, err := os.Stat(filepath.Join(l.importer.PackageDir(digests[name]), harnesspkg.RootfsFile))
		return err == nil
	}
	dry, err := g.Run(ctx, true)
	if err != nil || dry.Images == nil || !slices.Equal(dry.Images.Unused, []string{digests["unused"]}) || dry.Images.Leftovers != 1 ||
		dry.Images.Bytes <= 1000 || dry.Archives != nil {
		t.Fatalf("dry run: %+v %v", dry.Images, err)
	}
	if !cached("unused") {
		t.Fatal("a dry run evicted a package")
	}
	if _, err = os.Stat(filepath.Join(staging, "crashed")); err != nil {
		t.Fatal("a dry run removed a leftover", err)
	}
	done, err := g.Run(ctx, false)
	if err != nil || !slices.Equal(done.Images.Unused, dry.Images.Unused) || done.Images.Leftovers != 1 || done.Images.Bytes != dry.Images.Bytes {
		t.Fatalf("the run did not do what its dry run said: %+v %v", done.Images, err)
	}
	if cached("unused") || !cached("approved") || !cached("booting") {
		t.Fatal("eviction", cached("unused"), cached("approved"), cached("booting"))
	}
	if _, err = os.Stat(filepath.Join(staging, "crashed")); !os.IsNotExist(err) {
		t.Fatal("an interrupted download's leftover stayed", err)
	}
	if _, err = os.Stat(filepath.Join(staging, "writing", "pkg", "harness.ext4")); err != nil {
		t.Fatal("a download still writing was removed", err)
	}
	if again, err := g.Run(ctx, false); err != nil || again.Found() {
		t.Fatalf("a second run found more: %+v %v", again.Images, err)
	}
}
