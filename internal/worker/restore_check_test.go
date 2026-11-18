//go:build linux && cgo

package worker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// databaseDigest hashes the rows of every table of the test's schema.
func databaseDigest(t *testing.T, db *pgxpool.Pool) map[string]string {
	t.Helper()
	rows, err := db.Query(t.Context(), `SELECT table_name FROM information_schema.tables
        WHERE table_schema=current_schema() AND table_type='BASE TABLE' ORDER BY table_name`)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(tables) < 50 {
		t.Fatal("tables", len(tables), err)
	}
	digest := map[string]string{}
	for _, table := range tables {
		var d string
		if err = db.QueryRow(t.Context(), `SELECT coalesce(md5(string_agg(t::text, ',' ORDER BY t::text)),'')
            FROM `+pgx.Identifier{table}.Sanitize()+` t`).Scan(&d); err != nil {
			t.Fatal(table, err)
		}
		digest[table] = d
	}
	return digest
}

// treeDigest names every entry under root with its mode, size, time and,
// for a file, the SHA-256 of its content.
func treeDigest(t *testing.T, root string) map[string]string {
	t.Helper()
	digest := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := fmt.Sprintf("%v %d %d", info.Mode(), info.Size(), info.ModTime().UnixNano())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			entry += " " + hex.EncodeToString(sum[:])
		}
		digest[strings.TrimPrefix(path, root)] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// luksVolume creates the agent's encrypted volume in the runtime root, as
// provisioning does, with the key the key authority holds for it.
func (l *restoreLab) luksVolume(e controlplane.Enrollment, runtimeRoot string) string {
	l.t.Helper()
	volumes, err := volumestore.New(runtimeRoot)
	if err != nil {
		l.t.Fatal(err)
	}
	var c volumestore.Container
	err = l.authority.HoldKey(l.t.Context(), l.binding(), func(ctx context.Context, key []byte) error {
		c, err = volumes.Prepare(ctx, volumestore.Spec{AgentID: e.AgentID, VolumeID: e.VolumeID, SizeMiB: restoreVolumeSize >> 20}, key)
		return err
	})
	if err != nil {
		l.t.Fatal(err)
	}
	return c.Path
}

// captureFile archives the file at path as the agent's volume.
func (l *restoreLab) captureFile(path, id string) restoreauthority.Archive {
	l.t.Helper()
	f, err := os.Open(path)
	if err != nil {
		l.t.Fatal(err)
	}
	defer f.Close()
	a, err := l.archives.Capture(l.t.Context(), volumearchive.Spec{ID: id, Binding: l.binding(), HarnessDigest: "sha256:" + strings.Repeat("a", 64),
		Size: restoreVolumeSize}, f, l.authority)
	if err != nil {
		l.t.Fatal(err)
	}
	return a
}

// The operator's restore test (OPR-5) checks the agent's newest recorded
// archive, as a restore after a host's loss would take it: its signed
// manifest, its bytes, that it is of the agent's current volume, and that
// the agent's key, lent by the key authority, opens its container. It
// changes nothing: no row of PostgreSQL, nothing in the authorities, the
// archive root or the runtime root, and it leaves its scratch directory
// empty. It fetches an archive missing here into its own directory, and
// names each failure: another key, altered bytes, no archive, an archive no
// store holds, an agent unknown here, a scratch directory inside the
// runtime.
func TestRestoreTestChecksTheNewestArchiveAndChangesNothing(t *testing.T) {
	forEachAuthority(t, testRestoreTestChecksTheNewestArchiveAndChangesNothing)
}

func testRestoreTestChecksTheNewestArchiveAndChangesNothing(t *testing.T, implementation string) {
	l := newRestoreLab(t, implementation)
	ctx := t.Context()
	runtimeRoot := filepath.Join(t.TempDir(), "runtime")
	volume := l.luksVolume(l.e, runtimeRoot)
	older := l.captureFile(volume, "arc_"+strings.Repeat("1", 32))
	l.recordArchive(l.e, older.ID, "26 hours")
	newest := l.captureFile(volume, "arc_"+strings.Repeat("2", 32))
	l.recordArchive(l.e, newest.ID, "2 hours")
	onDemand := l.captureFile(volume, "arc_"+strings.Repeat("3", 32)) // newer, but not recorded
	// A container of the agent's volume ID formatted with another key,
	// signed as the agent's archive: only the key check refuses it.
	stranger, err := volumestore.New(filepath.Join(t.TempDir(), "stranger"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	c, err := stranger.Prepare(ctx, volumestore.Spec{AgentID: l.e.AgentID, VolumeID: l.e.VolumeID, SizeMiB: restoreVolumeSize >> 20}, key)
	if err != nil {
		t.Fatal(err)
	}
	forged := l.captureFile(c.Path, "arc_"+strings.Repeat("4", 32))

	scratch := t.TempDir()
	test := RestoreTest{Store: l.store, HostID: "local", Authority: l.authority, RuntimeRoot: runtimeRoot, Archives: l.archives, Scratch: scratch}
	binding := l.binding()
	losses, err := l.authority.Losses(ctx, l.e.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	database, archives, runtime := databaseDigest(t, l.db), treeDigest(t, l.archives.Root()), treeDigest(t, runtimeRoot)
	unchanged := func(step string) {
		t.Helper()
		if got := databaseDigest(t, l.db); !maps.Equal(got, database) {
			for table := range got {
				if got[table] != database[table] {
					t.Errorf("%s: the table %s changed", step, table)
				}
			}
		}
		if !maps.Equal(treeDigest(t, l.archives.Root()), archives) || !maps.Equal(treeDigest(t, runtimeRoot), runtime) {
			t.Fatal(step, ": the archive root or the runtime root changed")
		}
		if b := l.binding(); b != binding {
			t.Fatal(step, ": the agent's binding changed", b, binding)
		}
		if now, err := l.authority.Losses(ctx, l.e.AgentID); err != nil || len(now) != len(losses) {
			t.Fatal(step, ": the authority's losses changed", now, err)
		}
		if left, err := os.ReadDir(scratch); err != nil || len(left) != 0 {
			t.Fatal(step, ": the scratch directory is not empty", left, err)
		}
	}

	report, err := test.Run(ctx, l.e.AgentID, "")
	if err != nil {
		t.Fatal(err)
	}
	if report.ArchiveID != newest.ID || report.ArchiveStore != "local" || report.CapturedAt == nil || report.Size != restoreVolumeSize ||
		report.ArchiveIncarnation != 1 || report.Incarnation != 1 || !slices.Equal(report.Checked, []string{"manifest", "digest", "volume", "copy", "key"}) {
		t.Fatalf("report %+v", report)
	}
	unchanged("the newest archive")
	if report, err = test.Run(ctx, l.e.AgentID, onDemand.ID); err != nil || report.CapturedAt != nil || len(report.Checked) != 5 {
		t.Fatalf("an archive taken on demand: %+v %v", report, err)
	}
	if _, err = test.Run(ctx, l.e.AgentID, forged.ID); RestoreTestFailure(err) != "key" {
		t.Fatal("another key's container passed", err)
	}
	unchanged("the failures")

	// Missing here: fetched from a store into the test's own directory.
	stores := offHostStores{"standby": t.TempDir(), "s3": t.TempDir()}
	if err = os.Rename(filepath.Join(l.archives.Root(), newest.ID), filepath.Join(stores["standby"], newest.ID)); err != nil {
		t.Fatal(err)
	}
	archives = treeDigest(t, l.archives.Root())
	if _, err = test.Run(ctx, l.e.AgentID, ""); RestoreTestFailure(err) != "archive_unavailable" {
		t.Fatal("an archive neither here nor fetched", err)
	}
	test.Fetch = stores.fetch
	if report, err = test.Run(ctx, l.e.AgentID, ""); err != nil || report.ArchiveID != newest.ID || report.ArchiveStore != "standby" {
		t.Fatalf("fetched: %+v %v", report, err)
	}
	unchanged("a fetched archive")
	// The fetched copy is checked too: a damaged copy on both stores fails.
	data, err := os.ReadFile(filepath.Join(stores["standby"], newest.ID, "volume.luks"))
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err = os.WriteFile(filepath.Join(stores["standby"], newest.ID, "volume.luks"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = test.Run(ctx, l.e.AgentID, ""); RestoreTestFailure(err) != "archive_unavailable" {
		t.Fatal("a damaged copy passed", err)
	}
	test.Fetch = nil
	// Altered bytes here.
	damaged := filepath.Join(l.archives.Root(), older.ID, "volume.luks")
	if data, err = os.ReadFile(damaged); err != nil {
		t.Fatal(err)
	}
	data[restoreVolumeSize/2] ^= 1
	if err = os.WriteFile(damaged, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = test.Run(ctx, l.e.AgentID, older.ID); RestoreTestFailure(err) != "archive" {
		t.Fatal("altered bytes passed", err)
	}
	// No archive recorded; an agent this host does not hold.
	other := l.addAgent("never-archived", true, 101)
	if _, err = test.Run(ctx, other.AgentID, ""); RestoreTestFailure(err) != "no_archive" {
		t.Fatal("an agent without archive", err)
	}
	if _, err = test.Run(ctx, "agt_"+strings.Repeat("0", 32), ""); RestoreTestFailure(err) != "state" {
		t.Fatal("an unknown agent", err)
	}
	inside := test
	inside.Scratch = filepath.Join(runtimeRoot, "scratch")
	if _, err = inside.Run(ctx, l.e.AgentID, ""); err == nil || errors.Is(err, ErrNoArchive) {
		t.Fatal("a scratch directory inside the runtime root", err)
	}
	if left, err := os.ReadDir(scratch); err != nil || len(left) != 0 {
		t.Fatal("the scratch directory is not empty", left, err)
	}
}
