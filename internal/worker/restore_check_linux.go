//go:build linux

package worker

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore"
)

var (
	// ErrNoArchive: PostgreSQL records no archive of the agent's volume.
	ErrNoArchive = errors.New("no archive of the agent's volume is recorded")
	// ErrArchiveKey: the agent's key does not open the archive's container.
	ErrArchiveKey = errors.New("the agent's key does not open the archive")
)

// RestoreTest checks that an agent can be restored from an archive, without
// restoring it (OPR-5): the archive is complete and is the one the restore
// authority signed, it is of the agent's current volume, and the agent's key,
// which the key authority lends, opens its container. It reads PostgreSQL and
// the archive root, and asks the authorities to validate the manifest and to
// lend the key: none of them is changed. It starts no VM and takes no
// barrier, so the agent and the maintenance worker run on. It writes only in
// a new private directory under Scratch, which it removes: the copy of the
// archive that libcryptsetup reads, and an archive fetched from a store.
type RestoreTest struct {
	Store     *controlplane.Store
	HostID    string
	Authority restoreauthority.Authority
	// RuntimeRoot is the worker's runtime root and Archives its archive
	// root: Scratch must lie outside both, and outside the authorities.
	RuntimeRoot string
	Archives    *volumearchive.Store
	Scratch     string
	// Fetch, when set, returns the fetcher that copies an archive missing
	// from Archives from the off-host stores into root (ScriptFetcher).
	Fetch func(root string) ArchiveFetcher
}

// RestoreTestReport is what a passed restore test checked.
type RestoreTestReport struct {
	AgentID   string `json:"agent_id"`
	ArchiveID string `json:"archive_id"`
	// ArchiveStore is where the archive was read: local, standby or s3.
	ArchiveStore string `json:"archive_store"`
	// CapturedAt is when PostgreSQL recorded the capture; absent for an
	// archive taken on demand.
	CapturedAt         *time.Time `json:"captured_at,omitempty"`
	ArchiveIncarnation uint64     `json:"archive_incarnation"`
	Incarnation        uint64     `json:"incarnation"`
	Size               int64      `json:"size"`
	// Checked lists what passed, in order.
	Checked []string `json:"checked"`
	Seconds float64  `json:"seconds"`
}

// Run tests the restore of agentID from archiveID, or from the newest archive
// PostgreSQL records for the agent's current volume when archiveID is empty:
// the one a restore after a host's loss would take (ADR 020 §3). An archive
// that is not in the archive root is fetched from the stores when Fetch is
// set.
func (t RestoreTest) Run(ctx context.Context, agentID, archiveID string) (RestoreTestReport, error) {
	started := time.Now()
	report := RestoreTestReport{AgentID: agentID, Checked: []string{}}
	if t.Store == nil || t.Authority == nil || t.Archives == nil || t.HostID == "" || agentID == "" ||
		!filepath.IsAbs(t.Scratch) || archiveID != "" && !volumearchive.ValidID(archiveID) {
		return report, controlplane.ErrInput
	}
	for _, root := range []string{t.RuntimeRoot, t.Archives.Root()} {
		if err := restoreauthority.CheckSeparation(root, t.Scratch); err != nil {
			return report, err
		}
	}
	if err := t.Authority.SeparateFrom(t.Scratch); err != nil {
		return report, err
	}
	e, err := t.Store.VolumeEnrollment(ctx, agentID, t.HostID)
	if err != nil {
		return report, err
	}
	report.Incarnation = e.Incarnation
	records, err := t.Store.VolumeArchives(ctx, agentID)
	if err != nil {
		return report, err
	}
	records = slices.DeleteFunc(records, func(r controlplane.VolumeArchive) bool { return r.CapturedAt == nil || r.VolumeID != e.VolumeID })
	slices.SortStableFunc(records, func(a, b controlplane.VolumeArchive) int {
		return cmp.Or(b.CapturedAt.Compare(*a.CapturedAt), cmp.Compare(b.ID, a.ID))
	})
	if archiveID == "" {
		if len(records) == 0 {
			return report, ErrNoArchive
		}
		archiveID = records[0].ID
	}
	report.ArchiveID = archiveID
	if i := slices.IndexFunc(records, func(r controlplane.VolumeArchive) bool { return r.ID == archiveID }); i >= 0 {
		report.CapturedAt = records[i].CapturedAt
	}
	work, err := t.workspace()
	if err != nil {
		return report, err
	}
	defer os.RemoveAll(work)
	archives, store := t.Archives, "local"
	if _, err = archives.Manifest(archiveID); errors.Is(err, fs.ErrNotExist) {
		if t.Fetch == nil {
			return report, ErrArchiveUnavailable
		}
		// Fetched into the test's own directory: the archive root stays as
		// it is.
		if archives, err = volumearchive.New(filepath.Join(work, "archives")); err != nil {
			return report, err
		}
		if store, err = fetchArchive(ctx, t.Authority, archives, t.Fetch(archives.Root()), archiveID, nil); err != nil {
			return report, err
		}
	} else if err != nil {
		return report, err
	}
	report.ArchiveStore = store
	// The manifest's MAC and binding, a store not sealed (ValidateArchive),
	// then the size and the digest of the bytes.
	f, a, err := archives.Open(ctx, archiveID, t.Authority)
	if err != nil {
		return report, err
	}
	defer f.Close()
	report.Checked = append(report.Checked, "manifest", "digest")
	report.ArchiveIncarnation, report.Size = a.Binding.Incarnation, a.Size
	if err = archiveFits(a, e); err != nil {
		return report, err
	}
	report.Checked = append(report.Checked, "volume")
	scratch := filepath.Join(work, "volume.luks")
	if err = copyArchive(ctx, f, a, scratch); err != nil {
		return report, err
	}
	report.Checked = append(report.Checked, "copy")
	// The key the store holds now: the volume keeps its key from one
	// incarnation to the next.
	b, err := t.Authority.Lookup(ctx, agentID)
	if err != nil {
		return report, err
	}
	if b.Store != agentID || b.Volume != e.VolumeID {
		return report, restoreauthority.ErrStale
	}
	err = t.Authority.HoldKey(ctx, b, func(_ context.Context, key []byte) error {
		return volumestore.CheckContainer(scratch, e.VolumeID, key)
	})
	if errors.Is(err, volumestore.ErrLUKS) {
		return report, errors.Join(ErrArchiveKey, err)
	}
	if err != nil {
		return report, err
	}
	report.Checked = append(report.Checked, "key")
	report.Seconds = time.Since(started).Seconds()
	return report, nil
}

// workspace creates the test's private directory under Scratch.
func (t RestoreTest) workspace() (string, error) {
	st, err := os.Lstat(t.Scratch)
	if err != nil {
		return "", err
	}
	if !st.IsDir() || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0o022 != 0 {
		return "", controlplane.ErrInput
	}
	return os.MkdirTemp(t.Scratch, "restore-test-")
}

// copyArchive copies the authenticated archive to path, a new private file,
// and checks the copy against the manifest's size and digest.
func copyArchive(ctx context.Context, f *os.File, a restoreauthority.Archive, path string) error {
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(contextReader{ctx, f}, a.Size+1))
	err = errors.Join(err, out.Close())
	if err != nil {
		return err
	}
	if n != a.Size || !bytes.Equal(h.Sum(nil), a.Digest[:]) {
		return volumearchive.ErrArchive
	}
	return nil
}

// contextReader stops a long copy when ctx ends.
type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(b)
}

var restoreTestFailures = []string{"no_archive", "archive_unavailable", "archive", "key", "authority", "state", "error"}

// RestoreTestFailures is the vocabulary of RestoreTestFailure.
func RestoreTestFailures() []string { return slices.Clone(restoreTestFailures) }

// RestoreTestFailure classifies why a restore test failed: no archive is
// recorded; none can be read here or fetched; the archive is incomplete,
// altered, unsigned or not of the agent's volume; the agent's key does not
// open it; an authority refused (a deleted agent's sealed store); the agent
// has no volume on this host; or any other error.
func RestoreTestFailure(err error) string {
	switch {
	case errors.Is(err, ErrNoArchive):
		return "no_archive"
	case errors.Is(err, ErrArchiveUnavailable):
		return "archive_unavailable"
	case errors.Is(err, ErrArchiveKey):
		return "key"
	case errors.Is(err, volumearchive.ErrArchive), errors.Is(err, ErrRestoreArchive):
		return "archive"
	case errors.Is(err, restoreauthority.ErrStale), errors.Is(err, restoreauthority.ErrSealed), errors.Is(err, restoreauthority.ErrUnavailable),
		errors.Is(err, restoreauthority.ErrConflict), errors.Is(err, restoreauthority.ErrInput), errors.Is(err, restoreauthority.ErrRevoked):
		return "authority"
	case errors.Is(err, controlplane.ErrStoreEnrollment), errors.Is(err, controlplane.ErrPlacement), errors.Is(err, controlplane.ErrNotFound),
		errors.Is(err, controlplane.ErrHostLost):
		return "state"
	}
	return "error"
}
