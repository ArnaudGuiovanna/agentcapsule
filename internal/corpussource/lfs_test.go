package corpussource_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/corpussource/forgetest"
)

// lfsRepo puts n LFS objects of various sizes in a repository.
func lfsRepo(t *testing.T, l *lab, kind, repo string, private bool, n int) ([]corpussource.Pointer, map[string][]byte) {
	t.Helper()
	objects := map[string][]byte{}
	var pointers []corpussource.Pointer
	for i := 0; i < n; i++ {
		b := randomBytes(t, 1+(i*997)%9000)
		oid := forgetest.OID(b)
		objects[oid] = b
		pointers = append(pointers, corpussource.Pointer{OID: oid, Size: int64(len(b))})
	}
	l.forge.Add(&forgetest.Repo{Kind: kind, Path: repo, Private: private, Token: secret, Objects: objects})
	return pointers, objects
}

// readDrive checks the drive's format (ADR 023 §6.2) and that each object
// is at its offset, with zeros between and after them.
func readDrive(t *testing.T, dir string, d corpussource.LFSDrive, objects map[string][]byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, corpussource.LFSFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw)%corpussource.Block != 0 || int64(len(raw)) != corpussource.Padded(d.Bytes) || string(raw[:8]) != corpussource.LFSMagic {
		t.Fatal("the drive's size or magic:", len(raw), d.Bytes)
	}
	sum := sha256.Sum256(raw[:d.Bytes])
	if d.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("the drive's sha256 is not its content's")
	}
	n := binary.BigEndian.Uint64(raw[8:16])
	var idx corpussource.LFSIndex
	dec := json.NewDecoder(bytes.NewReader(raw[16 : 16+n]))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&idx); err != nil || idx.Schema != corpussource.LFSSchema || len(idx.Objects) != len(objects) || d.Objects != len(objects) {
		t.Fatal("the drive's index:", err, idx.Schema, len(idx.Objects))
	}
	covered := make([]bool, len(raw))
	for i := range 16 + int(n) {
		covered[i] = true
	}
	var total int64
	for i, o := range idx.Objects {
		if o.Offset%corpussource.Block != 0 || o.Offset < 16+int64(n) || (i > 0 && (o.OID <= idx.Objects[i-1].OID || o.Offset < idx.Objects[i-1].Offset+idx.Objects[i-1].Length)) {
			t.Fatal("an object out of place:", o)
		}
		if !bytes.Equal(raw[o.Offset:o.Offset+o.Length], objects[o.OID]) {
			t.Fatal("an object's bytes are not the forge's:", o.OID)
		}
		for j := o.Offset; j < o.Offset+o.Length; j++ {
			covered[j] = true
		}
		total += o.Length
	}
	if total != d.ObjectBytes {
		t.Fatal("object bytes", total, d.ObjectBytes)
	}
	for i, c := range covered {
		if !c && raw[i] != 0 {
			t.Fatal("a byte outside the head and the objects is not zero:", i)
		}
	}
}

// LFS objects come through the batch API, each checked against its oid,
// into one drive with its index at its head. The credential goes to the
// forge's batch API only; each object's host gets the header the forge gave
// for it.
func TestLFSObjectsFillTheDrive(t *testing.T) {
	for _, kind := range []string{corpussource.GitHub, corpussource.GitLab} {
		t.Run(kind, func(t *testing.T) {
			l := newLab(t, limits)
			repo := "acme/media"
			if kind == corpussource.GitLab {
				repo = "school/media"
			}
			pointers, objects := lfsRepo(t, l, kind, repo, true, 130)
			// The builder may list an object twice; it is fetched once.
			pointers = append(pointers, pointers[3])
			src := source(kind, repo)
			if _, err := l.fetcher.LFS(t.Context(), src, "", pointers, l.dir, corpussource.LFSOptions{}); !errors.Is(err, corpussource.ErrDenied) {
				t.Fatal("a private repository's LFS without the credential:", err)
			}
			l.forge.Reset()
			batches := 0
			d, err := l.fetcher.LFS(t.Context(), src, secret, pointers, l.dir, corpussource.LFSOptions{BeforeBatch: func() error { batches++; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			if batches != 2 {
				t.Fatal("130 objects in", batches, "batch calls")
			}
			readDrive(t, l.dir, d, objects)
			for _, req := range l.forge.Requests() {
				switch {
				case strings.HasSuffix(req.Path, "/objects/batch"):
					if !strings.HasPrefix(req.Authorization, "Basic ") {
						t.Fatal("the batch call went without the credential")
					}
				case strings.HasPrefix(req.Authorization, "Basic ") && kind == corpussource.GitHub:
					t.Fatal("the credential went to the LFS host")
				}
			}

			// Download URLs that carry their own signature, with no header:
			// GitHub's LFS host gets no credential; GitLab's forge serves the
			// object itself and gets the repository's.
			l.forge.SignedURLs = true
			l.forge.Reset()
			dir := t.TempDir()
			if d, err = l.fetcher.LFS(t.Context(), src, secret, pointers, dir, corpussource.LFSOptions{}); err != nil {
				t.Fatal("signed download URLs:", err)
			}
			readDrive(t, dir, d, objects)
			for _, req := range l.forge.Requests() {
				if req.Host == forgetest.GitHubLFS && req.Authorization != "" {
					t.Fatal("a credential went to the LFS host")
				}
				if strings.Contains(req.Path, "/gitlab-lfs/") && !strings.HasPrefix(req.Authorization, "Basic ") {
					t.Fatal("the forge's own download went without the repository's credential")
				}
			}
		})
	}
}

// An object whose bytes do not hash to its oid fails the fetch as
// integrity, and is not recorded as verified.
func TestAlteredLFSObjectIsRefused(t *testing.T) {
	l := newLab(t, limits)
	pointers, _ := lfsRepo(t, l, corpussource.GitHub, "acme/media", false, 5)
	l.forge.Tampered[pointers[2].OID] = true
	src := source(corpussource.GitHub, "acme/media")
	if _, err := l.fetcher.LFS(t.Context(), src, "", pointers, l.dir, corpussource.LFSOptions{}); !errors.Is(err, corpussource.ErrIntegrity) {
		t.Fatal("an altered object:", err)
	}
	if raw, _ := os.ReadFile(filepath.Join(l.dir, corpussource.LFSJournal)); strings.Contains(string(raw), pointers[2].OID) {
		t.Fatal("an altered object was recorded as verified")
	}
	// A pointer whose size the forge contradicts is refused too.
	bad := []corpussource.Pointer{{OID: pointers[0].OID, Size: pointers[0].Size + 1}}
	if _, err := l.fetcher.LFS(t.Context(), src, "", bad, t.TempDir(), corpussource.LFSOptions{}); !errors.Is(err, corpussource.ErrIntegrity) {
		t.Fatal("a pointer of the wrong size:", err)
	}
	missing := []corpussource.Pointer{{OID: strings.Repeat("ab", 32), Size: 10}}
	if _, err := l.fetcher.LFS(t.Context(), src, "", missing, t.TempDir(), corpussource.LFSOptions{}); !errors.Is(err, corpussource.ErrNotFound) {
		t.Fatal("an object the forge does not have:", err)
	}
}

// A retry downloads only what an earlier attempt did not verify: a cut in
// the second batch leaves every object before it, which is not fetched
// again.
func TestLFSResumesWithoutDownloadingVerifiedObjects(t *testing.T) {
	l := newLab(t, limits)
	pointers, objects := lfsRepo(t, l, corpussource.GitLab, "school/media", false, 120)
	head, idx, err := corpussource.LFSLayout(pointers, limits)
	if err != nil || len(head) == 0 {
		t.Fatal(err)
	}
	cut := idx.Objects[110].OID // in the second batch
	l.forge.Cut[cut] = 1
	src := source(corpussource.GitLab, "school/media")
	if _, err = l.fetcher.LFS(t.Context(), src, "", pointers, l.dir, corpussource.LFSOptions{}); !errors.Is(err, corpussource.ErrUnavailable) {
		t.Fatal("a cut download:", err)
	}
	l.forge.Reset()
	d, err := l.fetcher.LFS(t.Context(), src, "", pointers, l.dir, corpussource.LFSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	readDrive(t, l.dir, d, objects)
	fetched := map[string]int{}
	for _, req := range l.forge.Requests() {
		if _, oid, ok := strings.Cut(req.Path, "/gitlab-lfs/objects/"); ok {
			fetched[oid]++
		}
	}
	if len(fetched) != 10 {
		t.Fatal("the retry fetched", len(fetched), "objects, not the 10 from the cut on")
	}
	for _, o := range idx.Objects[:110] {
		if fetched[o.OID] != 0 {
			t.Fatal("a verified object was fetched again")
		}
	}
	// Once complete, a retry downloads nothing at all.
	l.forge.Reset()
	if again, err := l.fetcher.LFS(t.Context(), src, "", pointers, l.dir, corpussource.LFSOptions{}); err != nil || again != d || len(l.forge.Requests()) != 0 {
		t.Fatal("a complete drive was fetched again:", err, len(l.forge.Requests()))
	}
	// Other pointers make another drive: the journal is forgotten.
	l.forge.Reset()
	if _, err = l.fetcher.LFS(t.Context(), src, "", pointers[:3], l.dir, corpussource.LFSOptions{}); err != nil || len(l.forge.Requests()) != 4 {
		t.Fatal("another set of pointers:", err, len(l.forge.Requests()))
	}
}

// The limits apply to the pointers before any download, and the storage
// check stops a fetch before its next batch.
func TestLFSLimits(t *testing.T) {
	l := newLab(t, corpussource.Limits{ArchiveBytes: 1, LFSBytes: 20_000, LFSObjects: 3})
	pointers, _ := lfsRepo(t, l, corpussource.GitHub, "acme/media", false, 4)
	src := source(corpussource.GitHub, "acme/media")
	if _, err := l.fetcher.LFS(t.Context(), src, "", pointers, l.dir, corpussource.LFSOptions{}); !errors.Is(err, corpussource.ErrTooLarge) {
		t.Fatal("too many objects:", err)
	}
	big := []corpussource.Pointer{{OID: strings.Repeat("ab", 32), Size: 20_001}}
	if _, err := l.fetcher.LFS(t.Context(), src, "", big, l.dir, corpussource.LFSOptions{}); !errors.Is(err, corpussource.ErrTooLarge) {
		t.Fatal("objects past the size limit:", err)
	}
	for _, p := range [][]corpussource.Pointer{{{OID: "ABAB", Size: 1}}, {{OID: strings.Repeat("ab", 32), Size: -1}},
		{{OID: strings.Repeat("ab", 32), Size: 1}, {OID: strings.Repeat("ab", 32), Size: 2}}} {
		if _, err := l.fetcher.LFS(t.Context(), src, "", p, l.dir, corpussource.LFSOptions{}); !errors.Is(err, corpussource.ErrIntegrity) {
			t.Fatal("an invalid pointer:", p, err)
		}
	}
	if len(l.forge.Requests()) != 0 {
		t.Fatal("refused pointers reached the forge")
	}
	full := errors.New("storage pressure")
	if _, err := l.fetcher.LFS(t.Context(), src, "", pointers[:2], l.dir, corpussource.LFSOptions{BeforeBatch: func() error { return full }}); !errors.Is(err, full) {
		t.Fatal("the storage check did not stop the fetch:", err)
	}
	if d, err := l.fetcher.LFS(t.Context(), src, "", nil, t.TempDir(), corpussource.LFSOptions{}); err != nil || d != (corpussource.LFSDrive{}) {
		t.Fatal("no pointer, no drive:", d, err)
	}
}

// The layout fits the index in the head, whatever its length: offsets grow
// the index, which may push the first object one block further.
func TestLFSLayoutFitsItsIndex(t *testing.T) {
	big := corpussource.Limits{LFSBytes: 1 << 40, LFSObjects: 20_000, ArchiveBytes: 1}
	for _, n := range []int{1, 2, 37, 38, 39, 40, 41, 300, 10_000} {
		var pointers []corpussource.Pointer
		for i := range n {
			sum := sha256.Sum256([]byte(fmt.Sprint(i)))
			pointers = append(pointers, corpussource.Pointer{OID: hex.EncodeToString(sum[:]), Size: int64(i) * 10_003})
		}
		head, idx, err := corpussource.LFSLayout(pointers, big)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(head)) > idx.Objects[0].Offset || idx.Objects[0].Offset != corpussource.Padded(int64(len(head))) {
			t.Fatal(n, "objects: head of", len(head), "bytes, first object at", idx.Objects[0].Offset)
		}
		again, _, _ := corpussource.LFSLayout(pointers, big)
		if !bytes.Equal(head, again) {
			t.Fatal("the same pointers gave another layout")
		}
	}
}
