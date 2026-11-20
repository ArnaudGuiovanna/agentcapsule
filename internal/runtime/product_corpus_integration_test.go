//go:build linux && cgo && kvm_integration && kvm_product_integration

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnesspkg"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumestore"
)

// The corpus KVM tests (ADR 023 §5, lot 4 of the corpus plan) boot the
// product guest with corpus drives. Their harness, when it comes from the
// registry, is capsule-echo with the probe-corpus behaviour: it reports what
// it sees of /corpus (cmd/capsule-echo/probe_corpus.go).

// corpusView mirrors capsule-echo's probe answer.
type corpusView struct {
	Present bool     `json:"present"`
	Options []string `json:"options"`
	Write   string   `json:"write"`
	Mounts  []struct {
		Name    string   `json:"name"`
		Options []string `json:"options"`
		Marker  string   `json:"marker"`
		Write   string   `json:"write"`
		Exec    string   `json:"exec"`
	} `json:"mounts"`
}

type corpusLab struct {
	t          *testing.T
	h          *FirecrackerHost
	keys       *keyauthority.Files
	storage    *volumestore.Store
	mu         sync.Mutex
	volumes    map[string]volumestore.Container
	initialize map[string]bool
	generation map[string]uint64
	cache      string
	agents     int
}

func newCorpusLab(t *testing.T) *corpusLab {
	t.Helper()
	authorityRoot, err := os.MkdirTemp(kvmSettings(t).RootParent, "keys-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(authorityRoot) })
	keys, err := keyauthority.Initialize(t.Context(), authorityRoot)
	if err != nil {
		t.Fatal(err)
	}
	l := &corpusLab{t: t, keys: keys, volumes: map[string]volumestore.Container{}, initialize: map[string]bool{}, generation: map[string]uint64{}}
	l.h, _ = newHostWithOptions(t, func(opts *FirecrackerOptions) {
		opts.Ready = nil
		opts.AuthenticatedControl = true
		opts.MaxActive = 4
		opts.BootTimeout = 60 * time.Second
		opts.PrepareGuest = l.prepareGuest
	})
	if l.storage, err = volumestore.New(l.h.root); err != nil {
		t.Fatal(err)
	}
	// The corpus cache shares the jails' file system: images are linked.
	l.cache = filepath.Join(l.h.root, "corpora")
	if err = os.Mkdir(l.cache, 0o700); err != nil {
		t.Fatal(err)
	}
	return l
}

// prepareGuest opens the agent's volume, and gives up as soon as the VMM is
// gone: a guest that refuses its drives restarts, which ends its VMM.
func (l *corpusLab) prepareGuest(ctx context.Context, id string, run VMRun, c *capsuleprotocol.Client) error {
	l.mu.Lock()
	volume, ok := l.volumes[id]
	initialize := l.initialize[id]
	l.mu.Unlock()
	if !ok {
		return errors.New("unknown test volume")
	}
	if err := ownedVolumeLock(run.PID, volume.Path); err != nil {
		return err
	}
	return l.keys.WithKey(ctx, id, volume.Spec.VolumeID, func(key []byte) error {
		boot := capsuleprotocol.VolumeBoot{Incarnation: 1, VolumeID: volume.Spec.VolumeID, UUID: volume.UUID, Initialize: initialize, PreviousShutdown: capsuleprotocol.ShutdownUnclean}
		for {
			err := c.OpenVolume(ctx, boot, key)
			if err == nil || !errors.Is(err, capsuleprotocol.ErrTransport) {
				return err
			}
			if syscall.Kill(run.PID, 0) == syscall.ESRCH {
				return errors.Join(errors.New("the VMM exited before the volume opened"), err)
			}
			select {
			case <-ctx.Done():
				return errors.Join(ctx.Err(), err)
			case <-time.After(20 * time.Millisecond):
			}
		}
	})
}

// image builds a read-only corpus image in the cache: an ext4 with uuid,
// as a corpus build makes it, holding a marker that names it and an
// executable bin/tool.
func (l *corpusLab) image(name, uuid string) CorpusImage {
	t := l.t
	t.Helper()
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "marker.txt"), []byte(name+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Any executable: on a noexec mount its execution fails EACCES before
	// anything is loaded; anything else is another outcome.
	copyFile(t, "/usr/bin/true", filepath.Join(src, "bin", "tool"), 0o755)
	path := filepath.Join(l.cache, name+".ext4")
	cmd := exec.Command("/usr/sbin/mkfs.ext4", "-q", "-F", "-t", "ext4", "-L", "corpus", "-U", uuid, "-O", "^has_journal",
		"-E", "root_owner=0:0,hash_seed="+uuid, "-d", src, path, "16M")
	cmd.Env = append(os.Environ(), "E2FSPROGS_FAKE_TIME=1", "LC_ALL=C")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("mkfs.ext4: %v: %s", err, out)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	return CorpusImage{Path: path, Digest: "sha256:" + hashFile(t, path), UUID: uuid, Mount: name}
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(dst, b, mode); err != nil {
		t.Fatal(err)
	}
}

// harness packs capsule-echo with the probe-corpus behaviour as a registry
// harness of base.
func (l *corpusLab) harness(base string) *HarnessImage {
	t := l.t
	t.Helper()
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, "opt", "echo"), 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile(t, filepath.Join(filepath.Dir(kvmSettings(t).Initrd), "capsule-echo"), filepath.Join(src, "opt", "echo", "harness"), 0o755)
	m := harnesspkg.HarnessManifest{Schema: harnesspkg.Schema, Name: "probe", Version: strings.ReplaceAll(base, "/", "-"), Protocol: harnesspkg.Protocol,
		Architecture: harnesspkg.Architecture, Base: base, Entrypoint: []string{"/opt/echo/harness", "probe-corpus"}}
	path := filepath.Join(l.h.root, "probe-"+m.Version+".ext4")
	if err := harnesspkg.BuildRootfs(t.Context(), m, src, path, 64); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	return &HarnessImage{Path: path, Digest: "sha256:" + hashFile(t, path), Entrypoint: m.Entrypoint}
}

// agent provisions an encrypted agent with harness (nil: built in) and
// corpora, and returns its ID.
func (l *corpusLab) agent(harness *HarnessImage, corpora ...CorpusImage) string {
	t := l.t
	t.Helper()
	l.agents++
	id := fmt.Sprintf("agt_%032x", 0xc0de0000+l.agents)
	volumeID := fmt.Sprintf("vol_%032x", 0xc0de0000+l.agents)
	if err := l.keys.Ensure(t.Context(), id, volumeID); err != nil {
		t.Fatal(err)
	}
	var volume volumestore.Container
	err := l.keys.WithKey(t.Context(), id, volumeID, func(key []byte) error {
		var e error
		volume, e = l.storage.Prepare(t.Context(), volumestore.Spec{AgentID: id, VolumeID: volumeID, SizeMiB: 128}, key)
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	l.volumes[id], l.initialize[id] = volume, true
	l.mu.Unlock()
	registration := ProvisionedAgent{ID: id, Volume: volume.Path, Device: volume.Device, Inode: volume.Inode,
		Resources: VMResources{VCPUs: 1, MemoryMiB: 256, VolumeMiB: 128}, Harness: harness, Corpora: corpora}
	if err = l.h.RegisterProvisioned(t.Context(), registration, 62300, 62399); err != nil {
		t.Fatal(err)
	}
	return id
}

// start boots id's next generation.
func (l *corpusLab) start(id string) (VMRun, error) {
	l.generation[id]++
	run, err := l.h.Start(l.t.Context(), id, l.generation[id])
	if err == nil {
		l.mu.Lock()
		l.initialize[id] = false
		l.mu.Unlock()
	}
	return run, err
}

func (l *corpusLab) stop(id string) {
	l.t.Helper()
	if err := l.h.Stop(l.t.Context(), id, l.generation[id]); err != nil {
		l.t.Fatal(err)
	}
}

// probe asks id's harness what it sees of /corpus.
func (l *corpusLab) probe(id string) corpusView {
	t := l.t
	t.Helper()
	c, err := l.h.Control(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	l.agents++
	r, err := c.Send(t.Context(), harnessstore.Event{ID: fmt.Sprintf("probe-%d", l.agents), Subjects: []string{"agent/" + id}, Body: []byte("probe-corpus")})
	if err != nil {
		t.Fatal("probe", err)
	}
	var v corpusView
	if err = json.Unmarshal(r.Result, &v); err != nil {
		t.Fatal("probe answer", err, string(r.Result))
	}
	return v
}

// setCorpora writes id's corpora into the host's record without the checks
// of ReplaceCorpora, as a drive-order fault would leave them: the guest's
// own UUID check is what refuses the boot.
func (l *corpusLab) setCorpora(id string, corpora []CorpusImage) {
	l.t.Helper()
	if err := l.h.locked(l.t.Context(), func(r *hostRegistry) error {
		r.Agents[id].Corpora = corpora
		return l.h.save(r)
	}); err != nil {
		l.t.Fatal(err)
	}
}

// refused boots id and expects the guest to refuse its drives: a failed
// boot whose console says capsule-init failed.
func (l *corpusLab) refused(id, why string) {
	t := l.t
	t.Helper()
	logs, _ := filepath.Glob(filepath.Join(l.h.root, "logs", "*.log"))
	run, err := l.start(id)
	if err == nil {
		t.Fatalf("%s: the guest booted (%s)", why, run.ID)
	}
	if !errors.Is(err, ErrBootFailed) {
		t.Fatalf("%s: not a failed boot: %v", why, err)
	}
	after, _ := filepath.Glob(filepath.Join(l.h.root, "logs", "*.log"))
	for _, log := range after {
		if slices.Contains(logs, log) {
			continue
		}
		if b, _ := os.ReadFile(log); strings.Contains(string(b), "CAPSULE_INIT_FAILED") {
			return
		}
	}
	t.Fatalf("%s: no console says capsule-init failed", why)
}

// sharedLock tells whether pid holds a shared (read) flock on path through
// one of its descriptors, as the patched VMM takes for a read-only drive.
func sharedLock(t *testing.T, pid int, path string) bool {
	t.Helper()
	want, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		got, err := os.Stat(fmt.Sprintf("/proc/%d/fd/%s", pid, e.Name()))
		if err != nil || !os.SameFile(want, got) {
			continue
		}
		info, _ := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, e.Name()))
		for _, line := range strings.Split(string(info), "\n") {
			if f := strings.Fields(line); len(f) >= 5 && f[0] == "lock:" && f[2] == "FLOCK" && f[4] == "READ" {
				return true
			}
		}
	}
	return false
}

const (
	financeKVM  = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
	handbookKVM = "6fa459ea-ee8a-4ca4-894e-db77e160355e"
)

// One corpus image serves three VMs at once: each jail holds a hard link to
// the cached image's inode, each VMM holds it under a shared lock, which
// keeps a writer out, and each harness reads it (COR, ADR 023 §5.1).
func TestProductGuestSharesOneCorpusImageAcrossThreeVMs(t *testing.T) {
	l := newCorpusLab(t)
	handbook := l.image("handbook", handbookKVM)
	harness := l.harness(harnesspkg.GuestBase2)
	var ids []string
	runs := map[string]VMRun{}
	for range 3 {
		id := l.agent(harness, handbook)
		run, err := l.start(id)
		if err != nil {
			t.Fatal("boot with a shared corpus", err)
		}
		ids, runs[id] = append(ids, id), run
	}
	cached, err := os.Stat(handbook.Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		run := runs[id]
		jailed, err := os.Stat(filepath.Join(l.h.jail(&run), "corpus0.ext4"))
		if err != nil || !os.SameFile(jailed, cached) {
			t.Fatal("a VM's corpus drive is not the cached image", err)
		}
		if !sharedLock(t, run.PID, handbook.Path) {
			t.Fatal("a VMM does not hold the corpus image under LOCK_SH", run.PID)
		}
		v := l.probe(id)
		if len(v.Mounts) != 1 || v.Mounts[0].Name != "handbook" || v.Mounts[0].Marker != "handbook\n" {
			t.Fatal("a harness does not read the shared corpus", v)
		}
	}
	if st := cached.Sys().(*syscall.Stat_t); st.Nlink != 4 {
		t.Fatal("links to the cached image: the cache and three jails", st.Nlink)
	}
	f, err := os.Open(handbook.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != syscall.EWOULDBLOCK {
		t.Fatal("a writer could take the image under its readers", err)
	}
	for _, id := range ids {
		l.stop(id)
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal("the stopped VMs still hold the image", err)
	}
	t.Log("one corpus image, one inode, three VMs under LOCK_SH, each harness reading it")
}

// From inside the harness, each corpus is mounted ro,nosuid,nodev,noexec,
// noatime: a write fails EROFS, an execution EACCES, and /corpus itself is
// read-only (ADR 023 §5.3).
func TestProductGuestMountsCorporaReadOnlyAndNoExec(t *testing.T) {
	l := newCorpusLab(t)
	id := l.agent(l.harness(harnesspkg.GuestBase2), l.image("finance", financeKVM), l.image("handbook", handbookKVM))
	if _, err := l.start(id); err != nil {
		t.Fatal(err)
	}
	v := l.probe(id)
	if !v.Present || v.Write != "EROFS" || !slices.Contains(v.Options, "ro") || !slices.Contains(v.Options, "noexec") {
		t.Fatal("/corpus seen from the harness", v)
	}
	if len(v.Mounts) != 2 {
		t.Fatal("mounts", v.Mounts)
	}
	for _, m := range v.Mounts {
		for _, option := range []string{"ro", "nosuid", "nodev", "noexec", "noatime"} {
			if !slices.Contains(m.Options, option) {
				t.Fatal("a corpus mount lacks", option, m)
			}
		}
		if m.Marker != m.Name+"\n" || m.Write != "EROFS" || m.Exec != "EACCES" {
			t.Fatal("a corpus seen from the harness", m)
		}
	}
	t.Logf("seen from the harness: %+v", v)
}

// A drive whose superblock carries another UUID than corpora.json refuses
// the boot before the harness starts; the same agent boots once its record
// is right again.
func TestProductGuestRefusesACorpusOfAnotherUUID(t *testing.T) {
	l := newCorpusLab(t)
	finance := l.image("finance", financeKVM)
	id := l.agent(l.harness(harnesspkg.GuestBase2), finance)
	if _, err := l.start(id); err != nil {
		t.Fatal(err)
	}
	l.stop(id)
	wrong := finance
	wrong.UUID = handbookKVM
	l.setCorpora(id, []CorpusImage{wrong})
	l.refused(id, "a corpus of another UUID")
	if err := l.h.ReplaceCorpora(t.Context(), id, []CorpusImage{wrong}); err == nil {
		t.Fatal("the host recorded an image under another UUID")
	}
	if err := l.h.ReplaceCorpora(t.Context(), id, []CorpusImage{finance}); err != nil {
		t.Fatal(err)
	}
	if _, err := l.start(id); err != nil {
		t.Fatal("the right UUID after a refusal", err)
	}
	if v := l.probe(id); len(v.Mounts) != 1 || v.Mounts[0].Marker != "finance\n" {
		t.Fatal("corpus after the refusal", v)
	}
}

// The extra drives follow the data volume, then the registry harness when
// there is one: corpora start at /dev/vdc with a registry harness and at
// /dev/vdb with the built-in one. The guest checks each drive's UUID, so a
// boot proves the order, and two corpora swapped in the record are refused.
func TestProductGuestOrdersCorporaWithAndWithoutARegistryHarness(t *testing.T) {
	l := newCorpusLab(t)
	finance, handbook := l.image("finance", financeKVM), l.image("handbook", handbookKVM)
	swapped := []CorpusImage{finance, handbook}
	swapped[0].UUID, swapped[1].UUID = handbook.UUID, finance.UUID
	for _, harness := range []*HarnessImage{l.harness(harnesspkg.GuestBase2), nil} {
		id := l.agent(harness, finance, handbook)
		run, err := l.start(id)
		if err != nil {
			t.Fatal("boot with two corpora, registry harness:", harness != nil, err)
		}
		var config struct {
			Drives []struct {
				ID string `json:"drive_id"`
			} `json:"drives"`
		}
		b, err := os.ReadFile(filepath.Join(l.h.jail(&run), "config.json"))
		if err != nil || json.Unmarshal(b, &config) != nil {
			t.Fatal("config", err)
		}
		var order []string
		for _, d := range config.Drives {
			order = append(order, d.ID)
		}
		want := []string{"data", "corpus0", "corpus1"}
		if harness != nil {
			want = []string{"data", "harness", "corpus0", "corpus1"}
			v := l.probe(id)
			if len(v.Mounts) != 2 || v.Mounts[0].Name != "finance" || v.Mounts[0].Marker != "finance\n" || v.Mounts[1].Marker != "handbook\n" {
				t.Fatal("each mount shows its own corpus", v)
			}
		}
		if !slices.Equal(order, want) {
			t.Fatal("drive order", order)
		}
		l.stop(id)
		l.setCorpora(id, swapped)
		l.refused(id, fmt.Sprintf("swapped corpora, registry harness: %v", harness != nil))
	}
}

// A harness of base 1 boots as before: no /corpus in its root, its echo
// unchanged. Given corpora, which it has no mount point for, its boot is
// refused rather than started without them.
func TestProductGuestRunsABaseOneHarnessUnchanged(t *testing.T) {
	l := newCorpusLab(t)
	id := l.agent(l.harness(harnesspkg.GuestBase))
	if _, err := l.start(id); err != nil {
		t.Fatal("a base-1 harness", err)
	}
	if v := l.probe(id); v.Present || len(v.Mounts) != 0 {
		t.Fatal("a base-1 harness sees /corpus", v)
	}
	c, err := l.h.Control(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Send(t.Context(), harnessstore.Event{ID: "echo", Subjects: []string{"agent/" + id}, Body: []byte("unchanged")})
	var reply struct {
		Echo []byte `json:"echo"`
	}
	if err != nil || json.Unmarshal(r.Result, &reply) != nil || string(reply.Echo) != "unchanged" {
		t.Fatal("the base-1 harness's echo", err, string(r.Result))
	}
	l.stop(id)
	if err = l.h.ReplaceCorpora(t.Context(), id, []CorpusImage{l.image("finance", financeKVM)}); err != nil {
		t.Fatal(err)
	}
	l.refused(id, "corpora for a base-1 harness")
}
