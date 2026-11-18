//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

// shippingLab ships archives with the platform's shipper
// (deploy/backup/agentcapsule-archive-ship.py) and rclone 1.60 to two
// crypt remotes over local directories, which stand for S3 and the
// standby's disk. rclone runs as nobody, as the shipper runs it as its own
// account in production. rclone comes from AGENTCAPSULE_KVM_RCLONE, or PATH,
// and runs from the lab's own copy, as the shipper comes from the sources
// under test.
type shippingLab struct {
	shipper, rclone, config string
}

func newShippingLab(t *testing.T) shippingLab {
	t.Helper()
	given := os.Getenv("AGENTCAPSULE_KVM_RCLONE")
	if given == "" {
		var err error
		if given, err = exec.LookPath("rclone"); err != nil {
			t.Fatal("this test ships archives with rclone 1.60: set AGENTCAPSULE_KVM_RCLONE or put rclone on PATH")
		}
	}
	// The shipper of the sources under test, whichever directory the test
	// runs from.
	shipper := filepath.Join(repositoryRoot(t), "deploy", "backup", "agentcapsule-archive-ship.py")
	if _, err := os.Stat(shipper); err != nil {
		t.Fatal("the archive shipper of the sources under test", err)
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(nobody.Uid)
	gid, _ := strconv.Atoi(nobody.Gid)
	// rclone, as nobody, runs its binary, reads its configuration and writes
	// both stores: all three must be within nobody's reach. TMPDIR is not:
	// the KVM campaign puts it in its output directory, of mode 0700, and
	// rclone may lie in a home directory. /var/tmp is, and is on disk.
	dir, err := os.MkdirTemp("/var/tmp", "acp-ship-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err = os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	rclone := filepath.Join(dir, "rclone")
	copyExecutable(t, given, rclone)
	if err = os.Chmod(rclone, 0o755); err != nil { // whatever the umask
		t.Fatal(err)
	}
	var conf strings.Builder
	for _, store := range []string{"standby", "s3"} {
		fmt.Fprintf(&conf, "[%s]\ntype = crypt\nremote = %s\n", store, filepath.Join(dir, store))
		for _, field := range []string{"password", "password2"} {
			secret := make([]byte, 32)
			if _, err = rand.Read(secret); err != nil {
				t.Fatal(err)
			}
			obscured, err := exec.Command(rclone, "obscure", hex.EncodeToString(secret)).Output()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&conf, "%s = %s\n", field, strings.TrimSpace(string(obscured)))
		}
		conf.WriteString("\n")
	}
	path := filepath.Join(dir, "rclone.conf")
	if err = os.WriteFile(path, []byte(conf.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0o644); err != nil { // whatever the umask
		t.Fatal(err)
	}
	for _, store := range []string{"standby", "s3"} {
		if err = os.Mkdir(filepath.Join(dir, store), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.Chown(filepath.Join(dir, store), uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	return shippingLab{shipper: shipper, rclone: rclone, config: path}
}

// command is the shipper with this lab's rclone, configuration and account.
func (s shippingLab) command() []string {
	return []string{"python3", "-I", s.shipper, "--rclone=" + s.rclone, "--rclone-config=" + s.config, "--user=nobody"}
}

func (s shippingLab) ship(t *testing.T, root string) {
	t.Helper()
	state := t.TempDir()
	cmd := exec.CommandContext(t.Context(), "python3", append(s.command()[1:], "--archive-root="+root, "ship",
		"--textfile-directory="+state, "--state-directory="+filepath.Join(state, "state"))...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("ship", err, string(out))
	}
}

// A host is lost after its agent's archive was shipped (ADR 020). The
// agent answers an invocation, is archived on demand, answers one more; the
// archive is shipped to both stores, encrypted with rclone crypt, and the
// host's own copy is deleted with the host. Another worker host, with its
// own runtime root, takes the lost host over: it fetches the archive from
// the standby's copy, verifies it against the restore authority, creates the
// agent's volume with its key, installs the archive there, boots it
// restricted and declares lost the one invocation after the archive. That
// invocation then runs again on the new host, at the new incarnation, and
// the lost host's worker gets no work.
func TestProductWorkerRestoresAgentFromShippedArchiveOnAnotherHost(t *testing.T) {
	l := newRegistryLab(t)
	shipping := newShippingLab(t)
	l.publish("1.0.0", "opt/echo")
	agent := l.create("moved", "1.0.0").AgentID
	before := l.invoke(agent, "before-archive", "written before the archive")
	l.await("invocation before the archive", true, func() bool { return l.answered(before, "written before the archive") })

	t.Log("stage: archive on demand, one invocation after it, then ship the archive")
	archives, err := volumearchive.New(filepath.Join(t.TempDir(), "archives"))
	if err != nil {
		t.Fatal(err)
	}
	archiveID := "arc_" + strings.Repeat("7", 32)
	manifest, err := l.worker.CaptureArchive(t.Context(), agent, archiveID, archives)
	if err != nil {
		t.Fatal(err)
	}
	after := l.invoke(agent, "after-archive", "lost with the host")
	l.await("invocation after the archive", true, func() bool { return l.answered(after, "lost with the host") })
	shipping.ship(t, archives.Root())

	t.Log("stage: the host is lost with its VMs and its archives; the standby takes it over")
	if err = l.worker.host.Retire(t.Context(), agent, ^uint64(0)); err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(archives.Root()); err != nil {
		t.Fatal(err)
	}
	if _, _, err = l.store.TakeOverHost(t.Context(), controlplane.OperatorCommand{Actor: "local-uid:0"}, "local", "standby"); err != nil {
		t.Fatal(err)
	}
	if err = l.store.DiscoverWork(t.Context(), "local", 10); !errors.Is(err, controlplane.ErrHostLost) {
		t.Fatal("the lost host still gets work", err)
	}
	root, err := os.MkdirTemp(config(t).RootParent, "product-standby-")
	if err != nil {
		t.Fatal(err)
	}
	options := opts(t, root)
	options.AuthenticatedControl, options.Ready, options.BootTimeout = true, nil, time.Minute
	if labRuntimeOptions != nil {
		labRuntimeOptions(&options)
	}
	standby, err := NewProvisioningPlacements(l.store, "standby", "standby-worker", 2*time.Minute, options, l.worker.provisioning.keys,
		l.worker.authority, ProvisioningConfig{FirstUID: 62500, LastUID: 62509})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := standby.host.Retire(ctx, agent, ^uint64(0)); err != nil {
			t.Error(err)
		}
		standby.Close()
	})
	if err = standby.EnableTransit(t.Context(), l.worker.transit.Load()); err != nil {
		t.Fatal(err)
	}
	// The standby's harness cache holds the release, as recovery.md has it prepared.
	if err = standby.EnableRegistry(l.importer); err != nil {
		t.Fatal(err)
	}

	t.Log("stage: fetch the archive from the standby's copy and restore the agent there")
	restored, err := volumearchive.New(filepath.Join(t.TempDir(), "standby-archives"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := standby.FetchArchive(t.Context(), restored, ScriptFetcher(shipping.command(), restored.Root()), archiveID, nil)
	if err != nil || store != "standby" {
		t.Fatal("fetch", store, err)
	}
	restoreID := "rst_" + strings.Repeat("8", 32)
	installed := false
	standby.afterRestoreStep = func(step string) error {
		if step != controlplane.RestoreReconciling || installed {
			return nil
		}
		plan, err := l.store.VolumeRestoreTarget(t.Context(), restoreID, "standby")
		if err != nil {
			return err
		}
		if plan.RelocatedFrom != "" || plan.Placement.HostID != "standby" {
			return errors.New("the volume was not created on the new host")
		}
		return standby.host.WithStoppedVolume(t.Context(), agent, plan.Placement.Generation, plan.Device, plan.Inode, func(r io.Reader) error {
			h := sha256.New()
			if _, err := io.Copy(h, r); err != nil {
				return err
			}
			if !bytes.Equal(h.Sum(nil), manifest.Digest[:]) {
				return errors.New("the installed volume is not the archive")
			}
			installed = true
			return nil
		})
	}
	result, err := standby.RestoreFromArchive(t.Context(), restoreID, agent, archiveID, restored, func(err error) { t.Error("the restore paused", err) })
	if err != nil {
		t.Fatal("restore", err)
	}
	if !installed || result.Incarnation != 2 || len(result.Losses) != 1 || result.Losses[0].InvocationID != after ||
		result.Losses[0].Rerun != controlplane.RerunQueued {
		t.Fatal("the restore on the new host", installed, result)
	}
	if got, _, err := standby.authority.OutcomeStatus(t.Context(), l.outcomeOf(agent, before)); err != nil || got != restoreauthority.StatusConfirmed {
		t.Fatal("an outcome the archive held", got, err)
	}

	t.Log("stage: the lost invocation runs again on the new host, at the new incarnation")
	l.worker = standby
	l.await("rerun of the lost invocation", true, func() bool { return l.answered(after, "lost with the host") })
	var v controlplane.Invocation
	l.request(l.user(), "GET", "/v1/invocations/"+after, "", nil, 200, &v)
	if v.LostAt == nil || v.CompletedAt == nil || !v.CompletedAt.After(*v.LostAt) {
		t.Fatal("the rerun of the lost invocation", v.LostAt, v.CompletedAt)
	}
	if run := l.runs(1)[agent]; run.Incarnation != 2 {
		t.Fatal("the rerun did not run at the new incarnation", run)
	}
	l.answers(agent, "after-restore", "answered on the new host")
	if e, err := l.store.VolumeEnrollment(t.Context(), agent, "standby"); err != nil || e.Stage != "READY" || e.Incarnation != 2 {
		t.Fatal("the volume on the new host", e, err)
	}
}
