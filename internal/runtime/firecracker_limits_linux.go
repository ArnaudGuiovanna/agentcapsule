//go:build linux

package runtime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
)

// DriveRate caps one drive of a VM (CAP-03, ADR 012): at most
// BandwidthMiBPerSecond and IOPS operations per second, reads and writes
// together. Firecracker enforces it in the VMM, with a token bucket refilled
// every second, so it needs no I/O controller in the host's cgroups.
type DriveRate struct {
	BandwidthMiBPerSecond int `json:"bandwidth_mib_per_second"`
	IOPS                  int `json:"iops"`
}

// DriveLimits are the ceilings of every VM of a host: Volume for the agent's
// encrypted volume and a corpus build's drives, Harness for a registry
// harness image, Corpus for each corpus image (ADR 023 §5.1). A harness image
// may be read whole once at full speed at each boot (a one-time burst of its
// size), then at Harness's rate; a corpus image only its first
// CorpusBurstBytes.
type DriveLimits struct {
	Volume  DriveRate `json:"volume"`
	Harness DriveRate `json:"harness"`
	Corpus  DriveRate `json:"corpus"`
}

// DefaultDriveLimits apply when the operator sets none (ADR 012).
var DefaultDriveLimits = DriveLimits{
	Volume:  DriveRate{BandwidthMiBPerSecond: 64, IOPS: 2000},
	Harness: DriveRate{BandwidthMiBPerSecond: 128, IOPS: 4000},
	Corpus:  DriveRate{BandwidthMiBPerSecond: 128, IOPS: 4000},
}

// CorpusBurstBytes caps the one-time burst of a corpus drive: a corpus of
// several GiB is read on demand, not whole at each boot.
const CorpusBurstBytes = 256 << 20

func (r DriveRate) valid() bool {
	return r.BandwidthMiBPerSecond >= 1 && r.BandwidthMiBPerSecond <= 4096 && r.IOPS >= 10 && r.IOPS <= 1_000_000
}

// Validate refuses a ceiling outside 1 MiB/s to 4 GiB/s or 10 to 1,000,000
// operations per second.
func (l DriveLimits) Validate() error {
	if !l.Volume.valid() || !l.Harness.valid() || !l.Corpus.valid() {
		return errors.New("invalid drive limits")
	}
	return nil
}

// orDefault: a zero rate means its default, so no VM boots unlimited, and a
// configuration that predates a drive kind keeps working.
func (l DriveLimits) orDefault() DriveLimits {
	for _, r := range []struct{ got, fallback *DriveRate }{
		{&l.Volume, &DefaultDriveLimits.Volume}, {&l.Harness, &DefaultDriveLimits.Harness}, {&l.Corpus, &DefaultDriveLimits.Corpus},
	} {
		if *r.got == (DriveRate{}) {
			*r.got = *r.fallback
		}
	}
	return l
}

// rateLimiter is the drive's Firecracker rate_limiter. A bucket holds one
// second of its rate and refills in 1000 ms. burst, in bytes, is spent once
// before the rate applies; its operations count one per 4 KiB.
func (r DriveRate) rateLimiter(burst int64) map[string]any {
	bandwidth := map[string]any{"size": int64(r.BandwidthMiBPerSecond) << 20, "refill_time": 1000}
	ops := map[string]any{"size": r.IOPS, "refill_time": 1000}
	if burst > 0 {
		bandwidth["one_time_burst"] = burst
		ops["one_time_burst"] = max(burst/4096, 1)
	}
	return map[string]any{"bandwidth": bandwidth, "ops": ops}
}

// jailerCommand starts the VMM of one boot under the jailer: its own UID and
// GID, chroot, PID namespace and attempt cgroup, with Firecracker's default
// seccomp filters. CLONE_NEWNET gives it a network namespace of its own with
// no interface but loopback, and the VM gets no network device (prepare): the
// guest's only way out is the vsock to this host, through the platform.
func (h *FirecrackerHost) jailerCommand(run *VMRun, uid uint32, group *os.File) *exec.Cmd {
	cmd := exec.Command(filepath.Join(h.root, "bin", "jailer"), "--id", run.ID, "--exec-file", filepath.Join(h.root, "bin", "firecracker"),
		"--uid", strconv.Itoa(int(uid)), "--gid", strconv.Itoa(int(uid)), "--chroot-base-dir", filepath.Join(h.root, "jails"),
		"--new-pid-ns", "--cgroup-version", "2", "--parent-cgroup", strings.TrimPrefix(h.group(run), "/sys/fs/cgroup/"),
		"--resource-limit", "no-file=256", "--", "--no-api", "--config-file", "/config.json")
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(group.Fd()), Cloneflags: syscall.CLONE_NEWNET}
	return cmd
}

// ErrBootFailed marks a boot that the guest failed (ADR 012): its VMM ran,
// holding the agent's volume, then exited or stopped answering on its control
// channel before it was ready, or it answered with an incompatible contract.
// Restart budgets count it. Other start errors are not the guest's: a full
// host, a busy volume, a refused lease, an authority or database outage, a
// caller that gave up, or a VMM that never started.
var ErrBootFailed = errors.New("guest failed to boot")

// bootFailureGrace bounds how long a failed attempt waits, before its
// cleanup, to tell a guest that failed from a platform that refused it.
const bootFailureGrace = 3 * time.Second

// guestFailed is asked, before cleanup, about an attempt whose VMM was
// identified and that then failed with the caller's context still alive.
// The guest failed if, within grace, its VMM exits, or if at the end of grace
// its control channel still gives no answer. A guest that answers, even with
// a refusal such as an unopened volume, is alive: the platform failed.
func guestFailed(ctx context.Context, cause error, grace time.Duration, exited func() bool, answers func(context.Context) bool) bool {
	if ctx.Err() != nil {
		return false
	}
	if errors.Is(cause, capsuleprotocol.ErrUnsupportedProtocol) || errors.Is(cause, capsuleprotocol.ErrCapabilitiesUnavailable) {
		return true
	}
	deadline := time.Now().Add(grace)
	for {
		if exited() {
			return true
		}
		if time.Now().After(deadline) {
			return answers != nil && !answers(ctx)
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// controlAnswers sends one health probe. Any authenticated answer counts,
// including a refusal: the client maps a reachable guest's error codes to the
// bare ErrTransport sentinel, and joins it with the dial or read error when
// nothing answered.
func controlAnswers(ctx context.Context, c *capsuleprotocol.Client) bool {
	probe, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err := c.Health(probe)
	return err == nil || !errors.Is(err, capsuleprotocol.ErrTransport) || err == capsuleprotocol.ErrTransport //nolint:errorlint // the sentinel itself means an answer
}

// bootFailure classifies a failed attempt of a; see guestFailed.
func (h *FirecrackerHost) bootFailure(ctx context.Context, a *HostAgent, cause error) error {
	if a.Run == nil || a.Run.PID == 0 {
		return cause
	}
	group := h.group(a.Run)
	exited := func() bool {
		busy, err := populated(group)
		return err == nil && !busy
	}
	var answers func(context.Context) bool
	if h.opts.AuthenticatedControl {
		answers = func(ctx context.Context) bool {
			c, err := h.controlClient(a)
			return err != nil || controlAnswers(ctx, c) // no client: not the guest's failure
		}
	}
	if guestFailed(ctx, cause, bootFailureGrace, exited, answers) {
		return errors.Join(ErrBootFailed, cause)
	}
	return cause
}
