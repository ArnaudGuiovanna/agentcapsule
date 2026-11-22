//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// hostAgentUID is the UID the host's registry gave the agent's VMM.
func (l *productPeerLab) hostAgentUID(agentID string) uint32 {
	l.t.Helper()
	var registry struct {
		Agents map[string]struct {
			UID uint32 `json:"uid"`
		} `json:"agents"`
	}
	raw, err := os.ReadFile(filepath.Join(l.root, "registry.json"))
	if err != nil || json.Unmarshal(raw, &registry) != nil {
		l.t.Fatal("host registry", err)
	}
	a, ok := registry.Agents[agentID]
	if !ok || a.UID == 0 {
		l.t.Fatal("the host registry gives the agent no UID of its own", agentID)
	}
	return a.UID
}

// agentState is the agent's state as its organization reads it.
func (l *registryLab) agentState(agentID string) string {
	l.t.Helper()
	var v struct {
		State string `json:"state"`
	}
	l.request(l.owner(), "GET", "/v1/agents/"+agentID, "", nil, 200, &v)
	return v.State
}

// procFields reads /proc/<pid>/status, one value per field, spaces collapsed.
func procFields(t *testing.T, pid int) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal("the VMM's status", err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.Join(strings.Fields(v), " ")
		}
	}
	return fields
}

// sameProcess reports whether pid still names the process that started at
// ticks (field 22 of /proc/<pid>/stat), not a later one with its number.
func sameProcess(pid int, ticks string) bool {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	i := strings.LastIndex(string(raw), ")")
	f := strings.Fields(string(raw[i+1:]))
	return i >= 0 && len(f) > 19 && f[19] == ticks && f[0] != "Z"
}

// runsAs lists the processes of the host whose real UID is uid.
func runsAs(t *testing.T, uid uint32) []string {
	t.Helper()
	paths, err := filepath.Glob("/proc/[0-9]*/status")
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue // the process ended meanwhile
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if f := strings.Fields(line); len(f) > 1 && f[0] == "Uid:" && f[1] == strconv.FormatUint(uint64(uid), 10) {
				found = append(found, path)
			}
		}
	}
	return found
}

// ownedBy lists the paths under root owned by uid.
func ownedBy(t *testing.T, root string, uid uint32) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid == uid {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// entries lists a directory, empty when it does not exist.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	return names
}

// A product wake starts a jailed microVM with the agent's planned resources,
// and the agent reads READY (RUN-002): the VMM runs as the agent's own UID
// and GID, without supplementary groups or capabilities, under seccomp,
// chrooted in its jail, as PID 1 of its own PID namespace, in its own mount
// and network namespaces, in its own cgroup with the plan's memory, CPU and
// process limits, with its open files bounded, and holds a KVM VM. A stop
// leaves nothing for another capsule (RUN-008): no process of the agent's
// UID, no jail, cgroup, socket, platform lock or boot credentials; only the
// agent's own volume is still its UID's, and its log stays the host's. After
// the agent's deletion, the next agent gets another UID.
func TestProductWorkerJailsEachVMAndLeavesNothingBehind(t *testing.T) {
	l := newRegistryLab(t)
	agent := l.createOn("jailed", "reference", "1.0.0").AgentID
	if got := l.agentState(agent); got != "READY" {
		t.Fatal("the woken agent is not READY", got)
	}
	run := l.runs(1)[agent]
	uid := l.hostAgentUID(agent)
	if uid < 62300 || uid > 62309 {
		t.Fatal("the VMM's UID is outside the host's provisioning range", uid)
	}
	sum := sha256.Sum256([]byte(l.root))
	hostGroup := filepath.Join("/sys/fs/cgroup", "acp-runtime-"+hex.EncodeToString(sum[:8]))
	group := filepath.Join(hostGroup, run.ID)
	jail := filepath.Join(l.root, "jails", "firecracker", run.ID, "root")

	t.Log("stage: the VMM of the product wake is jailed")
	status := procFields(t, run.PID)
	ids := fmt.Sprintf("%d %d %d %d", uid, uid, uid, uid)
	if status["Uid"] != ids || status["Gid"] != ids || status["Groups"] != "" || status["CapEff"] != "0000000000000000" ||
		status["Seccomp"] != "2" || status["NSpid"] != fmt.Sprintf("%d 1", run.PID) {
		t.Fatalf("the VMM's identity: Uid %q Gid %q Groups %q CapEff %q Seccomp %q NSpid %q",
			status["Uid"], status["Gid"], status["Groups"], status["CapEff"], status["Seccomp"], status["NSpid"])
	}
	root, err := os.Stat(fmt.Sprintf("/proc/%d/root", run.PID))
	want, err2 := os.Stat(jail)
	if err != nil || err2 != nil || !os.SameFile(root, want) {
		t.Fatal("the VMM is not chrooted in its jail", err, err2)
	}
	for _, ns := range []string{"mnt", "pid", "net"} {
		own, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", run.PID, ns))
		host, err2 := os.Readlink("/proc/self/ns/" + ns)
		if err != nil || err2 != nil || own == host {
			t.Fatal("the VMM shares the host's namespace", ns, err, err2)
		}
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", run.PID))
	if err != nil || strings.TrimSpace(string(raw)) != "0::"+strings.TrimPrefix(group, "/sys/fs/cgroup") {
		t.Fatal("the VMM is not in its own cgroup", string(raw), err)
	}
	for file, want := range map[string]string{"memory.max": strconv.Itoa((256 + 256) << 20), "cpu.max": "100000 100000", "pids.max": "32"} {
		raw, err := os.ReadFile(filepath.Join(group, file))
		if err != nil || strings.TrimSpace(string(raw)) != want {
			t.Fatal("the cgroup's limit", file, strings.TrimSpace(string(raw)), want, err)
		}
	}
	raw, err = os.ReadFile(fmt.Sprintf("/proc/%d/limits", run.PID))
	if err != nil {
		t.Fatal(err)
	}
	bounded := false
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "Max open files"); ok {
			f := strings.Fields(rest)
			bounded = len(f) >= 2 && f[0] == "256" && f[1] == "256"
		}
	}
	if !bounded {
		t.Fatal("the VMM's open files are not bounded at 256", string(raw))
	}
	kvm := false
	for _, fd := range entries(t, fmt.Sprintf("/proc/%d/fd", run.PID)) {
		if target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", run.PID, fd)); err == nil && target == "anon_inode:kvm-vm" {
			kvm = true
		}
	}
	if !kvm {
		t.Fatal("the VMM holds no KVM VM")
	}
	var cfg struct {
		Machine struct {
			VCPUs     int `json:"vcpu_count"`
			MemoryMiB int `json:"mem_size_mib"`
		} `json:"machine-config"`
		Network json.RawMessage `json:"network-interfaces"`
	}
	raw, err = os.ReadFile(filepath.Join(jail, "config.json"))
	if err != nil || json.Unmarshal(raw, &cfg) != nil || cfg.Machine.VCPUs != 1 || cfg.Machine.MemoryMiB != 256 || cfg.Network != nil {
		t.Fatal("the VM's configuration is not the plan, or has a network device", string(raw), err)
	}
	credentials, err := os.Stat(filepath.Join(l.root, "credentials", run.ID+".json"))
	if err != nil || credentials.Mode().Perm() != 0o600 || credentials.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("the boot credentials are not the host's alone", err)
	}
	// S-20: no serial console in production, and the VMM's log is the host's
	// alone while the VM runs.
	var boot struct {
		Source struct {
			Args string `json:"boot_args"`
		} `json:"boot-source"`
	}
	if json.Unmarshal(raw, &boot) != nil || strings.Contains(boot.Source.Args, "console=ttyS0") || !strings.Contains(boot.Source.Args, "8250.nr_uarts=0") {
		t.Fatal("the guest has a serial console", boot.Source.Args)
	}
	log, err := os.Stat(filepath.Join(l.root, "logs", run.ID+".log"))
	if err != nil || log.Mode().Perm() != 0o600 || log.Sys().(*syscall.Stat_t).Uid != 0 || log.Size() > 2<<20 { // the cap, and one monitor period
		t.Fatal("the VM's log is not the host's alone, or exceeds its limit", err)
	}
	// P-12: the kernel is the cached image itself, readable but not writable
	// by the VMM; L-15: the platform socket is the VMM's, not a link.
	kernel, err := os.Stat(filepath.Join(jail, "kernel"))
	cached, err2 := os.Stat(filepath.Join(l.root, "bin", "kernel"))
	if err != nil || err2 != nil || !os.SameFile(kernel, cached) || kernel.Mode().Perm() != 0o444 || kernel.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("the jail's kernel is not the cached image", err, err2)
	}
	socket, err := os.Lstat(filepath.Join(jail, "vsock_5001"))
	if err != nil || socket.Mode()&os.ModeSocket == 0 || socket.Mode().Perm() != 0o600 || socket.Sys().(*syscall.Stat_t).Uid != uid {
		t.Fatal("the platform socket is not the VMM's", err)
	}

	t.Log("stage: a stop leaves nothing for another capsule")
	l.lifecycle(agent, "sleep", "jailed-sleep")
	l.runs(0)
	if got := l.agentState(agent); got != "STOPPED" {
		t.Fatal("the stopped agent reads", got)
	}
	if sameProcess(run.PID, run.StartTicks) {
		t.Fatal("the VMM survived the stop")
	}
	if found := runsAs(t, uid); len(found) != 0 {
		t.Fatal("processes still run as the agent's UID", found)
	}
	for _, dir := range []string{filepath.Join(l.root, "jails", "firecracker"), filepath.Join(l.root, "credentials"), filepath.Join(l.root, "platform")} {
		if left := entries(t, dir); len(left) != 0 {
			t.Fatal("left behind in", dir, left)
		}
	}
	for _, name := range entries(t, hostGroup) {
		if info, err := os.Stat(filepath.Join(hostGroup, name)); err == nil && info.IsDir() {
			t.Fatal("a VM cgroup is left", name)
		}
	}
	err = filepath.WalkDir(l.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Its log included (S-20).
		if strings.Contains(d.Name(), run.ID) {
			return fmt.Errorf("%s names the stopped VM", path)
		}
		if d.Type()&fs.ModeSocket != 0 {
			return fmt.Errorf("a socket is left: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err := l.store.VolumeEnrollment(t.Context(), agent, "local")
	if err != nil {
		t.Fatal(err)
	}
	volume := filepath.Join(l.root, "volumes", e.VolumeID+".luks")
	if owned := ownedBy(t, l.root, uid); len(owned) != 1 || owned[0] != volume {
		t.Fatal("the agent's UID owns more than its volume", owned)
	}

	t.Log("stage: after the deletion, the next agent gets another UID")
	var deletion struct {
		OperationID string `json:"operation_id"`
	}
	l.request(l.owner(), "DELETE", "/v1/agents/"+agent, "jailed-delete", nil, 202, &deletion)
	l.awaitOperation(l.owner, deletion.OperationID)
	if owned := ownedBy(t, l.root, uid); len(owned) != 0 {
		t.Fatal("the deleted agent's UID still owns", owned)
	}
	next := l.createOn("next", "reference", "1.0.0").AgentID
	nextUID := l.hostAgentUID(next)
	if nextUID == uid {
		t.Fatal("the next agent reuses the deleted agent's UID", uid)
	}
	if got := procFields(t, l.runs(1)[next].PID)["Uid"]; got != fmt.Sprintf("%d %d %d %d", nextUID, nextUID, nextUID, nextUID) {
		t.Fatal("the next VMM does not run as its own UID", got)
	}
}
