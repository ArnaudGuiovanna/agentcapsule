//go:build linux

package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// labRules count, in the lab's namespace, the packets that leave by another
// interface than loopback, and those to each probe's port: 1001 (TCP) and
// 1002 (UDP) for the probe run directly, 2001 and 2002 for the confined one.
const labRules = `table inet lab {
  counter outside {}
  counter tcp1001 {}
  counter udp1002 {}
  counter tcp2001 {}
  counter udp2002 {}
  chain output {
    type filter hook output priority filter; policy accept;
    oifname != "lo" counter name outside
    tcp dport 1001 counter name tcp1001
    udp dport 1002 counter name udp1002
    tcp dport 2001 counter name tcp2001
    udp dport 2002 counter name udp2002
  }
}
`

// labSetup runs as root of a user namespace that owns a new network
// namespace: loopback, and a dummy interface the default route goes
// through, so that an attempt to reach another host sends a packet there
// (the technique of TestWorkerFlowsDialOnlyTheirConfiguredEndpoints).
const labSetup = `set -e
out=$1 rules=$2
shift 2
ip link set lo up
ip link add dummy0 type dummy
ip link set dummy0 addrgenmode none
ip link set dummy0 up
ip addr add 192.0.2.1/24 dev dummy0
ip route add default via 192.0.2.254 dev dummy0
nft -f "$rules"
status=0
"$@" > "$out/probes.log" 2>&1 || status=$?
nft -j list ruleset > "$out/nft.json"
exit $status
`

// networkProbe tries a TCP connection and a UDP datagram to the lab's
// gateway, with bash's /dev/tcp and /dev/udp, from regular builtins.
func networkProbe(tcp, udp int) string {
	return "exec 2>&1\n" +
		"true 3<>/dev/tcp/192.0.2.254/" + strconv.Itoa(tcp) + " && echo TCP-CONNECTED\n" +
		"echo x 3<>/dev/udp/192.0.2.254/" + strconv.Itoa(udp) + " >&3 && echo UDP-SENT\n" +
		"echo done\n"
}

// REG-01: a confined program cannot reach the network. In a lab whose only
// way out is a dummy interface, the probe run directly sends its TCP and UDP
// packets there, and the same probe confined sends none: it cannot open a
// socket, and its own network namespace has no interface.
func TestConfinedProgramCannotReachTheNetwork(t *testing.T) {
	// The lab's namespace belongs to a user namespace of this account, where
	// the probes run as root of it: confined like any account but root.
	cannotReachTheNetwork(t, []string{"--user", "--map-root-user"}, 0)
}

// cannotReachTheNetwork runs TestNetworkProbesInTheLab in a lab made with
// unshare, with these options and --net, then reads its counters. uid, when
// not 0, is the UID and GID the confined probe runs as.
func cannotReachTheNetwork(t *testing.T, options []string, uid uint32) {
	t.Helper()
	for _, tool := range []string{"unshare", "ip", "nft", "bash"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(tool, "is required: util-linux, iproute2, nftables, bash, and unprivileged user namespaces")
		}
	}
	dir := t.TempDir()
	rules := filepath.Join(dir, "lab.nft")
	if err := os.WriteFile(rules, []byte(labRules), 0o600); err != nil {
		t.Fatal(err)
	}
	args := append(append(options, "--net", "--fork", "--", "sh", "-c", labSetup, "sh", dir, rules),
		os.Args[0], "-test.run", "^TestNetworkProbesInTheLab$", "-test.count=1", "-test.v")
	cmd := exec.CommandContext(t.Context(), "unshare", args...)
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_SANDBOX_LAB="+strconv.FormatUint(uint64(uid), 10))
	output, err := cmd.CombinedOutput()
	probes, _ := os.ReadFile(filepath.Join(dir, "probes.log"))
	if err != nil || !strings.Contains(string(probes), "--- PASS: TestNetworkProbesInTheLab ") {
		t.Fatalf("the probes in the lab: %v %s\n%s", err, output, probes)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "nft.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ruleset struct {
		Items []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets int    `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err = json.Unmarshal(raw, &ruleset); err != nil {
		t.Fatal(err)
	}
	counters := map[string]int{}
	for _, item := range ruleset.Items {
		if c := item.Counter; c != nil {
			counters[c.Name] = c.Packets
		}
	}
	t.Logf("packets in the lab: %v", counters)
	if counters["tcp1001"] < 1 || counters["udp1002"] != 1 {
		t.Fatal("the lab did not count the direct probe's packets: it cannot see the confined one's either", counters)
	}
	if counters["tcp2001"] != 0 || counters["udp2002"] != 0 {
		t.Error("the confined probe's packets reached the lab's network", counters)
	}
	if counters["outside"] != counters["tcp1001"]+counters["udp1002"] {
		t.Error("other packets left the lab", counters)
	}
}

// TestNetworkProbesInTheLab runs only inside the lab of
// cannotReachTheNetwork.
func TestNetworkProbesInTheLab(t *testing.T) {
	lab := os.Getenv("AGENTCAPSULE_SANDBOX_LAB")
	if lab == "" {
		return
	}
	uid, err := strconv.ParseUint(lab, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	o := Options{UID: uint32(uid), GID: uint32(uid)}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	// Directly: the TCP connection waits for an answer that never comes;
	// its first packet is counted.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	direct, _ := exec.CommandContext(ctx, bash, "-c", "true 3<>/dev/tcp/192.0.2.254/1001").CombinedOutput()
	sent, err := exec.CommandContext(t.Context(), bash, "-c", "echo x 3<>/dev/udp/192.0.2.254/1002 >&3 && echo UDP-SENT").CombinedOutput()
	if err != nil || !strings.Contains(string(sent), "UDP-SENT") {
		t.Fatalf("the direct probe could not send its datagram: %v %s (TCP: %s)", err, sent, direct)
	}
	out, err := o.Run(t.Context(), "", bash, "-c", networkProbe(2001, 2002))
	t.Logf("confined probe: %s", out)
	if err != nil || strings.Contains(string(out), "CONNECTED") || strings.Contains(string(out), "SENT") ||
		strings.Count(string(out), "Operation not permitted") < 2 || !strings.HasSuffix(string(out), "done\n") {
		t.Errorf("the confined probe: %v\n%s", err, out)
	}
}
