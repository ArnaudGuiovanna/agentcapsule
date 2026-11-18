//go:build linux && cgo

package worker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// egressFlows are worker tests whose flows reach each kind of endpoint a
// worker is configured for: a model provider through the gateway, from a
// guest's call; a registry, public and private, and a hostile one; the
// authority service; the off-host stores of the archives (through a
// fetcher).
var egressFlows = []string{"TestModelErrorsReachTheGuestAndLeaveItsVMRunning", "TestWorkerImportsVerifiedPackagesIntoTheCache",
	"TestPrivateRegistryImportsNeedCredentials", "TestRejectedImportLeaksNoRegistrySecret", "TestTheHostNeverRunsWhatAPackageHolds",
	"TestRestoreTestChecksTheNewestArchiveAndChangesNothing", "TestRestoreHostMovesTheLostHostsAgentsHere",
	"TestGarbageCollectionEvictsOnlyImagesNoAgentCanBoot"}

// egressRules count, in the namespace, the packets that leave by another
// interface than loopback, the UDP datagrams, and on loopback the TCP
// connections opened, by port, and the ports that accepted one.
const egressRules = `table inet egress {
  set connected { type inet_service; flags dynamic; counter; }
  set accepted { type inet_service; flags dynamic; counter; }
  counter outside {}
  counter datagrams {}
  chain output {
    type filter hook output priority filter; policy accept;
    oifname != "lo" counter name outside
    meta l4proto udp counter name datagrams
    oifname "lo" tcp flags & (syn | ack) == syn add @connected { tcp dport }
    oifname "lo" tcp flags & (syn | ack) == syn | ack add @accepted { tcp sport }
  }
}
`

// egressSetup runs as root of a user namespace that owns a new network
// namespace: loopback, and a dummy interface the default routes go
// through, so that an attempt to reach another host sends a packet there.
// The command then runs as this account again, and the counters are saved.
const egressSetup = `set -e
out=$1 rules=$2 uid=$3 gid=$4
shift 4
ip link set lo up
ip link add dummy0 type dummy
ip link set dummy0 addrgenmode none
ip link set dummy0 up
ip addr add 192.0.2.1/24 dev dummy0
ip route add default via 192.0.2.254 dev dummy0
ip -6 addr add 2001:db8::1/64 dev dummy0 nodad
ip -6 route add default via 2001:db8::fe dev dummy0
nft -f "$rules"
status=0
unshare --user --map-user="$uid" --map-group="$gid" -- "$@" > "$out/flows.log" 2>&1 || status=$?
nft -j list ruleset > "$out/nft.json"
ip -j -s link show dev dummy0 > "$out/dummy0.json"
exit $status
`

// DEP-1: the worker's flows, run in a network namespace whose only way out
// is a dummy interface, send no packet out of it and no UDP datagram (no DNS
// query), and every TCP connection they open goes to a port where something
// the flows started, the endpoint they are configured for, listens. The
// flows are the worker tests of egressFlows; the API and the binaries are
// checked by scripts/verify-install.py the same way.
func TestWorkerFlowsDialOnlyTheirConfiguredEndpoints(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_TEST_POSTGRES") == "" {
		if os.Getenv("AGENTCAPSULE_REQUIRE_POSTGRES") == "1" {
			t.Fatal("PostgreSQL required")
		}
		t.Skip("run scripts/verify-postgres.py")
	}
	for _, tool := range []string{"unshare", "ip", "nft"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(tool, "is required: util-linux, iproute2 and nftables, and unprivileged user namespaces")
		}
	}
	dir := t.TempDir()
	rules := filepath.Join(dir, "egress.nft")
	if err := os.WriteFile(rules, []byte(egressRules), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "unshare", "--user", "--map-root-user", "--net", "--fork", "--", "sh", "-c", egressSetup, "sh",
		dir, rules, strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid()),
		os.Args[0], "-test.run", "^("+strings.Join(egressFlows, "|")+")$", "-test.count=1", "-test.v")
	output, err := cmd.CombinedOutput()
	flows, _ := os.ReadFile(filepath.Join(dir, "flows.log"))
	if err != nil {
		t.Fatalf("the flows in the namespace: %v %s\n%s", err, output, tail(flows, 60))
	}
	for _, name := range egressFlows {
		if !strings.Contains(string(flows), "--- PASS: "+name+" ") {
			t.Fatalf("%s did not pass in the namespace:\n%s", name, tail(flows, 60))
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "dummy0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var link []struct {
		Stats struct {
			TX struct {
				Packets *int `json:"packets"`
			} `json:"tx"`
		} `json:"stats64"`
	}
	if err = json.Unmarshal(raw, &link); err != nil || len(link) != 1 || link[0].Stats.TX.Packets == nil {
		t.Fatal("the dummy interface's counters", string(raw), err)
	}
	tx := *link[0].Stats.TX.Packets
	raw, err = os.ReadFile(filepath.Join(dir, "nft.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ruleset struct {
		Items []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets int    `json:"packets"`
			} `json:"counter"`
			Set *struct {
				Name  string `json:"name"`
				Elems []struct {
					Elem struct {
						Port    int `json:"val"`
						Counter struct {
							Packets int `json:"packets"`
						} `json:"counter"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err = json.Unmarshal(raw, &ruleset); err != nil {
		t.Fatal(err)
	}
	counters, sets := map[string]int{}, map[string]map[int]int{}
	for _, item := range ruleset.Items {
		if c := item.Counter; c != nil {
			counters[c.Name] = c.Packets
		}
		if s := item.Set; s != nil {
			sets[s.Name] = map[int]int{}
			for _, e := range s.Elems {
				sets[s.Name][e.Elem.Port] = e.Elem.Counter.Packets
			}
		}
	}
	t.Logf("in the namespace: %d packets on the dummy interface, %v; connections by port %v; ports that accepted %v",
		tx, counters, sets["connected"], sets["accepted"])
	if tx != 0 || counters["outside"] != 0 {
		t.Error("packets left the namespace: something tried to reach another host")
	}
	if c, ok := counters["datagrams"]; !ok || c != 0 {
		t.Error("UDP datagrams were sent (a DNS query?):", c)
	}
	if len(sets["connected"]) < len(egressFlows) {
		t.Error("the counters saw too few connections: they do not see the flows", sets["connected"])
	}
	var stray []int
	for port := range sets["connected"] {
		if _, ok := sets["accepted"][port]; !ok {
			stray = append(stray, port)
		}
	}
	slices.Sort(stray)
	if len(stray) != 0 {
		t.Error("connections to ports where nothing the flows started listens:", stray)
	}
}

// tail is the last n lines of b.
func tail(b []byte, n int) string {
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n") + fmt.Sprintf("\n(%d lines)", len(lines))
}
