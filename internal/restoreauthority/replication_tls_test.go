//go:build linux && cgo

package restoreauthority

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/telemetry"
)

type serverChild struct {
	Dir, RestoreID, KeyID, Listen string
}

func (s serverChild) files(role string) authoritylog.TLSFiles {
	peer := map[string]string{authoritylog.RolePrimary: authoritylog.RoleReplica, authoritylog.RoleReplica: authoritylog.RolePrimary}[role]
	return authoritylog.TLSFiles{
		Certificate: filepath.Join(s.Dir, "tls", role+".crt"), Key: filepath.Join(s.Dir, "tls", role+".key"),
		PeerCertificate: filepath.Join(s.Dir, "tls", peer+".crt"), RestoreAuthority: s.RestoreID, KeyAuthority: s.KeyID,
	}
}

// startReplicaServer runs the replica in another process, over mutual TLS,
// and returns its address.
func startReplicaServer(t *testing.T, conf serverChild) (string, *exec.Cmd) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestReplicaServerChild$", "-test.timeout=120s")
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_REPLICATION_CHILD=1")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.ExtraFiles = []*os.File{reader}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	reader.Close()
	json.NewEncoder(writer).Encode(conf)
	writer.Close()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	address, ok := strings.CutPrefix(strings.TrimSpace(line), "listening ")
	if err != nil || !ok {
		t.Fatal("replica server did not start", line, err)
	}
	return address, cmd
}

func TestReplicaServerChild(t *testing.T) {
	var conf serverChild
	if !childConfig(t, &conf) {
		return
	}
	replica, err := OpenReplica(t.Context(), filepath.Join(conf.Dir, "replica"), conf.RestoreID, conf.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	config, err := conf.files(authoritylog.RoleReplica).ServerTLS()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", conf.Listen)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(os.Stdout, "listening %s\n", listener.Addr())
	server := &authoritylog.Server{Replica: replica, Config: config}
	t.Fatal(server.Serve(context.Background(), listener))
}

func percentile(d []time.Duration, q float64) time.Duration {
	s := slices.Clone(d)
	slices.Sort(s)
	return s[int(q*float64(len(s)-1))]
}

func mean(d []time.Duration) time.Duration {
	var total time.Duration
	for _, x := range d {
		total += x
	}
	return total / time.Duration(len(d))
}

// The primary and the replica run in two processes and talk over mutual TLS
// on loopback. This also measures what a replicated write costs.
func TestTwoProcessesOverMutualTLS(t *testing.T) {
	dir := t.TempDir()
	keys, c := primary(t, dir)
	unlock, recipient := newUnlockKey(t)
	snapshot := filepath.Join(dir, "snapshot.sqlite")
	if _, err := c.Snapshot(t.Context(), keys, recipient, snapshot); err != nil {
		t.Fatal(err)
	}
	replica, err := InitializeReplica(t.Context(), filepath.Join(dir, "replica"), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	if err = os.Mkdir(filepath.Join(dir, "tls"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{authoritylog.RolePrimary, authoritylog.RoleReplica} {
		certificate, key, err := authoritylog.GenerateCertificate(role, c.Identity(), keys.Identity())
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "tls", role+".crt"), certificate, 0644); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, "tls", role+".key"), key, 0600); err != nil {
			t.Fatal(err)
		}
	}
	conf := serverChild{Dir: dir, RestoreID: c.Identity(), KeyID: keys.Identity(), Listen: "127.0.0.1:0"}
	address, server := startReplicaServer(t, conf)
	config, err := conf.files(authoritylog.RolePrimary).ClientTLS()
	if err != nil {
		t.Fatal(err)
	}
	client, err := authoritylog.NewClient(address, config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = c.Replicate(t.Context(), client); err != nil {
		t.Fatal(err)
	}
	keys.SetJournal(c)
	registry := telemetry.NewRegistry()
	c.ObserveReplication(authoritylog.NewMetrics(registry))
	b := everyWrite(t, keys, c)
	p := &pair{dir: dir, keys: keys, catalog: c, replica: replica, unlock: unlock, recipient: recipient}
	p.same(t)

	// The cost of a replicated write: one round trip and one fsync on the
	// replica, after the local commit. The baseline is a standalone catalogue
	// on the same disk.
	const writes = 200
	measure := func(c *Catalog, b Binding, prefix string) []time.Duration {
		d := make([]time.Duration, 0, writes)
		for i := range writes {
			start := time.Now()
			if err := c.RecordOutcome(t.Context(), b, Outcome{ID: fmt.Sprintf("%s-%d", prefix, i), Digest: sha256.Sum256([]byte(prefix))}); err != nil {
				t.Fatal(err)
			}
			d = append(d, time.Since(start))
		}
		return d
	}
	replicatedWrites := measure(c, b, "replicated")
	_, standalone := primary(t, filepath.Join(dir, "standalone"))
	alone, err := standalone.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	standaloneWrites := measure(standalone, alone, "standalone")
	trips := make([]time.Duration, 0, writes)
	for range writes {
		start := time.Now()
		if _, err = client.Sync(t.Context(), c.request(1, nil)); err != nil {
			t.Fatal(err)
		}
		trips = append(trips, time.Since(start))
	}
	t.Logf("RecordOutcome over %d writes: replicated mean %v p50 %v p95 %v max %v; standalone mean %v p50 %v p95 %v; empty round trip mean %v p50 %v",
		writes, mean(replicatedWrites), percentile(replicatedWrites, 0.5), percentile(replicatedWrites, 0.95), percentile(replicatedWrites, 1),
		mean(standaloneWrites), percentile(standaloneWrites, 0.5), percentile(standaloneWrites, 0.95), mean(trips), percentile(trips, 0.5))
	p.same(t)

	// The standby stops: a write commits locally, then waits and fails.
	server.Process.Kill()
	server.Wait()
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	err = c.RecordOutcome(ctx, b, Outcome{ID: "while-down", Digest: sha256.Sum256([]byte("down"))})
	cancel()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatal("write returned without the standby", err)
	}
	var out strings.Builder
	registry.WriteTo(&out)
	if !strings.Contains(out.String(), `agentcapsule_authority_replication_last_error{kind="unreachable"} 1`) ||
		!strings.Contains(out.String(), "agentcapsule_authority_replication_lag_records 1\n") {
		t.Fatal("the outage is not visible in the metrics", out.String())
	}
	// It comes back on the same address: the next transaction resends.
	conf.Listen = address
	startReplicaServer(t, conf)
	if _, err = c.Lookup(t.Context(), b.Store); err != nil {
		t.Fatal(err)
	}
	p.same(t)
	out.Reset()
	registry.WriteTo(&out)
	if !strings.Contains(out.String(), `agentcapsule_authority_replication_last_error{kind="none"} 1`) ||
		!strings.Contains(out.String(), "agentcapsule_authority_replication_lag_records 0\n") {
		t.Fatal("the recovery is not visible in the metrics", out.String())
	}
}
