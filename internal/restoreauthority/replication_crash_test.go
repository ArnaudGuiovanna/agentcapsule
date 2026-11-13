//go:build linux && cgo

package restoreauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// replicationCrash configures a child process that stops at a boundary of
// the stream, where the parent kills it with SIGKILL.
type replicationCrash struct {
	Dir, RestoreID, KeyID string
	Operation, Boundary   string
	Request               authoritylog.Request
}

func streamOperation(ctx context.Context, keys *keyauthority.Files, c *Catalog, operation string) error {
	switch operation {
	case "outcome":
		return c.RecordOutcome(ctx, Binding{Store: "store-a", Volume: "volume-a", Incarnation: 1}, Outcome{ID: "event-1", Digest: sha256.Sum256([]byte("one"))})
	case "revocation":
		_, err := c.BeginRevocation(ctx, "agent/one")
		return err
	case "ensure":
		return keys.Ensure(ctx, streamAgent, streamVolume)
	case "revoke":
		return keys.Revoke(ctx, streamAgent, streamVolume)
	}
	return ErrInput
}

// killChild starts this test binary as a child running test, waits until it
// reports that it reached its boundary, then kills it with SIGKILL.
func killChild(t *testing.T, test string, conf any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+test+"$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_REPLICATION_CHILD=1")
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	cmd.ExtraFiles = []*os.File{reader}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	reader.Close()
	if err = json.NewEncoder(writer).Encode(conf); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	var ready [5]byte
	if _, err = io.ReadFull(stdout, ready[:]); err != nil || string(ready[:]) != "ready" {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal("child did not reach its boundary", err, stderr.String())
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL || strings.Contains(stderr.String(), "DATA RACE") {
		t.Fatal("SIGKILL/race observation failed", err, stderr.String())
	}
}

func childConfig(t *testing.T, conf any) bool {
	if os.Getenv("AGENTCAPSULE_REPLICATION_CHILD") != "1" {
		return false
	}
	file := os.NewFile(3, "configuration")
	defer file.Close()
	if err := json.NewDecoder(file).Decode(conf); err != nil {
		t.Fatal(err)
	}
	return true
}

func stopHere() {
	os.Stdout.WriteString("ready")
	<-make(chan struct{})
}

// The primary dies before its commit, between its commit and the send, and
// after the replica applied the record but before the acknowledgment reached
// it. The next transaction resends from the replica's last sequence, and the
// operation's retries record nothing twice.
func TestPrimarySIGKILLBetweenCommitAndAcknowledgment(t *testing.T) {
	for _, operation := range []string{"outcome", "revocation", "ensure", "revoke"} {
		for _, boundary := range []string{"before_commit", "after_commit", "after_apply"} {
			t.Run(operation+"/"+boundary, func(t *testing.T) {
				p := replicated(t)
				if _, err := p.catalog.Register(t.Context(), "store-a", "volume-a"); err != nil {
					t.Fatal(err)
				}
				if operation == "revoke" {
					if err := p.keys.Ensure(t.Context(), streamAgent, streamVolume); err != nil {
						t.Fatal(err)
					}
				}
				before, _ := p.catalog.Replication(t.Context())
				killChild(t, "TestPrimaryCrashChild", replicationCrash{Dir: p.dir, RestoreID: p.catalog.Identity(), KeyID: p.keys.Identity(), Operation: operation, Boundary: boundary})
				state, _ := p.catalog.Replication(t.Context())
				position, _ := p.replica.Position(t.Context())
				want := map[string][2]uint64{"before_commit": {0, 0}, "after_commit": {1, 0}, "after_apply": {1, 1}}[boundary]
				if state.Committed.Seq != before.Committed.Seq+want[0] || position.Seq != before.Committed.Seq+want[1] {
					t.Fatal("unexpected durable state", before.Committed.Seq, state.Committed.Seq, position.Seq)
				}
				var used bool
				err := p.keys.WithKey(t.Context(), streamAgent, streamVolume, func([]byte) error { used = true; return nil })
				switch operation {
				case "ensure":
					if err == nil || used {
						t.Fatal("a key the replica may lack was usable", err)
					}
				case "revoke":
					if !errors.Is(err, keyauthority.ErrRevoked) || used {
						t.Fatal("a key being destroyed was usable", err)
					}
				}
				// Any transaction, here a read, first brings the replica up.
				if _, err = p.catalog.Lookup(t.Context(), "store-a"); err != nil {
					t.Fatal(err)
				}
				if position, _ = p.replica.Position(t.Context()); position.Seq != state.Committed.Seq {
					t.Fatal("unacknowledged record not resent", position.Seq, state.Committed.Seq)
				}
				var after ReplicationState
				for i := range 2 {
					if err = streamOperation(t.Context(), p.keys, p.catalog, operation); err != nil {
						t.Fatal("stable retry failed", err)
					}
					previous := after
					after, _ = p.catalog.Replication(t.Context())
					if i == 1 && operation != "revoke" && after.Committed.Seq != previous.Committed.Seq {
						t.Fatal("a repeated retry was recorded again")
					}
				}
				p.same(t)
				if operation == "ensure" {
					if err = p.keys.WithKey(t.Context(), streamAgent, streamVolume, func([]byte) error { return nil }); err != nil {
						t.Fatal("replicated key unusable", err)
					}
				}
			})
		}
	}
}

func TestPrimaryCrashChild(t *testing.T) {
	var conf replicationCrash
	if !childConfig(t, &conf) {
		return
	}
	keys, err := keyauthority.Open(filepath.Join(conf.Dir, "keys"), conf.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	c, err := Open(t.Context(), filepath.Join(conf.Dir, "restore"), conf.RestoreID, conf.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	replica, err := OpenReplica(t.Context(), filepath.Join(conf.Dir, "replica"), conf.RestoreID, conf.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	link := &tap{target: replica}
	if err = c.Replicate(t.Context(), link); err != nil {
		t.Fatal(err)
	}
	keys.SetJournal(c)
	if conf.Boundary == "after_apply" {
		link.afterAck = stopHere
	} else {
		c.hook = func(boundary string) {
			if boundary == conf.Boundary {
				stopHere()
			}
		}
	}
	if err = streamOperation(t.Context(), keys, c, conf.Operation); err != nil {
		t.Fatal(err)
	}
	t.Fatal("fault boundary was not reached")
}

// The replica dies inside its apply transaction, and after its commit but
// before its answer. It restarts at a consistent position; the primary
// resends, and a duplicate is acknowledged without a second apply.
func TestReplicaSIGKILLMidApply(t *testing.T) {
	for _, operation := range []string{"outcome", "ensure"} {
		for _, boundary := range []string{"replica_before_commit", "replica_after_commit"} {
			t.Run(operation+"/"+boundary, func(t *testing.T) {
				p := replicated(t)
				if _, err := p.catalog.Register(t.Context(), "store-a", "volume-a"); err != nil {
					t.Fatal(err)
				}
				before, _ := p.replica.Position(t.Context())
				// The standby is unreachable: the record waits in the log.
				p.link.set(true)
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				err := streamOperation(ctx, p.keys, p.catalog, operation)
				cancel()
				if !errors.Is(err, ErrUnavailable) {
					t.Fatal(err)
				}
				records, _, err := p.catalog.readLog(t.Context(), before.Seq, before.Seq+1)
				if err != nil || len(records) != 1 {
					t.Fatal(records, err)
				}
				request := p.catalog.request(1, records)
				killChild(t, "TestReplicaCrashChild", replicationCrash{Dir: p.dir, RestoreID: p.catalog.Identity(), KeyID: p.keys.Identity(), Boundary: boundary, Request: request})
				position, err := p.replica.Position(t.Context())
				want := before.Seq
				if boundary == "replica_after_commit" {
					want++
				}
				if err != nil || position.Seq != want {
					t.Fatal("replica restarted at an unexpected position", position, err)
				}
				var check string
				if err = p.replica.db.QueryRow("PRAGMA integrity_check").Scan(&check); err != nil || check != "ok" {
					t.Fatal(check, err)
				}
				p.link.set(false)
				if err = streamOperation(t.Context(), p.keys, p.catalog, operation); err != nil {
					t.Fatal(err)
				}
				p.same(t)
			})
		}
	}
}

func TestReplicaCrashChild(t *testing.T) {
	var conf replicationCrash
	if !childConfig(t, &conf) {
		return
	}
	replica, err := OpenReplica(t.Context(), filepath.Join(conf.Dir, "replica"), conf.RestoreID, conf.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	replica.hook = func(boundary string) {
		if boundary == conf.Boundary {
			stopHere()
		}
	}
	if _, err = replica.Sync(t.Context(), conf.Request); err != nil {
		t.Fatal(err)
	}
	t.Fatal("fault boundary was not reached")
}
