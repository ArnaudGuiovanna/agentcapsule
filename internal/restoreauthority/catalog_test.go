//go:build linux && cgo

package restoreauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
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

	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

const testKeyIdentity = "keyauth_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestCurrentFenceAndRevocationPublicationRequireIndependentACKs(t *testing.T) {
	c, a := fixture(t)
	b, err := c.Register(t.Context(), "store-b", "volume-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.BeginRevocation(t.Context(), "agent/x"); err != nil {
		t.Fatal(err)
	}
	scan, err := c.Scan(t.Context(), a)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []func() error{
		func() error {
			return c.WithCurrentFences(t.Context(), scan, func() error { t.Error("snapshot mistaken for guest ACK"); return nil })
		},
		func() error {
			return c.WithRevocation(t.Context(), "agent/x", []Binding{a, b}, func() error { t.Error("missing ACK published"); return nil })
		},
	} {
		if err = check(); !errors.Is(err, ErrStale) {
			t.Fatal(err)
		}
	}
	// Trusted guest ACK is supplied explicitly in this catalogue-only test.
	if err = c.RecordVerifiedFence(t.Context(), scan); err != nil {
		t.Fatal(err)
	}
	if err = c.WithRevocation(t.Context(), "agent/x", []Binding{a, b}, func() error { t.Error("missing second store ignored"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	if err = c.RecordRetiredSeal(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	called := false
	if err = c.WithRevocation(t.Context(), "agent/x", []Binding{a, b}, func() error { called = true; return nil }); err != nil || !called {
		t.Fatal(err)
	}
	if _, err = c.BeginRevocation(t.Context(), "agent/new"); err != nil {
		t.Fatal(err)
	}
	if err = c.WithCurrentFences(t.Context(), scan, func() error { t.Error("boot missed new revocation"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	// An ACK of x remains valid for x after unrelated catalogue growth.
	if err = c.WithRevocation(t.Context(), "agent/x", []Binding{a, b}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	next, err := c.ReserveIncarnation(t.Context(), a, "restore")
	if err != nil {
		t.Fatal(err)
	}
	if err = c.WithRevocation(t.Context(), "agent/x", []Binding{a, b}, func() error { t.Error("old incarnation published"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	if ack, _, err := c.SubjectBarrier(t.Context(), next, "agent/x"); err != nil || ack {
		t.Fatal("new incarnation inherited ACK", ack, err)
	}
}

func TestBindingGateSerializesReservationAndNeverEnrolls(t *testing.T) {
	c, b := fixture(t)
	other := reopen(t, c)
	if _, err := c.Lookup(t.Context(), "missing"); !errors.Is(err, ErrStale) {
		t.Fatal("lookup fabricated binding", err)
	}
	if got, err := c.Lookup(t.Context(), b.Store); err != nil || got != b {
		t.Fatal(got, err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- c.WithBinding(t.Context(), b, func() error { close(entered); <-release; return nil }) }()
	<-entered
	reserved := make(chan error, 1)
	go func() { _, err := other.ReserveIncarnation(t.Context(), b, "restore"); reserved <- err }()
	select {
	case err := <-reserved:
		close(release)
		<-done
		t.Fatal("reservation overtook active key/confirmation gate", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-reserved; err != nil {
		t.Fatal(err)
	}
	if err := c.WithBinding(t.Context(), b, func() error { t.Error("obsolete binding used"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal(err)
	}
	current, err := c.Lookup(t.Context(), b.Store)
	if err != nil || current.Incarnation != 2 {
		t.Fatal(current, err)
	}
	if err = c.RecordRetiredSeal(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Lookup(t.Context(), b.Store); !errors.Is(err, ErrSealed) {
		t.Fatal("sealed store lookup admitted", err)
	}
}

func fixture(t *testing.T) (*Catalog, Binding) {
	t.Helper()
	c, err := Initialize(t.Context(), filepath.Join(t.TempDir(), "authority"), testKeyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	b, err := c.Register(t.Context(), "store-a", "volume-a")
	if err != nil {
		t.Fatal(err)
	}
	return c, b
}

func reopen(t *testing.T, c *Catalog) *Catalog {
	t.Helper()
	next, err := Open(t.Context(), c.root, c.identity, c.keyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { next.Close() })
	return next
}

// nothingMissing inspects an image that holds every recorded outcome.
func nothingMissing([]Outcome) ([]string, error) { return nil, nil }

func receipt(t *testing.T, c *Catalog, b Binding) Receipt {
	t.Helper()
	r, err := c.Scan(t.Context(), b)
	if err != nil {
		t.Fatal(err)
	}
	// These catalogue tests supply the trusted-worker precondition explicitly.
	// A real restore coordinator must authenticate the durable guest fence ACK.
	if err = c.RecordVerifiedFence(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestInitializationIdentityAndMissingAuthorityFailClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "authority")
	type result struct {
		c   *Catalog
		err error
	}
	results := make(chan result, 8)
	for range 8 {
		go func() { c, err := Initialize(t.Context(), root, testKeyIdentity); results <- result{c, err} }()
	}
	identity := ""
	for range 8 {
		r := <-results
		if r.err != nil {
			t.Error(r.err)
			continue
		}
		if identity != "" && r.c.Identity() != identity {
			t.Error("concurrent initialization replaced the identity")
		}
		identity = r.c.Identity()
		r.c.Close()
	}
	if t.Failed() {
		return
	}
	if c, err := Open(t.Context(), root, "restoreauth_"+strings.Repeat("b", 32), testKeyIdentity); err == nil {
		c.Close()
		t.Fatal("replaced identity accepted")
	}
	if c, err := Initialize(t.Context(), root, "keyauth_"+strings.Repeat("b", 32)); !errors.Is(err, ErrConflict) {
		if c != nil {
			c.Close()
		}
		t.Fatal("key authority rebound", err)
	}
	c, err := Open(t.Context(), root, identity, testKeyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	path := filepath.Join(root, "catalog.sqlite")
	if err = os.Rename(path, path+".offline"); err != nil {
		t.Fatal(err)
	}
	called := false
	if err = c.WithSubjectKey(t.Context(), "subject", func() error { called = true; return nil }); !errors.Is(err, ErrUnavailable) || called {
		t.Fatal("cached SQL connection bypassed missing authority", err)
	}
	if replacement, err := Initialize(t.Context(), root, testKeyIdentity); !errors.Is(err, ErrUnavailable) {
		if replacement != nil {
			replacement.Close()
		}
		t.Fatal("missing initialized authority recreated", err)
	}
	if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing catalogue path was created", err)
	}
	if err = os.Rename(path+".offline", path); err != nil {
		t.Fatal(err)
	}
	if err = c.WithSubjectKey(t.Context(), "subject", func() error { called = true; return nil }); err != nil || !called {
		t.Fatal("available authority failed to recover", err)
	}
	c.Close()
	if err = os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	if replacement, err := Initialize(t.Context(), root, testKeyIdentity); !errors.Is(err, ErrUnavailable) {
		if replacement != nil {
			replacement.Close()
		}
		t.Fatal("lost initialized schema was silently re-created", err)
	}
	if got, err := readIdentity(root); err != nil || got != identity {
		t.Fatal("failed recovery replaced the pinned identity", err)
	}
}

func TestAuthorityPathSeparationAndInodeReplacement(t *testing.T) {
	c, b := fixture(t)
	if err := c.SeparateFrom(filepath.Join(c.root, "missing-data")); !errors.Is(err, ErrInput) {
		t.Fatal("nested restore domain accepted", err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(c.root, alias); err != nil {
		t.Fatal(err)
	}
	if err := c.SeparateFrom(filepath.Join(alias, "not-created")); !errors.Is(err, ErrInput) {
		t.Fatal("nested symlink restore domain accepted", err)
	}
	if err := c.SeparateFrom(filepath.Join(t.TempDir(), "data")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.root, "catalog.sqlite")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Scan(t.Context(), b); !errors.Is(err, ErrUnavailable) {
		t.Fatal("live connection accepted replacement inode", err)
	}
}

func TestConcurrentReservationAndOldReceiptCannotRebind(t *testing.T) {
	c, old := fixture(t)
	peer := reopen(t, c)
	before := receipt(t, c, old)
	type result struct {
		b   Binding
		err error
	}
	results := make(chan result, 8)
	for i := range 8 {
		go func() {
			catalog := []*Catalog{c, peer}[i%2]
			b, err := catalog.ReserveIncarnation(t.Context(), old, "restore-one")
			results <- result{b, err}
		}()
	}
	next := old
	next.Incarnation++
	for range 8 {
		r := <-results
		if r.err != nil || r.b != next {
			t.Fatal("idempotent reservation raced", r, next)
		}
	}
	if _, err := c.ReserveIncarnation(t.Context(), old, "different-restore"); !errors.Is(err, ErrStale) {
		t.Fatal("obsolete reservation accepted", err)
	}
	if err := peer.RecordVerifiedFence(t.Context(), before); !errors.Is(err, ErrStale) {
		t.Fatal("old incarnation receipt rebound", err)
	}
	r, err := peer.Scan(t.Context(), next)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err = peer.WithActivation(t.Context(), r, nothingMissing, func() error { called = true; return nil }); !errors.Is(err, ErrStale) || called {
		t.Fatal("reservation retained old fence ACK", err)
	}
	if _, err = c.Register(t.Context(), old.Store, "another-volume"); !errors.Is(err, ErrConflict) {
		t.Fatal("volume rebound", err)
	}
	other, err := c.Register(t.Context(), "store-b", "volume-b")
	if err != nil || other.Incarnation != 1 {
		t.Fatal("independent store changed", other, err)
	}
}

func TestReceiptRevisionAndForgeryCannotPublish(t *testing.T) {
	c, b := fixture(t)
	old := receipt(t, c, b)
	for range 2 {
		if revision, err := c.BeginRevocation(t.Context(), "agent/revoked"); err != nil || revision != 1 {
			t.Fatal("revocation replay changed revision", revision, err)
		}
	}
	current := receipt(t, c, b)
	if err := c.RecordVerifiedFence(t.Context(), old); !errors.Is(err, ErrStale) {
		t.Fatal("acknowledgment revision regressed", err)
	}
	forged := current
	forged.Subjects = nil
	if err := c.RecordVerifiedFence(t.Context(), forged); !errors.Is(err, ErrStale) {
		t.Fatal("modified snapshot accepted", err)
	}
	called := false
	publish := func() error { called = true; return nil }
	if err := c.WithActivation(t.Context(), old, nothingMissing, publish); !errors.Is(err, ErrStale) || called {
		t.Fatal("stale activation snapshot accepted", err)
	}
	if err := c.WithActivation(t.Context(), current, nothingMissing, publish); err != nil || !called {
		t.Fatal("current activation denied", err)
	}
	if err := c.RecordRetiredSeal(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	peer := reopen(t, c)
	if _, err := peer.ReserveIncarnation(t.Context(), b, "resurrect"); !errors.Is(err, ErrSealed) {
		t.Fatal("sealed store restored", err)
	}
	if err := peer.WithActivation(t.Context(), current, nothingMissing, publish); !errors.Is(err, ErrSealed) {
		t.Fatal("sealed store activated", err)
	}
}

func TestActivationRequiresActualRecoveredData(t *testing.T) {
	c, b := fixture(t)
	path := filepath.Join(t.TempDir(), "application.sqlite")
	open := func() *sql.DB {
		db, err := sql.Open("sqlite3", path+"?_synchronous=FULL")
		if err != nil {
			t.Fatal(err)
		}
		return db
	}
	db := open()
	if _, err := db.Exec("CREATE TABLE effects(event TEXT PRIMARY KEY,body BLOB); CREATE TABLE seen(event TEXT PRIMARY KEY,result BLOB)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	backup, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	db = open()
	body := []byte("actual committed application state")
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec("INSERT INTO effects VALUES('event',?); INSERT INTO seen VALUES('event',?)", body, body); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	db.Close()
	archive, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	o := Outcome{ID: "event", Digest: sha256.Sum256(body)}
	if err = c.RecordOutcome(t.Context(), b, o); err != nil {
		t.Fatal(err)
	}
	changed := o
	changed.Digest[0] ^= 1
	if err = c.RecordOutcome(t.Context(), b, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("acknowledged outcome mutated", err)
	}
	next, err := c.ReserveIncarnation(t.Context(), b, "restore")
	if err != nil {
		t.Fatal(err)
	}
	r := receipt(t, c, next)
	inspect := func(required []Outcome) ([]string, error) {
		if len(required) != 1 || required[0] != o {
			t.Fatal("lost independent outcome journal", required)
		}
		db := open()
		defer db.Close()
		missing := []string{}
		for _, o := range required {
			var effect, result []byte
			err := db.QueryRow("SELECT e.body,s.result FROM effects e JOIN seen s ON s.event=e.event WHERE e.event=?", o.ID).Scan(&effect, &result)
			if errors.Is(err, sql.ErrNoRows) {
				missing = append(missing, o.ID)
				continue
			}
			if err != nil {
				return nil, err
			}
			if sha256.Sum256(effect) != o.Digest || sha256.Sum256(result) != o.Digest {
				missing = append(missing, o.ID)
			}
		}
		return missing, nil
	}
	if err = os.WriteFile(path, backup, 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	publish := func() error { called = true; return nil }
	if err = c.WithActivation(t.Context(), r, inspect, publish); !errors.Is(err, ErrHistory) || called {
		t.Fatal("journal ID invented absent application data", err)
	}
	// The repair copies the actual archived data; the journal ID alone never does.
	repair := func(missing []Outcome) error { return os.WriteFile(path, archive, 0600) }
	losses, err := c.Activate(t.Context(), r, Restoration{Inspect: inspect, Repair: repair, Publish: publish})
	if err != nil || !called || len(losses) != 0 {
		t.Fatal("actual recovered data rejected", losses, err)
	}
}

func TestPublicationSerializesConcurrentRevocation(t *testing.T) {
	c, b := fixture(t)
	peer := reopen(t, c)
	r := receipt(t, c, b)
	entered, release := make(chan struct{}), make(chan struct{})
	publication := make(chan error, 1)
	go func() {
		publication <- c.WithActivation(t.Context(), r, nothingMissing, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	intent := make(chan error, 1)
	go func() { _, err := peer.BeginRevocation(t.Context(), "new-subject"); intent <- err }()
	select {
	case err := <-intent:
		close(release)
		<-publication
		t.Fatal("revocation crossed publication guard", err)
	case <-time.After(80 * time.Millisecond):
	}
	close(release)
	if err := <-publication; err != nil {
		t.Fatal(err)
	}
	if err := <-intent; err != nil {
		t.Fatal(err)
	}
	if err := c.WithActivation(t.Context(), r, nothingMissing, func() error { t.Error("old publication called"); return nil }); !errors.Is(err, ErrStale) {
		t.Fatal("new revision not observed", err)
	}
}

func TestSubjectKeyGateUsesIndependentIntent(t *testing.T) {
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Initialize(t.Context(), filepath.Join(t.TempDir(), "authority"), keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	agent, volume := "agt_"+strings.Repeat("a", 32), "vol_"+strings.Repeat("b", 32)
	if err = keys.Ensure(t.Context(), agent, volume); err != nil {
		t.Fatal(err)
	}
	grants := 0
	grant := func() error {
		return keys.WithKey(t.Context(), agent, volume, func(key []byte) error {
			if len(key) != 32 {
				t.Error("invalid key grant")
			}
			grants++
			return nil
		})
	}
	if err = c.WithSubjectKey(t.Context(), agent, grant); err != nil || grants != 1 {
		t.Fatal(err, grants)
	}
	if _, err = c.BeginRevocation(t.Context(), agent); err != nil {
		t.Fatal(err)
	}
	peer := reopen(t, c)
	if err = peer.WithSubjectKey(t.Context(), agent, grant); !errors.Is(err, ErrRevoked) || grants != 1 {
		t.Fatal("new grant bypassed durable intent", err, grants)
	}
	// This deliberate direct call shows the limit: a policy denial is not
	// destruction, and the volume-unlock provider is not wired to this gate yet.
	if err = grant(); err != nil || grants != 2 {
		t.Fatal("fixture must retain its raw key", err)
	}
}

type crashConfig struct {
	Root, Identity, Boundary, Operation string
	Binding                             Binding
	Receipt                             Receipt
}

// everythingMissing inspects an image that lacks every recorded outcome.
func everythingMissing(recorded []Outcome) ([]string, error) {
	ids := []string{}
	for _, o := range recorded {
		ids = append(ids, o.ID)
	}
	return ids, nil
}

// prepareCrash brings the catalogue to the state the operation needs. The
// declaration and the rerun follow a restore of an image that lacks the outcome.
func prepareCrash(t *testing.T, c *Catalog, conf *crashConfig) {
	t.Helper()
	if conf.Operation != "declare" && conf.Operation != "rerun" {
		return
	}
	if err := c.RecordOutcome(t.Context(), conf.Binding, Outcome{ID: "durable-result", Digest: sha256.Sum256([]byte("committed data"))}); err != nil {
		t.Fatal(err)
	}
	next, err := c.ReserveIncarnation(t.Context(), conf.Binding, "restore")
	if err != nil {
		t.Fatal(err)
	}
	conf.Binding, conf.Receipt = next, receipt(t, c, next)
	if conf.Operation == "rerun" {
		if _, err = c.declareLosses(t.Context(), conf.Receipt, everythingMissing); err != nil {
			t.Fatal(err)
		}
	}
}

func crashOperation(ctx context.Context, c *Catalog, conf crashConfig) error {
	switch conf.Operation {
	case "reserve":
		_, err := c.ReserveIncarnation(ctx, conf.Binding, "durable-reservation")
		return err
	case "revoke":
		_, err := c.BeginRevocation(ctx, "durable-intent")
		return err
	case "outcome":
		return c.RecordOutcome(ctx, conf.Binding, Outcome{ID: "durable-result", Digest: sha256.Sum256([]byte("committed data"))})
	case "declare":
		_, err := c.declareLosses(ctx, conf.Receipt, everythingMissing)
		return err
	case "rerun":
		return c.RecordRerun(ctx, conf.Binding, Outcome{ID: "durable-result", Digest: sha256.Sum256([]byte("rerun data"))})
	default:
		return ErrInput
	}
}

func TestAuthoritySIGKILLBeforeAndAfterCommit(t *testing.T) {
	for _, operation := range []string{"reserve", "revoke", "outcome", "declare", "rerun"} {
		for _, boundary := range []string{"before_commit", "after_commit"} {
			t.Run(operation+"/"+boundary, func(t *testing.T) {
				c, b := fixture(t)
				conf := crashConfig{Root: c.root, Identity: c.identity, Binding: b, Boundary: boundary, Operation: operation}
				prepareCrash(t, c, &conf)
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAuthorityCrashChild$", "-test.timeout=30s")
				cmd.Env = append(os.Environ(), "AGENTCAPSULE_RESTORE_CHILD=1")
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
					t.Fatal("child did not reach transaction boundary", err, stderr.String())
				}
				if err = cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
				err = cmd.Wait()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL || strings.Contains(stderr.String(), "DATA RACE") {
					t.Fatal("SIGKILL/race observation failed", err, stderr.String())
				}
				peer := reopen(t, c)
				want := int64(0)
				if boundary == "after_commit" {
					want = 1
				}
				var got int64
				query := map[string]string{"reserve": "SELECT incarnation-1 FROM stores WHERE id='store-a'", "revoke": "SELECT revision FROM authority", "outcome": "SELECT count(*) FROM outcomes",
					"declare": "SELECT count(*) FROM losses", "rerun": "SELECT count(*) FROM reruns"}[operation]
				if err = peer.db.QueryRow(query).Scan(&got); err != nil || got != want {
					t.Fatal("unexpected durable transaction outcome", got, want, err)
				}
				for range 2 {
					if err = crashOperation(t.Context(), peer, conf); err != nil {
						t.Fatal("stable retry failed", err)
					}
				}
				if err = peer.db.QueryRow(query).Scan(&got); err != nil || got != 1 {
					t.Fatal("retry duplicated durable transition", got, err)
				}
			})
		}
	}
}

func TestAuthorityCrashChild(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_RESTORE_CHILD") != "1" {
		return
	}
	file := os.NewFile(3, "configuration")
	defer file.Close()
	var conf crashConfig
	if err := json.NewDecoder(file).Decode(&conf); err != nil {
		t.Fatal(err)
	}
	c, err := Open(t.Context(), conf.Root, conf.Identity, testKeyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.hook = func(boundary string) {
		if boundary == conf.Boundary {
			os.Stdout.WriteString("ready")
			<-make(chan struct{})
		}
	}
	if err := crashOperation(t.Context(), c, conf); err != nil {
		t.Fatal(err)
	}
	t.Fatal("fault boundary was not reached")
}
