//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/pgnotify"
)

type corpusWatchEvent struct {
	Version int
	Event   string
	Data    struct {
		State, Step, Label string
		Attempt            int
		Seq                int64
	}
}

type liveCorpusWatch struct {
	cmd           *exec.Cmd
	next          *json.Decoder
	attempt       int
	started, done int64
}

func configureCorpusWatch(t *testing.T, lab *productPeerLab, organization, token string) func(context.Context, ...string) *exec.Cmd {
	t.Helper()
	hub, err := pgnotify.New(lab.store.Connect, "agentcapsule_invocation_stream")
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() { defer close(stopped); _ = hub.Run(ctx) }()
	t.Cleanup(func() { stop(); <-stopped })
	if err = lab.worker.EnableOutputStreams(DefaultOutputStreams, hub); err != nil {
		t.Fatal(err)
	}
	if err = lab.handler.StartEventStreams(ctx, 8); err != nil {
		t.Fatal(err)
	}
	var migration string
	if err = lab.db.QueryRow(ctx, "SELECT name FROM schema_migrations WHERE version=63").Scan(&migration); err != nil || migration != "corpus-build-streams" {
		t.Fatal("corpus watch migration", migration, err)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: lab.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	binary := os.Getenv("AGENTCAPSULE_KVM_CLI")
	if binary == "" {
		t.Fatal("AGENTCAPSULE_KVM_CLI must name the product CLI")
	}
	cli := func(ctx context.Context, args ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Env = append(os.Environ(), "AGENTCAPSULE_CONFIG_DIR="+filepath.Join(dir, "context"))
		return cmd
	}
	for _, args := range [][]string{{"context", "add", "orion", "--url", lab.server.URL, "--ca", ca, "--kind", "organization", "--organization", organization}, {"context", "use", "orion"}, {"login", "--token-file", "-"}} {
		cmd := cli(ctx, args...)
		if args[0] == "login" {
			cmd.Stdin = strings.NewReader(token)
		}
		if err = cmd.Run(); err != nil {
			t.Fatal("CLI", args[0], err)
		}
	}
	t.Log("PostgreSQL migration 63", migration)
	return cli
}

func beginCorpusWatch(t *testing.T, cli func(context.Context, ...string) *exec.Cmd, build string) *liveCorpusWatch {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	t.Cleanup(cancel)
	cmd := cli(ctx, "corpus-build", "watch", build)
	r, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cancel()
			_ = cmd.Wait()
		}
	})
	w := &liveCorpusWatch{cmd: cmd, next: json.NewDecoder(r)}
	var ev corpusWatchEvent
	if err = w.next.Decode(&ev); err != nil || ev.Version != 1 || ev.Event != "state" || ev.Data.State != "QUEUED" || ev.Data.Attempt < 1 {
		t.Fatal("initial CLI subscription", ev, err)
	}
	w.attempt = ev.Data.Attempt
	return w
}

// Read both conversion steps before allowing the worker to run packaging.
func (w *liveCorpusWatch) conversion(t *testing.T, pdf string) {
	t.Helper()
	for w.done == 0 {
		var e corpusWatchEvent
		if err := w.next.Decode(&e); err != nil {
			t.Fatal("live CLI conversion", err)
		}
		if e.Event == "state" {
			continue
		}
		if e.Event != "step" || e.Data.Step != "file-1" || e.Data.Label != pdf || e.Data.Seq <= 0 {
			t.Fatal("unexpected conversion event", e)
		}
		switch {
		case w.started == 0 && e.Data.State == "started":
			w.started = e.Data.Seq
		case w.started > 0 && e.Data.State == "done" && e.Data.Seq > w.started:
			w.done = e.Data.Seq
		default:
			t.Fatal("unexpected file progress", e)
		}
	}
}

func (w *liveCorpusWatch) review(t *testing.T, lab *productPeerLab, reader, build, pdf string) {
	t.Helper()
	if w.done == 0 {
		t.Fatal("conversion completed without live file steps")
	}
	for {
		var e corpusWatchEvent
		if err := w.next.Decode(&e); err != nil {
			t.Fatal("watch ended before REVIEW", err)
		}
		if e.Event == "end" && e.Data.State == "REVIEW" {
			break
		}
		if e.Event != "state" {
			t.Fatal("unexpected event after conversion", e)
		}
	}
	if err := w.cmd.Wait(); err != nil {
		t.Fatal("corpus-build watch", err)
	}
	cursor := fmt.Sprintf("%d:%d", w.attempt, w.started)
	req, err := http.NewRequestWithContext(t.Context(), "GET", lab.server.URL+"/v1/corpus-builds/"+build+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+reader)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Last-Event-ID", cursor)
	resp, err := lab.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("authorized replay", resp.StatusCode, err)
	}
	var events []string
	for block := range bytes.SplitSeq(bytes.TrimSpace(raw), []byte("\n\n")) {
		var e corpusWatchEvent
		var id string
		for line := range strings.SplitSeq(string(block), "\n") {
			field, val, _ := strings.Cut(line, ": ")
			switch field {
			case "event":
				e.Event = val
			case "id":
				id = val
			case "data":
				if err = json.Unmarshal([]byte(val), &e.Data); err != nil {
					t.Fatal(err)
				}
			}
		}
		if e.Event == "" {
			continue
		}
		events = append(events, e.Event)
		switch e.Event {
		case "state", "end":
			if e.Data.State != "REVIEW" {
				t.Fatal("replay state", e)
			}
		case "step":
			if id != fmt.Sprintf("%d:%d", w.attempt, w.done) || e.Data.Seq != w.done || e.Data.Step != "file-1" || e.Data.State != "done" || e.Data.Label != pdf {
				t.Fatal("replayed file", e, id)
			}
		}
	}
	if strings.Join(events, ",") != "state,step,end" {
		t.Fatal("replay events", events)
	}
	t.Logf("CLI live file-1 started=%d:%d done=%d:%d before packaging; administrator replay after REVIEW from %s returned done", w.attempt, w.started, w.attempt, w.done, cursor)
}

func corpusReviewAdmin(t *testing.T, l *productPeerLab, i *tenantIdentity, owner string) func() string {
	t.Helper()
	l.request(owner, "POST", "/v1/members", "reviewer", controlplane.CreateMemberInput{Issuer: i.trust.Issuer, Subject: "orion-reviewer", DisplayName: "Course reviewer", Role: "org_admin"}, 201, nil)
	return func() string { return i.tokenFor(t, "orion-reviewer", "corpus:manage") }
}
