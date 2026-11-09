//go:build linux && cgo && kvm_integration && kvm_product_integration

package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/api"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/runtime"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type productPeer struct {
	owner  controlplane.User
	token  string
	agent  controlplane.AgentCreation
	volume string
}

type productPeerLab struct {
	t             *testing.T
	worker        *Placements
	db            *pgxpool.Pool
	keys          *keyauthority.Files
	server        *httptest.Server
	admin         string
	root          string
	authorityRoot string
	peers         []*productPeer
	store         *controlplane.Store
	accounts      *controlplane.Accounts
	handler       *api.Server
}

// Only installation configuration is written directly. Accounts, reservations,
// messages, consent and lifecycle commands enter through the actual HTTP API.
// There are no seeded agents, placements, mailboxes, mandates or guest effects.
func newProductPeerLab(t *testing.T) *productPeerLab {
	t.Helper()
	dsn := os.Getenv("AGENTCAPSULE_TEST_POSTGRES")
	if dsn == "" {
		t.Fatal("real PostgreSQL required for product peer path")
	}
	adminDB, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("product_peers_%d", time.Now().UnixNano())
	if _, err = adminDB.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		adminDB.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := adminDB.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
		adminDB.Close()
	})
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	scoped := cfg.ConnString() + " search_path=" + schema + ",pg_catalog"
	store, err := controlplane.Open(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err = store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	db, err := pgxpool.New(t.Context(), scoped)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	accounts, err := controlplane.NewAccounts(store, bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.InitializeReceiptKey(t.Context()); err != nil {
		t.Fatal(err)
	}
	admin, err := store.BootstrapService(t.Context(), "product-peers-admin", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	configuration := config(t)
	if _, err = store.RegisterLocalRelease(t.Context(), controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+digest(t, configuration.Initrd)); err != nil {
		t.Fatal(err)
	}
	if err = store.ConfigureHostStorage(t.Context(), "local", 512); err != nil {
		t.Fatal(err)
	}
	transit, err := controlplane.NewTransit(store, "product-peers", map[string][]byte{"product-peers": bytes.Repeat([]byte{0x63}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	keys, err := keyauthority.Initialize(t.Context(), filepath.Join(t.TempDir(), "keys"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(configuration.RootParent, "product-peers-")
	if err != nil {
		t.Fatal(err)
	}
	options := opts(t, root)
	options.AuthenticatedControl, options.Ready, options.BootTimeout = true, nil, time.Minute
	authorityRoot := filepath.Join(t.TempDir(), "restore-authority")
	authority, err := restoreauthority.Initialize(t.Context(), authorityRoot, keys.Identity())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { authority.Close() })
	w, err := NewProvisioningPlacements(store, "local", "product-peers-worker", 2*time.Minute, options, keys, authority, ProvisioningConfig{FirstUID: 62300, LastUID: 62309})
	if err != nil {
		t.Fatal(err)
	}
	lab := &productPeerLab{t: t, worker: w, db: db, keys: keys, admin: admin, root: root, authorityRoot: authorityRoot, store: store, accounts: accounts}
	t.Cleanup(func() {
		// Only this test's reserved identities; the runner owns root cleanup.
		for _, p := range lab.peers {
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			if err := w.host.Retire(ctx, p.agent.AgentID, ^uint64(0)); err != nil {
				t.Error(err)
			}
			cancel()
		}
		w.Close()
	})
	if err = w.EnableTransit(t.Context(), transit); err != nil {
		t.Fatal(err)
	}
	handler, err := api.NewForHostWithTransit(store, accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	lab.handler = handler
	lab.server = httptest.NewServer(handler)
	lab.server.Client().Timeout = 15 * time.Second
	t.Cleanup(lab.server.Close)
	return lab
}

// Do not print tokens or private response bodies, even on assertion failure.
func (l *productPeerLab) request(token, method, path, key string, input any, code int, out any) []byte {
	l.t.Helper()
	var body []byte
	var err error
	if input != nil {
		body, err = json.Marshal(input)
		if err != nil {
			l.t.Fatal(err)
		}
	}
	r, err := http.NewRequestWithContext(l.t.Context(), method, l.server.URL+path, bytes.NewReader(body))
	if err != nil {
		l.t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	response, err := l.server.Client().Do(r)
	if err != nil {
		l.t.Fatal("HTTP transport", method, path, err)
	}
	defer response.Body.Close()
	if response.StatusCode != code {
		l.t.Fatalf("HTTP %s %s: got %d, want %d", method, path, response.StatusCode, code)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		l.t.Fatal(err)
	}
	if out != nil {
		if err = json.Unmarshal(data, out); err != nil {
			l.t.Fatal("invalid HTTP response shape", method, path)
		}
	}
	return data
}

func (l *productPeerLab) createPeer(name string) *productPeer {
	l.t.Helper()
	p := &productPeer{}
	l.request(l.admin, "POST", "/v1/users", "user/"+name, controlplane.CreateUserInput{DisplayName: name}, 201, &p.owner)
	var token controlplane.TokenResponse
	l.request(l.admin, "POST", "/v1/users/"+p.owner.ID+"/tokens", "token/"+name, controlplane.IssueTokenInput{ExpiresAt: time.Now().Add(time.Hour)}, 201, &token)
	p.token = token.Token
	input := controlplane.CreateAgentInput{Name: name, Harness: controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, Resources: controlplane.AgentResources{VCPUs: 1, MemoryMiB: 256, DataVolumeMiB: 128}}
	l.request(p.token, "POST", "/v1/agents", "agent/"+name, input, 202, &p.agent)
	l.peers = append(l.peers, p)
	var replay controlplane.AgentCreation
	l.request(p.token, "POST", "/v1/agents", "agent/"+name, input, 202, &replay)
	if p.agent != replay || p.agent.AgentID == "" || p.agent.OperationID == "" {
		l.t.Fatal("agent reservation replay changed")
	}
	return p
}

func (l *productPeerLab) await(stage string, dispatch bool, check func() bool) {
	l.t.Helper()
	l.awaitFor(stage, dispatch, 2*time.Minute, check)
}

// awaitFor is await with its own bound, for stages that wait on a real model.
func (l *productPeerLab) awaitFor(stage string, dispatch bool, bound time.Duration, check func() bool) {
	l.t.Helper()
	ctx, cancel := context.WithTimeout(l.t.Context(), bound)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if check() {
			return
		}
		if dispatch {
			opts := DispatchOptions{Batch: 4, WorkLease: 3 * time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 10 * time.Second}
			// A pass is short; if one is not, record where every goroutine
			// waits, so that a slow step can be named afterwards.
			watch := time.AfterFunc(45*time.Second, func() { l.dumpStacks(stage) })
			err := l.worker.DispatchPass(ctx, opts, 90*time.Second)
			watch.Stop()
			if err != nil {
				l.t.Fatal(stage, "worker dispatch", err)
			}
		}
		select {
		case <-ctx.Done():
			l.t.Fatal(stage, "did not reach expected state", ctx.Err())
		case <-ticker.C:
		}
	}
}

// dumpStacks writes every goroutine's stack to the campaign's observations. It
// runs on a timer goroutine, so it never fails the test itself.
func (l *productPeerLab) dumpStacks(stage string) {
	var c labConfig
	dir := os.TempDir()
	if b, err := os.ReadFile(os.Getenv("AGENTCAPSULE_KVM_CONFIG")); err == nil && json.Unmarshal(b, &c) == nil && c.Output != "" {
		dir = c.Output
	}
	name := strings.NewReplacer("/", "_", " ", "_").Replace(l.t.Name() + "-" + stage)
	path := filepath.Join(dir, fmt.Sprintf("stacks-%s-%d.txt", name, time.Now().Unix()))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	_ = pprof.Lookup("goroutine").WriteTo(f, 2)
	l.t.Log("a dispatch pass exceeded 45 s; goroutine stacks in", path)
}

func (l *productPeerLab) operation(p *productPeer, id, kind string) controlplane.PlatformOperation {
	l.t.Helper()
	var op controlplane.PlatformOperation
	l.await(kind, true, func() bool {
		l.request(p.token, "GET", "/v1/operations/"+id, "", nil, 200, &op)
		if op.Status == "FAILED" || op.Status == "CANCELED" {
			l.t.Fatal(kind, "unexpected terminal operation", op.Status, op.ErrorCode)
		}
		return op.Status == "SUCCEEDED"
	})
	if op.AgentID != p.agent.AgentID || op.Kind != kind || op.CompletedAt == nil {
		l.t.Fatal("invalid operation completion", kind)
	}
	return op
}

func (l *productPeerLab) command(p *productPeer, kind string, round int) {
	l.t.Helper()
	key := fmt.Sprintf("%s/%d", kind, round)
	path := "/v1/agents/" + p.agent.AgentID + "/" + kind
	var accepted, replay controlplane.AgentCreation
	l.request(p.token, "POST", path, key, struct{}{}, 202, &accepted)
	op := l.operation(p, accepted.OperationID, kind)
	if kind == "sleep" && (op.UncleanStop == nil || *op.UncleanStop) {
		l.t.Fatal("sleep did not confirm a clean shutdown")
	}
	l.request(p.token, "POST", path, key, struct{}{}, 202, &replay)
	if replay != accepted {
		l.t.Fatal("lifecycle receipt changed")
	}
}

func (l *productPeerLab) inbox(p *productPeer) []controlplane.InboxItem {
	l.t.Helper()
	var v struct {
		Items []controlplane.InboxItem `json:"items"`
	}
	body := l.request(p.token, "GET", "/v1/me/inbox", "", nil, 200, &v)
	if bytes.Contains(body, []byte("do not relay")) {
		l.t.Fatal("inbox metadata leaked private content")
	}
	return v.Items
}

func (l *productPeerLab) view(p *productPeer, id string) controlplane.RequestView {
	l.t.Helper()
	var v controlplane.RequestView
	l.request(p.token, "GET", "/v1/agent-requests/"+id, "", nil, 200, &v)
	if v.ID != id {
		l.t.Fatal("request identity changed")
	}
	return v
}

func (l *productPeerLab) pending(a, b *productPeer, round int) string {
	l.t.Helper()
	var accepted, replay controlplane.AgentCreation
	input := capsuleprotocol.OwnerMessage{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "/ask " + b.agent.AgentID + " /ask third-agent do not relay"}}}
	key := fmt.Sprintf("instruction/%d", round)
	path := "/v1/agents/" + a.agent.AgentID + "/messages"
	l.request(a.token, "POST", path, key, input, 202, &accepted)
	l.request(a.token, "POST", path, key, input, 202, &replay)
	if accepted != replay {
		l.t.Fatal("instruction retry changed receipt")
	}
	var id string
	l.await("manual pending request", true, func() bool {
		for _, item := range l.inbox(b) {
			if item.State == "PENDING_APPROVAL" {
				if id != "" && id != item.RequestID {
					l.t.Fatal("multiple pending requests")
				}
				id = item.RequestID
			}
		}
		return id != ""
	})
	if v := l.view(a, id); v.State != "PENDING_APPROVAL" || v.SenderAgentID != a.agent.AgentID || v.RecipientAgentID != b.agent.AgentID {
		l.t.Fatal("invalid request before consent")
	}
	if _, err := l.worker.store.HeadDelivery(l.t.Context(), b.agent.AgentID); !errors.Is(err, controlplane.ErrNoDelivery) {
		l.t.Fatal("delivery allowed before consent", err)
	}
	return id
}

func (l *productPeerLab) accept(a, b *productPeer, id string) {
	l.t.Helper()
	path := "/v1/me/inbox/requests/" + id + "/accept"
	l.request(a.token, "POST", path, "foreign/"+id, struct{}{}, 404, nil)
	l.request(l.admin, "POST", path, "admin/"+id, struct{}{}, 403, nil)
	var first, replay controlplane.OwnerRequestReceipt
	l.request(b.token, "POST", path, "accept/"+id, struct{}{}, 200, &first)
	l.request(b.token, "POST", path, "accept/"+id, struct{}{}, 200, &replay)
	if first != replay || first.RequestID != id || first.State != "DELIVERING" {
		l.t.Fatal("consent receipt not stable")
	}
}

func (l *productPeerLab) runs(count int) map[string]runtime.VMRun {
	l.t.Helper()
	runs, err := l.worker.Reconcile(l.t.Context())
	if err != nil || len(runs) != count {
		l.t.Fatal("unexpected physical VM count", len(runs), count, err)
	}
	for _, run := range runs {
		if run.PID <= 0 || run.ID == "" || run.Generation == 0 || run.FenceOnly {
			l.t.Fatal("ordinary physical VM missing")
		}
	}
	return runs
}

func (l *productPeerLab) probe(p *productPeer, replayed bool) *capsuleprotocol.Client {
	l.t.Helper()
	c, err := l.worker.host.Control(l.t.Context(), p.agent.AgentID)
	if err != nil {
		l.t.Fatal(err)
	}
	// Same event ID in both real guest stores, distinct envelopes/content. This
	// extra control probe tests persistent isolation; it is not a business result.
	body := []byte("private volume for " + p.agent.AgentID)
	e := harnessstore.Event{ID: "two-owner-persistence", Subjects: []string{"agent/" + p.agent.AgentID}, Body: body}
	receipt, err := c.Send(l.t.Context(), e)
	if err != nil || receipt.Replayed != replayed {
		l.t.Fatal("guest deduplication/persistence", err)
	}
	var v struct {
		Echo []byte `json:"echo"`
	}
	if json.Unmarshal(receipt.Result, &v) != nil || !bytes.Equal(v.Echo, body) {
		l.t.Fatal("private volume contents crossed or changed")
	}
	if replayed {
		health, err := c.HealthStatus(l.t.Context())
		if err != nil || health.PreviousShutdown != capsuleprotocol.ShutdownClean {
			l.t.Fatal("clean shutdown metadata not preserved", err)
		}
	}
	return c
}

func (l *productPeerLab) delete(p *productPeer, afterAdmission func()) {
	l.t.Helper()
	path := "/v1/agents/" + p.agent.AgentID
	var accepted, replay controlplane.AgentCreation
	l.request(p.token, "DELETE", path, "delete", nil, 202, &accepted)
	if afterAdmission != nil {
		afterAdmission()
	}
	op := l.operation(p, accepted.OperationID, "delete")
	if op.DeletionPhase != "COMPLETE" {
		l.t.Fatal("deletion did not include physical cleanup")
	}
	l.request(p.token, "DELETE", path, "delete", nil, 202, &replay)
	if replay != accepted {
		l.t.Fatal("deletion replay changed")
	}
	var agent controlplane.AgentView
	l.request(p.token, "GET", path, "", nil, 200, &agent)
	if agent.State != "DELETED" {
		l.t.Fatal("agent deletion not final")
	}
	if _, err := l.worker.authority.Lookup(l.t.Context(), p.agent.AgentID); !errors.Is(err, restoreauthority.ErrSealed) {
		l.t.Fatal("independent deletion seal missing", err)
	}
	if err := l.keys.Ensure(l.t.Context(), p.agent.AgentID, p.volume); !errors.Is(err, keyauthority.ErrRevoked) {
		l.t.Fatal("deleted key could be recreated", err)
	}
	if err := l.keys.WithKey(l.t.Context(), p.agent.AgentID, p.volume, func([]byte) error { l.t.Error("deleted key delivered"); return nil }); !errors.Is(err, keyauthority.ErrRevoked) {
		l.t.Fatal("key revocation missing", err)
	}
	if _, err := os.Lstat(filepath.Join(l.root, "volumes", p.volume+".luks")); !errors.Is(err, os.ErrNotExist) {
		l.t.Fatal("deleted volume still exists", err)
	}
	l.request(p.token, "POST", path+"/wake", "wake-deleted", struct{}{}, 409, nil)
	if err := l.worker.Fence(l.t.Context(), p.agent.AgentID, "agent/future-revocation"); err != nil {
		l.t.Fatal("removed store cannot acknowledge future barrier", err)
	}
}

// This is a physical integration test, never satisfied by local mocks or by
// compilation. The independent runner requires this exact test to pass.
func TestProductWorkerTwoOwnersPrivateExchange(t *testing.T) {
	l := newProductPeerLab(t)
	t.Log("stage: create two owners and reserve their agents through HTTP")
	a, b := l.createPeer("owner-a"), l.createPeer("owner-b")
	if a.owner.ID == b.owner.ID || a.agent.AgentID == b.agent.AgentID {
		t.Fatal("owners/agents not distinct")
	}
	for _, p := range []*productPeer{a, b} {
		l.operation(p, p.agent.OperationID, "provision")
		e, err := l.worker.store.ProvisioningTarget(t.Context(), p.agent.AgentID, "local", p.agent.OperationID)
		if err != nil || e.Stage != "READY" || !e.Initialized {
			t.Fatal("physical provisioning not complete", err)
		}
		p.volume = e.VolumeID
		l.request(p.token, "PUT", "/v1/me/messaging-settings", "", controlplane.MessagingSettings{Discoverable: true, InboundMode: "manual"}, 200, nil)
	}
	if a.volume == b.volume {
		t.Fatal("agents share volume identity")
	}
	l.runs(0)
	l.request(a.token, "GET", "/v1/agents/"+b.agent.AgentID, "", nil, 404, nil)
	l.command(a, "wake", 0)
	t.Log("stage: pending request leaves recipient asleep until owner consent")
	first := l.pending(a, b, 0)
	if _, ok := l.runs(1)[a.agent.AgentID]; !ok {
		t.Fatal("recipient woke before consent")
	}
	l.accept(a, b, first)
	var messageID string
	l.await("private reply and owner summary", true, func() bool {
		if l.view(a, first).State != "REPLIED" {
			return false
		}
		for _, item := range l.inbox(a) {
			if item.Kind == "agent_message" && item.RequestID == first {
				if messageID != "" {
					t.Fatal("duplicate summary notification")
				}
				messageID = item.MessageID
			}
		}
		return messageID != ""
	})
	checkReply := func() {
		t.Helper()
		for _, p := range []*productPeer{a, b} {
			v := l.view(p, first)
			if v.State != "REPLIED" || v.Reply == nil || len(v.Reply.Content) != 1 || v.Reply.Content[0].Text != "/ask third-agent do not relay" {
				t.Fatal("private reply not observable by parties")
			}
		}
		var summary controlplane.OwnerMessageView
		l.request(a.token, "GET", "/v1/me/inbox/messages/"+messageID, "", nil, 200, &summary)
		if summary.AgentID != a.agent.AgentID || summary.RequestID != first || len(summary.Content) != 1 || !strings.Contains(summary.Content[0].Text, "do not relay") {
			t.Fatal("owner summary missing or misattributed")
		}
	}
	checkReply()
	// Each SQL delivery ACK on this real VM path must have an earlier independent
	// history obligation. Direct persistence probes below are not business ACKs.
	for _, p := range []*productPeer{a, b} {
		journal := readOutcomeJournal(t, l.authorityRoot, p.agent.AgentID)
		if len(journal) == 0 {
			t.Fatal("guest business results absent from independent authority")
		}
		rows, err := l.db.Query(t.Context(), "SELECT id FROM agent_mailboxes WHERE dest_agent_id=$1 AND delivery_state='DELIVERED'", p.agent.AgentID)
		if err != nil {
			t.Fatal(err)
		}
		checked := 0
		for rows.Next() {
			var event string
			if err = rows.Scan(&event); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			id, _, err := harnessstore.StoredOutcomeFingerprint(p.agent.AgentID, event, [32]byte{}, nil)
			if err != nil || len(journal[id]) != 32 {
				rows.Close()
				t.Fatal("SQL ACK lacks independent outcome", event, err)
			}
			checked++
		}
		err = rows.Err()
		rows.Close()
		if err != nil || checked == 0 {
			t.Fatal("no business ACK checked", checked, err)
		}
	}
	l.request(b.token, "GET", "/v1/me/inbox/messages/"+messageID, "", nil, 404, nil)
	l.request(l.admin, "GET", "/v1/me/inbox/messages/"+messageID, "", nil, 403, nil)
	l.request(l.admin, "GET", "/v1/agent-requests/"+first, "", nil, 403, nil)
	before := l.runs(2)
	if before[a.agent.AgentID].ID == before[b.agent.AgentID].ID || before[a.agent.AgentID].PID == before[b.agent.AgentID].PID {
		t.Fatal("two distinct VMMs required")
	}
	old := []*capsuleprotocol.Client{l.probe(a, false), l.probe(b, false)}
	t.Log("stage: archive a running agent after authenticated clean stop and physical exclusion")
	archives, err := volumearchive.New(filepath.Join(t.TempDir(), "archives"))
	if err != nil {
		t.Fatal(err)
	}
	archiveID := "arc_" + strings.Repeat("c", 32)
	manifest, err := l.worker.CaptureArchive(t.Context(), a.agent.AgentID, archiveID, archives)
	if err != nil {
		t.Fatal("cold encrypted capture", err)
	}
	if manifest.Binding.Store != a.agent.AgentID || manifest.Binding.Volume != a.volume || manifest.Binding.Incarnation != before[a.agent.AgentID].Incarnation {
		t.Fatal("archive identity does not match captured VM")
	}
	if _, alive := l.runs(1)[a.agent.AgentID]; alive {
		t.Fatal("archive did not retire source writer")
	}
	file, inspected, err := archives.Open(t.Context(), archiveID, l.worker.authority)
	if err != nil {
		t.Fatal("archive authentication/hash", err)
	}
	var magic [6]byte
	_, err = io.ReadFull(file, magic[:])
	file.Close()
	if err != nil || !bytes.Equal(magic[:], []byte{'L', 'U', 'K', 'S', 0xba, 0xbe}) || inspected.Digest != manifest.Digest {
		t.Fatal("archive is not the encrypted container", err)
	}
	retry, err := l.worker.CaptureArchive(t.Context(), a.agent.AgentID, archiveID, archives)
	if err != nil || retry.Digest != manifest.Digest {
		t.Fatal("archive retry changed captured bytes", err)
	}
	t.Log("stage: clean sleep and wake preserve distinct guest data and private reply")
	l.command(a, "sleep", 0)
	l.command(b, "sleep", 0)
	l.runs(0)
	l.command(a, "wake", 1)
	l.command(b, "wake", 1)
	after := l.runs(2)
	for i, p := range []*productPeer{a, b} {
		if after[p.agent.AgentID].Generation <= before[p.agent.AgentID].Generation || after[p.agent.AgentID].ID == before[p.agent.AgentID].ID {
			t.Fatal("wake reused old boot identity")
		}
		l.probe(p, true)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		err := old[i].Health(ctx)
		cancel()
		if err == nil {
			t.Fatal("old boot control channel still accepted")
		}
	}
	checkReply()
	for _, query := range []string{"SELECT count(*) FROM agent_requests", "SELECT count(*) FROM owner_messages"} {
		var count int
		if err := l.db.QueryRow(t.Context(), query).Scan(&count); err != nil || count != 1 {
			t.Fatal("retry or peer text created duplicate work", count, err)
		}
	}
	t.Log("stage: deletion cancels an accepted request queued before delivery")
	second := l.pending(a, b, 1)
	if second == first {
		t.Fatal("new instruction reused previous request")
	}
	l.accept(a, b, second)
	queued, err := l.worker.store.HeadDelivery(t.Context(), b.agent.AgentID)
	if err != nil {
		t.Fatal("accepted request not queued", err)
	}
	l.request(a.token, "DELETE", "/v1/agents/"+b.agent.AgentID, "foreign-delete", nil, 404, nil)
	// No delivery pass occurs between acceptance and DELETE: the test observes
	// cancellation of queued work, not an artificially claimed writer race.
	l.delete(b, func() {
		l.request(a.token, "GET", "/v1/me/inbox/messages/"+messageID, "", nil, 404, nil)
		// The older delivery ticket is tried before the deletion job. Its
		// refusal is expected; all other dispatch passes must succeed. Observe
		// both the selected ticket and the absence of any guest RPC attempt.
		var claimed controlplane.WorkerJob
		l.worker.afterWorkClaim = func(j controlplane.WorkerJob) { claimed = j }
		options := DispatchOptions{Batch: 1, WorkLease: 3 * time.Minute, DeliveryLease: 30 * time.Second, RetryBase: time.Second, RetryMax: 10 * time.Second}
		err := l.worker.DispatchPass(t.Context(), options, 90*time.Second)
		l.worker.afterWorkClaim = nil
		if claimed.Kind != "delivery" || claimed.ID != queued || !onlyProductUnavailable(err) {
			t.Fatal("deletion did not reject the older queued delivery", claimed.Kind, err)
		}
		var attempts int
		var reached bool
		if err := l.db.QueryRow(t.Context(), "SELECT attempts,may_have_reached FROM agent_mailboxes WHERE id=$1", queued).Scan(&attempts, &reached); err != nil || attempts != 0 || reached {
			t.Fatal("revoked delivery consumed a guest RPC attempt", attempts, reached, err)
		}
		t.Log("stage: queued delivery refused after deletion admission, before any guest RPC")
	})
	if v := l.view(a, second); v.State != "CANCELED" || v.Payload != nil || v.Reply != nil {
		t.Fatal("queued request survived recipient deletion")
	}
	if v := l.view(a, first); v.State != "REPLIED" || v.Payload != nil || v.Reply != nil {
		t.Fatal("terminal history changed or deleted content remains")
	}
	if _, ok := l.runs(1)[a.agent.AgentID]; !ok {
		t.Fatal("sender retired with deleted recipient")
	}
	// The sender remains able to consume the terminal status, then is itself
	// removed through the owner API. No test-only SQL completion is permitted.
	l.await("terminal notification drained", true, func() bool {
		_, err := l.worker.store.HeadDelivery(t.Context(), a.agent.AgentID)
		if err != nil && !errors.Is(err, controlplane.ErrNoDelivery) {
			t.Fatal(err)
		}
		return errors.Is(err, controlplane.ErrNoDelivery)
	})
	l.delete(a, nil)
	l.runs(0)
	t.Log("stage: both API deletions completed with revoked keys and absent volumes")
}

// DispatchPass joins work and completion errors. Accept only the expected
// business refusal, never a join that also contains storage/lease failures.
func onlyProductUnavailable(err error) bool {
	if err == controlplane.ErrUnavailable {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyProductUnavailable(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return onlyProductUnavailable(wrapped.Unwrap())
	}
	return false
}
