//go:build linux

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/guestinit"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The boot observations are fixtures; authorization, encrypted contents, SQL
// receipts and the two independently executed product harnesses are real.
type peerProcessAPI struct {
	store         *controlplane.Store
	transit       *controlplane.Transit
	caller        controlplane.VMCaller
	unknownSubmit atomic.Bool
	unknownReply  atomic.Bool
	unknownOwner  atomic.Bool
}

func peerAPIError(err error) error {
	if err == nil {
		return nil
	}
	code := "unavailable"
	switch {
	case errors.Is(err, controlplane.ErrPlacement):
		code = "unauthorized"
	case errors.Is(err, controlplane.ErrTransition):
		code = "transition"
	case errors.Is(err, controlplane.ErrMandate):
		code = "mandate"
	case errors.Is(err, controlplane.ErrNotFound):
		code = "not_found"
	case errors.Is(err, controlplane.ErrInput):
		code = "invalid"
	case errors.Is(err, controlplane.ErrConflict):
		code = "conflict"
	}
	return &capsuleprotocol.PlatformError{Code: code}
}
func (a *peerProcessAPI) Validate(ctx context.Context) error {
	return peerAPIError(a.store.ValidateVMCaller(ctx, a.caller))
}
func (a *peerProcessAPI) Search(ctx context.Context, candidates []string) ([]string, error) {
	r, err := a.store.SearchDirectoryFromVM(ctx, a.caller, candidates)
	return r, peerAPIError(err)
}
func (a *peerProcessAPI) Submit(ctx context.Context, key string, in capsuleprotocol.Submission) (capsuleprotocol.PlatformReceipt, error) {
	r, err := a.transit.SubmitFromVM(ctx, a.caller, key, in)
	if err == nil && a.unknownSubmit.Load() {
		return capsuleprotocol.PlatformReceipt{}, &capsuleprotocol.PlatformError{Code: "commit_unknown"}
	}
	return capsuleprotocol.PlatformReceipt{RequestID: r.RequestID, State: string(r.State), Replayed: r.Replayed}, peerAPIError(err)
}
func (a *peerProcessAPI) Reply(ctx context.Context, id, key string, in capsuleprotocol.Reply) (capsuleprotocol.PlatformReceipt, error) {
	r, err := a.transit.ReplyFromVM(ctx, a.caller, id, key, in)
	if err == nil && a.unknownReply.Swap(false) {
		return capsuleprotocol.PlatformReceipt{}, &capsuleprotocol.PlatformError{Code: "commit_unknown"}
	}
	return capsuleprotocol.PlatformReceipt{RequestID: r.RequestID, State: string(r.State), Replayed: r.Replayed}, peerAPIError(err)
}
func (a *peerProcessAPI) PostOwner(ctx context.Context, key string, in capsuleprotocol.OwnerPost) (capsuleprotocol.OwnerPostReceipt, error) {
	r, err := a.transit.PostOwnerFromVM(ctx, a.caller, key, in)
	if err == nil && a.unknownOwner.Swap(false) {
		return capsuleprotocol.OwnerPostReceipt{}, &capsuleprotocol.PlatformError{Code: "commit_unknown"}
	}
	return r, peerAPIError(err)
}

type processPeerRuntime struct {
	clients map[string]*capsuleprotocol.Client
}

func (r processPeerRuntime) Send(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	return r.clients[target].Send(ctx, e)
}
func (r processPeerRuntime) Invoke(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	return r.clients[target].Invoke(ctx, e)
}
func (r processPeerRuntime) Fence(ctx context.Context, target, subject string) error {
	return r.clients[target].Fence(ctx, subject)
}

func TestTwoRealHarnessesPrivateExchangeAndOutgoingRestart(t *testing.T) {
	s, store, admin, dsn := apiLab(t)
	tr, err := controlplane.NewTransit(store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x71}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = tr.ActivateKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	s, err = NewForHostWithTransit(store, s.accounts, "local", tr)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ConfigureHostStorage(t.Context(), "local", 512); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RegisterLocalRelease(t.Context(), controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	_, tokenA := apiOwner(t, s, admin, "A")
	_, tokenB := apiOwner(t, s, admin, "B")
	a := messagingAgentFixture(t, s, store, tokenA, 501)
	b := messagingAgentFixture(t, s, store, tokenB, 502)
	if r := call(t, s, "PUT", "/v1/me/messaging-settings", tokenB, "", `{"discoverable":true,"inbound_mode":"manual"}`); r.Code != 200 {
		t.Fatal(r.Code)
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	root, err := os.MkdirTemp("", "acp-peers-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "capsule-echo")
	buildCtx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	build := exec.CommandContext(buildCtx, "go", "build", "-race", "-o", binary, "./cmd/capsule-echo")
	build.Dir = filepath.Join("..", "..")
	output, err := build.CombinedOutput()
	cancel()
	if err != nil {
		t.Fatalf("build %v %s", err, output)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid, gid = 1000, 1000
	}
	rt := processPeerRuntime{clients: map[string]*capsuleprotocol.Client{}}
	processes := map[string]*guestinit.Process{}
	opts := map[string]guestinit.ProcessOptions{}
	apis := map[string]*peerProcessAPI{}
	// Explicit cleanup runs before temporary directories and credentials vanish.
	defer func() {
		for _, p := range processes {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := p.Stop(ctx)
			cancel()
			if err != nil {
				t.Error(err)
			}
		}
	}()
	for i, caller := range []controlplane.VMCaller{a, b} {
		id := capsuleprotocol.Identity{Incarnation: 1, AgentID: caller.AgentID, Generation: caller.Generation, VMID: caller.VMID}
		host, guest, err := capsuleprotocol.NewBootCredentials(id, time.Hour, true)
		if err != nil {
			t.Fatal(err)
		}
		api := &peerProcessAPI{store: store, transit: tr, caller: caller}
		api.unknownSubmit.Store(i == 0)
		api.unknownReply.Store(i == 1)
		api.unknownOwner.Store(i == 0)
		apis[id.AgentID] = api
		handler, err := capsuleprotocol.NewPlatformHandler(id, api)
		if err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lifetime, stop := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- capsuleprotocol.ServeAuthenticated(lifetime, listener, *host.Platform, handler) }()
		defer func() { stop(); <-done }()
		remote, err := capsuleprotocol.NewPlatformClient(*guest.Platform, func(ctx context.Context) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
		})
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, id.AgentID)
		if err = os.Mkdir(dir, 0711); err != nil {
			t.Fatal(err)
		}
		data := filepath.Join(dir, "data")
		if err = os.Mkdir(data, 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.Chown(data, int(uid), int(gid)); err != nil {
			t.Fatal(err)
		}
		opts[id.AgentID] = guestinit.ProcessOptions{Boot: guestinit.HarnessBoot{Protocol: capsuleprotocol.Version, PreviousShutdown: capsuleprotocol.ShutdownClean, Identity: id, DataDirectory: data, SupervisorUID: uint32(os.Geteuid()), PlatformSocket: filepath.Join(dir, "platform.sock")}, Entrypoint: []string{binary}, SocketPath: filepath.Join(dir, "control.sock"), UID: uid, GID: gid, Platform: remote}
	}
	start := func(id string) {
		t.Helper()
		ready, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		p, err := guestinit.StartHarness(t.Context(), ready, opts[id])
		if err != nil {
			t.Fatal(err)
		}
		processes[id] = p
		c, err := capsuleprotocol.NewLocalClient(opts[id].Boot.Identity, opts[id].SocketPath)
		if err != nil {
			t.Fatal(err)
		}
		rt.clients[id] = c
	}
	start(a.AgentID)
	start(b.AgentID)
	input, _ := json.Marshal(capsuleprotocol.OwnerMessage{Content: []capsuleprotocol.TextContent{{Type: "text", Text: "/ask " + b.AgentID + " /ask third-agent do not relay"}}})
	if r := call(t, s, "POST", "/v1/agents/"+a.AgentID+"/messages", tokenA, "instruction", string(input)); r.Code != 202 {
		t.Fatal(r.Code)
	}
	dispatch := func(id string) {
		t.Helper()
		head, err := store.HeadDelivery(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if err = tr.DispatchMailbox(t.Context(), head, time.Minute, rt); err != nil {
			t.Fatal(err)
		}
	}
	dispatch(a.AgentID)
	wait := func(check func() bool) {
		t.Helper()
		deadline := time.NewTimer(10 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			if check() {
				return
			}
			select {
			case <-deadline.C:
				t.Fatal("condition not reached")
			case <-ticker.C:
			}
		}
	}
	var requestID string
	wait(func() bool {
		return pool.QueryRow(t.Context(), "SELECT id FROM agent_requests WHERE sender_agent_id=$1", a.AgentID).Scan(&requestID) == nil
	})
	if _, err = store.HeadDelivery(t.Context(), b.AgentID); !errors.Is(err, controlplane.ErrNoDelivery) {
		t.Fatal("manual recipient woken before consent", err)
	}
	// Stop the real sender while all remote submission receipts are unknown.
	stopCtx, stop := context.WithTimeout(t.Context(), 5*time.Second)
	err = processes[a.AgentID].Stop(stopCtx)
	stop()
	if err != nil {
		t.Fatal(err)
	}
	apis[a.AgentID].unknownSubmit.Store(false)
	start(a.AgentID)
	localCount := func(id, query string) int {
		db, err := sql.Open("sqlite3", "file:"+filepath.Join(opts[id].Boot.DataDirectory, "harness.db")+"?mode=ro")
		if err != nil {
			return -1
		}
		defer db.Close()
		var n int
		if err = db.QueryRowContext(t.Context(), query).Scan(&n); err != nil {
			return -1
		}
		return n
	}
	wait(func() bool {
		return localCount(a.AgentID, "SELECT count(*) FROM reference_outgoing WHERE state='done'") == 1
	})
	if r := call(t, s, "POST", "/v1/me/inbox/requests/"+requestID+"/accept", tokenB, "accept", `{}`); r.Code != 200 {
		t.Fatal(r.Code)
	}
	dispatch(b.AgentID)
	wait(func() bool {
		var state string
		return pool.QueryRow(t.Context(), "SELECT state FROM agent_requests WHERE id=$1", requestID).Scan(&state) == nil && state == "REPLIED"
	})
	dispatch(a.AgentID)
	wait(func() bool {
		return localCount(b.AgentID, "SELECT count(*) FROM reference_outgoing WHERE state='done'") == 1
	})
	wait(func() bool {
		return localCount(a.AgentID, "SELECT count(*) FROM reference_outgoing WHERE state='done'") == 2
	})
	r := call(t, s, "GET", "/v1/me/inbox", tokenA, "", "")
	var inbox struct {
		Items []controlplane.InboxItem `json:"items"`
	}
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &inbox) != nil {
		t.Fatal("owner inbox", r.Code)
	}
	messageID := ""
	for _, item := range inbox.Items {
		if item.Kind == "agent_message" && item.RequestID == requestID {
			if messageID != "" {
				t.Fatal("duplicate summary notification")
			}
			messageID = item.MessageID
		}
	}
	if messageID == "" || strings.Contains(r.Body.String(), "do not relay") {
		t.Fatal("missing summary or plaintext metadata")
	}
	for _, check := range []struct {
		token string
		code  int
	}{{tokenA, 200}, {tokenB, 404}, {admin, 403}} {
		r = call(t, s, "GET", "/v1/me/inbox/messages/"+messageID, check.token, "", "")
		if r.Code != check.code {
			t.Fatal("summary ownership", r.Code, check.code)
		}
		if r.Code == 200 && !strings.Contains(r.Body.String(), "do not relay") {
			t.Fatal("summary content missing")
		}
	}
	for _, token := range []string{tokenA, tokenB} {
		r := call(t, s, "GET", "/v1/agent-requests/"+requestID, token, "", "")
		var v controlplane.RequestView
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &v) != nil || v.Reply == nil || v.Reply.Content[0].Text != "/ask third-agent do not relay" {
			t.Fatal("private reply not observable", r.Code)
		}
	}
	var n int
	if err = pool.QueryRow(t.Context(), "SELECT count(*) FROM agent_requests").Scan(&n); err != nil || n != 1 {
		t.Fatal("retry/peer text created another request", n, err)
	}
	if localCount(a.AgentID, "SELECT count(*) FROM echo_events") != 2 || localCount(b.AgentID, "SELECT count(*) FROM echo_events") != 1 {
		t.Fatal("duplicate local effect")
	}
	if localCount(a.AgentID, "SELECT count(*) FROM reference_outgoing") != 2 || localCount(b.AgentID, "SELECT count(*) FROM reference_outgoing") != 1 {
		t.Fatal("peer reply acquired outgoing authority")
	}
	if err = pool.QueryRow(t.Context(), "SELECT count(*) FROM owner_messages").Scan(&n); err != nil || n != 1 {
		t.Fatal("duplicate owner summary", n, err)
	}
	var payloadID string
	if err = pool.QueryRow(t.Context(), "SELECT payload_id FROM owner_messages WHERE id=$1", messageID).Scan(&payloadID); err != nil {
		t.Fatal(err)
	}
	principalB, err := store.Authenticate(t.Context(), tokenB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tr.ReadForOwner(t.Context(), principalB, payloadID); !errors.Is(err, controlplane.ErrNotFound) {
		t.Fatal("generic reader leaked summary to peer owner", err)
	}
	if r = call(t, s, "DELETE", "/v1/agents/"+b.AgentID, tokenA, "foreign-delete", ""); r.Code != 404 {
		t.Fatal("foreign deletion", r.Code)
	}
	r = call(t, s, "DELETE", "/v1/agents/"+b.AgentID, tokenB, "delete", "")
	var deletion controlplane.AgentCreation
	if r.Code != 202 || json.Unmarshal(r.Body.Bytes(), &deletion) != nil || deletion.OperationID == "" {
		t.Fatal("delete admission", r.Code)
	}
	initialDeletion := r.Body.String()
	if replay := call(t, s, "DELETE", "/v1/agents/"+b.AgentID, tokenB, "delete", ""); replay.Code != 202 || replay.Body.String() != initialDeletion {
		t.Fatal("delete replay")
	}
	if r = call(t, s, "GET", "/v1/me/inbox/messages/"+messageID, tokenA, "", ""); r.Code != 404 {
		t.Fatal("summary survived peer deletion", r.Code)
	}
	if err = store.ReconcileRevocation(t.Context(), b.AgentID, rt); err != nil {
		t.Fatal(err)
	}
	r = call(t, s, "GET", "/v1/operations/"+deletion.OperationID, tokenB, "", "")
	var progress controlplane.PlatformOperation
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &progress) != nil || progress.Status != "RUNNING" || progress.DeletionPhase != "RETIRING" || progress.CompletedAt != nil {
		t.Fatal("barriers falsely completed deletion", r.Code, progress)
	}
}
