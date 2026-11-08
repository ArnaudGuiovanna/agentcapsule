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
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/guestinit"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

type processInstructionRuntime struct {
	client   *capsuleprotocol.Client
	loseACK  bool
	replayed bool
}

func (r *processInstructionRuntime) Send(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	return r.client.Send(ctx, e)
}
func (r *processInstructionRuntime) Fence(ctx context.Context, target, subject string) error {
	return r.client.Fence(ctx, subject)
}
func (r *processInstructionRuntime) Invoke(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	receipt, err := r.client.Invoke(ctx, e)
	if err == nil && r.loseACK {
		r.loseACK = false
		clear(receipt.Result)
		return harnessstore.Receipt{}, capsuleprotocol.ErrTransport
	}
	r.replayed = receipt.Replayed
	return receipt, err
}

func TestHTTPInstructionResultFromRealHarnessAfterLostACK(t *testing.T) {
	s, store, admin, dsn := apiLab(t)
	tr, err := controlplane.NewTransit(store, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x45}, 32)}, 7*24*time.Hour)
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
	if err = store.ConfigureHostStorage(t.Context(), "local", 256); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RegisterLocalRelease(t.Context(), controlplane.HarnessReference{Name: "reference", Version: "1.0.0"}, "sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	_, token := apiOwner(t, s, admin, "owner")
	_, foreign := apiOwner(t, s, admin, "foreign")
	if r := call(t, s, "POST", "/v1/agents", token, "create", agentInput); r.Code != 202 {
		t.Fatal(r.Code)
	}
	jobs, err := store.PendingProvisioning(t.Context(), "local", 10)
	if err != nil || len(jobs) != 1 {
		t.Fatal(err)
	}
	e := jobs[0]
	// Provisioning observations are explicit fixtures. The instruction, result,
	// SQL transactions, authenticated transport and child harness below are real.
	if err = store.RecordProvisionedVolume(t.Context(), controlplane.ProvisionedVolume{AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, OperationID: e.OperationID, Device: 1, Inode: 100}); err != nil {
		t.Fatal(err)
	}
	p, err := store.ClaimFencePlacement(t.Context(), e.AgentID, e.HostID, "fixture", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ConfirmFencePlacement(t.Context(), e.AgentID, e.HostID, "fixture", p.Generation, "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err = store.RecordEnrollmentInitialized(t.Context(), controlplane.EnrollmentBoot{Incarnation: 1, AgentID: e.AgentID, HostID: e.HostID, VolumeID: e.VolumeID, Generation: p.Generation, VMID: "0123456789abcdef"}); err != nil {
		t.Fatal(err)
	}
	if err = store.BeginPlacementStop(t.Context(), e.AgentID, e.HostID, p.Generation); err != nil {
		t.Fatal(err)
	}
	if err = store.ObservePlacementStopped(t.Context(), e.AgentID, e.HostID, p.Generation, true); err != nil {
		t.Fatal(err)
	}
	if err = store.ActivateProvisionedAgent(t.Context(), e); err != nil {
		t.Fatal(err)
	}

	root, err := os.MkdirTemp("", "acp-instruction-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	if err = os.Mkdir(data, 0700); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if uid == 0 {
		uid, gid = 1000, 1000
	}
	if err = os.Chown(data, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "capsule-echo")
	buildCtx, cancelBuild := context.WithTimeout(t.Context(), 90*time.Second)
	build := exec.CommandContext(buildCtx, "go", "build", "-race", "-o", binary, "./cmd/capsule-echo")
	build.Dir = filepath.Join("..", "..")
	output, err := build.CombinedOutput()
	cancelBuild()
	if err != nil {
		t.Fatalf("build harness: %v %s", err, output)
	}
	host, guest, err := capsuleprotocol.NewCredentials(capsuleprotocol.Identity{Incarnation: 1, AgentID: e.AgentID, Generation: 2, VMID: "0123456789abcdee"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	process, err := guestinit.StartHarness(ctx, t.Context(), guestinit.ProcessOptions{Boot: guestinit.HarnessBoot{Protocol: capsuleprotocol.Version, PreviousShutdown: capsuleprotocol.ShutdownClean, Identity: host.Identity, DataDirectory: data, SupervisorUID: uint32(os.Geteuid())}, Entrypoint: []string{binary}, SocketPath: filepath.Join(root, "control.sock"), UID: uid, GID: gid})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := process.Stop(stop); err != nil {
			t.Error(err)
		}
	}()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- capsuleprotocol.ServeAuthenticated(ctx, l, guest, process.Proxy()) }()
	defer func() { cancel(); <-done }()
	client, err := capsuleprotocol.NewClient(host, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", l.Addr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	input := `{"content":[{"type":"text","text":"private round trip from owner"}]}`
	r := call(t, s, "POST", "/v1/agents/"+e.AgentID+"/messages", token, "instruction", input)
	var accepted controlplane.AgentCreation
	if r.Code != 202 || json.Unmarshal(r.Body.Bytes(), &accepted) != nil {
		t.Fatal("admission", r.Code)
	}
	id, err := store.HeadDelivery(t.Context(), e.AgentID)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &processInstructionRuntime{client: client, loseACK: true}
	if err = tr.DispatchMailbox(t.Context(), id, time.Minute, runtime); !errors.Is(err, capsuleprotocol.ErrTransport) {
		t.Fatal("lost response acknowledged", err)
	}
	resultPath := "/v1/operations/" + accepted.OperationID + "/result"
	if r = call(t, s, "GET", resultPath, token, "", ""); r.Code != 404 {
		t.Fatal("unacknowledged result exposed", r.Code)
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// Advance the SQL lease clock without a wall-clock minute; no effect/result
	// is inserted by the fixture. The actual harness must replay its own result.
	if _, err = pool.Exec(t.Context(), "UPDATE agent_mailboxes SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if err = tr.DispatchMailbox(t.Context(), id, time.Minute, runtime); err != nil || !runtime.replayed {
		t.Fatal("harness did not replay", err)
	}
	r = call(t, s, "GET", resultPath, token, "", "")
	var actual, want capsuleprotocol.OwnerMessage
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &actual) != nil || json.Unmarshal([]byte(input), &want) != nil || len(actual.Content) != 1 || actual.Content[0] != want.Content[0] {
		t.Fatal("private result mismatch", r.Code)
	}
	for _, test := range []struct {
		token string
		code  int
	}{{foreign, 404}, {admin, 403}} {
		if r = call(t, s, "GET", resultPath, test.token, "", ""); r.Code != test.code {
			t.Fatal("private result authorization", r.Code)
		}
	}
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(data, "harness.db")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var effects int
	if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM echo_events").Scan(&effects); err != nil || effects != 1 {
		t.Fatal("actual process effect repeated", effects, err)
	}
	var ciphertext []byte
	if err = pool.QueryRow(t.Context(), "SELECT ciphertext FROM transit_payloads WHERE kind='instruction_result' AND ref_id=$1", accepted.OperationID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte(want.Content[0].Text)) {
		t.Fatal("private result not encrypted", err)
	}
}
