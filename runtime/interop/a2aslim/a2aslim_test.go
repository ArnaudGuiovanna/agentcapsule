//go:build interop_services

// A2A 1.0 over SLIM through the private node of deploy/interop, with the
// official transport (github.com/agntcy/slim-a2a-go). Started by
// scripts/verify-interop.py --services with INTEROP_CERTS and
// INTEROP_SLIM_ENDPOINT set. Synthetic data only.
package a2aslim

import (
	"bufio"
	"context"
	"fmt"
	"iter"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2aclient"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	a2aslimrpc "github.com/agntcy/slim-a2a-go/a2aslimrpc/v1"
	slim "github.com/agntcy/slim-bindings-go/v3"
	slimrpc "github.com/agntcy/slim-bindings-go/v3/slim_rpc"
)

const (
	agentA = "agentcapsule/int01/agent-a"
	agentB = "agentcapsule/int01/agent-b"
	secret = "int01-synthetic-app-secret-0123456789abcdef" // gitleaks:allow (synthetic)
)

func TestMain(m *testing.M) {
	if os.Getenv("INTEROP_HELPER") == "a2a-server" {
		os.Exit(serve())
	}
	os.Exit(m.Run())
}

func connect(name string) (*slim.App, uint64, *slim.Name, error) {
	slim.InitializeWithDefaults()
	certs := filepath.Join(os.Getenv("INTEROP_CERTS"), "slim-bridge")
	cfg := slim.NewSecureClientConfig(os.Getenv("INTEROP_SLIM_ENDPOINT"))
	cfg.Tls.CaSource = slim.CaSourceFile{Path: filepath.Join(certs, "slim-ca.pem")}
	cfg.Tls.IncludeSystemCaCertsPool = false
	cfg.Tls.Source = slim.TlsSourceFile{Cert: filepath.Join(certs, "client.crt"), Key: filepath.Join(certs, "client.key")}
	n, err := slim.NameFromString(name)
	if err != nil {
		return nil, 0, nil, err
	}
	svc := slim.GetGlobalService()
	app, err := svc.CreateAppWithSecret(n, secret)
	if err != nil {
		return nil, 0, nil, err
	}
	conn, err := svc.ConnectAsync(cfg)
	if err == nil {
		err = app.SubscribeAsync(app.Name(), &conn)
	}
	if err != nil {
		app.Destroy()
		return nil, 0, nil, err
	}
	return app, conn, n, nil
}

// executor answers like a harness would: submitted, working, one artifact,
// completed. It reports the caller identity the transport verified.
type executor struct{}

func (executor) Execute(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	caller, ok := a2aslimrpc.CallerFromContext(ctx)
	fmt.Printf("SERVER-CALLER ok=%v subject=%s\n", ok, caller.Subject)
	text := ""
	if ec.Message != nil {
		for _, p := range ec.Message.Parts {
			if t, ok := p.Content.(a2a.Text); ok {
				text = string(t)
			}
		}
	}
	return func(yield func(a2a.Event, error) bool) {
		for _, ev := range []a2a.Event{
			a2a.NewSubmittedTask(ec, ec.Message),
			a2a.NewStatusUpdateEvent(ec, a2a.TaskStateWorking, nil),
			a2a.NewArtifactEvent(ec, a2a.NewTextPart("answer to: "+text)),
			a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil),
		} {
			if !yield(ev, nil) {
				return
			}
		}
	}
}

func (executor) Cancel(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		yield(a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCanceled, nil), nil)
	}
}

func serve() int {
	app, conn, name, err := connect(agentB)
	if err != nil {
		fmt.Println("SERVER-ERROR", err)
		return 1
	}
	server := slimrpc.ServerNewWithConnection(app, name, &conn)
	a2aslimrpc.NewHandler(a2asrv.NewHandler(executor{})).RegisterWith(server)
	fmt.Println("SERVER-READY")
	if err = server.ServeBlocking(); err != nil {
		fmt.Println("SERVER-ERROR", err)
		return 1
	}
	return 0
}

// Agent A sends an A2A message to agent B's SLIM name and reads the task back;
// B runs in another process with its own mutual-TLS connection to the node.
func TestA2AOverSLIMThroughThePrivateNode(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "INTEROP_HELPER=a2a-server")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var lines []string
	ready, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "SERVER-") {
				continue
			}
			mu.Lock()
			lines = append(lines, line)
			mu.Unlock()
			if line == "SERVER-READY" {
				close(ready)
			}
		}
	}()
	defer func() { _ = cmd.Process.Kill(); <-done; _ = cmd.Wait() }()
	select {
	case <-ready:
	case <-done:
		t.Fatal("A2A server exited", lines)
	case <-time.After(30 * time.Second):
		t.Fatal("A2A server not ready")
	}

	app, conn, _, err := connect(agentA)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Destroy()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	// The Agent Card names B's SLIM address as its interface.
	card := &a2a.AgentCard{
		Name: "Synthetic agent B", Description: "INT-01 qualification", Version: "1.0.0",
		SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(agentB, a2aslimrpc.SLIMProtocol)},
		DefaultInputModes:   []string{"text/plain"}, DefaultOutputModes: []string{"text/plain"},
	}
	client, err := a2aclient.NewFactory(a2aclient.WithDefaultsDisabled(), a2aslimrpc.WithSLIMRPCTransport(app, &conn)).CreateFromCard(ctx, card)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Destroy()
	result, err := client.SendMessage(ctx, &a2a.SendMessageRequest{Message: a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart("synthetic question"))})
	if err != nil {
		t.Fatal("SendMessage", err)
	}
	task, ok := result.(*a2a.Task)
	if !ok || task.Status.State != a2a.TaskStateCompleted || len(task.Artifacts) != 1 || len(task.Artifacts[0].Parts) != 1 ||
		task.Artifacts[0].Parts[0].Content != a2a.Text("answer to: synthetic question") {
		t.Fatalf("unexpected result %#v", result)
	}
	got, err := client.GetTask(ctx, &a2a.GetTaskRequest{ID: task.ID})
	if err != nil || got.ID != task.ID || got.Status.State != a2a.TaskStateCompleted {
		t.Fatal("GetTask", err)
	}
	// The server saw A's verified SLIM identity (name plus instance suffix).
	mu.Lock()
	defer mu.Unlock()
	seen := false
	for _, l := range lines {
		seen = seen || strings.HasPrefix(l, "SERVER-CALLER ok=true subject="+agentA)
	}
	if !seen {
		t.Fatal("the server did not see agent A's identity", lines)
	}
}
