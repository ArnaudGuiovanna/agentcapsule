//go:build interop_services

// Tests against the private services of deploy/interop, started by
// scripts/verify-interop.py --services:
//
//	INTEROP_CERTS          the make-certs.sh directory (with --test-identities)
//	INTEROP_DIRECTORY_ADDR the Directory edge, 127.0.0.1:<port>
//	INTEROP_SLIM_ENDPOINT  the SLIM node, https://127.0.0.1:<port>
//
// Only synthetic records and messages are used.
package interopprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "github.com/agntcy/dir/api/core/v1"
	searchv1 "github.com/agntcy/dir/api/search/v1"
	storev1 "github.com/agntcy/dir/api/store/v1"
	slim "github.com/agntcy/slim-bindings-go/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	slimAgentA  = "agentcapsule/int01/agent-a"
	slimAgentB  = "agentcapsule/int01/agent-b"
	slimAbsent  = "agentcapsule/int01/absent"
	slimSecret  = "int01-synthetic-app-secret-0123456789abcdef" // gitleaks:allow (synthetic)
	helperRole  = "INTEROP_HELPER"
	helperReady = "HELPER-READY"
)

// TestMain runs a helper process (another SLIM client with its own connection
// to the node) when the test binary is started again with INTEROP_HELPER.
func TestMain(m *testing.M) {
	switch os.Getenv(helperRole) {
	case "":
		os.Exit(m.Run())
	case "slim-echo":
		os.Exit(slimEcho())
	case "slim-connect":
		os.Exit(slimConnect())
	default:
		os.Exit(2)
	}
}

func certs(t testing.TB, parts ...string) string {
	dir := os.Getenv("INTEROP_CERTS")
	if dir == "" {
		t.Fatal("INTEROP_CERTS is not set")
	}
	return filepath.Join(append([]string{dir}, parts...)...)
}

func requiredEnv(t testing.TB, key string) string {
	v := os.Getenv(key)
	if v == "" {
		t.Fatal(key + " is not set")
	}
	return v
}

// ---------------------------------------------------------------- Directory

// directoryConn dials the Directory edge with the generated gRPC stubs only:
// the full client module pulls in Cosign, Kubernetes and OIDC libraries.
func directoryConn(t *testing.T, cert, key, ca string) *grpc.ClientConn {
	t.Helper()
	creds := insecure.NewCredentials()
	if ca != "" {
		pool := x509.NewCertPool()
		pem, err := os.ReadFile(ca)
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			t.Fatal("Directory CA", err)
		}
		config := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
		if cert != "" {
			pair, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			config.Certificates = []tls.Certificate{pair}
		}
		creds = credentials.NewTLS(config)
	}
	conn, err := grpc.NewClient(requiredEnv(t, "INTEROP_DIRECTORY_ADDR"), grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func controlPlaneConn(t *testing.T) *grpc.ClientConn {
	return directoryConn(t, certs(t, "control-plane", "directory.crt"), certs(t, "control-plane", "directory.key"), certs(t, "control-plane", "directory-ca.pem"))
}

func pushRecord(ctx context.Context, store storev1.StoreServiceClient, record *corev1.Record) (*corev1.RecordRef, error) {
	stream, err := store.Push(ctx)
	if err != nil {
		return nil, err
	}
	if err = stream.Send(record); err != nil {
		return nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, err
	}
	return stream.Recv() // validation errors arrive here
}

func pullRecord(ctx context.Context, store storev1.StoreServiceClient, ref *corev1.RecordRef) (*corev1.Record, error) {
	stream, err := store.Pull(ctx)
	if err != nil {
		return nil, err
	}
	if err = stream.Send(ref); err != nil {
		return nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, err
	}
	return stream.Recv()
}

func deleteRecord(ctx context.Context, store storev1.StoreServiceClient, ref *corev1.RecordRef) error {
	stream, err := store.Delete(ctx)
	if err != nil {
		return err
	}
	if err = stream.Send(ref); err != nil {
		return err
	}
	_, err = stream.CloseAndRecv()
	return err
}

func searchRecords(ctx context.Context, search searchv1.SearchServiceClient, queries ...*searchv1.RecordQuery) ([]string, error) {
	limit := uint32(100)
	stream, err := search.SearchCIDs(ctx, &searchv1.SearchCIDsRequest{Queries: queries, Limit: &limit})
	if err != nil {
		return nil, err
	}
	var cids []string
	for {
		r, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return cids, nil
		}
		if err != nil {
			return nil, err
		}
		cids = append(cids, r.GetRecordCid())
	}
}

func agentRecord(t *testing.T, fields map[string]any) *corev1.Record {
	t.Helper()
	record := map[string]any{
		"schema_version": "1.1.0", "version": "1.0.0",
		"description": "Synthetic agent of the INT-01 qualification.",
		"authors":     []string{"Agent Capsule qualification <qualification@example.invalid>"},
		"created_at":  "2026-11-09T00:00:00Z",
		"skills": []map[string]any{
			{"id": 10301, "name": "language_processing/language_generation/text_completion"},
			{"id": 10302, "name": "language_processing/language_generation/summarization"},
		},
		"domains": []map[string]any{{"id": 111, "name": "technology/artificial_intelligence"}},
	}
	for k, v := range fields {
		if v == nil {
			delete(record, k)
		} else {
			record[k] = v
		}
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	r, err := corev1.UnmarshalRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDirectoryPublishesSearchesAndDeletes(t *testing.T) {
	conn := controlPlaneConn(t)
	store, search := storev1.NewStoreServiceClient(conn), searchv1.NewSearchServiceClient(conn)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	scope := fmt.Sprintf("agentcapsule.local/int01-%d", time.Now().UnixNano())
	summarizer := agentRecord(t, map[string]any{"name": scope + "/summarizer"})
	completer := agentRecord(t, map[string]any{"name": scope + "/completer", "skills": []map[string]any{
		{"id": 10301, "name": "language_processing/language_generation/text_completion"}}})
	var refs []*corev1.RecordRef
	for _, r := range []*corev1.Record{summarizer, completer} {
		ref, err := pushRecord(ctx, store, r)
		if err != nil {
			t.Fatal("push", err)
		}
		if ref.GetCid() != r.GetCid() {
			t.Fatal("the server and the client compute different CIDs", ref.GetCid(), r.GetCid())
		}
		refs = append(refs, ref)
	}
	// Indexed on push: a skill search confined to this scope finds exactly the
	// summarizer, by skill ID and by skill name.
	for _, skill := range []*searchv1.RecordQuery{
		{Type: searchv1.RecordQueryType_RECORD_QUERY_TYPE_SKILL_ID, Value: "10302"},
		{Type: searchv1.RecordQueryType_RECORD_QUERY_TYPE_SKILL_NAME, Value: "*summarization"},
	} {
		cids, err := searchRecords(ctx, search, &searchv1.RecordQuery{Type: searchv1.RecordQueryType_RECORD_QUERY_TYPE_NAME, Value: scope + "/*"}, skill)
		if err != nil || len(cids) != 1 || cids[0] != refs[0].GetCid() {
			t.Fatal("skill search", skill.GetValue(), cids, err)
		}
	}
	cids, err := searchRecords(ctx, search, &searchv1.RecordQuery{Type: searchv1.RecordQueryType_RECORD_QUERY_TYPE_NAME, Value: scope + "/*"})
	if err != nil || len(cids) != 2 {
		t.Fatal("scope search", cids, err)
	}
	pulled, err := pullRecord(ctx, store, refs[0])
	if err != nil || pulled.GetCid() != refs[0].GetCid() {
		t.Fatal("pull", err)
	}
	for _, ref := range refs {
		if err = deleteRecord(ctx, store, ref); err != nil {
			t.Fatal("delete", err)
		}
	}
	if _, err = pullRecord(ctx, store, refs[0]); status.Code(err) != codes.NotFound {
		t.Fatal("a deleted record can still be pulled", err)
	}
	if cids, err = searchRecords(ctx, search, &searchv1.RecordQuery{Type: searchv1.RecordQueryType_RECORD_QUERY_TYPE_NAME, Value: scope + "/*"}); err != nil || len(cids) != 0 {
		t.Fatal("a deleted record is still found", cids, err)
	}
}

func TestDirectoryValidatesRecordsAgainstThePrivateSchema(t *testing.T) {
	store := storev1.NewStoreServiceClient(controlPlaneConn(t))
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	name := fmt.Sprintf("agentcapsule.local/int01-invalid-%d", time.Now().UnixNano())
	for label, c := range map[string]struct {
		fields map[string]any
		reason string
	}{
		"unknown skill":       {map[string]any{"name": name, "skills": []map[string]any{{"id": 99999, "name": "document-review"}}}, "no class is defined for 99999"},
		"missing description": {map[string]any{"name": name, "description": nil}, `Required attribute "description" is missing`},
		"no skill":            {map[string]any{"name": name, "skills": nil}, `Required attribute "skills" is missing`},
	} {
		_, err := pushRecord(ctx, store, agentRecord(t, c.fields))
		if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), c.reason) {
			t.Fatal(label, "was not refused by the schema:", err)
		}
	}
}

func TestDirectoryEdgeAdmitsOnlyTheControlPlane(t *testing.T) {
	ca := certs(t, "control-plane", "directory-ca.pem")
	for label, conn := range map[string]*grpc.ClientConn{
		"plaintext":             directoryConn(t, "", "", ""),
		"no client certificate": directoryConn(t, "", "", ca),
		"other workload":        directoryConn(t, certs(t, "test", "other.crt"), certs(t, "test", "other.key"), ca),
		"unknown authority":     directoryConn(t, certs(t, "test", "rogue.crt"), certs(t, "test", "rogue.key"), ca),
	} {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		_, err := searchRecords(ctx, searchv1.NewSearchServiceClient(conn), &searchv1.RecordQuery{Type: searchv1.RecordQueryType_RECORD_QUERY_TYPE_NAME, Value: "*"})
		cancel()
		if status.Code(err) != codes.Unavailable {
			t.Fatal(label, "was not refused at the edge:", err)
		}
	}
}

// --------------------------------------------------------------------- SLIM

func slimConfig(cert, key string) slim.ClientConfig {
	endpoint := os.Getenv("INTEROP_SLIM_ENDPOINT")
	cfg := slim.NewSecureClientConfig(endpoint)
	cfg.Tls.CaSource = slim.CaSourceFile{Path: filepath.Join(os.Getenv("INTEROP_CERTS"), "slim-bridge", "slim-ca.pem")}
	cfg.Tls.IncludeSystemCaCertsPool = false
	if cert != "" {
		cfg.Tls.Source = slim.TlsSourceFile{Cert: cert, Key: key}
	}
	var backoff slim.BackoffConfig = slim.BackoffConfigFixedInterval{Config: slim.FixedIntervalBackoff{Interval: 500 * time.Millisecond, MaxAttempts: 3}}
	cfg.Backoff = &backoff
	return cfg
}

func bridgeConfig() slim.ClientConfig {
	dir := filepath.Join(os.Getenv("INTEROP_CERTS"), "slim-bridge")
	return slimConfig(filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"))
}

// One connection per process: the bindings refuse a second connection to the
// same endpoint from the same service.
var slimConn = sync.OnceValues(func() (uint64, error) {
	slim.InitializeWithDefaults()
	return slim.GetGlobalService().ConnectAsync(bridgeConfig())
})

func slimApp(name string) (*slim.App, uint64, error) {
	conn, err := slimConn()
	if err != nil {
		return nil, 0, fmt.Errorf("connect: %w", err)
	}
	n, err := slim.NameFromString(name)
	if err != nil {
		return nil, 0, err
	}
	// The asynchronous constructor panics outside a Tokio runtime (v3.3.9).
	app, err := slim.GetGlobalService().CreateAppWithSecret(n, slimSecret)
	if err != nil {
		return nil, 0, err
	}
	if err = app.SubscribeAsync(app.Name(), &conn); err != nil {
		app.Destroy()
		return nil, 0, fmt.Errorf("subscribe: %w", err)
	}
	return app, conn, nil
}

func slimEcho() int {
	app, _, err := slimApp(slimAgentB)
	if err != nil {
		fmt.Println("HELPER-ERROR", err)
		return 1
	}
	fmt.Println(helperReady)
	for {
		wait := time.Minute
		session, err := app.ListenForSessionAsync(&wait)
		if err != nil {
			continue
		}
		go func() {
			for {
				wait := time.Minute
				msg, err := session.GetMessageAsync(&wait)
				if err != nil {
					return
				}
				fmt.Printf("HELPER-RECEIVED %s\n", msg.Payload)
				_ = session.PublishToAndWaitAsync(msg.Context, append([]byte("reply:"), msg.Payload...), nil, nil)
			}
		}()
	}
}

func slimConnect() int {
	slim.InitializeWithDefaults()
	conn, err := slim.GetGlobalService().ConnectAsync(slimConfig(os.Getenv("INTEROP_CERT"), os.Getenv("INTEROP_KEY")))
	if err != nil {
		fmt.Println("HELPER-REFUSED", err)
		return 0
	}
	n, _ := slim.NameFromString("agentcapsule/int01/connect-probe")
	app, err := slim.GetGlobalService().CreateAppWithSecret(n, slimSecret)
	if err == nil {
		err = app.SubscribeAsync(app.Name(), &conn)
	}
	if err != nil {
		fmt.Println("HELPER-REFUSED", err)
		return 0
	}
	fmt.Println("HELPER-CONNECTED")
	return 0
}

type helper struct {
	cmd   *exec.Cmd
	mu    sync.Mutex
	lines []string
	ready chan struct{}
	done  chan struct{}
}

func startHelper(t *testing.T, role string, env ...string) *helper {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(append(os.Environ(), helperRole+"="+role), env...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = cmd.Stdout
	h := &helper{cmd: cmd, ready: make(chan struct{}), done: make(chan struct{})}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(h.done)
		scanner := bufio.NewScanner(out)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "HELPER-") {
				continue
			}
			h.mu.Lock()
			h.lines = append(h.lines, line)
			h.mu.Unlock()
			if line == helperReady {
				close(h.ready)
			}
		}
	}()
	t.Cleanup(h.stop)
	return h
}

func (h *helper) stop() {
	_ = h.cmd.Process.Kill()
	<-h.done
	_ = h.cmd.Wait()
}

func (h *helper) output() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.lines, "\n")
}

func (h *helper) awaitReady(t *testing.T) {
	t.Helper()
	select {
	case <-h.ready:
	case <-h.done:
		t.Fatal("helper exited:", h.output())
	case <-time.After(30 * time.Second):
		t.Fatal("helper not ready:", h.output())
	}
}

func openSession(t *testing.T, app *slim.App, conn uint64, to string, cfg slim.SessionConfig) (*slim.Session, error) {
	t.Helper()
	remote, err := slim.NameFromString(to)
	if err != nil {
		t.Fatal(err)
	}
	if err = app.SetRouteAsync(remote, conn); err != nil {
		t.Fatal("route", err)
	}
	return app.CreateSessionAndWaitAsync(cfg, remote)
}

// Two clients, each with its own mutual-TLS connection, exchange requests and
// replies through the node, in order.
func TestSLIMExchangeThroughThePrivateNode(t *testing.T) {
	b := startHelper(t, "slim-echo")
	b.awaitReady(t)
	app, conn, err := slimApp(slimAgentA)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Destroy()
	session, err := openSession(t, app, conn, slimAgentB, slim.SessionConfig{SessionType: slim.SessionTypePointToPoint})
	if err != nil {
		t.Fatal("session", err)
	}
	defer func() { _ = app.DeleteSessionAndWaitAsync(session) }()
	for i := range 100 {
		payload := fmt.Sprintf("request-%03d", i)
		if err = session.PublishAndWaitAsync([]byte(payload), nil, nil); err != nil {
			t.Fatal("publish", err)
		}
		wait := 10 * time.Second
		msg, err := session.GetMessageAsync(&wait)
		if err != nil || string(msg.Payload) != "reply:"+payload {
			t.Fatal("reply", i, string(msg.Payload), err)
		}
		if c := msg.Context.SourceName.Components(); len(c) < 3 || strings.Join(c[:3], "/") != slimAgentB {
			t.Fatal("reply from", c)
		}
	}
}

// The node refuses a client without a certificate or with one from another
// authority, and admits the platform bridge (positive control).
func TestSLIMNodeAdmitsOnlyTheSLIMAuthority(t *testing.T) {
	for label, c := range map[string]struct {
		cert, key, want string
	}{
		"bridge":                {certs(t, "slim-bridge", "client.crt"), certs(t, "slim-bridge", "client.key"), "HELPER-CONNECTED"},
		"no client certificate": {"", "", "HELPER-REFUSED"},
		"unknown authority":     {certs(t, "test", "rogue.crt"), certs(t, "test", "rogue.key"), "HELPER-REFUSED"},
		"directory authority":   {certs(t, "control-plane", "directory.crt"), certs(t, "control-plane", "directory.key"), "HELPER-REFUSED"},
	} {
		h := startHelper(t, "slim-connect", "INTEROP_CERT="+c.cert, "INTEROP_KEY="+c.key)
		select {
		case <-h.done:
		case <-time.After(60 * time.Second):
			t.Fatal(label, "connection attempt did not end")
		}
		out := h.output()
		if !strings.HasPrefix(out, c.want) {
			t.Fatal(label, "expected", c.want, "got", out)
		}
		t.Logf("%s: %s", label, out)
	}
}

// SLIM keeps nothing for an absent recipient: a session to a name nobody
// subscribed fails, and a message sent while the recipient is down is never
// delivered after it comes back. Durability is the platform mailbox's job.
func TestSLIMKeepsNothingForAnAbsentRecipient(t *testing.T) {
	app, conn, err := slimApp(slimAgentA + "-absent")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Destroy()
	retries, interval := uint32(2), 200*time.Millisecond
	if s, err := openSession(t, app, conn, slimAbsent, slim.SessionConfig{SessionType: slim.SessionTypePointToPoint, MaxRetries: &retries, Interval: &interval}); err == nil {
		_ = app.DeleteSessionAndWaitAsync(s)
		t.Fatal("a session reached a name nobody subscribed")
	}

	b := startHelper(t, "slim-echo")
	b.awaitReady(t)
	session, err := openSession(t, app, conn, slimAgentB, slim.SessionConfig{SessionType: slim.SessionTypePointToPoint})
	if err != nil {
		t.Fatal("session", err)
	}
	b.stop()
	// Fire-and-forget: the publish succeeds although nobody receives it.
	if err = session.PublishAndWaitAsync([]byte("sent-while-down"), nil, nil); err != nil {
		t.Fatal("publish while down", err)
	}
	_ = app.DeleteSessionAndWaitAsync(session)

	again := startHelper(t, "slim-echo")
	again.awaitReady(t)
	session, err = openSession(t, app, conn, slimAgentB, slim.SessionConfig{SessionType: slim.SessionTypePointToPoint})
	if err != nil {
		t.Fatal("session after restart", err)
	}
	defer func() { _ = app.DeleteSessionAndWaitAsync(session) }()
	if err = session.PublishAndWaitAsync([]byte("sent-after-restart"), nil, nil); err != nil {
		t.Fatal(err)
	}
	wait := 10 * time.Second
	if msg, err := session.GetMessageAsync(&wait); err != nil || string(msg.Payload) != "reply:sent-after-restart" {
		t.Fatal("reply after restart", err)
	}
	time.Sleep(2 * time.Second)
	if strings.Contains(again.output(), "sent-while-down") {
		t.Fatal("SLIM delivered a message sent while the recipient was down")
	}
}
