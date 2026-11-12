//go:build linux

package agentadapter

import (
	"context"
	"iter"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

// agentServer is an A2A agent built with the official SDK's server: it echoes
// the text, and its answer depends on the text's first word.
func agentServer(seen *[]string, mu *sync.Mutex) http.Handler {
	executor := a2asrv.AgentExecutorFunc(func(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
		return func(yield func(a2a.Event, error) bool) {
			text := ""
			if p := ec.Message.Parts; len(p) > 0 {
				if t, ok := p[0].Content.(a2a.Text); ok {
					text = string(t)
				}
			}
			if mu != nil {
				mu.Lock()
				*seen = append(*seen, ec.Message.ID+" "+text)
				mu.Unlock()
			}
			word, _, _ := strings.Cut(text, " ")
			var events []a2a.Event
			switch word {
			case "direct":
				events = []a2a.Event{a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("direct answer"))}
			case "fail":
				events = []a2a.Event{a2a.NewSubmittedTask(ec, ec.Message), a2a.NewStatusUpdateEvent(ec, a2a.TaskStateFailed, nil)}
			case "input":
				events = []a2a.Event{a2a.NewSubmittedTask(ec, ec.Message), a2a.NewStatusUpdateEvent(ec, a2a.TaskStateInputRequired, nil)}
			case "crash":
				os.Exit(3)
			default:
				events = []a2a.Event{
					a2a.NewSubmittedTask(ec, ec.Message),
					a2a.NewStatusUpdateEvent(ec, a2a.TaskStateWorking, nil),
					a2a.NewArtifactEvent(ec, a2a.NewTextPart("echo: "+text)),
					a2a.NewStatusUpdateEvent(ec, a2a.TaskStateCompleted, nil),
				}
			}
			for _, e := range events {
				if word != "direct" {
					time.Sleep(20 * time.Millisecond)
				}
				if !yield(e, nil) {
					return
				}
			}
		}
	})
	return a2asrv.NewJSONRPCHandler(a2asrv.NewHandler(executor))
}

type ready struct{}

func (ready) WaitReady(context.Context) error { return nil }

func serverConfig(url string) Config {
	return Config{Version: 1, Server: &ServerConfig{Command: []string{"/bin/true"}, URL: url, ReadySeconds: 1}, Input: "stdin",
		TimeoutSeconds: 30, ModelAddress: DefaultModelAddress, A2AAddress: DefaultA2AAddress}
}

// Each job is one message to the agent's server; the answer is its text
// artifacts, or its direct message; any other ending is a failed run.
func TestServerRunnerSendsEachJobAsAMessage(t *testing.T) {
	var seen []string
	var mu sync.Mutex
	server := httptest.NewServer(agentServer(&seen, &mu))
	defer server.Close()
	run := ServerRunner(serverConfig(server.URL), ready{})
	for _, c := range []struct {
		text string
		want Output
	}{
		{"hello there", Output{Completed: true, Text: "echo: hello there"}},
		{"direct question", Output{Completed: true, Text: "direct answer"}},
		{"fail now", Output{}},
		{"input please", Output{}},
	} {
		if got := run(t.Context(), Job{ID: "op-" + strings.Fields(c.text)[0], Text: c.text}); got != c.want {
			t.Errorf("%q: %+v", c.text, got)
		}
	}
	if len(seen) != 4 || seen[0] != "agentcapsule-op-hello hello there" {
		t.Fatal(seen)
	}
}

// A server that never comes up fails the job after the configured wait.
func TestServerRunnerGivesUpOnAServerThatIsNotThere(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	l.Close()
	cfg := serverConfig("http://" + address)
	s, err := NewSupervisor(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if got := ServerRunner(cfg, s)(t.Context(), Job{ID: "op", Text: "hello"}); got.Completed || time.Since(start) > 5*time.Second {
		t.Fatal(got, time.Since(start))
	}
}

// TestA2AServerChild is the agent's server process of the supervisor test.
func TestA2AServerChild(t *testing.T) {
	address := os.Getenv("A2A_SERVER_CHILD")
	if address == "" {
		return
	}
	l, err := net.Listen("tcp", address)
	if err != nil {
		os.Exit(4)
	}
	_ = http.Serve(l, agentServer(nil, nil))
	os.Exit(5)
}

// privatePort returns a free loopback address below the ephemeral port range:
// no listener on port 0 and no outgoing connection of a concurrent test can be
// given that port while the server is down between two starts.
func privatePort(t *testing.T) string {
	t.Helper()
	low := 32768
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
		if f := strings.Fields(string(b)); len(f) == 2 {
			if n, err := strconv.Atoi(f[0]); err == nil && n > 12000 {
				low = n
			}
		}
	}
	for range 200 {
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(10000+rand.IntN(low-10000)))
		if l, err := net.Listen("tcp", address); err == nil {
			l.Close()
			return address
		}
	}
	t.Fatal("no free port below the ephemeral range")
	return ""
}

// The supervisor starts the server, starts it again after it dies (the job it
// was running fails), and stops it with the adapter.
func TestSupervisorKeepsTheServerRunning(t *testing.T) {
	address := privatePort(t)
	cfg := serverConfig("http://" + address)
	cfg.Server.Command = []string{os.Args[0], "-test.run=^TestA2AServerChild$"}
	cfg.Server.ReadySeconds = 20
	cfg.Env = map[string]string{"A2A_SERVER_CHILD": address}
	s, err := NewSupervisor(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	run := ServerRunner(cfg, s)
	if got := run(t.Context(), Job{ID: "op-1", Text: "hello"}); got != (Output{Completed: true, Text: "echo: hello"}) {
		t.Fatal(got)
	}
	if got := run(t.Context(), Job{ID: "op-2", Text: "crash"}); got.Completed {
		t.Fatal("a job survived its server", got)
	}
	// The next job goes to the new server: wait until the supervisor has seen
	// the old one die and started another. A job sent before that may still
	// reach the dying process, and fails as one sent during the crash would.
	for deadline := time.Now().Add(20 * time.Second); s.Starts() < 2; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the server was not started again")
		}
	}
	if got := run(t.Context(), Job{ID: "op-3", Text: "again"}); got != (Output{Completed: true, Text: "echo: again"}) {
		t.Fatal(got)
	}
	if s.Starts() != 2 {
		t.Fatal("starts", s.Starts())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the supervisor did not stop")
	}
	if conn, err := net.DialTimeout("tcp", address, time.Second); err == nil {
		conn.Close()
		t.Fatal("the server outlived the adapter")
	}
}
