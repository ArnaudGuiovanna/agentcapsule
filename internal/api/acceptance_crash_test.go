//go:build linux

package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAPIProcessChild is the API process of TestAPIKilledAfterAcceptance: the
// API of the lab's database, with the receipt key of apiLab and the transit
// key of tenantInvocationLab, on a loopback listener it prints. With
// AGENTCAPSULE_API_CHILD_KILL, it dies by SIGKILL as soon as it has written a
// 202 to POST /v1/agents/{id}/invocations or /messages: nothing runs after
// the acknowledgement.
func TestAPIProcessChild(t *testing.T) {
	dsn := os.Getenv("AGENTCAPSULE_API_CHILD_DSN")
	if dsn == "" {
		return
	}
	ctx := context.Background()
	s, err := controlplane.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	// As agentcapsule-api: the organization model only.
	s.CloseLegacyOwnerDomain()
	accounts, err := controlplane.NewAccounts(s, bytes.Repeat([]byte{0x36}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err = accounts.CheckReceiptKey(ctx); err != nil {
		t.Fatal(err)
	}
	transit, err := controlplane.NewTransit(s, "v1", map[string][]byte{"v1": bytes.Repeat([]byte{0x45}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.CheckKeys(ctx); err != nil {
		t.Fatal(err)
	}
	server, err := NewForHostWithTransit(s, accounts, "local", transit)
	if err != nil {
		t.Fatal(err)
	}
	var handler http.Handler = server
	if os.Getenv("AGENTCAPSULE_API_CHILD_KILL") != "" {
		handler = dieAfterAcceptance(server)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("LISTENING %s\n", l.Addr())
	t.Fatal((&http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}).Serve(l))
}

// dieAfterAcceptance answers an acceptance of an invocation or a message in
// full, with its length, flushes it to the socket, then kills the process.
func dieAfterAcceptance(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accepting := r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/agents/") &&
			(strings.HasSuffix(r.URL.Path, "/invocations") || strings.HasSuffix(r.URL.Path, "/messages"))
		if !accepting {
			next.ServeHTTP(w, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.Header().Set("Content-Length", strconv.Itoa(rec.Body.Len()))
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		if rec.Code != http.StatusAccepted {
			return
		}
		// The whole request was read, so closing the socket sends the
		// answer then FIN, never a reset.
		_, _ = io.Copy(io.Discard, r.Body)
		w.(http.Flusher).Flush()
		_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
		select {}
	})
}

type apiProcess struct {
	url string
	cmd *exec.Cmd
	// exited is closed once the process has ended, with its error in err.
	exited chan struct{}
	err    error
}

func startAPIProcess(t *testing.T, dsn string, dieAfterAcceptance bool) *apiProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestAPIProcessChild$", "-test.timeout=120s")
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_API_CHILD_DSN="+dsn, "AGENTCAPSULE_API_CHILD_KILL=")
	if dieAfterAcceptance {
		cmd.Env = append(cmd.Env, "AGENTCAPSULE_API_CHILD_KILL=1")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &apiProcess{cmd: cmd, exited: make(chan struct{})}
	lines := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		lines <- line
		_, _ = io.Copy(io.Discard, stdout)
		p.err = cmd.Wait()
		close(p.exited)
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-p.exited
	})
	select {
	case line := <-lines:
		address, ok := strings.CutPrefix(strings.TrimSpace(line), "LISTENING ")
		if !ok {
			t.Fatalf("API process: %q %s", line, stderr.String())
		}
		p.url = "http://" + address
	case <-time.After(60 * time.Second):
		t.Fatal("the API process did not start", stderr.String())
	}
	return p
}

func (p *apiProcess) call(t *testing.T, method, path, token, key, body string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, p.url+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("incomplete answer", err)
	}
	return resp.StatusCode, resp.Header, b
}

// countingEcho is echoRuntime, counting the invocations its harness receives.
type countingEcho struct {
	echoRuntime
	invoked atomic.Int32
}

func (r *countingEcho) Invoke(ctx context.Context, target string, e harnessstore.Event) (harnessstore.Receipt, error) {
	r.invoked.Add(1)
	return r.echoRuntime.Invoke(ctx, target, e)
}

// EVT-001: the API process is killed (SIGKILL) right after it has written the
// 202 that accepts an invocation, by either route. A new API process on the
// same database answers the invocation under its ID, replays the same answer
// to the same Idempotency-Key without creating anything, and the worker's
// dispatch delivers it once; its result is then readable.
func TestAPIKilledAfterAcceptanceLosesNoInvocation(t *testing.T) {
	for _, route := range []string{"invocations", "messages"} {
		t.Run(route, func(t *testing.T) {
			l, transit, agent, _, bob := tenantInvocationLab(t)
			text := "accepted before the crash, by " + route
			input := `{"content":[{"type":"text","text":"` + text + `"}]}`
			path := "/v1/agents/" + agent + "/" + route

			first := startAPIProcess(t, l.dsn, true)
			code, header, accepted := first.call(t, "POST", path, bob, "crash-"+route, input)
			if code != 202 || header.Get("Idempotency-Replayed") != "" {
				t.Fatal("acceptance", code, string(accepted))
			}
			select {
			case <-first.exited:
				var exit *exec.ExitError
				if !errors.As(first.err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
					t.Fatal("the API process was not killed after its 202", first.err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("the API process outlived its 202")
			}
			var id string
			if route == "invocations" {
				var inv controlplane.Invocation
				if json.Unmarshal(accepted, &inv) != nil || inv.ID == "" || inv.State != "accepted" {
					t.Fatal("invocation", string(accepted))
				}
				id = inv.ID
			} else {
				var op controlplane.AgentCreation
				if json.Unmarshal(accepted, &op) != nil || op.OperationID == "" || op.AgentID != agent {
					t.Fatal("operation", string(accepted))
				}
				id = op.OperationID
			}

			second := startAPIProcess(t, l.dsn, false)
			code, _, body := second.call(t, "GET", "/v1/invocations/"+id, bob, "", "")
			var got controlplane.Invocation
			if code != 200 || json.Unmarshal(body, &got) != nil || got.ID != id || got.AgentID != agent || got.State != "accepted" {
				t.Fatal("the accepted invocation after the crash", code, string(body))
			}
			code, header, replayed := second.call(t, "POST", path, bob, "crash-"+route, input)
			if code != 202 || header.Get("Idempotency-Replayed") != "true" || !bytes.Equal(replayed, accepted) {
				t.Fatal("the retry is not the acknowledged answer", code, string(replayed))
			}
			db, err := pgxpool.New(t.Context(), l.dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var instructions, mailboxes int
			if err = db.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM owner_instructions),(SELECT count(*) FROM agent_mailboxes WHERE instruction_id=$1)`,
				id).Scan(&instructions, &mailboxes); err != nil || instructions != 1 || mailboxes != 1 {
				t.Fatal("work created by the crash or its retry", instructions, mailboxes, err)
			}

			head, err := l.store.HeadDelivery(t.Context(), agent)
			if err != nil {
				t.Fatal("nothing to deliver after the crash", err)
			}
			rt := &countingEcho{}
			if err = transit.DispatchMailbox(t.Context(), head, time.Minute, rt); err != nil {
				t.Fatal(err)
			}
			if _, err = l.store.HeadDelivery(t.Context(), agent); !errors.Is(err, controlplane.ErrNoDelivery) {
				t.Fatal("work left after the delivery", err)
			}
			if rt.invoked.Load() != 1 {
				t.Fatal("deliveries", rt.invoked.Load())
			}
			resultPath := "/v1/invocations/" + id + "/result"
			if route == "messages" {
				resultPath = "/v1/operations/" + id + "/result"
			}
			code, _, body = second.call(t, "GET", resultPath, bob, "", "")
			var result capsuleprotocol.OwnerMessage
			if code != 200 || json.Unmarshal(body, &result) != nil || len(result.Content) != 1 || result.Content[0].Text != text {
				t.Fatal("result", code, string(body))
			}
			code, _, body = second.call(t, "GET", "/v1/invocations/"+id, bob, "", "")
			if code != 200 || json.Unmarshal(body, &got) != nil || got.State != "completed" || !got.ResultAvailable {
				t.Fatal("completion", code, string(body))
			}
		})
	}
}
