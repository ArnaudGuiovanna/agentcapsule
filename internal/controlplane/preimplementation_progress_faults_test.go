package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This proxy belongs only to the test's private schema/cluster. Stopping it
// disconnects the real owner-lookup pool without stopping the independent SQL
// observer or fabricating an unavailable response in application code.
type p3SQLProxy struct {
	address, network, target string
	listener                 net.Listener
	cancel                   context.CancelFunc
	done                     chan struct{}
	mu                       sync.Mutex
	closing                  bool
	connections              map[net.Conn]bool
	writers                  sync.WaitGroup
}

func (p *p3SQLProxy) start(t *testing.T) {
	t.Helper()
	l, err := net.Listen("tcp", p.address)
	if err != nil {
		t.Fatal(err)
	}
	p.address, p.listener = l.Addr().String(), l
	p.closing = false
	p.connections = map[net.Conn]bool{}
	p.done = make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	p.cancel = cancel
	go func() {
		defer close(p.done)
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			if p.closing {
				p.mu.Unlock()
				conn.Close()
				continue
			}
			p.connections[conn] = true
			p.writers.Add(1)
			p.mu.Unlock()
			go func() {
				defer p.writers.Done()
				defer func() { conn.Close(); p.mu.Lock(); delete(p.connections, conn); p.mu.Unlock() }()
				upstream, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, p.network, p.target)
				if err != nil {
					return
				}
				p.mu.Lock()
				if p.closing {
					p.mu.Unlock()
					upstream.Close()
					return
				}
				p.connections[upstream] = true
				p.mu.Unlock()
				defer func() { upstream.Close(); p.mu.Lock(); delete(p.connections, upstream); p.mu.Unlock() }()
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, conn); upstream.Close(); close(copied) }()
				_, _ = io.Copy(conn, upstream)
				conn.Close()
				<-copied
			}()
		}
	}()
}

func (p *p3SQLProxy) stop() {
	if p.cancel == nil {
		return
	}
	p.mu.Lock()
	p.closing = true
	p.cancel()
	p.listener.Close()
	for conn := range p.connections {
		conn.Close()
	}
	p.mu.Unlock()
	<-p.done
	p.writers.Wait()
	p.cancel = nil
}

func (a *p3Replay) setupLookupOutage(t *testing.T) {
	t.Helper()
	cfg := a.s.pool.Config().Copy()
	original := cfg.ConnConfig
	p := &p3SQLProxy{address: "127.0.0.1:0", network: "tcp", target: net.JoinHostPort(original.Host, strconv.Itoa(int(original.Port)))}
	if strings.HasPrefix(original.Host, "/") {
		p.network = "unix"
		p.target = filepath.Join(original.Host, fmt.Sprintf(".s.PGSQL.%d", original.Port))
	}
	p.start(t)
	a.lookupProxy = p
	t.Cleanup(p.stop)
	host, port, err := net.SplitHostPort(p.address)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.Host, cfg.ConnConfig.Port = host, uint16(n)
	cfg.ConnConfig.TLSConfig = nil
	cfg.ConnConfig.Fallbacks = nil
	cfg.ConnConfig.ConnectTimeout = time.Second
	cfg.MaxConns = 2
	cfg.MinConns = 0
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	reader := &Store{pool: pool}
	a.lookup = reader
	t.Cleanup(reader.Close)
	tx, err := reader.begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rollback(tx)
	accounts, err := NewAccounts(reader, bytes.Repeat([]byte{0x74}, 32))
	if err != nil {
		t.Fatal(err)
	}
	transit, err := NewTransit(reader, "progress", map[string][]byte{"progress": bytes.Repeat([]byte{0x75}, 32)}, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = transit.CheckKeys(t.Context()); err != nil {
		t.Fatal(err)
	}
	a.catalog, err = NewAgentCatalogWithTransit(accounts, "host", transit)
	if err != nil {
		t.Fatal(err)
	}
}

// The process below executes SQL-side worker operations using production
// methods. mTLS/SQLite callbacks remain in the parent replay driver; this is
// not the Firecracker Placements service and does not prove host recovery.
type p3WorkerConfig struct{ DSN string }
type p3WorkerCommand struct {
	Op, Mailbox, Token, RequestID string
	Caller                        VMCaller
	Reply                         capsuleprotocol.Reply
}
type p3WorkerResponse struct {
	Op, Error string
	PID       int
	Attempt   DeliveryAttempt
	Receipt   Receipt
}

func TestP3SQLWorkerChild(t *testing.T) {
	if os.Getenv("AGENTCAPSULE_P3_SQL_CHILD") != "1" {
		return
	}
	configuration := os.NewFile(3, "private-worker-configuration")
	var c p3WorkerConfig
	if configuration == nil || json.NewDecoder(configuration).Decode(&c) != nil {
		os.Exit(2)
	}
	configuration.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	s, err := Open(ctx, c.DSN)
	if err != nil {
		os.Exit(3)
	}
	tr, err := NewTransit(s, "progress", map[string][]byte{"progress": bytes.Repeat([]byte{0x75}, 32)}, 7*24*time.Hour)
	if err != nil || tr.CheckKeys(ctx) != nil {
		os.Exit(4)
	}
	cancel()
	defer s.Close()
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	if encoder.Encode(p3WorkerResponse{Op: "ready", PID: os.Getpid()}) != nil {
		os.Exit(5)
	}
	jobs := map[string]WorkerJob{}
	for {
		var command p3WorkerCommand
		if decoder.Decode(&command) != nil {
			os.Exit(0)
		}
		response := p3WorkerResponse{Op: command.Op, PID: os.Getpid()}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := func() error {
			switch command.Op {
			case "ping":
				return s.pool.Ping(ctx)
			case "discover":
				return s.DiscoverWork(ctx, "host", 16)
			case "claim":
				if err := s.DiscoverWork(ctx, "host", 16); err != nil {
					return err
				}
				job, err := s.ClaimWork(ctx, "host", time.Hour)
				if err != nil {
					return err
				}
				if job.Kind != "delivery" || job.ID != command.Mailbox {
					return errors.New("unexpected worker ticket")
				}
				jobs[command.Mailbox] = job
				attempt, err := s.ClaimDelivery(ctx, command.Mailbox, time.Hour)
				if err != nil {
					return err
				}
				if err = s.AuthorizeDispatch(ctx, attempt.ID, attempt.Token); err != nil {
					return err
				}
				attempt.Envelope, err = tr.resolveDelivery(ctx, attempt)
				response.Attempt = attempt
				return err
			case "ack":
				job, ok := jobs[command.Mailbox]
				if !ok {
					return errors.New("unknown worker ticket")
				}
				if err := s.acknowledgeDelivery(ctx, command.Mailbox, command.Token, tr); err != nil {
					return err
				}
				if err := s.CompleteWork(ctx, job); err != nil {
					return err
				}
				delete(jobs, command.Mailbox)
				return nil
			case "reply":
				var err error
				response.Receipt, err = tr.ReplyFromVM(ctx, command.Caller, command.RequestID, "progress-reply", command.Reply)
				return err
			default:
				return errors.New("unknown command")
			}
		}()
		cancel()
		// Never expose DSN, SQL values, keys or private content in diagnostics.
		if err != nil {
			response.Error = "operation_failed"
		}
		if encoder.Encode(response) != nil {
			os.Exit(6)
		}
	}
}

type p3SQLWorker struct {
	cmd     *exec.Cmd
	in      io.WriteCloser
	out     io.ReadCloser
	encoder *json.Encoder
	decoder *json.Decoder
	done    chan error
	stopped bool
	errors  *bytes.Buffer
}

func startP3SQLWorker(t *testing.T, dsn string) *p3SQLWorker {
	t.Helper()
	configuration, writeConfig, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer configuration.Close()
	defer writeConfig.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestP3SQLWorkerChild$", "-test.timeout=90s")
	cmd.Env = append(os.Environ(), "AGENTCAPSULE_P3_SQL_CHILD=1")
	cmd.ExtraFiles = []*os.File{configuration}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	w := &p3SQLWorker{cmd: cmd, in: in, out: out, encoder: json.NewEncoder(in), decoder: json.NewDecoder(out), done: make(chan error, 1), errors: stderr}
	go func() { w.done <- cmd.Wait() }()
	t.Cleanup(func() {
		if !w.stopped {
			w.kill(t)
		}
	})
	if err = json.NewEncoder(writeConfig).Encode(p3WorkerConfig{DSN: dsn}); err != nil {
		t.Fatal("worker configuration pipe")
	}
	writeConfig.Close()
	configuration.Close()
	ready := w.exchange(t, nil)
	if ready.Op != "ready" || ready.PID != cmd.Process.Pid || ready.Error != "" {
		t.Fatal("SQL worker not ready")
	}
	return w
}

func (w *p3SQLWorker) exchange(t *testing.T, command *p3WorkerCommand) p3WorkerResponse {
	t.Helper()
	if w.stopped {
		t.Fatal("command sent to stopped SQL worker")
	}
	type result struct {
		r   p3WorkerResponse
		err error
	}
	done := make(chan result, 1)
	go func() {
		if command != nil {
			if err := w.encoder.Encode(command); err != nil {
				done <- result{err: err}
				return
			}
		}
		var r p3WorkerResponse
		err := w.decoder.Decode(&r)
		done <- result{r, err}
	}()
	select {
	case got := <-done:
		if got.err != nil || got.r.Error != "" {
			t.Fatal("SQL worker protocol/operation failure")
		}
		if command != nil && got.r.Op != command.Op {
			t.Fatal("SQL worker response mismatch")
		}
		return got.r
	case <-time.After(10 * time.Second):
		w.kill(t)
		t.Fatal("SQL worker response timed out")
	}
	return p3WorkerResponse{}
}

func (w *p3SQLWorker) kill(t *testing.T) {
	t.Helper()
	if w.stopped {
		return
	}
	if err := w.cmd.Process.Kill(); err != nil {
		t.Fatal("cannot kill owned SQL worker", err)
	}
	select {
	case err := <-w.done:
		var exited *exec.ExitError
		if !errors.As(err, &exited) {
			t.Fatal("SQL worker did not exit by signal")
		}
		status, ok := exited.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatal("SQL worker was not killed by SIGKILL")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned SQL worker did not exit")
	}
	w.stopped = true
	w.in.Close()
	w.out.Close()
	// Wait has drained stderr, so this also checks the instrumented child;
	// killing it must not silently discard a previously reported data race.
	if bytes.Contains(w.errors.Bytes(), []byte("DATA RACE")) {
		t.Fatal("SQL worker race detector reported a conflict")
	}
}

func (a *p3Replay) availabilityStep(t *testing.T, op protocolAction) (bool, error) {
	t.Helper()
	switch op.Name {
	case "loseStore":
		a.local.stopLocal(t, p1Int(op.Args[0]))
		return true, nil
	case "recoverStore":
		i := p1Int(op.Args[0])
		a.local.boots[i] = a.local.launchLocal(t, i, false)
		return true, nil
	case "loseAuthority":
		a.lookupProxy.stop()
		// Exercise the same production method as observe. No cached response
		// may be served while its current database authority is unreachable.
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		if _, err := a.catalog.Request(ctx, a.principals[0], a.bound[0].id); err == nil {
			t.Fatal("owner lookup succeeded through disconnected authority")
		}
		return true, nil
	case "recoverAuthority":
		a.lookupProxy.start(t)
		return true, nil
	case "crashWorker":
		a.sqlWorker.kill(t)
		var count int
		if err := a.s.pool.QueryRow(t.Context(), "SELECT count(*) FROM worker_jobs WHERE kind='delivery'").Scan(&count); err != nil {
			return true, err
		}
		if count != 1 {
			t.Fatal("durable work lost at worker crash")
		}
		return true, nil
	case "recoverWorker":
		old := a.sqlWorker.cmd.Process.Pid
		a.sqlWorker = startP3SQLWorker(t, a.dsn)
		if a.sqlWorker.cmd.Process.Pid == old {
			t.Fatal("worker process not replaced")
		}
		return true, nil
	}
	return false, nil
}

func (a *p3Replay) compareAvailability(t *testing.T, w p3Observation, index int) {
	t.Helper()
	stores := []int{}
	for i := range 2 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		err := a.local.boots[i].client.Health(ctx)
		cancel()
		if err == nil {
			stores = append(stores, i)
		}
	}
	p1Equal(t, index, "P3 reachable local stores", stores, w.Capacity.Available)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	err := a.lookup.pool.Ping(ctx)
	cancel()
	p1Equal(t, index, "P3 lookup SQL availability", err == nil, w.Capacity.AuthorityUp)
	workerUp := true
	if a.sqlWorker != nil {
		workerUp = !a.sqlWorker.stopped
		if workerUp {
			r := a.sqlWorker.exchange(t, &p3WorkerCommand{Op: "ping"})
			p1Equal(t, index, "P3 live worker PID", r.PID, a.sqlWorker.cmd.Process.Pid)
		}
	} else {
		workerUp = a.s.pool.Ping(t.Context()) == nil
	}
	p1Equal(t, index, "P3 SQL worker availability", workerUp, w.Capacity.WorkerUp)
}

func (a *p3Replay) refuse(t *testing.T, op protocolAction) {
	t.Helper()
	err := a.step(t, op)
	switch op.Name {
	case "commitClose":
		if !errors.Is(err, ErrPendingFences) {
			t.Fatal("missing store barrier did not block completion", err)
		}
	case "fence":
		if err == nil {
			t.Fatal("unreachable local store acknowledged fence")
		}
	case "observe":
		if err == nil {
			t.Fatal("owner observed result without current lookup authority")
		}
	default:
		t.Fatal("unsupported P3 refusal", op.Name)
	}
}
