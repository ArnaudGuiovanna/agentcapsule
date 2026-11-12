//go:build linux

package agentadapter

import (
	"context"
	"io"
	"net"
	"net/url"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Supervisor keeps the agent's A2A server running for the life of the
// adapter: it starts the configured command in the agent's home, in a process
// group of its own, starts it again with a growing delay (up to 30 s) when it
// exits, and stops the whole group when the adapter stops.
type Supervisor struct {
	cfg     Config
	home    string
	address string // host:port of the server's URL

	mu      sync.Mutex
	running bool          // a server process is alive
	changed chan struct{} // closed, then replaced, at each start or exit
	starts  int
}

func NewSupervisor(cfg Config, home string) (*Supervisor, error) {
	if cfg.Server == nil {
		return nil, ErrConfig
	}
	u, err := url.Parse(cfg.Server.URL)
	if err != nil {
		return nil, ErrConfig
	}
	return &Supervisor{cfg: cfg, home: home, address: u.Host, changed: make(chan struct{})}, nil
}

func (s *Supervisor) set(running bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = running
	if running {
		s.starts++
	}
	close(s.changed)
	s.changed = make(chan struct{})
}

// Starts counts the server's starts.
func (s *Supervisor) Starts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.starts
}

// WaitReady returns once a server process is alive and accepts connections
// on its address.
func (s *Supervisor) WaitReady(ctx context.Context) error {
	for {
		s.mu.Lock()
		running, changed := s.running, s.changed
		s.mu.Unlock()
		if running {
			conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", s.address)
			if err == nil {
				conn.Close()
				return nil
			}
		}
		wait := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			wait.Stop()
			return ctx.Err()
		case <-changed:
		case <-wait.C:
		}
		wait.Stop()
	}
}

// Run supervises the server until ctx ends.
func (s *Supervisor) Run(ctx context.Context) error {
	delay := time.Second
	for {
		started := time.Now()
		cmd := exec.Command(s.cfg.Server.Command[0], s.cfg.Server.Command[1:]...)
		cmd.Dir = s.home
		cmd.Env = s.cfg.Environment(s.home, nil)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, io.Discard, io.Discard
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := cmd.Start(); err == nil {
			s.set(true)
			exited := make(chan struct{})
			go func() {
				_ = cmd.Wait()
				close(exited)
			}()
			select {
			case <-ctx.Done():
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
				select {
				case <-exited:
				case <-time.After(5 * time.Second):
				}
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				<-exited
				s.set(false)
				return ctx.Err()
			case <-exited:
				// Whatever the server left in its group goes with it.
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				s.set(false)
			}
		}
		if time.Since(started) > time.Minute {
			delay = time.Second // it ran for a while: not a crash loop
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		delay = min(2*delay, 30*time.Second)
	}
}
