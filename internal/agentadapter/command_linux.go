//go:build linux

package agentadapter

import (
	"context"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// CommandRunner runs the configured command once per job, in the agent's home
// (its private data directory), in a process group of its own. A run ends with
// the program: whatever it left in its group is stopped, and a run that
// outlives the configured timeout is killed and counts as failed.
func CommandRunner(cfg Config, home string) Runner {
	return func(ctx context.Context, job Job) Output {
		ctx, cancel := context.WithTimeout(ctx, cfg.Timeout())
		defer cancel()
		args := append([]string(nil), cfg.Command[1:]...)
		if cfg.Input == "argument" {
			args = append(args, job.Text)
		}
		cmd := exec.CommandContext(ctx, cfg.Command[0], args...)
		cmd.Dir = home
		extra := map[string]string{"AGENTCAPSULE_JOB_ID": job.ID}
		if len(job.Files) > 0 {
			extra["AGENTCAPSULE_FILES_DIR"] = filepath.Dir(job.Files[0])
		}
		cmd.Env = cfg.Environment(home, extra)
		if cfg.Input == "stdin" {
			cmd.Stdin = strings.NewReader(job.Text)
		}
		out := &capped{max: MaxAnswerBytes + 1}
		cmd.Stdout = out
		cmd.Stderr = io.Discard
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = 5 * time.Second
		err := cmd.Run()
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		if err != nil {
			return Output{}
		}
		return Output{Completed: true, Text: out.String()}
	}
}

// capped keeps the beginning of an output and discards the rest, so that a
// verbose program never blocks on a full pipe.
type capped struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.max - len(c.b); room > 0 {
		c.b = append(c.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.b)
}
