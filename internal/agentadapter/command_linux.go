//go:build linux

package agentadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
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
		if cfg.Input == "job-json" {
			body, err := json.Marshal(struct {
				Kind    string                        `json:"kind"`
				Text    string                        `json:"text"`
				Content []capsuleprotocol.ContentPart `json:"content,omitempty"`
			}{job.Kind, job.Text, job.Content})
			if err != nil {
				return Output{}
			}
			cmd.Stdin = bytes.NewReader(body)
		}
		out := &capped{max: MaxAnswerBytes + 1}
		cmd.Stdout = out
		var progress *stdoutProgress
		if job.Delta != nil {
			progress = &stdoutProgress{delta: job.Delta}
			cmd.Stdout = io.MultiWriter(out, progress)
		}
		cmd.Stderr = io.Discard
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = 5 * time.Second
		err := cmd.Run()
		if progress != nil {
			progress.flush()
		}
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

// stdoutProgress keeps an incomplete UTF-8 character across pipe reads. Small
// pieces also fit the NDJSON frame limit after escaping control characters.
type stdoutProgress struct {
	delta   func(string)
	pending []byte
}

func (w *stdoutProgress) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		count := min(len(p), 8192)
		w.pending = append(w.pending, p[:count]...)
		p = p[count:]
		end := 0
		for end < len(w.pending) && utf8.FullRune(w.pending[end:]) {
			_, size := utf8.DecodeRune(w.pending[end:])
			end += size
		}
		if end > 0 {
			text := strings.ToValidUTF8(strings.ReplaceAll(string(w.pending[:end]), "\x00", ""), "�")
			if text != "" {
				w.delta(text)
			}
			w.pending = append(w.pending[:0], w.pending[end:]...)
		}
	}
	return n, nil
}
func (w *stdoutProgress) flush() {
	if len(w.pending) > 0 {
		w.delta("�")
		w.pending = nil
	}
}
