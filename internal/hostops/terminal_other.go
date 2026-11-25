//go:build !linux

package hostops

import (
	"context"
	"errors"
	"io"
	"os/exec"
)

// Local installation is a Linux-only operation. SSH runs without prompts.
func isTerminal(stream any) bool { return false }

func localController(context.Context, []string, string, bool, io.Reader, io.Writer, io.Writer) (*exec.Cmd, error) {
	return nil, errors.New("local host operations require Linux")
}
