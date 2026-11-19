// Package hostops runs the installation's Linux helper locally or over SSH.
// The transport sends the same program in both cases. User inputs travel in a
// base64-encoded JSON argument, never as shell syntax.
package hostops

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"runtime"
)

//go:embed host.py
var controller []byte

//go:embed setup.py
var setup []byte

//go:embed diagnose.py
var diagnostics []byte

// Version is set by the release build.
var Version = "development"

var sshTarget = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.@:\[\]-]*$`)

// Run handles install, update, restore, self update and host operation commands.
// --ssh selects a host alias from the operator's own SSH configuration.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("host command required")
	}
	if args[0] == "self" {
		return selfUpdate(ctx, args[1:], stdout, stderr)
	}
	var host string
	var forwarded []string
	for i := 0; i < len(args); i++ {
		if args[i] != "--ssh" {
			forwarded = append(forwarded, args[i])
			continue
		}
		if host != "" || i+1 == len(args) || !sshTarget.MatchString(args[i+1]) {
			return errors.New("expected --ssh USER@HOST or SSH alias")
		}
		host = args[i+1]
		i++
	}
	argsJSON, err := json.Marshal(append([]string{Version}, forwarded...))
	if err != nil {
		return err
	}
	encoded := base64.RawURLEncoding.EncodeToString(argsJSON)
	var cmd *exec.Cmd
	if host != "" {
		cmd = exec.CommandContext(ctx, "ssh", "-T", "-o", "BatchMode=yes", "--", host, "sudo", "-n", "python3", "-I", "-", encoded)
	} else {
		if runtime.GOOS != "linux" {
			return errors.New("use --ssh USER@HOST to select the Ubuntu KVM host")
		}
		cmd = exec.CommandContext(ctx, "python3", "-I", "-", encoded)
	}
	source := bytes.Join([][]byte{setup, diagnostics, controller}, []byte("\n"))
	program := "import base64\nHELPER_SOURCE=base64.b64decode('" + base64.StdEncoding.EncodeToString(source) + "')\nexec(compile(HELPER_SOURCE, 'agentcapsule-host', 'exec'))\n"
	cmd.Stdin = bytes.NewBufferString(program)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("host command: %w", err)
	}
	return nil
}
