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
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/oidclifecycle"
)

//go:embed host.py
var controller []byte

//go:embed setup.py
var setup []byte

//go:embed diagnose.py
var diagnostics []byte

//go:embed portable.py
var portable []byte

//go:embed capabilities.py
var capabilities []byte

//go:embed trusted_root.json
var trustedRoot []byte

// Version is set by the release build.
var Version = "development"

var sshTarget = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.@:\[\]-]*$`)

// Run handles install, update, restore, self update and host operation commands.
// --ssh selects a host alias from the operator's own SSH configuration.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, allowPrompt bool) error {
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
	interactive := allowPrompt && host == "" && args[0] == "install" &&
		isTerminal(stdin) && isTerminal(stdout) && isTerminal(stderr)
	if interactive {
		fmt.Fprintln(stderr, "Preparing the local Agent Capsule installation (system services, storage and a demonstration agent).")
		if !slices.Contains(forwarded, "--plan-only") {
			forwarded = append(forwarded, "--follow-install")
		}
	}
	argsJSON, err := json.Marshal(append([]string{Version}, forwarded...))
	if err != nil {
		return err
	}
	encoded := base64.RawURLEncoding.EncodeToString(argsJSON)
	var cmd *exec.Cmd
	if host != "" {
		// OpenSSH joins the remote arguments as a command. Only the fixed
		// selector and the URL-safe base64 envelope enter that command.
		const selectPython = `'p=/var/lib/agentcapsule-userspace/python/bin/python3; [ -x "$p" ] || p=/usr/bin/python3; exec "$p" -I - "$1"'`
		cmd = exec.CommandContext(ctx, "ssh", "-T", "-o", "BatchMode=yes", "--", host,
			"sudo", "-n", "/bin/sh", "-c", selectPython, "--", encoded)
	} else {
		if runtime.GOOS != "linux" {
			return errors.New("use --ssh USER@HOST to select the Linux KVM host")
		}
		cmd, err = localController(ctx, forwarded, encoded, interactive, stdin, stdout, stderr)
		if err != nil || cmd == nil {
			return err
		}
	}
	root := []byte("import base64\nTRUSTED_ROOT=base64.b64decode('" + base64.StdEncoding.EncodeToString(trustedRoot) + "')")
	lifecycle := []byte("OIDC_LIFECYCLE=base64.b64decode('" + base64.StdEncoding.EncodeToString(oidclifecycle.ContainerLifecycle) + "')")
	source := bytes.Join([][]byte{root, lifecycle, setup, diagnostics, capabilities, portable, controller}, []byte("\n"))
	program := "import base64\nHELPER_SOURCE=base64.b64decode('" + base64.StdEncoding.EncodeToString(source) + "')\nexec(compile(HELPER_SOURCE, 'agentcapsule-host', 'exec'))\n"
	cmd.Stdin = bytes.NewBufferString(program)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("host command: %w", err)
	}
	return nil
}
