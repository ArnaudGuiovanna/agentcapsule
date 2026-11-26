package main

import (
	"context"
	"io"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/hostops"
)

const installHelp = `Usage: agentcapsule install [options]

Install the signed server bundle on this x86-64 Linux host with systemd and
KVM. This CLI selects its release tag, or the latest stable release for an
unversioned CLI. In a terminal, install asks for sudo if needed and reports
progress until the demonstration agent responds.

  --ssh USER@HOST        Connect from this workstation using SSH and sudo -n
  --to TAG               Select an exact release tag
  --profile FILE         Read the installation profile JSON on the target
  --plan-only            Verify release metadata and return the operation ID
  --json                 Print the operation receipt immediately (local root)
  --non-interactive      Run without prompts or a terminal progress display
  --offline DIR          Read release assets from this directory on the target
  --trusted-root FILE    Use this trusted Sigstore root for offline verification
  --development-key FILE Trust a local public key for an offline -dev.N build
  --allow-older          Install a release older than this CLI's, or than the
                         highest release the host has installed

  agentcapsule install
  agentcapsule install --ssh admin@host --plan-only
  agentcapsule install --ssh admin@host
  agentcapsule host operation wait host_ID --ssh admin@host

Repeat the plan's options without --plan-only to start installation.
`

func runHostCommand(ctx context.Context, args []string, in io.Reader, out, errout io.Writer) (bool, error) {
	forward := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "--json" && arg != "--non-interactive" {
			forward = append(forward, arg)
		}
	}
	if len(forward) == 0 {
		return false, nil
	}
	if slices.Equal(forward, []string{"help", "install"}) ||
		(forward[0] == "install" && (slices.Contains(forward, "--help") || slices.Contains(forward, "-h"))) {
		_, err := io.WriteString(out, installHelp)
		return true, err
	}
	if len(forward) >= 2 && forward[0] == "host" && forward[1] == "pi" && (len(forward) == 2 || slices.Contains(forward, "--help") || slices.Contains(forward, "-h")) {
		_, err := io.WriteString(out, "Usage: agentcapsule host pi enable --corpus-repo OWNER/REPOSITORY [--ssh USER@HOST]\nPrompts for sudo in a local terminal. Writes an import receipt to stdout. See agentcapsule help pi.\n")
		return true, err
	}
	switch forward[0] {
	case "install", "update", "rollback", "self", "host", "restore", "archive":
		allowPrompt := !slices.Contains(args, "--json") && !slices.Contains(args, "--non-interactive")
		return true, hostops.Run(ctx, forward, in, out, errout, allowPrompt)
	}
	return false, nil
}
