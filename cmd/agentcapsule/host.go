package main

import (
	"context"
	"io"
	"slices"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/hostops"
)

const installHelp = `Usage: agentcapsule install [options]

Install the signed server bundle for this CLI's release tag on Ubuntu 24.04
amd64 with systemd and KVM. An unversioned CLI defaults to the latest stable
release online. Run as root on the host or select an SSH target.

  --ssh USER@HOST        Connect from this workstation using SSH and sudo -n
  --to TAG               Select an exact release tag
  --profile FILE         Read the installation profile JSON on the target
  --plan-only            Verify release metadata and return the operation ID
  --offline DIR          Read release assets from this directory on the target
  --trusted-root FILE    Use this trusted Sigstore root for offline verification
  --development-key FILE Trust a local public key for an offline -dev.N build

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
	switch forward[0] {
	case "install", "update", "rollback", "self", "host", "restore", "archive":
		return true, hostops.Run(ctx, forward, in, out, errout)
	}
	return false, nil
}
