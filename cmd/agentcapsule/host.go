package main

import (
	"context"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/hostops"
	"io"
)

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
	switch forward[0] {
	case "install", "update", "self", "host", "restore", "archive":
		return true, hostops.Run(ctx, forward, in, out, errout)
	}
	return false, nil
}
