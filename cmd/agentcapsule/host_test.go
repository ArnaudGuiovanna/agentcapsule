package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

func TestInstallHelpOnWorkstation(t *testing.T) {
	// Workstation help must work without a local Python or SSH executable.
	t.Setenv("PATH", t.TempDir())
	for _, args := range [][]string{{"install", "--help"}, {"install", "-h"}, {"help", "install"}, {"install", "--ssh", "admin@host", "--help"}} {
		var out bytes.Buffer
		if err := run(context.Background(), args, nil, &out, io.Discard); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		for _, flag := range []string{"--ssh", "--to", "--profile", "--plan-only", "--offline", "--trusted-root", "--development-key"} {
			if !strings.Contains(out.String(), flag) {
				t.Errorf("%v: missing install option %s", args, flag)
			}
		}
	}
}
