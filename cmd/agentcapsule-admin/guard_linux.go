//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// guard is what every destructive command takes (API-02, ADR 014): -confirm,
// which must repeat the command's target, and -dry-run, which checks
// everything and changes nothing. A command that runs is audited with its
// outcome; a dry run is not.
type guard struct {
	confirm *string
	dryRun  *bool
}

func newGuard(f *flag.FlagSet, target string) guard {
	return guard{confirm: f.String("confirm", "", "repeat "+target+" to confirm; not needed with -dry-run"),
		dryRun: f.Bool("dry-run", false, "check and print what the command would do, change nothing")}
}

// allows reports whether the command may run on target: a dry run always
// may; otherwise -confirm must name the same target.
func (g guard) allows(target string) bool {
	return *g.dryRun || target != "" && *g.confirm == target
}

func (g guard) command() controlplane.OperatorCommand {
	return controlplane.OperatorCommand{Actor: fmt.Sprintf("local-uid:%d", os.Geteuid()), DryRun: *g.dryRun}
}

// report prints the outcome as one JSON object on standard output.
func report(out controlplane.OperatorOutcome) int {
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "outcome_output_failed")
		return 1
	}
	return 0
}
