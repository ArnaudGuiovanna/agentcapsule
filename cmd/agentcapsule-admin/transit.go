//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"os"
	"time"
)

func activateTransitKeys(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("activate-transit-keys", flag.ContinueOnError)
	active := f.String("active-key", "", "new active transit key ID")
	var files operatorconfig.KeyFiles
	f.Var(&files, "key", "repeatable key ID=/absolute/private/key-file")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *active == "" || len(files) == 0 {
		return fail("configuration_required")
	}
	keys, err := files.Read()
	if err != nil {
		return fail("transit_key_file_invalid")
	}
	defer operatorconfig.ClearKeys(keys)
	dsn := os.Getenv("AGENTCAPSULE_DATABASE_URL")
	if dsn == "" {
		return fail("database_configuration_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := controlplane.Open(ctx, dsn)
	if err != nil {
		return fail("database_initialization_failed")
	}
	defer s.Close()
	t, err := controlplane.NewTransit(s, *active, keys, 7*24*time.Hour)
	if err != nil {
		return fail("transit_configuration_invalid")
	}
	if err = t.ActivateKeys(ctx); err != nil {
		return fail("transit_activation_rejected")
	}
	fmt.Fprintln(os.Stdout, "transit_keys_activated")
	return 0
}
