//go:build linux

package main

import (
	"context"
	"encoding/json"
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
	dsn, code := databaseURL()
	if code != "" {
		return fail(code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := controlplane.OpenWith(ctx, dsn, controlplane.AdminConnections)
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

// transitKeyUsage prints, for each activated transit key, the live content it
// still seals (docs/api/README.md, "Rotating the transit keys"). It reads no
// key file: a key with nothing live can leave the configuration.
func transitKeyUsage(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("transit-key-usage", flag.ContinueOnError)
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 {
		return fail("configuration_required")
	}
	dsn, code := databaseURL()
	if code != "" {
		return fail(code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := controlplane.OpenWith(ctx, dsn, controlplane.AdminConnections)
	if err != nil {
		return fail("database_initialization_failed")
	}
	defer s.Close()
	keys, err := s.TransitKeyUsage(ctx)
	if err != nil {
		return fail("database_schema_unavailable")
	}
	out, err := json.Marshal(struct {
		Keys []controlplane.TransitKeyUse `json:"keys"`
	}{keys})
	if err != nil {
		return fail("output_failed")
	}
	fmt.Fprintln(os.Stdout, string(out))
	return 0
}
