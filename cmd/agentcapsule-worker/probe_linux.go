package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/llmgateway"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/worker"
)

func providerProbe(path string, mode operatorconfig.Mode, tenant, alias string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	cfg, err := worker.LoadServiceConfig(path)
	if err != nil {
		return fail("configuration_invalid")
	}
	dsn, code := operatorconfig.DatabaseURL(mode)
	if code != "" {
		return fail(code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	database, err := cfg.DatabaseConnections()
	if err != nil {
		return fail("configuration_invalid")
	}
	s, err := controlplane.OpenWith(ctx, dsn, database)
	if err != nil {
		return fail("database_unavailable")
	}
	defer s.Close()
	service, err := cfg.OpenLLM(s, mode == operatorconfig.Production)
	if err != nil || service == nil {
		return fail("llm_gateway_not_configured")
	}
	probe, err := service.Probe(ctx, tenant, alias)
	if err != nil {
		switch {
		case errors.Is(err, controlplane.ErrNotFound):
			return fail("alias_unavailable")
		case errors.Is(err, llmgateway.ErrAddressRefused):
			return fail("worker_egress_denied")
		case errors.Is(err, llmgateway.ErrRejected):
			return fail("provider_transport_refused")
		default:
			return fail("provider_unreachable")
		}
	}
	if err = json.NewEncoder(os.Stdout).Encode(probe); err != nil {
		return fail("probe_output_failed")
	}
	return 0
}
