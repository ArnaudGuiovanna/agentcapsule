//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
)

// takeOverHost records that a host takes over the agents of a lost one
// (REC-03, ADR 020). It is final: the lost host's worker gets no work again,
// and no agent is reserved there. Run it once the lost host is fenced. It
// moves no agent: agentcapsule-worker -restore-host does, one restore each.
func takeOverHost(args []string) int {
	fail := func(code string) int { fmt.Fprintln(os.Stderr, code); return 1 }
	f := flag.NewFlagSet("take-over-host", flag.ContinueOnError)
	lost := f.String("lost-host", "", "the lost host's ID, as its worker configuration names it")
	host := f.String("host", "", "the ID of the worker host that takes its agents over")
	if err := f.Parse(args); err != nil {
		return 1
	}
	if f.NArg() != 0 || *lost == "" || *host == "" {
		return fail("configuration_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, code := openOperatorStore(ctx, fail)
	if s == nil {
		return code
	}
	defer s.Close()
	t, err := s.TakeOverHost(ctx, *lost, *host)
	if errors.Is(err, controlplane.ErrHostLost) {
		return fail("take_over_host_rejected_host_lost")
	}
	if err != nil {
		if reason, definite := definiteRefusal(err); definite {
			return fail("take_over_host_rejected_" + reason)
		}
		return fail("take_over_host_unconfirmed_retry_same_command")
	}
	agents, err := s.LostHostAgents(ctx, *lost)
	if err != nil {
		return fail("take_over_host_recorded_agents_unavailable")
	}
	waiting := 0
	for _, a := range agents {
		if a.HostID == *lost {
			waiting++
		}
	}
	if err = json.NewEncoder(os.Stdout).Encode(struct {
		LostHost    string    `json:"lost_host"`
		Host        string    `json:"host"`
		TakenOverAt time.Time `json:"taken_over_at"`
		Agents      int       `json:"agents_to_restore"`
	}{t.LostHostID, t.HostID, t.TakenOverAt, waiting}); err != nil {
		return 1
	}
	return 0
}
