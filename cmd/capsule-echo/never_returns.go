//go:build linux

package main

import (
	"context"
	"errors"
	"strings"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// neverReturnText, in an invocation's text, makes a never-returns harness
// hold that invocation.
const neverReturnText = "never return"

// forever is a statement that never ends: it counts the rows of an endless
// recursion, one row at a time, in constant memory.
const forever = `WITH RECURSIVE forever(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM forever) SELECT count(*) FROM forever`

var errHeld = errors.New("held an invocation until the harness stopped (test behaviour)")

// neverReturns is the never-returns behaviour (ADR 012, question 7). An
// invocation whose text holds neverReturnText runs, inside its store's write
// transaction, a statement that never ends. It runs under the harness's
// lifetime, not the request's deadline: the store cannot roll the
// transaction back while the statement runs, so the store stays held, every
// later delivery finds it busy, and no fence can commit, until the harness
// is told to stop. Other invocations and other events are handled as usual,
// so that the same release answers once its VM was stopped and booted
// again.
func neverReturns(agent string, handle mutation, lifetime context.Context) mutation {
	return func(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) ([]byte, error) {
		i, err := capsuleprotocol.DecodeInvocation(e, agent)
		if err != nil || !asksToHold(i) {
			return handle(ctx, e, tx)
		}
		_, err = tx.ExecContext(lifetime, forever)
		return nil, errors.Join(errHeld, err)
	}
}

func asksToHold(i capsuleprotocol.Invocation) bool {
	for _, part := range i.Content {
		if part.Type == "text" && strings.Contains(part.Text, neverReturnText) {
			return true
		}
	}
	return false
}
