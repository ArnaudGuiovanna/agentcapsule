//go:build linux && cgo

package restoreauthority

import (
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/authoritylog"
)

// Every statement of the stream, and both key writes, have a kind, and the
// kinds degraded mode lets through are the decided ones (ADR 005, question 2
// and item 17). A new statement without a kind fails here.
func TestEveryStatementAndKeyWriteIsClassified(t *testing.T) {
	if len(statementKinds) != len(statements) {
		t.Fatal("a statement has no kind, or a kind no statement")
	}
	continuing := map[string]bool{}
	for s := range statements {
		kind, ok := statementKinds[s]
		if !ok || !slices.Contains(authoritylog.WriteKinds(), kind) {
			t.Fatal("statement", s, "is not classified")
		}
		continuing[kind] = authoritylog.ContinuesDegraded(kind)
	}
	want := map[string]bool{
		authoritylog.WriteOutcome: true, authoritylog.WriteRerun: true, authoritylog.WriteFence: true,
		authoritylog.WriteRevocationStart: true, authoritylog.WriteRegistration: false,
		authoritylog.WriteReservation: false, authoritylog.WriteLoss: false, authoritylog.WriteSeal: false,
	}
	if fmt.Sprint(continuing) != fmt.Sprint(want) {
		t.Fatal("statements continue in degraded mode:", continuing)
	}
	for kind, op := range map[string]authoritylog.Op{
		authoritylog.WriteKeyCreate:  {Kind: authoritylog.OpKeyCreate},
		authoritylog.WriteKeyDestroy: {Kind: authoritylog.OpKeyRevoke},
		"":                           {Kind: "unknown"},
	} {
		if opKind(op) != kind || authoritylog.ContinuesDegraded(opKind(op)) {
			t.Fatal("key write", op.Kind, opKind(op))
		}
	}
	outcome := authoritylog.Op{Kind: authoritylog.OpStatement, Statement: int(stmtOutcome)}
	seal := authoritylog.Op{Kind: authoritylog.OpStatement, Statement: int(stmtSeal)}
	if !continues(authoritylog.Record{Ops: []authoritylog.Op{outcome}}) || continues(authoritylog.Record{Ops: []authoritylog.Op{outcome, seal}}) ||
		continues(authoritylog.Record{}) || continues(authoritylog.Record{Ops: []authoritylog.Op{{Kind: authoritylog.OpStatement, Statement: 999}}}) {
		t.Fatal("a record continues only if each of its operations does")
	}
	// An operation runs only statements of its kind: a read or an outcome
	// cannot seal, so degraded mode never lets a seal through.
	_, c := primary(t, t.TempDir())
	if _, err := c.Register(t.Context(), "store-a", "volume-a"); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{authoritylog.WriteRead, authoritylog.WriteOutcome, authoritylog.WriteFence} {
		err := c.operate(t.Context(), kind, func(tx *sql.Tx) error {
			_, err := c.exec(t.Context(), tx, stmtSeal, "store-a")
			return err
		})
		if !errors.Is(err, errMisclassified) {
			t.Fatal(kind, "ran a seal", err)
		}
	}
	if _, err := c.Lookup(t.Context(), "store-a"); err != nil {
		t.Fatal("the store was sealed", err)
	}
}
