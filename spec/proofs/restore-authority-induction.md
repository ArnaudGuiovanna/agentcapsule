# Induction for the restore authority

Run `python3 scripts/check-restore-authority-induction.py` from a checkout with
the pinned Quint npm installation under `spec/` and the model-checker tools
installed as described in the [model guide](../README.md). Python 3.11 or newer
provides the standard-library file digests. The command uses the native Z3
library shipped in the checked Apalache jar and creates a fresh evidence
directory under `quint/results`. The `--output` option selects a new or empty
directory. `--quint-dir` can reuse another checkout’s installed dependencies
when both npm manifest and lockfile match.

The theorem is `safety` for every finite execution of `restoreAuthorityTiny`
from the specified initial state. The instance fixes one store, one subject
and one event. Epochs range over unbounded SMT integers and the proof has no
execution-depth limit. The three actions `losePrimary`, `promote` and
`seedStandby` can repeat forever while increasing the epoch, so the concrete
TLC enumeration cannot finish with an exhausted graph. The original TLC job,
its counterexample search, and its configured time budget retain their own
verdict.

The entry point uses the existing model runner to select exactly the checked
Quint module and its dependencies. It verifies the toolchain, compiles the
instance to Quint IR and binds every constant from the actual instance. It
checks that the selected operators are `init`, `step` and `safety`. The
local projector expands every alternative of `step`, checks the two state
assignments and symbolically computes the fields observed by each proof family.
Guards or values outside a projection receive arbitrary symbols. A shared
symbol represents the same expression evaluated on the same input. Pointwise
set membership respects congruence. Instantiation of a universal constraint
over the singleton event domain uses a separately verified support lemma.

For each inductive family Z3 checks the initial state, preservation by every
action, and implications to the source properties or exported lemmas.
An arbitrary event, subject, loss or receipt in a lemma stands for every
value of that type. The proof uses the same parameterized predicate to export
and instantiate a lemma. The certificate requires an acyclic chain of
successful exports. Collective replication is split at the seven conjuncts
actually present in the source and reassembled in source order.

A successful run writes `certificate.json`, each family's SMT-LIB queries and
solver output, and the input, tool and control digests. For the audited input
the certificate covers 21 safety conjuncts, 45 action alternatives and
24 inductive families. Each proof antecedent is checked for satisfiability.
Two branches are disabled in the positive instance. The
configured retirement guard disables `skipRetirement`, and epoch fencing
disables `oldPrimaryResends`. Eleven modified guards exercise the expected
failed induction steps. A separate control inserts a contradiction and requires
the checker to reject the run.

The proof relies on the pinned Quint compiler, the local IR projection and
theory encoding, and the pinned Z3 solver. The output records this distinction
and can be regenerated without any TLC state files. It establishes the
specified model property. Correspondence to Go code is covered separately by
the repository's projection checks and integration tests.
