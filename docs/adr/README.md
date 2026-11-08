# Architecture decision records

Two numbering spaces coexist in this repository. They are independent and must
not be confused. When citing a decision, always include its source.

| Source | Identifiers | Status |
|---|---|---|
| [`docs/product.md`](../product.md) §ADR | `ADR-001` to `ADR-012` | Current product decisions (product spec v1.0). |
| This directory | `docs/adr/NNN-*.md`, plus the `D-xx` decision labels of the [roadmap](../../ROADMAP.md) §6 | Decisions taken while implementing the plan. |

## Records in this directory

| File | Decision label | Subject |
|---|---|---|
| [001-organization-identity.md](001-organization-identity.md) | D-01 | Organization identity foundations and tenant transition |
| [002-assignment-revocation.md](002-assignment-revocation.md) | D-02 | Assignments, revocation and private results |
| [003-restore-rpo.md](003-restore-rpo.md) | D-03 | RPO, confirmation and restore. **Option B chosen**; the P2 model is still to be updated. |

Decisions D-04 (closure and capacity) and
D-05 (keys, secrets and recovery domains) are still open; see the roadmap. A
new record takes the next free `NNN` in this directory and names its
`D-xx` label if it has one.
