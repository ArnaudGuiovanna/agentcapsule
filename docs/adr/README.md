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
| [003-restore-rpo.md](003-restore-rpo.md) | D-03 | RPO, confirmation and restore. **Option B chosen** on November 8, 2026: an announced loss within the window. The P2 model is revised for a declared loss and implemented; the product owner confirmed its defaults on November 16, 2026. |
| [004-recovery-objectives.md](004-recovery-objectives.md) | REC-01 | Failure domains and recovery objectives: database RPO 15 min, volume RPO 24 h, RTO 1 h on a standby host, backups to S3 and over SSH. |
| [005-keys-outside-restored-domain.md](005-keys-outside-restored-domain.md) | D-05 | Keys, secrets and revocations outside the restored domain. **Option (a) chosen** on November 13, 2026: a synchronous replica of the authorities on the standby. Finding 1 decided on November 15: in degraded mode, a revocation is reported pending until the standby holds it, except a bearer token's. |
| [006-authority-service.md](006-authority-service.md) | D-05 | The authority service: one process per host owns both authorities, serves the worker and the API on local sockets, and holds the link to the standby. **Accepted** on November 16, 2026; wave 1 (the service and its protocol, used by tests only) is built. |
| [007-delivery-closure-and-priority.md](007-delivery-closure-and-priority.md) | D-04 | Delivery closure and priority. **Decided** by the product owner on November 16, 2026: a reply whose delivery dies leaves the request replied, readable by the sender's agent until the end of its retention, and the operator is told; no priority in the MVP, priority moves to P1. **Built** on November 16, 2026, with the death at its deadline of a delivery whose agent never boots. **Amended** on November 16, 2026 (§7): a request's closure fences its two parties only; review fixes; request content closed before delivery kept 7 days from its closure (default pending the product owner). |
| [012-limits-restart-budgets-egress.md](012-limits-restart-budgets-egress.md) | CAP-03 | Disk ceilings per VM, restart budgets and FAILED, egress only through the platform. **Built** on November 16, 2026; defaults pending the product owner; KVM proof pending. |
| [013-release-supply-chain.md](013-release-supply-chain.md) | VAL-03 | The release supply chain: tools pinned by digest, SPDX SBOMs by syft, govulncheck reachability and grype severity gates with an expiring allowlist, builds reproducible and checked on every pull request, cosign keyless and SLSA provenance from a tag-only workflow. **Proposed**; five questions for the product owner, defaults applied. |

D-04 is decided in ADR 007; its remaining work is listed under EVT-02 of the roadmap. D-05 is
decided; its implementation continues under ADR 005 and ADR 006. A new
record takes the next free `NNN` in this directory and names its `D-xx`
label if it has one; several records may share one.
