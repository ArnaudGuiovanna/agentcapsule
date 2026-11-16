# OPS-01 — Transport security and preflight

Date: November 16, 2026. **Status: built; four defaults pending the product
owner** (see [Questions](#questions-for-the-product-owner)). References:
[docs/product.md](../product.md) §2 (MVP outcome, KVM required), §4 (API
conventions, RUN-012), §6 (secure by default), OPS-01 of the
[roadmap](../../ROADMAP.md). The operator's side is in
[docs/install.md](../install.md).

## Context

The MVP uses the agents "over HTTPS", and the API is "versioned `/v1` JSON
over HTTPS". RUN-012 asks for a mandatory preflight: no Firecracker mode
without `/dev/kvm` and a compatible kernel. OPS-01 listed as remaining: TLS
everywhere, a private Directory and SLIM, pinned versions, and a preflight on
a target host.

An inventory of every hop of a production install, before this change:

| Hop | Before | Gap |
|---|---|---|
| Clients → API | HTTPS with `-tls-cert` and `-tls-key`, or plain HTTP on a loopback address. The certificate was loaded by `ServeTLS` without checks, and never again. | Plain HTTP allowed in any install. No check of key, expiry or name. A renewal needed a restart. |
| API, worker, admin → PostgreSQL | Whatever `AGENTCAPSULE_DATABASE_URL` said. pgx's default is `sslmode=prefer`: TLS without verification, falling back to clear text. | Clear text or an unverified server possible, without warning. |
| Worker ↔ guests | vsock, mutual TLS per boot. | None. |
| Worker → Directory | Mutual TLS to an HAProxy edge on loopback that admits one common name. | None. |
| Edge → Directory server → schema server | Clear text on an internal Docker network without a route out. | Accepted (below). |
| Worker ↔ SLIM bridge | Unix sockets with peer user checks. | None. |
| Bridge → SLIM node | Mutual TLS 1.3 on loopback, its own CA; the bridge refuses a node that is not `https`. | None. |
| Worker → model providers | HTTPS, or plain HTTP to `localhost`, `127.0.0.1` or `::1`. | A provider key could cross clear text. An organization administrator could point the worker at any loopback port of the host. |
| Worker → registries | HTTPS, or plain HTTP for a `local` rule, which may carry Basic credentials. | Credentials and packages in clear on the operator's network. |
| Worker → authority replica | Mutual TLS 1.3, pinned certificates. | None. |
| Backups | pgBackRest and rclone: HTTPS to S3 with verification, SFTP with a pinned host key, data encrypted before it leaves. | None. |
| Prometheus → `/metrics` | Plain HTTP on loopback, unauthenticated. | Accepted (below). |

There was no preflight. `NewFirecrackerHost` checked the runtime root and the
artifacts' digests, but nothing checked `/dev/kvm`, the kernel or cgroups: a
wrong host failed at the first boot. In CI, gitleaks was checked against the
checksums file of its own release, which pins nothing.

## Decision

### 1. Two modes, production by default

`AGENTCAPSULE_MODE` is unset or `production`, or `development`. Any other
value stops the process. Development allows clear text on loopback and to
PostgreSQL, a `local` registry rule and a model provider on plain HTTP, and
every process says so on standard error at each start. It never relaxes the
host checks: VM isolation is never simulated.

An environment variable, not a flag: the three binaries read the database URL
from the environment already, and `agentcapsule-admin` has a flag set per
command.

### 2. The API serves HTTPS only in production

Without `-tls-cert` and `-tls-key` the API refuses to start, even on
loopback. The files are checked at start: absolute paths to regular files, the
certificate writable only by its owner, the key private (0600), the key
matching, the certificate valid now and issued for `serverAuth` when it lists
usages. With `-tls-server-name`, the certificate must cover that name. TLS 1.2
and 1.3 only, Go's default cipher suites. `SIGHUP` reloads both files for new
connections; files that fail the checks leave the old certificate in service.

### 3. PostgreSQL over a Unix socket or verified TLS

In production the API, the worker and `agentcapsule-admin` accept the
connection string only when every host it can reach, fallbacks included, is a
Unix socket or uses TLS with the server's certificate and name verified
(`sslmode=verify-full`, or `sslrootcert=system`). The check parses the string
with pgx, so `PG*` variables count, and never quotes it.

### 4. Providers and registries over HTTPS

In production the gateway refuses a model provider whose URL is not `https`,
before anything is sent (`rejected`). The worker refuses to start with a
`local` registry rule. The API still accepts the registration of a
`http://localhost` provider: the refusal happens where the hop would be.

### 5. Two clear-text hops stay, inside the host

- **The Directory's internal network.** The Directory server has no
  authentication of its own without SPIRE ([interop.md](../interop.md)). It
  and the schema server sit on a Docker network without a route out and
  without a published port; only the edge joins it. Reaching it takes root or
  the Docker socket on the host, which already reach everything.
- **Metrics.** `/metrics` binds loopback only and serves counters without
  content, tokens or request identifiers. A Prometheus on the host scrapes it.

### 6. The preflight

`internal/preflight` checks a host without changing it. The worker runs the
**mandatory** checks at every start and refuses to start when one fails,
printing each failure and its fix (RUN-012):
- `/dev/kvm` is the KVM device, opens read-write, answers API 12 and has the 14
  capabilities Firecracker 1.17 requires on x86_64;
- the kernel is 5.14 or later, since the worker kills an attempt with
  `cgroup.kill`; a kernel other than Firecracker's validated 6.1 and 6.18 is a
  warning;
- cgroup v2, with `cpu`, `memory` and `pids` offered and delegated by the root;
- mount, PID and network namespaces;
- the runtime root on a local, persistent file system, read-write, without
  `nodev` or `noexec`, because the jailer creates device nodes and runs
  Firecracker in each chroot;
- each pinned artifact's SHA-256, Firecracker's and the jailer's version
  (v1.17.0), and an ELF kernel.

`agentcapsule-worker -preflight` adds the clock, disk use (70% warning, 80%
failure, the alert levels), the authorities' directories (present, private,
apart from the data and each other), the metrics port, the Directory's client
certificate and a mutual TLS probe of its edge, the replica's certificates and
address, the registry rules and PostgreSQL (TLS confirmed by `pg_stat_ssl`).
`agentcapsule-api -preflight` checks the API's certificate, ports, receipt
key, the clock and PostgreSQL.

Disk use and the clock are not checked at start: a disk at 81% must not stop
running agents. A service that does not answer (the Directory edge, the
replica) is a warning; a refusal is a failure.

### 7. Pinned versions

gitleaks is now pinned by SHA-256 in CI. [docs/install.md](../install.md#pinned-versions)
lists what is pinned and what is not: CI's Ubuntu packages, the Go archive of
`setup-go`, the Dagger engine image, the Rust toolchain, the host's own
packages, and the platform's binaries, which are not signed yet.

## What was built and checked

- `internal/operatorconfig`: modes, the database rule, server and client
  certificate checks, the reloadable server certificate.
- `internal/preflight` and `ServiceConfig.Preflight` in `internal/worker`.
- The API, the worker and `agentcapsule-admin` apply the mode.
- The gateway's HTTPS rule.
- Tests: every check on a fake host root, and the KVM probe on a real
  `/dev/kvm` when the user may open it; TLS 1.1 and clear text refused; a
  reload served, a bad reload kept out; each production refusal of the three
  binaries; the API process serving HTTPS in production, refusing clear text
  and serving a renewed certificate after `SIGHUP` (PostgreSQL campaign);
  `scripts/verify-failover.py` now starts both APIs in production over HTTPS.

## What remains

- A KVM run: the worker binary with the mandatory checks
  (`verify-runtime.py --control-guest` starts it in
  `TestMaintenanceServiceRecoversRenewalCrashesWithoutIncomingWork`).
- A preflight on a production server, with PostgreSQL over `verify-full`
  across hosts and a public certificate.
- A metric and an alert for the API certificate's expiry.
- systemd units for the API and the worker (planned with ADR 006).
- The items not pinned yet (section 7).

## Questions for the product owner

Each default below is in the code; the product owner can change it.

1. **A reverse proxy on the same host.** An operator puts nginx in front of
   the API for TLS and wants nginx to talk plain HTTP to the API on
   `127.0.0.1`. Options: (a) refuse: nginx must talk HTTPS to the API, or the
   operator lets the API terminate TLS itself; (b) allow plain HTTP on
   loopback in production behind an explicit flag. **Default and
   recommendation: (a).** The API terminates TLS on its own, and a local
   process that takes the port while the API is down would receive the
   clients' tokens.
2. **A model server on the same host.** An organization uses Ollama at
   `http://127.0.0.1:11434`. Options: (a) refuse in production: put TLS in
   front of it; (b) allow plain HTTP to loopback. **Default and
   recommendation: (a).** With (b), any organization administrator can make
   the worker send requests, with the provider key, to any plain HTTP service
   on the host's loopback (the metrics endpoints, a local model server of
   another organization).
3. **A private registry on the operator's network.** A registry at
   `10.0.0.5:5000` needs a `local` rule, which uses plain HTTP and is refused
   in production. Options: (a) refuse: use a registry with HTTPS and a public
   name; (b) add a rule kind for a private address with HTTPS and a private
   CA. **Default: (a). Recommendation: build (b) when a customer needs it.**
4. **A host kernel Firecracker does not validate.** A server runs Ubuntu
   24.04's kernel 6.8. Options: (a) refuse to start; (b) start with a
   warning in the preflight. **Default and recommendation: (b).** The
   kernel has what the worker needs, and 6.1 and 6.18 are not what most
   distributions ship.
