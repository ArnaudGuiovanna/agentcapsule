# OPS-01 — Transport security and preflight

Date: November 16, 2026. **Status: built; six defaults pending the product
owner** (see [Questions](#questions-for-the-product-owner)). Amended on
November 16, 2026: the addresses the worker may call a model provider at
(§4, questions 5 and 6), then the addresses of registries, which now take
the same classes (§4). References:
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
| Worker → model providers | HTTPS, or plain HTTP to `localhost`, `127.0.0.1` or `::1`. | A provider key could cross clear text. An organization administrator could point the worker at any loopback port of the host and, over HTTPS, at any address: the host, the operator's network, a cloud metadata service (found after this record; §4). |
| Worker → registries | HTTPS, or plain HTTP for a `local` rule, which may carry Basic credentials. | Credentials and packages in clear on the operator's network. The address check took `0.1.2.3`, NAT64 forms of private addresses and `168.63.129.16` for public addresses, and a `local` rule opened every address, cloud metadata included (found after this record; §4). |
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
PostgreSQL, a `local` registry rule and a model provider on plain HTTP (at
an address the operator allows, §4), and every process says so on standard
error at each start. It never relaxes the host checks: VM isolation is never
simulated.

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

**Provider addresses** (amended on November 16, 2026). HTTPS alone let an
organization administrator register a provider at an internal address: the
worker then sent its requests, with the provider key, to a service of the
host or of the operator's network. The gateway now applies the registry
client's approach:
- It connects only to public addresses. It checks each address when it
  connects, after DNS resolution, so a public name that resolves to an
  internal address is refused like the address. This holds in both modes.
- Refused unless the operator allows them: loopback, private (RFC 1918,
  RFC 4193), shared (carrier-grade NAT, RFC 6598) and the other reserved
  ranges. IPv4-mapped and NAT64 (`64:ff9b::/96`) addresses count as the IPv4
  address they carry.
- Always refused, even inside an allowed range: unspecified, multicast and
  link-local addresses (`169.254.0.0/16` and `fe80::/10`, where most clouds
  serve instance metadata), `0.0.0.0/8`, and the metadata addresses outside
  these ranges: `100.100.100.200` (Alibaba), `168.63.129.16` (Azure),
  `fd00:ec2::254` and `fd00:ec2::23` (AWS), `fd20:ce::254` (Google).
- The operator, not an organization, allows internal providers:
  `allowed_internal_providers` in the worker's `llm` section, as `host:port`
  or CIDR prefixes ([install.md](../install.md#model-providers-on-internal-addresses)).
  There is no default entry, so question 2's default still holds.
- No redirect is followed. A 3xx answer is a refusal (`rejected`): the key
  never reaches another address. Environment proxies are ignored, as for
  registries: the check would see the proxy, not the provider.
- A refused address is `rejected` for the call: nothing was sent, the
  reservation is released and the provider's breaker stays closed.
- The API refuses an `https` URL that writes an internal address out (an IP
  address, `localhost`, or a numeric form such as `127.1`), with the code
  `provider_address_not_allowed`. A model server on the operator's network is
  registered by its name, which its certificate covers. The check at
  connection is the real guard: the API does not know the worker's allowlist.

**Registry addresses** (amended on November 16, 2026). The registry
client had its own address check, with the gaps the gateway's check closes.
Both now use the same classes, in `internal/addrpolicy`:
- A rule connects to public addresses. A `local` rule (development only)
  also connects to internal ones. No rule connects to the always-refused
  addresses above, metadata included.
- The client checks each address when it connects, after DNS resolution:
  the registry, its token service and its blob hosts alike.
- A redirect is followed when it leads to the rule's host or one of its
  `blob_hosts`, a registry's CDN, as before, at most three times. Its
  connection takes the same check. Credentials and tokens never follow a
  redirect to another host.
- A refused address fails the import with the code `policy`. Environment
  proxies are ignored.

Tests run mock providers on loopback. They reach them through a constructor
that takes test options and panics outside a test binary (`testing.Testing`),
so no configuration can reach those options.

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
- The registry client's address check on the shared classes
  (`internal/addrpolicy`, `internal/ociregistry`). Tests, through a test
  resolver and network: `0.1.2.3`, `64:ff9b::a00:1` and `168.63.129.16`
  refused for a public rule; a public name resolving to an internal address
  refused through the import path, nothing dialed; a redirect to a blob host
  that resolves to an internal or metadata address refused, a redirect to a
  public one followed without the registry's token; a `local` rule opening
  internal addresses but no metadata address, directly or by redirect. Each
  failed before the change.
- The gateway's address policy and the operator's allowlist
  (`internal/llmgateway/egress.go`, `ServiceLLM` in `internal/worker`), and
  the API's refusal of an internal address at registration. Tests: each
  class of address refused before anything is sent, a public name resolving
  to `127.0.0.1` through a test resolver, the allowlist by name, address and
  prefix, metadata addresses refused inside an allowed prefix, five redirect
  statuses never followed, the worker's configuration, and the registration
  refusal and its API code.
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
   another organization). **Amended:** with TLS in front of it, the operator
   may now allow such a server in the worker's configuration (§4); plain
   HTTP stays refused in production.
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
5. **A model server the operator allows.** The operator runs a model server
   at `models.corp.example:11434` on their network and allows it in the
   worker's configuration. Options: (a) every organization of the
   installation may register it as a provider; (b) the operator also names
   the organizations that may. **Default: (a). Recommendation: (a) for the
   MVP, (b) when a server is dedicated to one customer.** Each organization
   sends its own key; what (a) shares is the server's capacity.
6. **A host that reaches the internet through a proxy.** The operator's
   servers reach the internet only through a corporate proxy
   (`HTTPS_PROXY`). Options: (a) the worker ignores the proxy, for model
   providers as for registries: providers are unreachable from such a host;
   (b) a proxy setting in the worker's configuration, and the proxy, not the
   worker, decides which addresses are reachable. **Default and
   recommendation: (a) until a customer needs (b).** Through a proxy, the
   worker's address check sees only the proxy.
