# Installing a host: TLS, modes and preflight

This page says how a production install keeps every hop encrypted and
authenticated, and how to check a host before and after installing it
(OPS-01, RUN-012). The decisions are in
[ADR 010](adr/010-transport-security-and-preflight.md). Installation is not
packaged yet: the services' own pages give their flags and files
([api](api/README.md), [worker](worker.md), [interop](interop.md),
[recovery](recovery.md)).

## Modes

Every process (`agentcapsule-api`, `agentcapsule-worker`,
`agentcapsule-admin`) reads `AGENTCAPSULE_MODE`:

| Value | Mode | What it allows |
|---|---|---|
| unset or `production` | Production | Only the hops of the table below. |
| `development` | Development | Plain HTTP for the API on a loopback address, a PostgreSQL connection without TLS, a local registry rule, a model provider on plain HTTP at an address the operator allows ([below](#model-providers-on-internal-addresses)), the API without the authority service. |

Any other value stops the process (`mode_invalid`). In development, each
process writes `development_mode_clear_text_allowed_never_use_in_production`
on standard error at every start. An API without the authority service
writes `development_mode_without_authority_service_never_use_in_production`
too. Development mode never weakens VM isolation:
the worker runs the same host checks in both modes.

## Every hop of a production install

| Hop | Protection | Configured by |
|---|---|---|
| Clients → API | HTTPS, TLS 1.2 or 1.3, the server's certificate. The API refuses to start without one. Clients authenticate with bearer tokens. | `-tls-cert`, `-tls-key`, `-tls-server-name` |
| API, worker, `agentcapsule-admin` → PostgreSQL | A Unix socket on the same host, or TLS with `sslmode=verify-full`: the server's certificate and name are checked. Anything that may fall back to clear text or skip the check is refused. | `AGENTCAPSULE_DATABASE_URL` |
| Worker ↔ guests | vsock (a Unix socket on the host), with mutual TLS under certificates issued for each boot. Agent and organization come from the channel, never from the payload. | Built in |
| Worker → Directory | Mutual TLS, TLS 1.2 or later, to the HAProxy edge on loopback. The edge admits only certificates of the Directory CA with the common name `agentcapsule-control-plane`. | Worker `directory` section, [deploy/interop](../deploy/interop) |
| Edge → Directory server → schema server | Clear text, inside one host, on an internal Docker network without a route out and without a published port. | [compose.yml](../deploy/interop/compose.yml) |
| Worker ↔ SLIM bridge | Two Unix sockets. Each side checks the other's user on every connection. | Worker `slim` section |
| SLIM bridge → SLIM node | Mutual TLS 1.3, with a client certificate from a separate SLIM CA, on loopback. The bridge refuses a node URL that is not `https`. | [slimbridge config](../runtime/slimbridge/config.example.json), [slim.yaml](../deploy/interop/slim.yaml) |
| Worker → model providers | HTTPS, with the system's CAs, to public addresses only unless the operator allows an internal one. No redirect, no environment proxy. Production refuses a provider URL on plain HTTP before anything is sent (`rejected`). | The organization's providers ([llm.md](api/llm.md)); internal ones in the worker's `llm` section ([below](#model-providers-on-internal-addresses)) |
| Worker → OCI registries | HTTPS. Credentials are sent only in answer to a challenge. Production refuses a `local` rule, which uses plain HTTP. | Worker `registry` section ([registry.md](registry.md)) |
| Worker, API → authority service | Two Unix sockets, on the same host. The service checks the peer's account on every connection: root on the worker's, the API's account (`api_uid`) or root on the API's. Each client pins both authorities' identities. | Worker `authority` section ([worker.md](worker.md)), the API's `-authority-socket` and identities ([docs/api](api/README.md#the-authority-service)) |
| Authority service → its replica | Mutual TLS 1.3 with pinned self-signed certificates bound to this host's authorities. | `authority_replica` in `authority.json` ([recovery.md](recovery.md#install-the-replica)) |
| pgBackRest → S3 | HTTPS, the server verified (pgBackRest's default). The data is encrypted before it leaves the host. | [deploy/backup/pgbackrest.conf](../deploy/backup/pgbackrest.conf) |
| pgBackRest and the archive shipper → standby | SFTP over SSH, the standby's host key checked against a pinned `known_hosts`. The data is encrypted before it leaves the host. | [deploy/backup](../deploy/backup) |
| Archive shipper → S3 | HTTPS, through an rclone crypt remote. | [rclone.conf.example](../deploy/backup/rclone.conf.example) |
| Prometheus → `/metrics` | Plain HTTP, on loopback only, without authentication. It carries technical counters only: no content, token or identifier from a request. | `-metrics-listen`, `metrics_listen` |

Two hops stay in clear text, both inside the host: the Directory's internal
network and the metrics endpoints. ADR 010 says why.

## API certificate

The API needs a certificate chain and its private key, in PEM:
- absolute paths to regular files, not symlinks;
- the certificate writable only by its owner (for example 0644);
- the key owned by the API's account (or root) with mode 0600;
- the certificate valid now and, if it lists extended key usages, issued for
  `serverAuth`.

With `-tls-server-name api.example.net`, the API also refuses a certificate
that does not cover that name. Give the name clients use.

The API serves TLS 1.2 and 1.3 only, with Go's default cipher suites. A plain
HTTP request gets `400` and reaches no route.

**Renewal.** Replace both files (write new files and rename them into place),
then send `SIGHUP` to the API. New connections get the new certificate, and
the API prints `tls_reloaded`. If the new files fail a check, the API keeps
the old certificate and prints `tls_reload_failed_<reason>`. With certbot,
copy the files from `live/` in a deploy hook, since the API does not follow
symlinks, then send `SIGHUP`.

Start failures print one code: `tls_required_in_production`,
`tls_files_invalid`, `tls_key_does_not_match_certificate`,
`tls_certificate_expired_or_not_yet_valid`,
`tls_certificate_does_not_cover_server_name`,
`tls_certificate_not_for_servers`.

## PostgreSQL

On a single host, use the Unix socket: there is no network hop.

```sh
AGENTCAPSULE_DATABASE_URL='host=/run/postgresql dbname=agentcapsule user=agentcapsule'
```

For a server on another host, use TLS that checks the server:

```sh
AGENTCAPSULE_DATABASE_URL='host=db.example.net dbname=agentcapsule user=agentcapsule sslmode=verify-full sslrootcert=/etc/agentcapsule/postgres-ca.pem'
```

On the server, set `ssl = on` with its certificate and key, and use only
`hostssl` lines for these users in `pg_hba.conf`. `sslmode=prefer` (the
default), `allow`, `require` and `verify-ca` are refused in production, as is a
host list with one such host. The check reads the string as the connection
does, including the `PG*` variables. A refused string stops the process with
`database_tls_required_in_production`; one that does not parse, or names an
unreadable `sslrootcert`, with `database_configuration_invalid`.

## Directory and SLIM

The shipped [deploy/interop](../deploy/interop) keeps both services private:
- they publish their ports on `127.0.0.1` only;
- the Directory is reached only through its mutual TLS edge;
- the SLIM node requires a client certificate from its own CA.

[make-certs.sh](../deploy/interop/make-certs.sh) writes lab certificates
valid for 30 days, with keys readable by the containers' users. On a host:
- give each key to its container's user with mode 0400 (HAProxy 99, SLIM
  65532);
- keep the CA keys off the host;
- renew before expiry.

See [interop.md](interop.md#running-on-a-host).

## Model providers on internal addresses

Organizations declare their own providers ([llm.md](api/llm.md)). The worker
calls a provider at a public address only. It checks each address when it
connects, after DNS resolution, so a public name that resolves to an
internal address is refused too. A refused call is `rejected`, and nothing is
sent. This holds in both modes.
- Refused unless you allow them: loopback, private (RFC 1918, RFC 4193),
  carrier-grade NAT (`100.64.0.0/10`) and the other reserved ranges.
- Always refused: unspecified, multicast and link-local addresses,
  `0.0.0.0/8`, and the cloud metadata addresses (`169.254.169.254` and the
  rest of `169.254.0.0/16`, `100.100.100.200`, `168.63.129.16`,
  `fd00:ec2::254`, `fd00:ec2::23`, `fd20:ce::254`).

To let organizations use a model server on your network or on the host, list
it in the worker's `llm` section:

```json
"llm": {
  "receipt_key": "/etc/agentcapsule/receipt.key",
  "allowed_internal_providers": ["models.corp.example:11434", "10.20.0.0/24"]
}
```

Each entry is one of:
- `name:port`: the provider URLs with this host name and port, whatever
  internal address the name resolves to;
- `address:port` (`10.20.0.7:443`, `[fd12::7]:443`): this address and port,
  whatever name the URL uses;
- a CIDR prefix inside one internal range, host bits at zero
  (`10.20.0.0/24`): every address in it, on every port.

There is no default entry. An entry that names a public or always-refused
address, or a prefix that leaves one internal range (`0.0.0.0/0`,
`10.0.0.0/7`), stops the worker with `llm_configuration_invalid`.

The organization registers the server by its name, for example
`https://models.corp.example:11434/v1`. The API refuses an `https` URL that
writes an internal address out (`provider_address_not_allowed`), and the
server's certificate must cover the name and chain to a CA of the system's
store. In production the server needs TLS. In development, plain HTTP to
`localhost`, `127.0.0.1` or `::1` works once allowed, for example
`"127.0.0.1:11434"` for a local Ollama.

Every organization of the installation may use an allowed server
([ADR 010](adr/010-transport-security-and-preflight.md), question 5). The
worker ignores `HTTP_PROXY` and `HTTPS_PROXY` for provider calls, and never
follows a redirect (question 6).

## Preflight

The preflight only reads. It creates no file, writes no setting and loads no
module. Each check prints `ok`, `warn` or `fail`. A check that is not `ok`
prints a `fix:` line under it. The last line is `preflight_passed` or
`preflight_failed`, and the exit code is 1 on a failure.

**Worker host.** Run as root, with the worker's configuration and environment:

```sh
AGENTCAPSULE_DATABASE_URL=... /opt/agentcapsule/agentcapsule-worker -config /etc/agentcapsule/worker.json -preflight
```

| Check | Fails when |
|---|---|
| `kvm` | `/dev/kvm` is missing, is not the KVM device (10:232), cannot be opened read-write, does not answer API 12, or lacks one of the 14 KVM capabilities Firecracker 1.17 requires on x86_64. |
| `kernel` | The kernel is older than 5.14: the worker uses `cgroup.kill`. A kernel other than 6.1 or 6.18 (Firecracker 1.17's validated host kernels) is a warning. |
| `cgroups` | `/sys/fs/cgroup` is not cgroup v2, or its root does not offer and delegate `cpu`, `memory` and `pids`. |
| `namespaces` | The kernel lacks mount, PID or network namespaces (the jailer creates them). |
| `runtime_filesystem` | The runtime root is on tmpfs, NFS, 9p, FUSE or overlayfs, is read-only, or is mounted `nodev` or `noexec` (the jailer creates device nodes and runs Firecracker in each chroot). Another file system than ext4, xfs or btrfs is a warning. |
| `artifact_firecracker`, `artifact_jailer`, `artifact_kernel`, `artifact_initrd` | A file is missing or does not match the SHA-256 the configuration pins. Firecracker or the jailer does not report v1.17.0. The kernel is not an ELF `vmlinux`. Once the worker has started, its copy under `<root>/bin` stands in for a missing source. |
| `clock` | The kernel says the clock is not synchronized. |
| `disk_runtime`, `disk_archives` | The file system is 80% used or more; from 70%, a warning. |
| `authority` | With the `authority` section: the authority service does not answer on its worker socket, holds other authorities than the pinned ones, or gives directories that overlap the runtime root or the archives. A service in degraded mode, or waiting for its standby, is a warning. The directories and the link to the standby are the service's ([recovery.md](recovery.md#install-the-authority-service)). |
| `metrics_listen` | The address is not loopback, or is in use. |
| `directory_certificate`, `directory_ca`, `directory_edge` | The client certificate is unusable, expired, not for `clientAuth`, or not named `agentcapsule-control-plane`; the CA file holds no certificate; the edge refuses the client or presents another CA's or another name's certificate. An edge that does not answer is a warning. |
| `registry` | A rule is `local` (production). |
| `postgresql` | The connection string may use clear text (production), or the server cannot be reached. The check confirms TLS with the server (`pg_stat_ssl`). |

**At every start**, the worker runs `kvm`, `kernel`, `cgroups`, `namespaces`,
`runtime_filesystem` and the four artifacts. If one fails, it prints the
failed checks with their fixes, then `preflight_failed`, and does not start.
That is RUN-012: no Firecracker without them.

**API.** Run as the API's account, with the API's flags:

```sh
AGENTCAPSULE_DATABASE_URL=... agentcapsule-api -receipt-key-file ... -host-id ... \
  -listen 0.0.0.0:8443 -tls-cert /etc/agentcapsule/api.crt -tls-key /etc/agentcapsule/api.key \
  -tls-server-name api.example.net \
  -authority-socket /run/agentcapsule-authority/api.sock -restore-authority-id ... -key-authority-id ... -preflight
```

It checks the mode, the certificate (`api_certificate`), the listen addresses
(`api_listen`, `metrics_listen`: free, so run it before starting the API), the
receipt key file, the authority service (`authority`), the clock and
PostgreSQL. `authority` fails when the flags are missing in production, when
the service does not answer on the socket, when this account may not open it
(not in `agentcapsule-authority-clients`), or when the service holds other
authorities than the pinned ones. A service in degraded mode, or waiting for
its standby, is a warning.

## Operator steps

1. **Host.** A Linux host with KVM, a 6.1 or 6.18 kernel, cgroup v2 and a time
   service (`systemd-timesyncd` or chrony). The runtime root, the archives and
   both authorities each in their own directory on local ext4 or xfs.
2. **Artifacts.** Build Firecracker and the jailer
   (`scripts/build-firecracker.py`), the guest kernel and the guest image, and
   write their SHA-256 in the worker's configuration
   ([config.example.json](../runtime/worker/config.example.json)).
3. **PostgreSQL.** On the same host, with the Unix socket. Otherwise with TLS
   and `sslmode=verify-full`.
4. **Certificates.** The API's server certificate, issued for the name clients
   use. The Directory and SLIM certificates from your own CAs, or from
   `make-certs.sh` for a lab.
5. **Private services.** Install [deploy/interop](../deploy/interop) and its
   unit ([interop.md](interop.md#running-on-a-host)).
6. **Schema and platform credential.** `agentcapsule-admin migrate`, then
   `agentcapsule-admin bootstrap-platform` ([bootstrap.md](bootstrap.md)): the
   API's preflight reads the receipt key it writes.
7. **Authority service.** Initialize both authorities, start
   `agentcapsule-authority serve`, give the worker its `authority` section and
   the API its `-authority-socket` and identities
   ([recovery.md](recovery.md#install-the-authority-service)). The API's
   account joins `agentcapsule-authority-clients`. Both preflights check that
   the service answers.
8. **Preflight.** Run `agentcapsule-worker -preflight` and
   `agentcapsule-api -preflight`, and fix every `fail`.
9. **Start** the authority service, the worker, then the API, without
   `AGENTCAPSULE_MODE`. The migrations of step 6 record the authorities'
   first epoch as reconciled: the API starts. After a failover it refuses
   (`authority_not_reconciled`) until `agentcapsule-admin reconcile` has run
   ([recovery.md](recovery.md#reconcile-the-database)). Run the
   preflights again after each change of host, certificate or configuration.
   Then create the organizations ([bootstrap.md](bootstrap.md#4-create-the-organization-and-its-first-owner)).

`scripts/verify-install.py` runs steps 3, 4 (the API's certificate) and 6 to
8 from an empty directory, without root: the authority service before the
API, which refuses to start without it. Then it creates an organization and
ends with a call by its owner. On a host without the artifacts or without
access to `/dev/kvm`, the worker's preflight reports them as failed and the
worker refuses to start.

## Pinned versions

Everything the install or CI fetches is pinned by digest or SHA-256, except
the items listed after the table.

| What | Pinned by |
|---|---|
| Directory, OASF, HAProxy and SLIM images | Digest, [compose.yml](../deploy/interop/compose.yml), checked against [profile.json](../runtime/interop/profile.json) by `verify-interop.py` |
| Firecracker and jailer | Upstream source SHA-256, patch SHA-256 and `Cargo.lock` ([manifest.json](../runtime/firecracker/manifest.json)); the built binaries by SHA-256 in the worker's configuration |
| Guest kernel | Source SHA-256 and configuration SHA-256 ([kernel.json](../runtime/guest/kernel.json)); the image by SHA-256 in the worker's configuration |
| Guest image and harnesses | SHA-256 in the worker's configuration; harnesses by OCI digest |
| Go modules | `go.sum` (and each module of `runtime/`) |
| SLIM native library | SHA-256 in [profile.json](../runtime/interop/profile.json) |
| pgBackRest 2.58 and rclone 1.60.1 (CI) | SHA-256 in `scripts/fetch-backup-tools.py`, from a fixed Ubuntu snapshot |
| SeaweedFS, OpenSSH (sftp) and Prometheus images (CI) | Digest |
| GitHub Actions | Commit SHA |
| Dagger CLI and gitleaks (CI) | SHA-256 in [ci.yml](../.github/workflows/ci.yml) |
| Python tools | `--require-hashes` requirement files |
| Quint tools | `spec/package-lock.json` integrity hashes |
| Harness base images | Digest in each Dockerfile and in the Dagger module |

Not pinned yet:
- CI installs `build-essential`, `libcryptsetup-dev` and PostgreSQL 16 from the
  runner's Ubuntu archive. Their versions are recorded in each run's
  toolchain log, not pinned.
- `actions/setup-go` pins Go 1.27.3 by version. The archive's SHA-256 is not
  pinned in the repository.
- The Dagger CLI starts its engine image by version tag (v0.21.11), not by
  digest.
- The Rust toolchain that builds Firecracker is pinned by version (1.97.0)
  through rustup, not by SHA-256.
- On a host, PostgreSQL, Docker, pgBackRest and rclone come from the
  distribution. The qualified versions are named in their pages.
- The platform's own binaries are built from source. Signed releases do not
  exist yet.

## What a real host still has to show

The checks are tested on a fake host root, and the KVM probe on this
development machine's `/dev/kvm`. On this machine, `scripts/verify-install.py`
runs the worker's preflight with every check passing when it is given the
artifacts, and shows the worker refusing to start when they are missing. It
runs them in a user namespace where its account is root, not as root. A KVM
host run as root must still show the worker starting with the mandatory
checks passing. `scripts/verify-runtime.py` with a control guest starts the
worker binary in `TestMaintenanceServiceRecoversRenewalCrashesWithoutIncomingWork`,
which covers the first part.
No campaign yet runs the preflight on a production server, with PostgreSQL
over `verify-full` across hosts, or with a public certificate.
