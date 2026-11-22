# Worker privilege separation: an unprivileged worker and a small root helper

Accepted on November 22, 2026, as the fix of finding A-03 of the v0.1.0
audit (lot ARCH-3). References: [ADR 005](005-keys-outside-restored-domain.md)
and [ADR 006](006-authority-service.md) (fencing, the restore authority),
[ADR 010](010-transport-security-and-preflight.md) (the preflight),
[ADR 012](012-limits-restart-budgets-egress.md) (VM limits),
[ADR 016](016-content-links-capabilities.md) (the platform channel),
[ADR 023](023-corpora.md) (corpus and build drives), the
[worker guide](../worker.md#confinement) and the
[installation guide](../install.md).

## Context

The worker was one root process. It drives Firecracker, which needs root,
and it also terminates the guests' mutual TLS, downloads harness packages and
corpora from registries and forges, calls model providers, reads PostgreSQL
and holds volume keys while they pass to a guest. It links 33 packages of
this repository, libcryptsetup and libpq-compatible clients. A flaw in any of
that network-facing code was a flaw in a root process. SEC-4 confined the
unit with systemd (S-05), but with `CAP_SYS_ADMIN` kept, code that takes over
the worker can undo the mount directives.

This record splits the worker in two processes: the network-facing work runs
as a dedicated account with no capability, and the few operations that need
root run in a small helper that accepts only typed requests about the
worker's own VMs and files.

## Inventory: what needed root (base a36dc65)

Every operation below ran in the root worker. The capability column is the
one SEC-4 derived for the unit (`deploy/systemd/agentcapsule-worker.service`).

| # | Operation | Code | Why it needs privilege |
|---|---|---|---|
| 1 | Runtime root owned by root, 0700 | `internal/runtime/firecracker_linux.go:190,228` | a check, not a need |
| 2 | The VMs' parent cgroup `/sys/fs/cgroup/acp-runtime-<hash>` and its `cgroup.subtree_control` | `firecracker_linux.go:263-268` | root-owned cgroup tree |
| 3 | A volume given to its VM's UID: `chown` and `fsync` | `Register` `firecracker_linux.go:409-414`; `ownVolume` `firecracker_provisioning_linux.go:211-218` | `CAP_CHOWN` |
| 4 | Build drives given to the builder's UID, 0400 or 0600 | `setWorkDrives` `firecracker_drives_linux.go:376-387` | `CAP_CHOWN`, `CAP_FOWNER` |
| 5 | The jail: directory, kernel hard link, initrd copy with the boot's files appended, volume and drive hard links, `config.json` | `prepare` `firecracker_linux.go:942-1016`; `placeBootImages` `firecracker_jail_linux.go:145-190`; `linkShared`, `linkOrCopy` | hard links to files of the VM's UID (`fs.protected_hardlinks`): `CAP_FOWNER`; a jail under root's tree |
| 6 | The run's cgroup and its limits (`memory.max`, `pids.max`, `cpu.max`, `memory.swap.max`) | `prepare` `firecracker_linux.go:1003-1014` | root-owned cgroup files |
| 7 | The jailer, started into the run's cgroup (`clone3` with `CLONE_INTO_CGROUP`) and a new network namespace; it unshares a mount and PID namespace, pivots into the chroot, creates `/dev/kvm`, `/dev/net/tun`, `/dev/urandom`, `/dev/userfaultfd`, chowns them and the chroot, sets limits and drops to the VM's UID | `jailerCommand` `firecracker_limits_linux.go:95-102`; `start` `firecracker_linux.go:845-851` | `CAP_SYS_ADMIN`, `CAP_MKNOD`, `CAP_CHOWN`, `CAP_SETUID`, `CAP_SETGID` |
| 8 | The platform socket `<jail>/vsock_5001`, bound in the VM's jail and given to its UID | `listenInJail`, `ownSocket` `firecracker_jail_linux.go:60-106` | write in a directory of the VM's UID: `CAP_DAC_OVERRIDE`; `CAP_CHOWN`, `CAP_FOWNER` |
| 9 | The guest's control channel: a connection to `<jail>/vsock` | `controlClient` `firecracker_control_linux.go:114-115` | the socket belongs to the VM's UID: `CAP_DAC_OVERRIDE` |
| 10 | Identifying a VMM: its PID file in the jail, `/proc/<pid>/stat`, `status`, `cgroup`, `root`, `exe` | `identify` `firecracker_linux.go:495-548` | a jail of the VM's UID; `root` and `exe` of another UID: `CAP_SYS_PTRACE` |
| 11 | The VMM's lock on its volume: `/proc/<pid>/fd` and `fdinfo` | `volumeLock` `firecracker_linux.go:1183-1214` | `CAP_SYS_PTRACE` |
| 12 | A run's cleanup: `cgroup.kill`, waiting for `cgroup.events`, removing the cgroup and the jail | `cleanup` `firecracker_linux.go:449-493` | root-owned cgroup files; files of the VM's UID and device nodes in the jail |
| 13 | A failed boot: has the VMM exited (`cgroup.events`) | `bootFailure` `firecracker_limits_linux.go:156-176` | a 0700 root cgroup directory |
| 14 | A registered volume opened: the boot's busy probe, a seal, an archive copy, a restore, a resize, a removal, a provisioning retry | `start` `firecracker_linux.go:802-813`; `SealAgent` `firecracker_seal_linux.go:69-85`; `WithStoppedVolume`, `installVolume` `firecracker_archive_linux.go:88-191`; `volumestore.Store` `Prepare`, `Grow`, `Remove` | the volume is 0600 and the VM's UID's: `CAP_DAC_OVERRIDE` |
| 15 | A build's output read once the builder stopped | `finishImage` `internal/worker/corpus_package_linux.go:45` | the builder's UID's file: `CAP_DAC_OVERRIDE` |
| 16 | Whether a corpus image or a build drive can be hard linked into the jails | `CheckLinkable` `firecracker_drives_linux.go:154-190` | a probe link in the jails' directory |
| 17 | Confined programs on untrusted input as the inspection UID: `debugfs` on harness and corpus images, the LUKS2 header check of a restore test (S-21) | `internal/sandbox`; callers in `internal/ociregistry`, `harnesspkg`, `corpuspkg`, `ext4image`, `volumestore/luks_check_linux.go`, `worker/restore_check_linux.go` | namespaces, `setresuid`: `CAP_SYS_ADMIN`, `CAP_SETUID`, `CAP_SETGID`, `CAP_SETPCAP`, `CAP_KILL` |
| 18 | The worker's SLIM socket given to the bridge's UID | `slimlink.Listen` `internal/slimlink/peer_linux.go:72` | `CAP_CHOWN` |
| 19 | An archive fetched from the stores: the shipper runs rclone as `agentcapsule-ship` | `ScriptFetcher` `internal/worker/host_restore_linux.go:45-60` | `setuid` |
| 20 | The authority service's worker socket | `authorityservice.Server.admits` `server_linux.go:252`; `cmd/agentcapsule-authority/main.go:525` | it admits root only |
| 21 | PostgreSQL as `agentcapsule_worker` | `PEER_MAP` `internal/hostops/setup.py:225` | the peer map names root |
| 22 | The start's preflight opens `/dev/kvm` read-write | `preflight.KVM` `internal/preflight/preflight_linux.go:200-230` | root or the `kvm` group |
| 23 | Files only root reads: `worker.json` (0600), the keys it names (receipt, transit, Directory client, registry and forge credentials) | `setup.py` `save`; `operatorconfig.ReadPrivate` | owner root |
| 24 | The operator modes (`-archive-agent`, `-restore-agent`, `-restore-host`, `-test-restore`, `-collect-garbage`) run as root | `setup.py` `worker_exclusive`, `run_storage`, `verify_volume_copies` | they wrote root-owned files in the worker's trees |

Nothing else in the worker needs privilege: PostgreSQL, the authority
service's protocol, the registries and forges, the model gateway and its
providers, the Directory, SLIM, the guests' mutual TLS, delivery, the
schedules, archives' contents, telemetry and the admission queues are plain
files and sockets.

## Decision

### 1. Two processes

- **`agentcapsule-worker`** runs as the account `agentcapsule-worker`, with no
  capability (`CapabilityBoundingSet=` empty), the profile the API and the
  authority service already have, plus what it truly needs (§6). It keeps
  everything the inventory does not list: PostgreSQL, the registries and
  forges, the model gateway, the guests' mutual TLS and platform channel,
  delivery, the authority service's client, the registry of the host
  (`registry.json`), the admission queues, the per-agent locks, the
  credentials of each boot, the VMM logs, archives and caches. It owns the
  runtime root, the archive root, the caches and the restore-test scratch.
- **`agentcapsule-worker-helper`** runs as root with the capabilities the
  jailer and the sandbox need. It does items 2 to 17 and 19 of the inventory,
  and nothing else: it opens no network socket, reads no database, holds no
  key and parses no guest data beyond a PID file.

Items 18 and 20 to 24 are solved without the helper: the SLIM socket's
directory is set-group-ID to the bridge's group, so the socket gets that
group without a `chown` (mode 0660); the authority service admits the worker
account named by `worker_uid` in `authority.json`; the peer map names
`agentcapsule-worker`; the helper checks KVM at its start; the files the
worker reads belong to it; and the operator modes run as the worker account
(`runuser -u agentcapsule-worker`).

### 2. A binary of its own, two internal packages

The helper is `cmd/agentcapsule-worker-helper`, a static Go binary built
without cgo. It imports two packages of this repository:
`internal/workerhelper` (the protocol, the checks and the operations) and
`internal/sandbox` (the confinement it already had), and `golang.org/x/sys`.
A subcommand of the worker binary was refused: that binary links 33
internal packages, libcryptsetup through cgo, PostgreSQL, HTTP and gRPC
clients, and their `init` functions run in every process that starts it,
including libcryptsetup's configuration. A test
(`cmd/agentcapsule-worker-helper`, `TestHelperImportsTwoInternalPackages`)
fails if the helper's import graph grows past these two packages.

The worker binary is still the program of the LUKS2 header check (S-21):
the helper runs it confined, as the inspection UID, under its registered
name (`agentcapsule-luks-check`), from the root-owned path the helper's unit
names. It never runs it unconfined.

### 3. The protocol

A Unix socket of type `SOCK_SEQPACKET` at
`/run/agentcapsule-worker-helper/worker.sock` (0660, root and the group
`agentcapsule-worker`). One message per request and one per answer: a JSON
object of at most 64 KiB, with at most four file descriptors (`SCM_RIGHTS`).
A connection carries one request at a time; the client keeps a few idle
connections.

- **Authentication.** The helper reads `SO_PEERCRED` at accept and admits
  the worker account's UID only. The worker checks that the helper's peer is
  root. A refused connection is closed at once.
- **Versioning.** Every request carries `"v": 1`. An unknown version or
  operation is refused with `unsupported`. `hello` returns the version, the
  jails' directory and the VMs' cgroup, which the worker compares with its
  own derivation.
- **Answers.** `{"ok": true, ...}` or `{"ok": false, "code": ..., "error":
  ...}`. The codes are closed: `invalid` (malformed), `refused` (a check
  failed), `unknown_agent`, `absent` (no identified VMM), `busy`, `failed`
  (the operation failed), `unavailable` (the sandbox cannot run), `limit`,
  `syscall` (the sandbox's), `unsupported`. The client maps them to errors
  of the runtime; a broken connection is `ErrHelperUnavailable`, never an
  absence.

The operations of version 1, and what each validates:

| Operation | Request | Validated against | Does |
|---|---|---|---|
| `hello` | — | — | returns the version and the layout |
| `give_volume` | volume name, agent, UID; the volume's descriptor | the descriptor is the regular file of that name in `<root>/volumes` (same inode, no link), 0600, one link, owned by the worker or already by that UID; the UID in the provisioning range, not the worker's nor the inspection UID, held by no other agent of the registry; the inode no other agent's | `fchown`, `fsync` |
| `open_volume` | volume path, write or not | the path is a registered agent's volume in `<root>/volumes`, reached without a symbolic link; the file is that agent's UID's, with the registry's device and inode | returns a descriptor (`O_NOFOLLOW`, `O_NONBLOCK`) |
| `give_drives` | agent, paths and modes | the agent is registered, without a run; each path under the corpus staging or the runtime root, a regular file of whole 4 KiB blocks with one link, owned by the worker or the agent; modes 0400 or 0600 only | `fchown`, `fchmod` |
| `reclaim_drives` | agent | the build drives the registry records for the agent, which has no run | gives them back to the worker (0600) |
| `check_linkable` | paths | each under the runtime root or a configured cache or staging, a regular file | a probe hard link into the jails, removed at once |
| `spawn` | agent, run, `config.json`, whether to listen; the boot appendix and the VMM log as descriptors | the run is the registry's, `STARTING`, of an unfenced agent with a UID of the range; every file the jail gets comes from the registry (§4) | builds the jail and the cgroup, binds the platform socket, starts the jailer; returns the listener |
| `observe` | agent, run | the run is the registry's | identifies the VMM (PID file, `/proc`), its volume lock |
| `populated` | agent, run | the run is the registry's | reads `cgroup.events` |
| `cleanup` | agent, run | the run is the registry's | kills the cgroup, waits up to 10 s, removes it and the jail |
| `dial` | agent, run | the run is the registry's; `vsock` is a socket of the VM's UID | returns a connected descriptor |
| `listen` | agent, run | the run is the registry's and `RUNNING`, not fence-only | binds `vsock_5001` for the VM's UID; returns the listener |
| `sandbox` | program or self name, arguments, image path, input; the image's descriptor | the program is the configured `debugfs` or the worker's own executable under a valid self name; the image path and the descriptor are the same file | runs it confined as the inspection UID |
| `fetch_archive` | store, archive ID, archive root | the store is `standby` or `s3`, the ID `arc_` and 32 hex digits, the root a 0700 directory of the worker reached without a link | runs the shipper's `fetch`, which writes as the worker (§7) |

No request names a UID to switch to, a binary to execute as root, a cgroup
path, a jail path or a file outside the configured roots: the helper derives
them.

### 4. What the helper trusts, and what it checks

The helper reads the worker's configuration `/etc/agentcapsule/worker.json`,
root-owned and not writable by others, for the runtime root, the pinned
Firecracker and jailer, the provisioning UID range, the inspection UID, the
caches and the archive root. The worker cannot change that file. It reads
the worker's registry `<root>/registry.json`, owned by the worker, reached
without a symbolic link and at most 16 MiB, for which agent owns which UID,
volume, run and drives. The worker can change the registry; the registry
says *which* of the worker's VMs and files a request concerns, never *what*
the helper may do as root. Whatever the registry says, the helper holds
these invariants:

- it executes as root only its own pinned copies of the jailer and of
  Firecracker, in `/var/lib/agentcapsule/vmm/bin` (root, 0700), checked
  against the configuration's SHA-256 at its start;
- the jails live in `/var/lib/agentcapsule/vmm/jails`, root's, out of the
  worker's tree: the worker cannot swap a directory under the jailer;
- a UID it gives a file to, or the jailer drops to, lies in the provisioning
  range and is neither the worker's nor the inspection UID;
- every path is resolved with `openat2(RESOLVE_NO_SYMLINKS)` below a
  configured root, and every file is checked through its own descriptor
  (owner, mode, links, device and inode) before it changes;
- it changes the owner of a file only from the worker to a VM's UID and
  back, never from root nor from another VM's UID;
- it reads `/proc` and the jail of a run only to answer `observe`, and
  answers facts (PID, start time, lock), never contents;
- it kills only through the `cgroup.kill` of a run's cgroup under its parent.

A worker taken over can thus start, stop and observe its own VMs, give its
own files to the VMs' UIDs and read their volumes: what it could already do
as the platform's worker. It cannot run code as root, write or chown a file
outside its trees, reach the authorities' directories, nor kill another
process.

### 5. The jails move

New boots get their jail under `/var/lib/agentcapsule/vmm/jails` (the
jailer's `--chroot-base-dir`), and the registry's `socket` field records it.
A run that a v0.1.0 worker started keeps its jail under
`<root>/jails` until it ends: the helper observes, dials, listens and cleans
it up there too, after checking that `<root>/jails`, `firecracker` and the
run's directory are root's and reached without a link, which a worker cannot
fake. The runtime root and the jails must be on one mount, as the volumes and
images are hard linked into the jails: the helper's unit makes
`/var/lib/agentcapsule` one writable mount (`ReadWritePaths=`). The VMs'
parent cgroup keeps its name, derived from the runtime root.

### 6. The worker's unit

`User=agentcapsule-worker`, no capability, `PrivateDevices`,
`ProtectControlGroups`, `ProtectProc=invisible`, `RestrictNamespaces`, a
system-call allow-list (`@system-service`), and the SEC-4 directives that
already applied. The worker spawns nothing that must outlive it, so its unit
keeps systemd's default `KillMode` and drops `Delegate`. It needs
`AF_NETLINK` (glibc's resolver) and `AF_ALG` (libcryptsetup formats a new
volume's key slot with the kernel's crypto API; formatting a regular file
needs no device). It keeps `ReadWritePaths` for its runtime root, archive
root and SLIM socket directory.

The helper's unit keeps the worker's SEC-4 profile: the capabilities the
jailer, the jail and the sandbox need (`CAP_SYS_ADMIN`, `CAP_MKNOD`,
`CAP_CHOWN`, `CAP_FOWNER`, `CAP_DAC_OVERRIDE`, `CAP_SETUID`, `CAP_SETGID`,
`CAP_SETPCAP`, `CAP_KILL`, `CAP_SYS_PTRACE`), `KillMode=process` and
`Delegate=yes`, so that a restart of the helper never stops a VM, and the
same deny-list of system calls. It loses `AF_INET` and `AF_INET6`: it
opens no network socket.

### 7. The archive fetch

The shipper's `fetch` runs as root from the helper, with `--owner
agentcapsule-worker`: it creates and writes the archive in the worker's
archive root as that account (`seteuid`), and returns to root only to start
rclone as `agentcapsule-ship`. A root the worker swapped for a link reaches
what the worker could write anyway.

### 8. Adoption, restarts and failures

- **The worker restarts.** Nothing changes from before: the registry, the
  per-boot credentials and the platform leases are the worker's files. Its
  census asks the helper to `observe` each run and `listen` again on each
  running VM's platform socket.
- **The helper restarts.** It holds no state across requests besides
  caches. The VMMs run in their run cgroups, outside the helper's unit, and
  survive it (`KillMode=process`); they are its children until it exits,
  then init's, as they were the worker's. A request under way fails with
  `ErrHelperUnavailable`; the worker retries as for any other transient
  error.
- **The helper is down.** Boots, stops and copies fail and are retried. A
  census never takes an unanswered `observe` for a dead VMM: the run stays,
  with its slot, and no fence or restore decision is taken on it.
- **A crash during a spawn.** The worker recorded `STARTING` first, as
  before. If the helper dies, the worker's `fail` retires the run through
  `cleanup` once the helper answers; until then the run holds its slot.
  If the worker dies, its next census retires the `STARTING` run, and the
  helper's `cleanup` kills whatever started. A descriptor the helper sent
  goes with the process that holds it.
- **Fencing and restores** (ADR 005, ADR 006). The worker still records a
  seal before it drains, and a removal after the key is revoked; the helper
  only performs the cgroup kill and opens the volume for the worker's
  `flock`. The order of the steps and their durable records are unchanged.

### 9. The upgrade of an existing host

An update from v0.1.0, or from a build of this branch before the split:

1. `systemd-sysusers` creates `agentcapsule-worker`, a member of
   `agentcapsule-authority-clients`; the SLIM directory gets the
   set-group-ID bit and the bridge's group.
2. The services are stopped as before. The update gives the worker its
   trees: every entry of the runtime root, the archive root and the
   restore-test scratch owned by root goes to `agentcapsule-worker`, except
   `<root>/jails`; the VMs' volumes and drives keep their UIDs.
3. `worker.json` becomes 0640 `root:agentcapsule-worker` and gains
   `"helper": {"socket": ...}`; the keys it names become the worker's.
   `authority.json` gains `worker_uid`; `pg_ident.conf` maps
   `agentcapsule-worker` to `agentcapsule_worker` instead of root.
4. The helper starts before the worker, pins its jailer and Firecracker,
   and the worker adopts the running VMs, whose jails stay where they are.

A root worker without a `helper` section still runs everything in process,
as before: for labs and the KVM test suites. A worker with a `helper`
section refuses to run as root.

### 10. The threat model

- **Before.** Any code execution in the worker (a TLS, HTTP, JSON or
  registry parsing flaw, a malicious model answer reaching a bug, a
  compromised dependency) was root, with `CAP_SYS_ADMIN`: the host, every
  authority's directory, PostgreSQL's data, the other services' keys.
- **After.** The same flaw gives the worker account: the platform's data the
  worker already handles (PostgreSQL as `agentcapsule_worker`, the volume
  keys that pass through it, the guests), and the helper's operations. It
  gives no root, no capability, no access to the authorities' directories,
  the other services' keys or other accounts' files.
- **The helper** is the new root surface: 14 operations, about 1,500 lines
  of Go, no network, no database, no cgo. A flaw in its checks matters as a
  flaw in the worker did before; the checks are unit-tested without root.
- **Unchanged.** A guest still meets Firecracker's seccomp filters, the
  jailer's chroot and its own UID; a VMM still cannot reach the helper (the
  socket admits only the worker's UID). Tenant isolation between agents does
  not rest on the worker being honest; it never did against a compromised
  worker, which holds the keys in flight.

## Consequences

- The worker's unit loses every capability; the helper's keeps SEC-4's.
- Each privileged step costs a local round trip and, for a descriptor, one
  `SCM_RIGHTS` transfer: about 50 µs. A boot polls `observe` every 20 ms.
- `docs/worker.md`, `docs/install.md`, the units and their test, the
  installer and `verify-install.py` describe and check the two processes.
- ADR 006 (the worker socket admits `worker_uid`), ADR 010 (the preflight
  is split) and ADR 012 (where the jails and cgroups are made) have a
  paragraph in their "Changes after the v0.1.0 audit".

## Tests

- `internal/workerhelper`: the protocol (versions, sizes, descriptors,
  closed codes), the peer check, and the refusals: a path outside the roots
  or through a link, an unknown agent, a run that is not the registry's,
  a UID outside the range or another agent's, a file of another owner, a
  program not configured; against a fake set of operations, without root.
- `internal/runtime`: the host driver against a fake helper: what a boot, a
  stop, a seal, a copy and an adoption ask, and that an unanswered helper is
  never an absence.
- Root (`root_integration`): the real operations on a scratch tree (chown,
  descriptors, cgroups when present, jail removal through links).
- KVM (`kvm_integration`): a boot, an adoption across a restart of the
  helper and of the worker, through the helper.

The KVM and root runs are listed in the audit log for the owner.
