# Guest runtime (in development)

The target runtime opens the encrypted volume **inside the microVM**. The host
keeps using a regular file and the already-verified Firecracker volume lock; it
never mounts the guest filesystem. Opening the volume, its one-time authorized
initialization and its verification on wake must be performed by `capsule-init`
before it starts the harness.

The previous reference kernel had no `CONFIG_MD`. The `kernel.json` manifest
([runtime/guest/kernel.json](../../runtime/guest/kernel.json)) and the script
below rebuild the same reference version with device-mapper and dm-crypt built
in (kernel config: [microvm-linux-6.1.config](../../runtime/guest/microvm-linux-6.1.config)).
The Linux archive is verified by SHA-256 against the value published by
kernel.org. Building does not change the host machine's kernel.

```sh
python3 scripts/build-guest-kernel.py \
  --tools <tools-dir>/guest-build \
  --output <output-dir>/guest-kernel --jobs 4
```

The private tools are Ubuntu packages extracted without a system install. The
build uses GCC, make, bc, bison, flex, m4 and libelf (headers **and** shared
library). `--tools` gives the paths of the extracted tools; the base compilers
come from the environment. Their names and digests are kept with the build
result. `artifacts.json` is produced only after a successful build and a check
of the required options. It is not proof of boot or of storage encryption, and
it does not certify production security maintenance of the kernel.

The prepared volume mechanism is LUKS2/dm-crypt. `luksFormat` creates a new
header and a new volume key; it must never be used as an automatic repair on an
existing volume. Provisioning recovery must identify a reserved, interrupted
volume without reformatting a published one. References:
[cryptsetup documentation](https://kernel.googlesource.com/pub/scm/utils/cryptsetup/cryptsetup/+/refs/heads/master/man/cryptsetup-luksFormat.8.adoc),
[dm-crypt documentation](https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html).

Physical creation, key delivery at boot and harness supervision are
implemented; the KVM campaigns that exercise them are run by
[scripts/verify-product-guest.py](../../scripts/verify-product-guest.py). The
`internal/verification/controlguest` program remains a lab guest and does not
replace these components.

The key delivery protocol is in `internal/capsuleprotocol/volume.go`.
`POST /v1/volume` carries the 32 key bytes in a bounded binary body, after TLS
authentication of the boot. The volume identity, its UUID and the
initialization authorization are metadata; the key appears in no header, no
response and no initrd. The server refuses any positive health or barrier
before the volume and the harness are available. An identical replay recovers
the result without repeating the open; a partial failure requires removing this
boot before a new attempt.

`FirecrackerOptions.PrepareGuest` calls this preparation before health and then
the placement confirmation. The worker validates the current authorization,
obtains the key from the key authority bound to the installation and uses this
callback (`internal/worker/volume_boot_linux.go`). The current tests of this
protocol use real TLS on loopback and a controlled callback, not dm-crypt or
KVM.

## Separate supervisor and harness

`cmd/capsule-init` and `internal/guestinit` perform the guest preparation:
checking the LUKS UUID, opening dm-crypt with the secret on stdin, creating
ext4 only if explicitly authorized and no signature exists, checking
UUID/ext4, mounting, and writing a private volume marker. An ordinary wake
creates neither a filesystem nor a missing marker. `e2fsck` may fix the errors
its automatic mode covers; codes requiring intervention or a reboot are
refused before mounting.

The mount code refuses to run outside the guest's root PID 1. At boot,
`capsule-init` also sets the loopback interface up. The VM has no other
interface, so this opens no route out: it only lets an adapted agent reach the
model endpoint of [capsule-adapter](../adapter.md) on 127.0.0.1. The supervisor
starts the harness under UID/GID 1000 in a dedicated cgroup. The harness
receives its non-secret configuration on FD 3 and its Unix listener on FD 4.
`SO_PEERCRED` authorizes only the supervisor to use this local server; the mTLS
credentials and the LUKS key stay in `capsule-init`. When the harness exits,
its descendants are removed and the guest stops, except during a requested
quiesce. `POST /v1/lifecycle/quiesce` closes admission, waits for calls already
admitted, then asks the harness to terminate. A successful exit with no
remaining descendant precedes `syncfs`, the normal unmounts and the closing of
dm-crypt. The supervisor then stays alive to acknowledge this sequence on the
mTLS channel of the current boot. The receipt is replayable; a failure is final
for that boot. A timeout, a killed process or a sync/unmount error never
produces a clean acknowledgment.

`cmd/capsule-echo` is the first manually packaged harness. It keeps the effect,
the deduplication and the result in its own SQLite transaction. A test runs
this binary under an unprivileged UID, restarts it, then kills it: the replay
does not repeat the effect and the barriers persist. This validates the
processes and SQLite on the test host, not the guest encrypted mount.
The `/v1/invoke` channel receives an owner instruction with a stable mandate.
The harness returns ordinary instructions as a private result. For an
`/ask <agent-id> <text>` instruction, it records a durable send under the
received mandate, then calls the platform after the SQLite commit. An incoming
request only prepares an echo reply; an incoming reply remains data and
provides no mandate. Key, content and deadline are kept across retries. The
private return can be read through the request API and through the separate
message the companion drops in its owner's inbox. An additional test links the
API, PostgreSQL, mTLS and this real process, with loss of the first result and
then a replay. This does not by itself validate execution in an encrypted VM.

**Harness from the registry.** When the host attaches a harness drive (an agent
pinned to an imported release, see [../registry.md](../registry.md)), the boot
archive carries `/etc/capsule/harness.json` with the entrypoint. `capsule-init`
then mounts `/dev/vdb` read-only (`nosuid`, `nodev`) on `/harness`, checks the
base mount points, binds `/dev`, `/run` and `/tmp`, mounts `/proc`, and starts
the entrypoint chrooted in `/harness` with the same user, cgroup, descriptors and
paths as the built-in harness. The decrypted data directory is bound at
`/harness/var/lib/agent` only while the harness process lives, so the encrypted
volume can still be closed during quiesce. Without that file, the harness built
into the platform image runs as before.

## Image and KVM run

```sh
python3 scripts/build-product-guest.py \
  --go <go-binary> \
  --cryptsetup <tools-dir>/guest-build/usr/sbin/cryptsetup \
  --output <output-dir>/product-guest-build
```

The output directory must be new. The recipe freezes sources, native binaries,
dependencies and digests; the initrd contains no volume key.

To run the KVM check, as root (needed for the jailer and cgroups):

```sh
sudo python3 scripts/verify-product-guest.py --help
```

[verify-product-guest.py](../../scripts/verify-product-guest.py) creates only
its own temporary volumes, keys, cgroups and VMs. It checks two independent
encrypted guests, replay and barriers after a forced stop, the refusal of a
wrong key and the refusal of a VMM without a lock **before** key delivery. It
also checks that the key is absent from the boot's initrd. It does not touch
user databases, mounts no guest volume on the host, and returns logs to the
calling account. Credentials, private volumes and keys are not copied into the
evidence. The optional worker checks create a temporary PostgreSQL cluster
under a non-root account (`--pg-user`) and verify reservation, real
provisioning, activation and persistence after wake. No placement or
availability row is pre-filled for this path; the cluster is stopped and
deleted after the run. This run does not replace the complete API/PostgreSQL
path or the model-to-Go trace replays.

## Outgoing harness calls

When the boot has a platform channel, its public FD 3 record contains
`platform_socket`, a Unix path managed by the supervisor. The Go harness can
build `capsuleprotocol.NewLocalPlatformClient(boot.Identity,
boot.PlatformSocket)`; it receives no TLS key and no volume secret. The
supervisor authenticates the client by its real UID, decodes only platform
calls and forwards them over mTLS/vsock with the identity of this boot. The
host server re-verifies this identity in every business transaction, including
replays.

The socket is removed with the process. Its directory belongs to the
supervisor and cannot be modified by the harness. A boot restricted to barriers
does not expose this channel. Old identities, wrong UIDs and a provenance
forged in HTTP headers are refused.

The outgoing call must follow the commit of a durable local intent and reuse
the same business key after a lost response. It must never be made from the
SQLite callback of an event: that callback must finish before the platform
passes under host admission. The bridge test uses a real child process, a
persistent SQLite intent and a test business server that loses a first receipt;
it is not yet the product's inter-agent path. Private inter-agent contents and
the outgoing-call queue of the reference harness remain to be connected.
