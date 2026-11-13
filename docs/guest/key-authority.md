# Local volume key authority

`internal/keyauthority` keeps one random LUKS open key per volume, bound to its
agent. The directory must be private, owned by the worker account and kept out
of data backups/restores. For the current host pilot, this account is root. Two
different paths do not guarantee two failure domains or two independent backup
policies.

The administrator explicitly initializes a new directory:

```sh
agentcapsule-admin init-key-authority -root /srv/agentcapsule-authority
```

The command returns a public `authority_id` to keep in the installation
configuration. It returns no key. Repeating it keeps the same identity. The
worker opens the authority with `keyauthority.Open(root, expectedIdentity)`: it
refuses an absent authority, a different one, or one with incorrect permissions,
without creating a replacement. Every operation re-verifies this identity.
The worker service opens this authority through `ServiceConfig.OpenVolumeKeys`
(`internal/worker/service_config_linux.go`) and passes it to provisioning.

A created key keeps its identity after an interruption. A permanent allocation
marker prevents generating another key if the published file disappears.
`WithKey` holds a shared lock during use and clears its buffer before releasing
the lock; the consumer must not keep a copy. `Revoke` waits for these uses,
syncs a permanent tombstone, then removes the managed file and any temporary
names. Restoring an old copy of the key file does not bypass this tombstone.

This file-based authority does not prove forensic erasure of the disk, of key
backups or of a VM's memory. Revocation must be coordinated with the removal of
key holders before any promise of erasure. Its identity detects an accidental
replacement; it does not detect the rollback to an old copy of the directory
carrying the same identity. The authority domain itself must therefore be
protected against such a rollback.

The tests cover process interruptions and a key restore that keeps the
independent tombstones. They are not yet the complete P2 restore path, nor a
validation of an external HSM or KMS.

## The replica on the standby

D-05 ([ADR 005](../adr/005-keys-outside-restored-domain.md)) adds a replica of
both authorities on the standby host. There are two modes.

- **Standalone**, the default. The keys exist on this host only. If the host
  is lost, every key is lost, so every archive can no longer be opened.
  **This mode gives no disaster protection.**
- **Synchronous.** The key authority and the restore authority share one
  stream of records. Each write returns only once the replica holds it on
  disk. The worker enables it with `authority_replica`
  ([worker.md](../worker.md#replica-of-the-authorities)).

In synchronous mode:
- `Ensure` publishes the key file first. Nobody can use the key yet: its
  allocation marker is missing. The stream records the key, wrapped, and
  waits for the replica. Only then does `Ensure` publish the marker.
- `Revoke` publishes the tombstone at once, which only denies. The stream
  records the destruction. The replica deletes its wrapped copy in the same
  transaction. Only then does `Revoke` remove the key file.
- After a crash at any step, no caller can use a key that the replica lacks.
  A retry records the same key again. The replica keeps one key per volume,
  and a destroyed key never comes back.

**The unlock key.** Keys leave the host only wrapped to the operator's unlock
key. `agentcapsule-authority unlock-key` creates it. The primary keeps only
its public part, the recipient, in the restore authority's catalogue. The
replica keeps only wrapped copies. The operator keeps the unlock key off both
hosts and gives it only to promote the replica. The wrapping is HPKE (RFC
9180) from Go's standard library: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256
and ChaCha20-Poly1305. Each copy is bound to its authority, agent and volume.
A commitment, a SHA-256 of the key with its binding, lets the replica tell
two keys apart without holding either.

**Arming.** The snapshot that creates the replica arms both authorities. It
writes a `replicated` file in the key authority's directory. From then on,
`Ensure` and `Revoke` refuse to run without the stream. A process configured
without the replica cannot write behind its back. `WithKey` still works.

The limits stay those above. SQLite's `secure_delete` overwrites a deleted
wrapped copy in the replica's file, and in the primary's log. Neither side
scrubs freed disk blocks, nor does this authority when it removes a key file.
[recovery.md](../recovery.md#the-authorities-replica-d-05) explains how to
install the replica.
