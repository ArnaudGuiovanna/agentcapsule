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
