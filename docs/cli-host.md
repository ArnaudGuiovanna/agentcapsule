# Install and operate a single host

Download the CLI for your OS and architecture from the selected GitHub release.
Verify its digest against the signed `SHA256SUMS` before renaming it to
`agentcapsule`. The release guide gives the exact cosign certificate identity,
issuer and provenance checks. [Release verification](release.md#verify-a-release)

The target is Ubuntu 24.04 amd64 with systemd, cgroup v2, KVM and persistent
local storage. Run the command as root on the target, or pass
`--ssh USER@HOST` from Linux, macOS or Windows. SSH uses the operator's SSH
configuration, known host keys and non-interactive sudo on the target. SSH
host aliases and all profile paths refer to the selected target.

```sh
agentcapsule install --to v0.1.0-rc.1 --profile /root/platform.json --plan-only
agentcapsule install --to v0.1.0-rc.1 --profile /root/platform.json
agentcapsule host operation show host_ID
agentcapsule host operation wait host_ID
agentcapsule host operation resume host_ID
```

The first two commands identify the same operation. The helper records its
input, checkpoints and outcome under `/var/lib/agentcapsule-install`. The
systemd instance continues after SSH disconnects and resumes after reboot.
On a failed phase read `journalctl -u agentcapsule-host@host_ID`, fix the
reported component, and resume. If the CLI itself contains a fix for the
failed phase, add `--refresh-helper` to resume using that verified CLI. All operations emit `agentcapsule.host/v1`
JSON. The operation returns distinct evidence for service startup, the
starter microVM's echo and backups. The probe uses a dedicated organization,
member and encrypted volume. Repeated updates use the same probe agent.

## Profile

An empty JSON object selects local PostgreSQL 16 on port 55432, a stand-alone
authority, private Directory and SLIM services, HTTPS with a generated local
certificate, and the public starter harness carried by the signed guest.
The probe reserves one agent with one vCPU, 256 MiB RAM and 128 MiB disk.
The normal profile provisions Keycloak and a dedicated realm database in the
same PostgreSQL cluster. Its HTTPS issuer defaults to port 9444. The PaaS
API defaults to 9443. Directory listens on loopback port 8443.

```json
{
  "schema": "agentcapsule.install/v1",
  "api_name": "agents.acme.example",
  "host_id": "worker-01",
  "platform_account": "operator-alice",
  "storage_mib": 32768,
  "max_active": 4,
  "tls_certificate": "/root/pki/api-chain.pem",
  "tls_key": "/root/pki/api-key.pem",
  "tls_ca": "/root/pki/ca.pem",
  "oidc_name": "identity.acme.example",
  "oidc_cert": "/root/pki/identity-chain.pem",
  "oidc_key": "/root/pki/identity-key.pem",
  "oidc_ca": "/root/pki/ca.pem",
  "monapp_redirect_uri": "https://monapp.acme.example/login/callback",
  "allow_internal_providers": ["models.acme.example:11434"]
}
```

`database_url_file` selects an existing PostgreSQL role and database for
the PaaS. Supply the DSN in a root-owned 0600 file. The API and worker apply
their usual TLS policy. `registry_rules` sets the worker's existing registry
rules. `interop_certs` selects a prepared Directory/SLIM PKI directory.
`first_uid` and `last_uid` select the dedicated jailer UID range.

The initial platform enrollment proof is in
`/etc/agentcapsule/first-enrollment.token` (0600). Transfer it to the named
operator through a private channel. It expires after 15 minutes and can be
redeemed once. Keep the API certificate or its CA with the CLI context.
Keycloak bootstrap credentials are in `/etc/agentcapsule/oidc.env` (0600).
The realm and discovery URL are described in the identity provider guide.
[OIDC provider](../deploy/oidc/README.md)

See the backup guide for the two encrypted repositories, off-host credentials
and volume shipping. Provide `pgbackrest_config` and `rclone_config` in the
installation profile. A missing destination is reported in the install
result. The single-host authority can be paired to a replica using the
recovery procedure. Verify custody of the receipt key, transit keys and
authority recovery material independently. [Recovery](recovery.md)

## Verify and load offline assets

On the connected station obtain the server bundle, package tar, OCI image
archive, `SHA256SUMS`, `SHA256SUMS.sigstore.json` and the pinned cosign Linux
binary under the name `cosign-linux-amd64`. Copy these files onto the target. The CLI embeds the Sigstore trusted root
whose verified TUF target SHA-256 is
`6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`.
Use `--trusted-root` to select an independently trusted replacement. The CLI
checks the verifier's pinned digest and the workflow identity for the exact
tag, then rechecks each archive before it is activated. The package tar holds
the APT dependency closure. The image archive uses the immutable manifest
references and the runtime verifies the loaded image's config digest.
Preflight checks the OS, cgroup controllers and KVM before large downloads.

```sh
agentcapsule install --offline /srv/rc1 --trusted-root /root/trusted_root.json --to v0.1.0-rc.1
```

Local development builds accept `--development-key /root/dev.pub` with
`--offline` and an explicit `vX.Y.Z-dev.N` tag. Their `SHA256SUMS.dev.sig`
is an Ed25519 signature over `SHA256SUMS`, generated by
`openssl pkeyutl -sign -rawin -inkey dev.key -in SHA256SUMS -out SHA256SUMS.dev.sig`.
The private build trust remains tied to this installation. Official tags use
the GitHub workflow certificate.

## Update and recovery

```sh
agentcapsule update check
agentcapsule update plan --to v0.1.0
agentcapsule update apply --plan host_ID
agentcapsule host operation wait host_ID
agentcapsule self update --to v0.1.0
agentcapsule archive --agent agt_ID --archive-id arc_ID
agentcapsule restore test --agent agt_ID --archive-id arc_ID
agentcapsule restore apply --agent agt_ID --archive-id arc_ID --restore-id rst_ID
```

The PaaS updater first prepares and verifies artifacts and a full backup.
It closes admissions, waits for existing work, stops affected services,
switches the installation symlink, applies the new binary's exact schema
history, and sends an invocation. The worker retains the configured kernel,
VMM and initrd paths of its existing guests. A failed migration leaves a
named operation to resume. Inspect the migrated data format and protocols
before reverting a binary. A restore uses the current authority and durable
restore ID and retains destruction and revocation state. The service
returns the observed result of the restore. The SQL database also holds the
OIDC realm when both are on the managed cluster. [Recovery](recovery.md)

The CLI updater verifies the signed digest for its own OS and architecture
using the operator's cosign installation, then stages the replacement beside
the current executable. Offline CLI updates take the same `--offline`,
`--trusted-root` and `--to` options.
