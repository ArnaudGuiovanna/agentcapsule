# Install and bootstrap

This page takes an installation from an empty PostgreSQL database to an
organization whose first owner signs in and names administrators. Each step
is an `agentcapsule-admin` command or an API call. Each step can be run again:
a repeat confirms what is done, or is refused; it never makes a second one.
Nothing has a default password. Every step leaves a record: the migrations in
`schema_migrations`, the other steps in an audit trail. The decisions are in
[ADR 001](adr/001-organization-identity.md#tenant-transition-and-operator-bootstrap-d-01).

The host itself (TLS for every hop, the PostgreSQL connection, the
development and production modes, the preflight) is described in
[docs/install.md](install.md). The worker, which runs the agents, is
described in [docs/worker.md](worker.md).

## Before you start

- Build the binaries: `go build -trimpath -o bin/ ./cmd/...`. The build needs
  Go 1.27.3, a C compiler and the headers of libcryptsetup
  (`libcryptsetup-dev`): the worker links it.
- Create a PostgreSQL database and a role that owns it. The admin commands and
  the API read the connection from `AGENTCAPSULE_DATABASE_URL`, in their
  protected environment, never from a flag.
- Create a private directory, owned by the account that runs the API:

  ```sh
  install -d -m 700 /etc/agentcapsule
  ```

- Install the authority service, with both authorities, and start it
  ([recovery.md](recovery.md#install-the-authority-service)). Keep the two
  identities that the init commands print: the API pins them. The API's account
  is the service's `api_uid`, and a member of the group
  `agentcapsule-authority-clients`.

- From the organization's identity provider, or from the client that will
  sign its users' tokens, get:
  - its **issuer**, the `iss` of its tokens;
  - an **audience** for this installation, the `aud` of its tokens;
  - its **Ed25519 public key**, 32 bytes in standard base64, and the key ID
    (`kid`) it puts in each token's header;
  - the **subject** (`sub`) of the person who will own the organization.

  The platform verifies tokens signed with EdDSA (Ed25519) only. It does not
  fetch keys (no OIDC discovery, no JWKS URL): the operator registers them.

## 1. Migrate

```sh
agentcapsule-admin migrate
```

It prints `migration_complete`. A database already at this version is only
checked. A database whose history differs from this binary is refused
(`database_migration_failed`): see
[ADR 001](adr/001-organization-identity.md#decisions-of-this-slice).

The migrations record that this database is reconciled with the authorities'
first epoch: the authorities were never promoted, so nothing set it behind
them. After a failover the API waits for `agentcapsule-admin reconcile`
([recovery.md](recovery.md#reconcile-the-database)); a new installation
needs no such step.

## 2. Create the platform operator's credential

```sh
agentcapsule-admin bootstrap-platform \
  -receipt-key-file /etc/agentcapsule/receipt.key \
  -token-file /etc/agentcapsule/platform.token
```

It prints `platform_bootstrap_complete`. It creates two private files (mode
0600) and never prints their content:
- the **receipt key**: 32 random bytes. The installation is bound to it. Keep
  it, and keep a copy off the host ([recovery.md](recovery.md)); a lost or
  replaced key is refused;
- the **platform token**: `acpp_` and 32 random bytes. It administers
  organizations and harness releases, and reads no organization's content. It
  expires after 30 days (`-token-lifetime`, at most 365 days).

Running the command again with the same files confirms the same credential,
without extending it. With another token file it is refused
(`platform_bootstrap_rejected_conflict`) while a platform credential is
active. The refused command still writes the new token file (mode 0600):
delete it, or use it for the replacement. To replace the credential, revoke it, then run the command
with a new token file:

```sh
agentcapsule-admin list-credentials
agentcapsule-admin revoke-credential -kind platform -id ptok_... -confirm ptok_... \
  -authority-socket /run/agentcapsule-authority/api.sock \
  -restore-authority-id restoreauth_... -key-authority-id keyauth_...
```

A revocation is recorded with the authority service before it commits
([api/README.md](api/README.md#revocations-pending-and-confirmed)): in
production `revoke-credential` refuses to run without these three flags
(`authority_required_in_production`), the API's own. Run it as the API's
account, or as root. Its outcome lists the revocation, `pending` until the
standby holds its record.

## 3. Start the API

```sh
AGENTCAPSULE_DATABASE_URL=... agentcapsule-api \
  -receipt-key-file /etc/agentcapsule/receipt.key -host-id local \
  -listen 0.0.0.0:8443 -tls-cert /etc/agentcapsule/api.crt -tls-key /etc/agentcapsule/api.key \
  -tls-server-name api.example.net \
  -authority-socket /run/agentcapsule-authority/api.sock \
  -restore-authority-id restoreauth_... -key-authority-id keyauth_...
```

`-host-id` names the worker's host: give the `host_id` of the worker's
configuration ([worker.md](worker.md)). Agents are created on that host.

The last three flags reach the authority service with the identities it
must hold ([docs/api](api/README.md#the-authority-service)). In production
the API refuses to start without them, or with another installation's
identities; it waits for a service that does not answer yet. It also refuses
a database not reconciled with the service's epoch
(`authority_not_reconciled`): only after a failover
([recovery.md](recovery.md#reconcile-the-database)).

In production the API serves HTTPS only. Its certificate, its preflight
(`-preflight`) and the development mode are described in
[docs/install.md](install.md), its other flags in [docs/api](api/README.md). The API serves only the organization
model: it refuses the tokens of the historical single-owner accounts
(`acp_`), whatever the database holds.

The calls below send the platform token from a header file, so that the
token never appears in a command line:

```sh
umask 077
printf 'Authorization: Bearer %s\n' "$(cat /etc/agentcapsule/platform.token)" > /etc/agentcapsule/platform.header
```

## 4. Create the organization and its first owner

```sh
curl -fsS -X POST https://api.example.net/v1/organizations \
  -H @/etc/agentcapsule/platform.header \
  -H 'Idempotency-Key: create-acme' -H 'Content-Type: application/json' \
  -d '{"name":"Acme","initial_owner":{"issuer":"https://idp.acme.example","subject":"alice","display_name":"Alice"}}'
```

The answer (201) gives the organization's `id` (`org_...`) and the
`owner_principal_id` of its first owner, with the role `org_owner`. The
owner's identity is recorded, not checked: it is checked when the owner
signs in, against the trust of step 5.

The same call with the same `Idempotency-Key` returns the same answer for 24
hours. Another call for an active organization of the same name, in any case,
is refused (409 `organization_name_taken`). Disabling an organization frees
its name: `POST /v1/organizations/{id}/disable`.

## 5. Register the organization's identity trust

Write the trust file. It holds only public keys; it may be readable by all,
but writable only by its owner:

```json
{
  "version": 1,
  "trusts": [{
    "tenant_id": "org_...",
    "issuer": "https://idp.acme.example",
    "audience": "agentcapsule:acme",
    "allowed_scopes": ["org:read", "member:read", "member:manage", "audit:read"],
    "max_ttl_seconds": 300,
    "keys": [{"kid": "2026-11", "public_key": "<32 bytes, standard base64>"}]
  }]
}
```

`allowed_scopes` bounds the scopes a token may carry: list those of the
routes the organization's users will call ([docs/api](api/README.md)). A
token's lifetime (`exp` minus `iat`) is at most `max_ttl_seconds`. Then:

```sh
agentcapsule-admin configure-delegation -action install \
  -operation-id acme-trust-1 -tenant-id org_... \
  -issuer https://idp.acme.example -audience agentcapsule:acme \
  -trust-file acme-trust.json
```

It prints the trust's state as JSON: `generation` (1) and `minimum_iat`. The
identity provider puts `"trust_generation": 1` in each token, and issues none
before `minimum_iat` (the next second). The API reads the trust from
PostgreSQL: no restart is needed.

Running the command again with the same `-operation-id` returns the same
answer (`"replayed": true`). Another operation ID with the same trust changes
nothing. A different trust for the same issuer and audience is refused
(`delegation_change_rejected_conflict`); so is an issuer and audience already
registered for another organization.

## 6. The first owner signs in and names administrators

The owner's token, signed by the identity provider, has `iss`, `aud`, `sub`
(`alice`), a unique `jti`, `iat`, `exp`, `trust_generation` and `scope`. The
full profile is in [tenant-identity.md](api/tenant-identity.md).

```sh
curl -fsS https://api.example.net/v1/organizations/current -H "Authorization: Bearer $TOKEN"
```

The answer shows the organization and the role `org_owner`. The owner then
names administrators, who sign in the same way:

```sh
curl -fsS -X POST https://api.example.net/v1/members -H "Authorization: Bearer $TOKEN" \
  -H 'Idempotency-Key: make-bob-admin' -H 'Content-Type: application/json' \
  -d '{"issuer":"https://idp.acme.example","subject":"bob","display_name":"Bob","role":"org_admin"}'
```

Registering the same person twice is refused (409). Members, teams, agents and
assignments are described in [docs/api](api/README.md).

Only a token signed by a registered key, for a registered member, is a user.
A user ID written by the caller is refused (401): a bare name as a bearer
token, a header such as `X-User-ID`, an unsigned token, a token signed by
another key, or a token for a subject that is not a member.

For each later organization, repeat steps 4 to 6.

## Before the first agent

An organization runs agents once the host has, in this order:
- the worker, on the authority service the API already uses, with its
  preflight passing
  ([install.md](install.md#operator-steps), [worker.md](worker.md));
- the host's capacity: `agentcapsule-admin configure-host -host-id local
  -storage-mib ...`, with the API's `-host-id`;
- a harness release, imported by the platform ([registry.md](registry.md)) or
  a local image approved with `agentcapsule-admin approve-local-harness`;
- the transit keys: `agentcapsule-admin activate-transit-keys`, then the API's
  `-transit-active-key` and `-transit-key`. The API admits no message without
  them ([docs/api](api/README.md#private-instructions)).

`scripts/verify-install.py` follows this page and
[install.md](install.md) from an empty directory, without root, up to the
worker's preflight and a call by the organization's owner.

## What is audited

| Action | Where to read it |
|---|---|
| Platform credential created or revoked | `agentcapsule-admin list-audit` |
| Organization created or disabled | `list-audit`, and the organization's `GET /v1/audit` |
| Identity trust installed, rotated, revoked; key added or retired; token revoked | `list-audit`, and the organization's `GET /v1/audit` |
| Members, teams, agents, assignments, service accounts | The organization's `GET /v1/audit` |

`list-audit` prints the latest operator actions, newest first, one JSON
object per line (`-limit`, 100 by default). The operator is named by the
local account that ran the command (`local-uid:<uid>`). No entry holds a
token, a key or content. The schema's migrations are recorded in
`schema_migrations`.

## Rotating an organization's keys

An identity provider changes its signing key from time to time. Add the new
key, let both sign during an overlap, then retire the old one:

```sh
agentcapsule-admin configure-delegation -action add-key -operation-id acme-key-2026-12 \
  -tenant-id org_... -issuer https://idp.acme.example -audience agentcapsule:acme \
  -key-id 2026-12 -public-key '<32 bytes, standard base64>' -confirm 2026-12
agentcapsule-admin configure-delegation -action retire-key -operation-id acme-retire-2026-11 \
  -tenant-id org_... -issuer https://idp.acme.example -audience agentcapsule:acme \
  -key-id 2026-11 -overlap 24h -confirm 2026-11 \
  -authority-socket /run/agentcapsule-authority/api.sock \
  -restore-authority-id restoreauth_... -key-authority-id keyauth_...
```

`retire-key`, `rotate`, `revoke-trust` and `revoke-token` revoke access:
like `revoke-credential`, they record it with the authority service before
they commit, and take its three flags in production. The result's
`revocations` says `pending` or `confirmed`.

Every change but `install` repeats its target in `-confirm` (the key ID, the
issuer for `rotate` and `revoke-trust`, the token ID for `revoke-token`) and
takes `-dry-run` ([ADR 014](adr/014-operations-capacity-diagnostics-audit.md)).

- `add-key` and `retire-key` keep the trust's `generation` and `minimum_iat`:
  tokens signed with the other keys keep working.
- During the overlap, tokens signed with the old key are accepted. From its
  end, they are refused, including a request already authenticated. With
  `-overlap 0s` (the default), the key is refused at once. The overlap is at
  most 30 days, and an earlier end is never pushed back.
- A key ID keeps its public key for good, and a retired key never returns.
- The trust always keeps a key without an end: retiring the last one is
  refused. To stop every sign-in of the organization at once, use
  `-action revoke-trust`.

Other changes:

| Need | Command |
|---|---|
| A key leaked: refuse it now | `retire-key -overlap 0s` on that key, after adding its replacement |
| Refuse every token issued so far, change scopes or lifetime | `-action rotate` with a new trust file: the generation goes up, keys absent from the file are retired, and the provider must sign with the new `trust_generation` after the new `minimum_iat` |
| Move the organization to another identity provider or client | `install` a trust with the new issuer or audience; both work side by side; then `revoke-trust` the old one |
| Refuse one token | `-action revoke-token -token-id <jti>` (without `-audience`) |

Each command takes a stable `-operation-id`: after an unknown result, run the
same command again. Its output never contains a token or a private key.
