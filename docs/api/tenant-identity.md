# Delegated identity and current organization

This part connects Ed25519 verification to already registered organizations,
principals and memberships. It adds a single metadata route:
`GET /v1/organizations/current`. It creates no principal from a JWT, issues no
token, attaches no legacy agent and opens no access to content. Initial
administration is described in [organizations.md](organizations.md).

## Registering a trust

The operator registers each organization's trust in PostgreSQL with a local
command; the API reads it there, in the transaction that consumes each token.
Registering or changing a trust needs no restart, and the API has no trust
file. The steps of a new installation are in [bootstrap.md](../bootstrap.md).

The command reads the trust from a local JSON file. The file is regular,
owned by the current user or root and not writable by group/others. It may be
publicly readable: it contains only **public** keys and policies. Private
signing keys stay with the trusted client.

```json
{
  "version": 1,
  "trusts": [{
    "tenant_id": "org_<existing_id>",
    "issuer": "https://client.example",
    "audience": "agentcapsule:organisation",
    "allowed_scopes": ["org:read"],
    "max_ttl_seconds": 300,
    "keys": [{"kid": "primary", "public_key": "<32_public_bytes_in_standard_base64_with_padding>"}]
  }]
}
```

Placeholders must be replaced before loading. The reader refuses unknown or
duplicate fields, malformed or wrongly sized keys, duplicate `kid`s, extra JSON,
unknown versions, ambiguous configurations and files over 1 MiB. It follows no
symlink and downloads no key/JWKS. `max_token_bytes`, if present, is ignored:
the API accepts tokens of at most 8 KiB.

```bash
agentcapsule-admin configure-delegation \
  -action install -operation-id install-client-v1 \
  -tenant-id 'org_<existing_id>' \
  -issuer https://client.example -audience agentcapsule:organisation \
  -trust-file /path/delegation.json
```

This local command uses `AGENTCAPSULE_DATABASE_URL` and the operator rights of
that connection. It is not an endpoint usable with a JWT. Its JSON output
contains only state, fingerprint, generation, `minimum_iat` and, for a key
change, the key ID and its end. The audit identifies the local account by UID;
it does not claim to identify an OIDC user. Installation does not create
members: `issuer` and `subject` must already match a `user` principal and an
active membership of the existing tenant. An issuer and audience serve one
organization only: installing them for a second one is refused.

A trust installed before migration 0034 has only its fingerprint in
PostgreSQL, not its keys: the API refuses its tokens until the operator runs
`rotate` with its file.

## Tokens and authorization

The API verifies each token with the registered key its `kid` names, in the
trust its `iss` and `aud` name. The client signs an EdDSA JWT with `kid`, `iss`, a single `aud`, `sub`, `jti`,
`trust_generation`, `iat`, `exp` and the `org:read` scope for this route. `nbf`
is optional. Dates are whole Unix seconds. The full profile is described in
[delegatedidentity](../../internal/delegatedidentity/README.md).

`trust_generation` is the positive integer returned by the operator's
installation/rotation, not a value freely chosen by the token. It must equal the
current generation in the database. String, fraction and exponential forms, zero
and values exceeding the maximum signed 64-bit integer are refused.

The tenant comes from the server-side trust. A `tenant_id` claim, if present,
must simply match it. No `role`/`roles` claim grants permission. A valid
signature is not enough: organization, principal, membership, issuer anchor,
trust and key must exist and be active; the fingerprint, the current signed
generation, the issuance threshold, the end of the key's overlap and the
absence of a JTI revocation are checked. `iat`,
`nbf` and `exp` are rechecked with the PostgreSQL clock, even if cryptographic
authentication took place earlier.

The consuming transaction repeats these checks in the order organization →
principal → membership → issuer → trust → key, with locks held until commit.
Trust/JTI mutations take an exclusive lock on the issuer anchor. This also
covers the case where no JTI tombstone exists yet. An already confirmed
revocation forbids a new admission; a read admitted earlier may finish before
the revocation is confirmed.

200 response:

```json
{
  "organization": {
    "id": "org_<id>", "name": "Engineering", "status": "active",
    "policy_version": 1, "created_at": "2026-11-07T12:00:00Z"
  },
  "principal_id": "prn_<id>",
  "display_name": "Alice",
  "role": "agent_user"
}
```

All active membership roles can read this metadata about their own organization
with `org:read`. The returned role comes from the current database. Tenant
tokens cannot call the global platform routes or the legacy owner/service
routes. Conversely, those legacy token types cannot call `current`. An
unauthenticated token or an inactive current authority produces 401; a wrong
identity type or scope: 403. No conversation body, token, key or identity of
another member is returned.

## Explicit rotation and revocation

Each mutation requires an `operation-id` that is stable across retries. The same
operation and the same parameters replay the initial receipt with no additional
effect; changing the parameters with this ID is refused. A receipt describes the
initial command, not the state of the trust after later commands.

- `install` creates the trust or confirms an identical configuration that is
  already active. It never reactivates a revoked trust and never replaces a
  different fingerprint.
- `rotate`, with the same arguments as `install`, explicitly replaces or
  reactivates an existing trust and increments its generation, including when
  the fingerprint stays identical. The client then uses this signed generation.
  A key absent from the new file is retired at once.
- `add-key`, with `-audience`, `-key-id` and `-public-key` (standard base64),
  adds a key to an active trust. Adding the same key again changes nothing.
- `retire-key`, with `-audience`, `-key-id` and `-overlap` (0 by default, at
  most 30 days), ends the key's validity after the overlap. An earlier end is
  never pushed back. The last key without an end cannot be retired.

`add-key` and `retire-key` keep the generation and the issuance threshold:
tokens signed with the other keys of the trust keep working. This is the
overlap of a routine key rotation. A key ID keeps its public key for good, and
a retired key never returns, neither by `add-key` nor by `rotate`.
- `revoke-trust`, with tenant/issuer/audience and without `trust-file`, revokes
  it.
- `revoke-token`, with tenant/issuer/`token-id` and without audience or
  `trust-file`, records a permanent JTI tombstone. The full token is never
  requested.

Activation sets `minimum_iat` to the next PostgreSQL second. Rotation takes the
second following the maximum of the old threshold and the current DB second. The
client must wait for this threshold before issuing new tokens; tokens from the
second of the change are refused. A retry never moves the threshold. The `iat`
threshold is a freshness rule; it proves neither the physical instant of signing
nor that of the rotation commit. It is the comparison of the signed generation
that refuses old epochs, even after a delayed commit, with a pre-signed future
`iat`, or on a return to the same fingerprint. Compromise of a key requires its
effective renewal: a holder of that key can sign a new generation, and the
counter does not replace this revocation.

Tombstones are indexed by **tenant + issuer + JTI**, without audience and
without fingerprint: changing the audience or the configuration does not
reactivate a revoked JTI. The client must avoid reusing them. Growth and
retention of these tombstones remain to be addressed without weakening this
guarantee. Changes, receipts and audits are atomic; an audit failure also rolls
back the activation or revocation.

## Limits

This is a delegation signed by an explicitly approved client, not OIDC/JWKS
discovery or a sign-in portal. Member and team mutations are described in
[members.md](members.md) and [teams.md](teams.md); agent assignments in
[agents-assignments.md](agents-assignments.md); service accounts and opaque
tenant tokens in [service-accounts.md](service-accounts.md).
Revoking this JWT does not retroactively cancel a job already accepted; no
tenant work route is added here. This PostgreSQL/HTTP verification is not a KVM
validation, nor a validation of harness memory sharing or of authority
restoration after a disaster. Older migrations and receipts remain unchanged.
