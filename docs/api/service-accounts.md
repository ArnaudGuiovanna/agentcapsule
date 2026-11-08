# Tenant service accounts

A service account is a `service`-type principal belonging to the organization,
with an administrative role and opaque `acps_` tokens. It lets an integrator (CI,
scripts) act on the tenant routes without a human account. It completes TEN-02.

## Guarantees

- **Ownership**: the account and its agents belong to the organization. A
  human's departure does not delete them.
- **Never an identity**: a service account neither creates nor manages accounts
  or tokens, including its own. The `/v1/service-accounts` routes require a
  human credential, `identity:manage` and a current role of `org_owner` or
  `org_admin`.
- **Roles**: never `org_owner`. An `org_admin` neither creates nor manages an
  `org_admin` account. The role is fixed at creation.
- **Secret**: `acps_` + 32 random bytes. Only the SHA-256 hash is stored. The
  secret appears only in the issuance response and its 24-hour encrypted
  receipt.
- **Scopes**: closed registry (`authorization.DelegableScopes`), without
  `identity:manage`, `platform:admin` or wildcard, and included in those of the
  issuing human credential. Effective rights remain bounded by the account's
  role: a scope creates no route, role or assignment.
- **Expiry**: explicit, strictly in the future, at most 365 days (PostgreSQL
  clock). A replay never lengthens the lifetime.
- **Revocation**: effective from the next request, including for an already
  authenticated principal, because organization, account, role and token are
  re-read under a shared lock in the transaction that consumes them.

## Lifetime tied to the issuer

Each token records the human who issued it. It is revoked:

- when that human is removed from the organization;
- when they lose the right to manage the account: a demoted `org_admin` loses
  the tokens of `org_admin` accounts (and all of them if the new role no longer
  manages identities);
- when the account is disabled (all its tokens).

Promoting a role resurrects no token. Another authorized human issues a new
token to transfer operation.

## Limits

- Revoking a JTI or rotating the trust that authenticated the issuer does not
  revoke its service tokens (a separate choice, not decided).
- Restoring an old SQL backup can lose revocations: invalidate or rotate the
  tokens before reopening (D-03/D-05).
- The encrypted issuance receipt contains a temporary copy of the secret, kept
  24 hours and protected by the installation's receipt key.
