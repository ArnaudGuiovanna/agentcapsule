# Delegated identity verification

This package verifies JWTs issued by a trusted client configured on the server.
It uses [`golang-jwt/jwt/v5` v5.3.1](https://github.com/golang-jwt/jwt/releases/tag/v5.3.1);
its [upstream security policy](https://github.com/golang-jwt/jwt/blob/v5.3.1/SECURITY.md)
covers the v5 branch. Cryptography, JWT decoding and standard validation are left
to that library; the additional checks define the platform's delegation profile.

`NewVerifier(Config)` takes immutable trusts: each `Issuer` and `Audience` pair maps
to exactly one `TenantID`, Ed25519 public keys indexed by `kid`, a maximum list of
scopes and an explicit `MaxTTL`. Ambiguous configurations are refused. The
constructor copies maps, keys and scopes. Rotation means building a new verifier;
no key or URL from the token is ever used.

`Verify(rawJWT)` returns `VerifiedIdentity{TenantID, Issuer, Audience, Subject,
TokenID, KeyID, TrustFingerprint, TrustGeneration, IssuedAt, NotBefore, ExpiresAt, Scopes}`.
The tenant comes from the server-side trust, never from a client choice.

`IssuedAt` and `NotBefore` (zero when absent) keep the signed times so they can be
rechecked against the PostgreSQL clock in the authorization transaction. The
issuance threshold set at activation or rotation never comes from the token.

`TrustFingerprint(issuer, audience)` exposes the `[32]byte` reference of the
configured trust. It is the SHA-256 of a versioned, compact UTF-8 JSON document
with these fields in this order: `domain` (fixed value
`agentcapsule.delegatedidentity.trust.v1`), `issuer`, `audience`, `tenant`, `keys`,
`scopes`, `max_ttl_nanoseconds`. Keys are sorted by `kid`, each encoded as
`{"kid": ..., "public_key": ...}`; public key bytes use the standard padded base64
of `encoding/json`. Scopes are sorted and an empty set encodes as `[]`. The TTL is
an integer number of nanoseconds. Strings follow the standard `encoding/json`
escaping. No map and no private key enters the encoding. The clock and the global
size limit are not fields of the trust.

The caller must record this reference from the trust configuration, then compare
the verified `TrustFingerprint` with the reference **currently active** in the
transaction that consumes the identity. Changing a key, the scopes, the TTL, the
issuer, the audience or the tenant changes the reference. An old verifier keeps its
old reference, so comparing against that same object does not detect a
configuration revocation. The hash identifies a configuration; it is neither a proof
of authority nor a replacement for the usual locks and checks.

The accepted profile requires:

- An Ed25519 signature with `alg: EdDSA` and a configured `kid`; `typ` absent or `JWT`.
- `iss`, a single audience `aud` (a string or a one-element array), `sub`, `jti`,
  `iat` and `exp`. Times are non-negative whole Unix seconds within 1970–9999;
  `exp > iat` and `exp - iat <= MaxTTL`.
- A mandatory `trust_generation`: an exact, strictly positive JSON integer of at most
  9223372036854775807. The verifier authenticates this signed value; the consuming
  transaction must compare it with the current generation installed independently in
  the database. Strings, fractions, exponent notation and overflow are refused. An
  `iat` time never replaces this epoch comparison.
- `exp` strictly in the future, `iat` not in the future, `nbf` not in the future when
  present. No implicit clock skew. The clock is injectable.
- `scope` absent, empty, or a space-separated string of scopes without duplicates,
  at most 64 scopes. Every scope must appear exactly in the trust; wildcards have no
  special meaning. The `scopes` variant is refused.
- `tenant_id`, if present in the token, must be a string equal to the trust's tenant.
  It never selects the tenant. Role claims grant no rights.
- No `crit` extension, no alternative `b64` payload, and no keys, certificates or URLs
  in the `jwk`, `jku`, `x5c` or `x5u` headers.

The compact token size is limited before parsing: 8 KiB by default, configurable up
to 64 KiB. Token errors always return `ErrInvalidToken` and an empty identity, with
no token content in the message. This package uses no network and no database
state.

The caller must still resolve `(tenant, issuer, subject)` to an authorized principal,
then check, in the consuming transaction, the current state of the organization, the
principal, the membership and the trust, the revocations and the permissions. A
valid signature creates neither a member nor a role. Revocation by `jti` must be
scoped at least by tenant and issuer. This package does not deduplicate tokens, does
not guarantee single use and does not handle access to history.

Targeted validation:

```bash
go test -race ./internal/delegatedidentity
```
