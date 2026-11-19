# MonApp and member provisioning

The sysadmin installs the identity provider. An Acme owner registers one OAuth client environment, applies an assignment policy, and delivers the application's public configuration to the developer. Keep the provisioning token in the backend's secret store. A member gets a separate API access token when signing in. The public SDK can implement these transactions in any language. [OpenAPI](../../openapi/openapi.yaml) · [Bundled Keycloak realm](../../deploy/oidc/README.md)

## Register the environment

Send requests to the installation's HTTPS URL. The API accepts JSON. All mutations require an `Idempotency-Key` header. Check the HTTP status before interpreting a response. Read `code` from `application/problem+json` on an error.

| Actor and command | HTTP request | Success |
|---|---|---|
| Acme owner, `app register monapp --config monapp.yaml` | `POST /v1/applications`, identity:manage | 201, application ID, OIDC parameters and backend token |
| Acme owner, `app show <id>` | `GET /v1/applications/{id}` | Public client configuration, pinned public keys, applied policy IDs |
| Acme owner, `app rotate <id>` | `POST /v1/applications/{id}/rotate` with `{}` or new `verification_keys` | Updated token, previous backend tokens revoked |
| Acme owner, `app revoke <id>` | `POST /v1/applications/{id}/revoke` with `{}` | Integration disabled, including current member sessions |
| Acme owner, `assignment-policy plan --file arrival.yaml` | `POST /v1/assignment-policies/plan`, agent:assign | 201, immutable plan ID and available inventory per pool |
| Acme owner, `assignment-policy apply --plan <id>` | `POST /v1/assignment-policies/{id}/apply` with `{}` | Effective policy with shared team grants after validation |
| Acme owner, `access explain --member <id> --agent <id>` | `GET /v1/access/explain?member=<id>&agent=<id>` | Effective permissions, source team/policy/assignment IDs |

Example registration body (replace the key with the real RSA public modulus of the issuer's signing key).

```json
{
  "name": "monapp",
  "issuer": "https://identity.acme.test/realms/agentcapsule",
  "client_id": "monapp",
  "audience": "agentcapsule-api",
  "redirect_uris": ["https://monapp.acme.test/signin/callback"],
  "verification_keys": [{"kty":"RSA","kid":"<key ID>","n":"<base64url modulus>","e":"AQAB"}]
}
```

Extract `kid`, `n`, `e` and `kty` from the trusted issuer's HTTPS JWKS. The API accepts pinned RS256 signing keys of 2,048–8,192 bits and supports overlapping keys. Configure the exact same redirect URIs at the IdP. Each issuer/client pair identifies one environment and organization. The backend's credential expires after 90 days. Restrict reads of the registration/rotation response, including terminal output in scripts. The owner can list registrations with `after` and `limit` (1–100).

## Configure personal and shared slots

```json
{
  "application_id": "app_<MonApp>",
  "allowed_teams": ["team_<Support>", "team_<Sales>"],
  "on_exhaustion": "wait",
  "slots": [
    {"name":"personal","pool_id":"pool_<assistants>","permissions":["read_metadata","invoke","read_content"]},
    {"name":"support","team_id":"team_<Support>","agent_id":"agt_<shared>","permissions":["read_metadata","invoke","read_content"]}
  ]
}
```

Each personal slot reserves one distinct agent from its configured pool. A second named slot may select another profile's pool. A shared slot grants the existing agent to the specified team when the policy is applied. App-managed team membership carries its source, so changing team removes only the previous membership owned by this integration. The effective assignment engine also sees direct grants and memberships from other sources.

`on_exhaustion` selects `wait`, `refuse` (409 `pool_exhausted`, no partial allocation), or `create` under the pinned pool template, host capacity and tenant quotas. An operator can replenish a pool with `POST /v1/pools/{id}/expand` and `{"count":2}`. The API polls durable waiters after restart and reports a retry delay. PostgreSQL enforces one reservation per organization/member/policy/slot and one personal reservation per agent. Offboarding retains these reservations and their volumes until the administrator performs the installation's retention or deletion procedure. A revoked assignment never returns a used personal volume to the pool.

## Connect the member

Discover the issuer's authorization and token endpoints under its `.well-known/openid-configuration`. Use a fresh random state, nonce and PKCE verifier per login. Send an authorization request with `response_type=code`, the registered callback, `code_challenge_method=S256`, and a base64url SHA-256 challenge. At the callback verify the exact redirect, issuer and state. Exchange the code, redirect and verifier at the trusted token endpoint. Use an OIDC client library to validate the ID token including nonce for the MonApp session. Send the **access token** as the API bearer credential. [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html) · [OAuth security guidance](https://www.rfc-editor.org/rfc/rfc9700.html)

Request `openid email member:accept org:read agent:read agent:invoke agent:content:read` for the example journey. The access token must have `iss`, an audience containing the API, the registered `client_id` or `azp`, `sub`, `jti`, `iat`, and `exp` (up to one hour after issuance). Use RFC 9068 header `typ=at+jwt` or Keycloak's verified claim `typ=Bearer`. The API rechecks credential time, the key generation, application, tenant, principal, membership and current rights for each protected transaction. A matching e-mail alone cannot bind or take over a previously registered principal.

## Provision the member from MonApp

1. An Acme administrator with `member:manage` or an eligible MonApp manager approves the invitation. For the latter path, list the manager's activated principal ID in the policy's `manager_ids` and request `member:invite` in their OIDC session. An integration's technical credential never acts as this human approver.

   ```http
   POST /v1/applications/{app}/invitations
   Authorization: Bearer <manager access token>
   Idempotency-Key: invite-alice-support
   Content-Type: application/json

   {"policy_id":"pol_<arrival>","team_id":"team_<Support>","email":"alice@acme.test","expires_at":"<UTC time within seven days>"}
   ```

   Expect 201 with `id`, `expires_at` and a single-use `proof`. The backend privately delivers the proof to the specified recipient. Keep it out of URLs, access logs and analytics.

2. Alice signs in and supplies her recipient proof. The API requires the member:accept scope and a verified email claim matching the invitation. It binds the activated principal to the verified issuer and subject. Only the application that issued the invitation can accept it. A replay by the original subject returns the same activation ID and stable slots.

   ```http
   POST /v1/applications/{app}/accept
   Authorization: Bearer <Alice access token>
   Idempotency-Key: accept-alice-support
   Content-Type: application/json

   {"proof":"<invitation proof>"}
   ```

3. Expect 200 and follow `GET /v1/applications/{app}/activations/{id}`. The durable activation ID identifies this operation. The response contains the `agents` slot map, member principal ID, event version and `state`. `preparing` and `waiting_capacity` carry a reason and retry interval. `failed` names an unavailable agent. `ready` means agents finished provisioning. Their current sleep/running state comes from `GET /v1/agents`.

4. List and invoke under Alice's own token. Post `{"content":[{"type":"text","text":"Hello"}]}` to `/v1/agents/{id}/invocations` with an idempotency key. Expect 202 with an invocation ID. Poll `GET /v1/invocations/{id}` until `completed`, then read `GET /v1/invocations/{id}/result`. Bob gets 404 for Alice's private result, including on a shared Support agent.

5. The MonApp backend owns the ordered membership events for its activations. Use the backend token or an authorized organization administrator for `PUT /v1/applications/{app}/activations/{id}`. Set `{"version":2,"team_id":"team_<Sales>"}` to transfer Alice, or omit `team_id` to leave the current team. A subsequent `{"version":3,"disabled":true}` revokes her membership. The response’s `admitted_work` lists counts of pending and running invocations. Those operations continue under their admission contract, and her next authenticated request fails. Read the activation to reconcile state after a lost response. The API prevents stale events and reactivation of a departed member. Existing manual principals and members promoted to administrative roles are outside this backend's authority.

Reusing an idempotency key with a different authenticated request returns 422. An expired unused invitation returns 409. Unknown or wrongly addressed proofs and foreign resources return 404. Invalid or expired credentials and a revoked integration's OIDC tokens return 401. A disallowed team/manager returns 403. A stale event returns 409. A revoking response can include `revocations`, showing the actual record status (pending or confirmed) when using the authority service. Poll `GET /v1/access-revocations/{id}` with an audit-authorized credential for changes.

## Run the conformance client

Use a fresh test organization and two fresh identities. Prepare a pool containing at least two assignable agents and a shared Support agent that can answer an invocation. Supply a second organization's bearer credential to check isolation. For the bundled realm the test-only browser client follows the Keycloak password form, verifies state, and writes a short-lived API access token to a newly created private file.

```bash
python3 examples/monapp/oidc-login.py --issuer https://identity.acme.test/realms/agentcapsule \
  --client-id monapp --redirect-uri https://monapp.acme.test/signin/callback \
  --username alice --password-file /secure/test-alice-password --output /secure/alice.jwt
python3 examples/monapp/verify.py scenario.json
```

Repeat the login for Bob. For an enterprise IdP, acquire the two access tokens using its standard browser flow. The scenario document has the following shape. Place registration parameters directly in `application`, using the registration object shown above.

```json
{
  "api": "https://paas.acme.test",
  "api_ca": "/secure/installation-root.pem",
  "application": {"name":"monapp","issuer":"<issuer>","client_id":"monapp","audience":"agentcapsule-api","redirect_uris":["<callback>"],"verification_keys":[{"kty":"RSA","kid":"<kid>","n":"<n>","e":"AQAB"}]},
  "admin_token_file": "/secure/acme-admin.jwt",
  "other_org_token_file": "/secure/other-owner.jwt",
  "members": [
    {"email":"alice@acme.test","token_file":"/secure/alice.jwt"},
    {"email":"bob@acme.test","token_file":"/secure/bob.jwt"}
  ],
  "support_team_id":"team_<Support>",
  "support_agent_id":"agt_<shared>",
  "pool_id":"pool_<personal>"
}
```

The scenario performs concurrent acceptance, replays a lost response, checks personal exclusivity, shared access, cross-tenant isolation and private results, and then moves and offboards Alice. Finally it revokes the test application and checks Bob's still-unexpired credential. It prints resource and revocation IDs. Its inputs are HTTPS and JSON so another language can replay the same sequence. [Reference client](../../examples/monapp/verify.py)
