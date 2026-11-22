# MonApp and member provisioning

The sysadmin installs the identity provider. An Acme owner registers one OAuth client environment, applies an assignment policy, and delivers the application's public configuration to the developer. Keep the provisioning token in the backend's secret store. A member gets a separate API access token when signing in. The public SDK can implement these transactions in any language. [OpenAPI](../../openapi/openapi.yaml) · [Bundled Keycloak realm](../../deploy/oidc/README.md)

## Register the environment

Send requests to the installation's HTTPS URL. The API accepts JSON. All mutations require an `Idempotency-Key` header. Check the HTTP status before interpreting a response. Read `code` from `application/problem+json` on an error.

The platform operator first approves the application's OIDC client, its issuer and client ID, for Acme. A client is approved for one organization at most, and a member's token reaches only the application of the organization its client is approved for. In the bundled Keycloak realm, one issuer for the whole installation, the operator creates each client for one organization and approves it for that organization. [Decision](../adr/001-organization-identity.md#application-clients-approved-by-the-platform-operator-sec-1b-finding-s-10)

| Actor and command | HTTP request | Success |
|---|---|---|
| Platform operator, `organization approve-client ORG_ID --file client.json` | `POST /v1/organizations/{id}/application-clients` with `{"issuer":"…","client_id":"monapp"}`, platform credential | 201 approval ID; 200 for a client approved for Acme already |
| Platform operator, `organization clients ORG_ID` | `GET /v1/organizations/{id}/application-clients` | Acme's approved clients, `approved_by` the platform account or `migration` |
| Platform operator, `organization withdraw-client ORG_ID APPROVAL_ID` | `POST /v1/organizations/{id}/application-clients/{approval_id}/withdraw` with `{}` | Approval withdrawn; the application registered for the client disabled, with its `revocations` |
| Acme owner, `app register monapp --config monapp.yaml --output-file backend.json` | `POST /v1/applications`, identity:manage | 201, application ID, OIDC parameters and backend token |
| Acme owner, `app show <id>` | `GET /v1/applications/{id}` | Public client configuration, pinned public keys, applied policy IDs |
| Acme owner, `app connection <id> --output-file monapp-public.json` | `GET /v1/applications/{id}` | Developer handoff with HTTPS API and issuer discovery URLs, organization and application IDs, audience, client ID, callbacks, PKCE method and applied policy IDs in `.data` |
| Acme owner, `app verify <id> [--issuer-ca PEM_FILE]` | `GET /v1/applications/{id}`, then HTTPS discovery and JWKS at the issuer | Active registration, matching issuer and pinned RSA signing keys, advertised code flow and PKCE method |
| Acme owner, `app rotate <id> --output-file backend-next.json` | `POST /v1/applications/{id}/rotate` with `{}` or new `verification_keys` | Updated token, previous backend tokens revoked |
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

Extract `kid`, `n`, `e` and `kty` from the trusted issuer's HTTPS JWKS. The API accepts pinned RS256 signing keys of 2,048–8,192 bits and supports overlapping keys. Configure the exact same redirect URIs at the IdP. Each issuer/client pair identifies one environment and organization. Without the operator's approval for Acme, registration returns 403 `application_client_not_approved`, the same answer whether another organization holds the client or none does. A 409 `invalid_transition` concerns Acme's own applications: the name, or the client already registered. The owner can list registrations with `after` and `limit` (1–100). Export the public connection after applying the policy.

Withdrawing an approval disables the application registered for its client at once, like `app revoke`; the operator can then approve the client for another organization, and Acme cannot register it again. Installations updated from v0.1.0 keep their registrations: the update approved each one's client for its organization (`approved_by` `migration`). Review them with `organization clients` and withdraw one an organization should not hold.

The registration and rotation commands write the 90-day backend credential to `.data.provisioning_token` in a new private output file. Load this value into the MonApp backend’s secret store. Its single scope, `application:sync`, permits reading and updating activations of that registration. A human administrator or an eligible signed-in manager approves invitations. The member’s OIDC access token authorizes agent and result requests.

For a routine credential rotation, run `agentcapsule app rotate APP_ID --output-file backend-next.json`. The old token is revoked when the API commits. Switch the backend to the new secret and use it to read a known activation at `GET /v1/applications/APP_ID/activations/ACTIVATION_ID` (200). The previous token receives 401 on the same route. The empty rotation body preserves the OIDC verification keys, so members can continue using their existing sessions. To replace those keys too, provide a `--file` containing `verification_keys`. Run `app verify APP_ID` against the issuer after the change.

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

Reusing an idempotency key with a different authenticated request returns 422. An expired unused invitation returns 409. Unknown or wrongly addressed proofs and foreign resources return 404. Invalid or expired credentials and the OIDC tokens of a revoked integration, or of a client whose approval was withdrawn, return 401. A disallowed team/manager returns 403. A stale event returns 409. A revoking response can include `revocations`, showing the actual record status (pending or confirmed) when using the authority service. Poll `GET /v1/access-revocations/{id}` with an audit-authorized credential for changes.

## Run the conformance client

The signed Linux workstation CLI source archive `agentcapsule-source.tar.gz` contains this guide, the sysadmin manual (`docs/cli.md`), the OpenAPI contract (`openapi/openapi.yaml`) and the two scripts in `examples/monapp/`. After verifying the release checksums, extract the archive and run the examples from its `agentcapsule/` directory. [Release verification](../release.md#verify-a-release)

Use a fresh test organization and two fresh identities. The platform operator approves the scenario's issuer and client ID for that organization first. Prepare a pool containing at least two assignable agents and a shared Support agent that can answer an invocation. Supply a second organization's bearer credential to check isolation. For the bundled realm the test-only browser client follows the Keycloak password form, verifies state, and writes a short-lived API access token to a newly created private file.

```bash
python3 examples/monapp/oidc-login.py --issuer https://identity.acme.test/realms/agentcapsule \
  --client-id monapp --redirect-uri https://monapp.acme.test/signin/callback \
  --username alice --password-file /secure/test-alice-password --output /secure/alice.jwt
python3 examples/monapp/verify.py scenario.json > report.json
```

Repeat the login for Bob. For an enterprise IdP, acquire each member’s access token using its standard browser flow. The scenario document has the following shape. Place registration parameters directly in `application`, using the registration object shown above.

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

The client issues a short-lived invitation, waits until its declared expiration and checks for `409 expired`. A changed body with the same invitation idempotency key returns `422 idempotency_key_reused`. Alice and Bob accept their own invitations concurrently. Each retries with both the original and a fresh idempotency key. Both retries must return the same activation, principal, policy and slot-to-agent mapping. The foreign owner receives `404 not_found` for Acme's application, invitation endpoint, activation, shared agent and revocation records. [Reference client](../../examples/monapp/verify.py)

The following additional inputs extend the same scenario. The report lists which optional checks ran and records the agents assigned to each personal slot.

| Scenario input | Fixture | Required result |
|---|---|---|
| `second_personal_pool_id` | Two more available agents. This can be the same pool if it has four available agents. | Alice and Bob each retain different `personal` and `research` agents, including across acceptance retries. |
| `refusal_pool_id` | A dedicated pool with one available or preparing agent. | Accepting a two-slot rule returns `409 pool_exhausted` and leaves the pool inventory intact. |
| `reassigned_email_token_file` | A private, current OIDC access token for another subject of the same issuer and client, with Alice's verified address and `member:accept`. A test IdP can reassign an address after issuing its former owner a token. | After Alice consumes the invitation, the other subject receives `403 forbidden` with the same proof. |
| `wrong_audience_token_file` | A private, current access token for the same issuer and client, issued for another API audience. | Accepting the valid proof returns `401 authentication_required`. |
| `sales_team_id` | An existing active destination team. If omitted, the administrator creates a Sales team through the API and needs team-management permission. | The version 2 event moves Alice from Support to Sales. Replaying the event and reading the activation return the Sales team and the original personal slots. |
| `sales_agent_id` | A distinct, ready shared agent that can answer a Sales invocation. | Alice gains Sales access after the transfer and can retrieve her new result. Bob completes a new Support invocation and cannot read the Sales agent or result. |
| `members[].keycloak_login` | Bundled test realm login, e.g. `{"username":"alice","password_file":"/secure/alice-password","ca_file":"/secure/identity-ca.pem"}`. The first registered callback is used unless `redirect_uri` is supplied. Configure Bob likewise. | A fresh browser and PKCE exchange after each event verifies the permissions of separate OIDC sessions. |

Alice’s original token loses access to the Support agent and her previous Support result as soon as the backend transfers her. Her personal agents remain accessible. With `keycloak_login` configured, Alice repeats these reads in a new session. After the version 3 departure, both of her existing sessions and a newly issued token receive `401 authentication_required`. The test submits a new invocation, replays a stale transfer and reads the final disabled activation. Bob can still open Support until the whole application is revoked. A subsequent Bob login then receives the same 401. A client for another OIDC provider can reproduce these assertions with a fresh authorization-code/PKCE flow at each event. The report records which session checks ran, the transfer, and the counts of admitted work at departure.

The client also checks that Alice’s consumed invitation cannot restore membership and the revoked backend token cannot read the activation. It reads each returned revocation record by ID and reports its actual `pending` or `confirmed` state. To repeat the read-only checks after restarting the API, retain the report and supply current administrator and member credentials. Keep short-lived member tokens valid during the check so that expiration cannot explain a denial.

```sh
python3 examples/monapp/verify.py scenario.json --check-revoked report.json
```

## Recovering a personal volume

Before granting the first access to a pool volume, the API records the immutable volume ID, agent ID and member ID in the restore authority. A replicated installation waits for the standby to acknowledge that record. If the authority is unavailable, the request returns HTTP 503 and can be retried with the same invitation and idempotency key.

Restoring a database snapshot that predates the assignment leaves the volume reserved outside PostgreSQL. On promotion, reconciliation imports the record. On a same-host restore, the API replays missing records before it opens its listener. A member whose assignment is absent from the snapshot may need another invitation and a fresh agent. The retained volume is excluded from pool and team assignments.
