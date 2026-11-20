# Identity provider for the single-host installation

The bundled realm uses authorization code with S256 PKCE. The MonApp callback must match the registered URI exactly. Its public OAuth client has no signing key. Store the separate PaaS provisioning credential in the application's backend.

1. Provide PostgreSQL with a dedicated database named `keycloak` and a login owning that database. Include it in the installation's backup and restoration checks.
2. Install Podman and load the pinned Keycloak image from the distribution or pull the digest printed in the unit. Place the unit in `/etc/systemd/system` and the realm in `/etc/agentcapsule/oidc/realm.json`.
3. Install a TLS certificate and key for the identity hostname in `/etc/agentcapsule/oidc-tls`. Allow the image user (UID 1000) to read the key. Create a root-only `/etc/agentcapsule/oidc.env` from the example. Set both passwords to independently generated secrets, the public HTTPS URL and the application's exact callback URL.
4. Run `systemctl daemon-reload` and `systemctl enable --now agentcapsule-oidc`. First startup imports the realm. Later starts use its PostgreSQL state. Log in to the administration console, create a permanent named administrator, then retire the bootstrap administrator and remove its two environment entries.
5. Configure SMTP and member verification, or have a trusted administrator verify the recipient's address when enrolling each user. The PaaS checks the verified email only during invitation acceptance. Subsequent sessions use the issuer and stable subject.

The discovery document is at `/realms/agentcapsule/.well-known/openid-configuration`. Register its issuer and keys using the application API. The API audience is `agentcapsule-api` and the authorized party is `monapp`. Enterprise providers can use the same access-token profile. [Integration contract](../../docs/api/applications.md)

For a manual installation, copy `container.py` to `/usr/local/lib/agentcapsule-host/oidc-container.py` with root ownership and mode 0700. The unit stores its Podman container ID privately. During an upgrade from an older unit it verifies the system journal’s Podman creation record before removing a residual container. An unrelated container occupying the name is reported and retained.
