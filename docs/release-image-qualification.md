# Offline image release qualification, 19 November 2026

The candidate contains six Linux amd64 images. Syft 1.55.0 scanned each Docker archive. Grype 0.121.0 used its 19 November 2026 database at 00:22:15 UTC. Each installed package was assessed against the existing policy for its pinned image. The release threshold is High or Critical. Duplicate detections occur when several binaries or JARs contain the same component.

| Image | Cataloged packages | Matches already covered | Outstanding matches | Distinct outstanding package advisories |
|---|---:|---:|---:|---:|
| directory | 214 | 0 | 0 | 0 |
| directory-edge | 25 | 9 | 0 | 0 |
| init | 1 | 0 | 0 | 0 |
| oasf | 28 | 36 | 0 | 0 |
| oidc | 561 | 0 | 6 | 6 |
| slim | 6 | 5 | 0 | 0 |

Six matches block release. All are in Keycloak, with one Critical and five High findings. Prior reviews of HAProxy, OASF and SLIM dependencies cover 50 matches. Directory v1.9.1 resolves the two outstanding detections of GO-2026-6860 in v1.8.0 and scans clean across its 214 packages.

On 20 November 2026 the pull request scan command also ran locally in WSL against the six pinned Linux amd64 registry images. It read the Keycloak image from the OIDC systemd unit. Each scanned image's configuration digest matched the signed `dev.12` inventory. With the same vulnerability database and policy, the command exited with code 1 on the same six Keycloak findings. The other five images passed the existing policy.

## Release decisions

The six findings below require an updated Keycloak image that passes the release scan.

| Image | Installed package | Fix reported by Grype | Advisory |
|---|---|---|---|
| oidc | `guava 33.6.0-jre` | 33.7.2 | GHSA-xxph-c9ww-hj94 (CVE-2026-102554) |
| oidc | `java-21-openjdk-headless 1:21.0.13.1.2-1.2.el9` | wont-fix | CVE-2026-91403 |
| oidc | `sqlite-libs 3.34.1-11.el9_8` | not-fixed | CVE-2026-119373, CVE-2026-119374, CVE-2026-119379, CVE-2026-119586 |

Keycloak 26.8.2 build 3 reduced the OIDC result from 66 blocking matches on 26.6.3 to six using the same Grype database. Its published container uses UBI 9 micro and OpenJDK 21. Red Hat also lists UBI 9 and OpenJDK 21 for its maintained 26.6.x container. Google has released the Guava fix. Red Hat still lists the RHEL 9 SQLite component as affected for all four findings. [Keycloak downloads](https://www.keycloak.org/downloads), [container build](https://github.com/keycloak/keycloak/blob/26.8.2/quarkus/container/Dockerfile), [Red Hat configurations](https://access.redhat.com/kb/7033107), [Guava release](https://github.com/google/guava/releases/tag/v33.7.2), [Red Hat SQLite advisory](https://access.redhat.com/security/cve/CVE-2026-119373)

The image includes the updated RHEL 9 trust store, `ca-certificates-2026.2.92_v9.0.319-90.3.el9_8`, which Red Hat identifies as the remedy for the OpenJDK RPM. Grype continues to report the JDK finding and the release gate rejects it. [Red Hat OpenJDK advisory](https://access.redhat.com/security/cve/CVE-2026-91403), [RHEL 9 trust store update](https://access.redhat.com/errata/RHSA-2026:88459)

The Keycloak server and JDK extracted from the pinned image passed a fresh realm import on PostgreSQL 16.15 and a database upgrade from Keycloak 26.6.3. Both members retained their subjects across the upgrade. The MonApp HTTP test authenticated them with S256 PKCE, checked access to their assigned agents, invoked an agent and confirmed revocation.

## Source and evidence identities

The reference for each archive appears below. The release carries its OCI configuration digest, archive SHA-256, SPDX document, pinned application source and third-party notices. The report covers the offline image inventories. The host packages, application binaries, compilation locks and registry scans have their own release checks.

* `ghcr.io/agntcy/dir-apiserver:v1.9.1@sha256:b42c7e47692e8ce5d154660e1b153e834033371740bbed95504a6498198ab386`
* `docker.io/library/haproxy:3.2-alpine@sha256:96ec3c75a9264ba94e733eeacb44051ed6e7b79bb77a73c2c36f236b6423f1f0`
* `ghcr.io/agntcy/oasf-schema:1.1.0@sha256:01df69976950fc321ebab2b6af069466f9524d88cfa9d5d16edac5bfc43f6294`
* `ghcr.io/agntcy/oasf-server:v2.0.0@sha256:4ef8f82f1c2a5b9dc703e208ef8764a558ec0301f7459a7073d2d8758d3d5f9f`
* `quay.io/keycloak/keycloak@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3`
* `ghcr.io/agntcy/slim:3.4.6@sha256:54fde7ce0ef8efa6a61fee47996e941e87acb4e62284e5d9c00eb761295619b7`
