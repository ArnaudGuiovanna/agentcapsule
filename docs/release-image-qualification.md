# Offline image release qualification, 19 November 2026

The candidate contains six Linux amd64 images. Syft 1.55.0 scanned each Docker archive. Grype 0.121.0 used its 19 November 2026 database at 00:22:15 UTC. Each installed package was assessed against the existing policy for its pinned image. The release threshold is High or Critical. Duplicate detections occur when several binaries or JARs contain the same component.

| Image | Cataloged packages | Matches already covered | Outstanding matches | Distinct outstanding package advisories |
|---|---:|---:|---:|---:|
| directory | 213 | 2 | 2 | 1 |
| directory-edge | 25 | 9 | 0 | 0 |
| init | 1 | 0 | 0 | 0 |
| oasf | 28 | 36 | 0 | 0 |
| oidc | 548 | 0 | 66 | 56 |
| slim | 6 | 5 | 0 | 0 |

The 68 outstanding matches represent 57 distinct package advisories. One concerns the Directory image, with the same Go module in two executables. The other 56 concern 20 packages in the Keycloak image. Prior review of HAProxy, OASF, SLIM and Directory dependencies accounts for 52 matches.

## Release decisions

1. Requalify a pinned Directory image with `golang.org/x/net` 0.62.0 or later against the listed advisory.
2. Requalify a pinned Keycloak image covering the Java and Red Hat updates below. The fixed versions are component versions reported by Grype. A Keycloak version alone cannot establish that a candidate includes the operating system fixes.
3. Four SQLite advisories have no vendor fix in this inventory. The OpenJDK advisory CVE-2026-91403 has vendor status `wont-fix`. These require an explicit disposition if they persist after repinning. The current release policy rejects them.

| Image | Installed package | Reported fixed versions | Advisories grouped by fix |
|---|---|---|---|
| directory | `golang.org/x/net v0.60.0` | 0.62.0 | GO-2026-6860 |
| oidc | `bcprov-jdk18on 1.84` | 1.85 | GHSA-9pwp-9qqc-pr26, GHSA-qp49-qgx5-5m26 |
| oidc | `ca-certificates 2025.2.80_v9.0.305-91.el9` | 0:2026.2.92_v9.0.319-90.3.el9_8 | CVE-2026-114406 |
| oidc | `guava 33.5.0-jre` | 33.7.2 | GHSA-xxph-c9ww-hj94 |
| oidc | `jackson-core 2.21.2` | 2.21.4 | GHSA-r7wm-3cxj-wff9 |
| oidc | `jackson-core 2.21.2` | 2.21.7 | GHSA-7hhh-6rmp-j9qf, GHSA-p6pp-m3f8-5c89 |
| oidc | `jackson-databind 2.21.2` | 2.21.4 | GHSA-j3rv-43j4-c7qm, GHSA-rmj7-2vxq-3g9f |
| oidc | `jackson-databind 2.21.2` | 2.21.6 | GHSA-q4xh-88c3-wmh7 |
| oidc | `jackson-databind 2.21.2` | 2.21.7 | GHSA-cxp5-3px4-pw24, GHSA-wv8q-qhhj-9h54 |
| oidc | `java-21-openjdk-headless 1:21.0.11.0.10-2.el9` | 1:21.0.12.0.8-1.2.el9 | CVE-2026-47063 |
| oidc | `java-21-openjdk-headless 1:21.0.11.0.10-2.el9` | 1:21.0.13.0.9-1.2.el9 | CVE-2026-91415 |
| oidc | `java-21-openjdk-headless 1:21.0.11.0.10-2.el9` | 1:21.0.13.1.2-1.2.el9 | CVE-2026-114938, CVE-2026-114939, CVE-2026-114940, CVE-2026-114941, CVE-2026-114942 |
| oidc | `java-21-openjdk-headless 1:21.0.11.0.10-2.el9` | wont-fix | CVE-2026-91403 |
| oidc | `keycloak-services 26.6.3` | 26.6.4 | GHSA-32h4-44jj-c5vx, GHSA-f5p5-6xmx-p252, GHSA-j97h-3f8r-mrjr, GHSA-v3f7-2p4r-mwfw |
| oidc | `keycloak-services 26.6.3` | 26.6.6 | GHSA-4gv3-mc9p-5wqc |
| oidc | `libacl 2.3.1-4.el9` | 0:2.4.0-1.el9_8 | CVE-2026-54369 |
| oidc | `micrometer-core 1.16.3` | 1.16.6 | GHSA-g3pr-3p32-fp23, GHSA-w737-wx49-qj23 |
| oidc | `netty-codec 4.1.133.Final` | 4.1.136.Final | GHSA-558v-64gr-wgg4 |
| oidc | `netty-codec-haproxy 4.1.133.Final` | 4.1.135.Final | GHSA-cc37-9q2j-3hfv, GHSA-h2qv-fj59-j46j |
| oidc | `netty-codec-haproxy 4.1.133.Final` | 4.1.136.Final | GHSA-q6cq-mhr2-jmr5 |
| oidc | `netty-codec-http 4.1.133.Final` | 4.1.136.Final | GHSA-6jqx-86gh-f27w, GHSA-jppx-w49h-x2qq, GHSA-mvh2-crg5-v77c |
| oidc | `netty-codec-http2 4.1.133.Final` | 4.1.136.Final | GHSA-93wv-jw9v-4972 |
| oidc | `netty-handler 4.1.133.Final` | 4.1.135.Final | GHSA-3qp7-7mw8-wx86, GHSA-c653-97m9-rcg9, GHSA-x4gw-5cx5-pgmh |
| oidc | `netty-handler 4.1.133.Final` | 4.1.137.Final | GHSA-c4c3-7fpv-j4q5 |
| oidc | `netty-resolver-dns 4.1.133.Final` | 4.1.135.Final | GHSA-5pvg-856g-cp85, GHSA-676x-f7gg-47vc |
| oidc | `pcre2 10.40-6.el9` | 0:10.40-7.el9_8 | CVE-2026-103111, CVE-2026-86145, CVE-2026-89161 |
| oidc | `pcre2-syntax 10.40-6.el9` | 0:10.40-7.el9_8 | CVE-2026-103111, CVE-2026-86145, CVE-2026-89161 |
| oidc | `postgresql 42.7.11` | 42.7.12 | GHSA-j92g-9f8w-j867 |
| oidc | `quarkus-vertx-http 3.33.2` | 3.33.2.1 | GHSA-qcxp-gm7m-4j5v |
| oidc | `sqlite-libs 3.34.1-10.el9_8` | 0:3.34.1-11.el9_8 | CVE-2026-11822, CVE-2026-11824 |
| oidc | `sqlite-libs 3.34.1-10.el9_8` | not-fixed | CVE-2026-119373, CVE-2026-119374, CVE-2026-119379, CVE-2026-119586 |

## Source and evidence identities

The reference for each archive appears below. The release carries its OCI configuration digest, archive SHA-256, SPDX document, pinned application source and third-party notices. The report covers the offline image inventories. The host packages, application binaries, compilation locks and registry scans have their own release checks.

* `ghcr.io/agntcy/dir-apiserver:v1.8.0@sha256:6b49d53c22e049b16d25d588b1f022c92cf573872f19ae55636d52252eb5522e`
* `docker.io/library/haproxy:3.2-alpine@sha256:96ec3c75a9264ba94e733eeacb44051ed6e7b79bb77a73c2c36f236b6423f1f0`
* `ghcr.io/agntcy/oasf-schema:1.1.0@sha256:01df69976950fc321ebab2b6af069466f9524d88cfa9d5d16edac5bfc43f6294`
* `ghcr.io/agntcy/oasf-server:v2.0.0@sha256:4ef8f82f1c2a5b9dc703e208ef8764a558ec0301f7459a7073d2d8758d3d5f9f`
* `quay.io/keycloak/keycloak@sha256:9b0330756022422149aa6502eb2def8cd47c6e1b000c7c65cdb13e7c0133e992`
* `ghcr.io/agntcy/slim:3.4.6@sha256:54fde7ce0ef8efa6a61fee47996e941e87acb4e62284e5d9c00eb761295619b7`
