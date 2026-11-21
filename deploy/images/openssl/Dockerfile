# syntax=docker/dockerfile:1
ARG BUILD_BASE=python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca
ARG RUNTIME_BASE=python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca
FROM ${BUILD_BASE} AS build
RUN apk add --no-cache alpine-sdk linux-headers perl
RUN adduser -D builder && addgroup builder abuild && mkdir -p /work/main/openssl /out && chown -R builder:builder /work /out
WORKDIR /work/main/openssl
ADD --chown=builder:builder --chmod=0644 --checksum=sha256:3db5f8f76df5014cc263e59f21c3399766b35c2e4d3cdbf1cbaab5c6138a0c2d https://raw.githubusercontent.com/alpinelinux/aports/0f4c7e8d0f5f7cebbdc2156eca4391080b732bf2/main/openssl/APKBUILD ./APKBUILD
ADD --chown=builder:builder --chmod=0644 --checksum=sha256:0b3a36c0f1b3d8e0adcf02c251374ce4d2578b0c9f4b88207bf85c5c1b58c7d8 https://raw.githubusercontent.com/alpinelinux/aports/0f4c7e8d0f5f7cebbdc2156eca4391080b732bf2/main/openssl/auxv.patch ./auxv.patch
ADD --chown=builder:builder --chmod=0644 --checksum=sha256:441311401af66e9f1b4b38730827ade609669196f91c56b82351a7226b903755 https://raw.githubusercontent.com/alpinelinux/aports/0f4c7e8d0f5f7cebbdc2156eca4391080b732bf2/main/openssl/openssl-fips.post-install ./openssl-fips.post-install
ADD --chown=builder:builder --chmod=0644 --checksum=sha256:50f7cc52fb146703379ca043d17e204c4fda99c684efe3db6d6f3ae1d175bd2a https://raw.githubusercontent.com/alpinelinux/aports/0f4c7e8d0f5f7cebbdc2156eca4391080b732bf2/main/openssl/CVE-2026-88822.patch ./CVE-2026-88822.patch
ADD --chown=builder:builder --chmod=0644 --checksum=sha256:a945077c0a978dbfe5af5e4f7174a2151466547f8fb94562f395baa7b6b7c147 https://raw.githubusercontent.com/alpinelinux/aports/0f4c7e8d0f5f7cebbdc2156eca4391080b732bf2/main/openssl/CVE-2026-88823.patch ./CVE-2026-88823.patch
ADD --chown=builder:builder --chmod=0644 --checksum=sha256:93d8e82fdc995172a6d5cc6952491658106191bd5ac221d34596adbddfcd1afe https://raw.githubusercontent.com/alpinelinux/aports/0f4c7e8d0f5f7cebbdc2156eca4391080b732bf2/main/openssl/CVE-2026-95691.patch ./CVE-2026-95691.patch
ADD --chown=builder:builder --chmod=0644 --checksum=sha256:0e328604c0038de6629a29322ae5f02d2f5f5128c2625b57ca64262efab99e05 https://raw.githubusercontent.com/alpinelinux/aports/0f4c7e8d0f5f7cebbdc2156eca4391080b732bf2/main/openssl/CVE-2026-95692.patch ./CVE-2026-95692.patch
ADD --chown=builder:builder --chmod=0644 --checksum=sha256:77d3759d279c71af59629c4a0fa82d8272a099762f2fa9e3f66d7ca5ed544157 https://raw.githubusercontent.com/alpinelinux/aports/0f4c7e8d0f5f7cebbdc2156eca4391080b732bf2/main/openssl/CVE-2026-107496.patch ./CVE-2026-107496.patch
ADD --chown=builder:builder --chmod=0644 --checksum=sha256:603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a https://distfiles.alpinelinux.org/distfiles/v3.24/openssl-3.5.9.tar.gz ./openssl-3.5.9.tar.gz
COPY --chown=builder:builder *.patch ./
USER builder
ENV JOBS=6 MAKEFLAGS=-j6 REPODEST=/out
RUN patch -p1 < alpine-recipe.patch && abuild-keygen -n -a
USER root
RUN cp ~builder/.abuild/*.rsa.pub /etc/apk/keys/
USER builder
RUN if ! abuild -r > /tmp/openssl-build.log 2>&1; then tail -70 /tmp/openssl-build.log; exit 1; fi \
    && grep -E "All tests successful|Result: PASS|Build complete|Updating .*repository index" /tmp/openssl-build.log \
    && cp "$HOME"/.abuild/*.rsa.pub /out/

FROM ${RUNTIME_BASE} AS runtime
USER root
ARG RUNTIME_USER=root
RUN --mount=type=bind,from=build,source=/out,target=/packages \
    set -eu; set -- /packages/*.rsa.pub; key=${1##*/}; cp "/packages/$key" "/etc/apk/keys/$key"; \
    set -- /packages/main/x86_64/libcrypto3-*.apk /packages/main/x86_64/libssl3-*.apk; \
    if apk info -e openssl; then set -- "$@" /packages/main/x86_64/openssl-3.5.9-r20261121.apk; fi; \
    apk --no-network add "$@"; rm "/etc/apk/keys/$key"
USER ${RUNTIME_USER}
