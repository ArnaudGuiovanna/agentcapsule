# Build the locked Pi distribution and exercise it with a loopback model before
# copying the runtime into the guest. Both bases are pinned for linux/amd64.
FROM node:26.13.1-bookworm-slim@sha256:40168539433ce47c04c4106f8ca42aee6f493cff42c08dede9e1f2ca0398b05b AS build
WORKDIR /opt/pi/release
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
FROM ubuntu:26.04@sha256:0d5255be560e2d2ddcfbfda88549e9e815ef29e7cd7fc62183d5709e6e2963c6
RUN apt-get update && apt-get install -y --no-install-recommends bash libstdc++6 libatomic1 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/node /usr/local/bin/node
COPY --from=build /opt/pi/release /opt/pi/release
COPY models.json start stream.mjs profile.mjs peers.mjs /opt/pi/
RUN chmod 0755 /opt/pi/start && /usr/local/bin/node --version

# Exercise Pi in its final runtime without shipping the test fixture.
RUN --mount=type=bind,source=profile.test.mjs,target=/opt/pi/profile.test.mjs PI_TEST_BIN=/opt/pi/release/node_modules/.bin/pi node --test /opt/pi/profile.test.mjs
