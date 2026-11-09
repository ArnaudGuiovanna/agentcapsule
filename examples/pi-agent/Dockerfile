# Pi, the coding agent, packed from an existing installation. Pi itself is not
# changed. scripts/build-pi-harness.py fills this context with the installed Pi
# release (pi/), the Node.js binary it runs on (node) and the one library that
# binary needs beyond Debian's (libatomic.so.1). It then adds capsule-adapter
# and packs the filesystem into harness.ext4: it never runs as a container.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
COPY node /usr/local/bin/node
COPY libatomic.so.1 /usr/local/lib/libatomic.so.1
COPY pi /opt/pi/release
COPY models.json start /opt/pi/
RUN ldconfig && chmod 0755 /usr/local/bin/node /opt/pi/start && chmod -R a+rX /opt/pi && /usr/local/bin/node --version
