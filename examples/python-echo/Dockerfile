# Filesystem of the python-echo harness. scripts/build-python-harness.py builds
# it, exports it and packs it into harness.ext4: it never runs as a container.
# The base is pinned by digest; the harness runs chrooted in this filesystem as
# an unprivileged user, read-only, with /dev, /proc, /run, /tmp and
# /var/lib/agent provided by the guest.
FROM python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca
COPY agentcapsule_harness.py harness.py /opt/harness/
RUN python3 -m compileall -q /opt/harness && chmod -R a+rX /opt/harness && mkdir -p /var/lib/agent
