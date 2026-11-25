# Filesystem of the python-echo harness. scripts/build-python-harness.py builds
# it, exports it and packs it into harness.ext4: it never runs as a container.
# The base is pinned by digest; the harness runs chrooted in this filesystem as
# an unprivileged user, read-only, with /dev, /proc, /run, /tmp and
# /var/lib/agent provided by the guest.
FROM ghcr.io/arnaudguiovanna/agentcapsule/runtime:python-3.13-20261125@sha256:c6211d5110e5afb9b1282a13d9cc429a16c65b2e4a6f4dd1237be17f46d4bf82
COPY agentcapsule_harness.py harness.py /opt/harness/
RUN python3 -m compileall -q /opt/harness && chmod -R a+rX /opt/harness && mkdir -p /var/lib/agent
