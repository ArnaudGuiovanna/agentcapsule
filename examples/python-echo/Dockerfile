# Filesystem of the python-echo harness. scripts/build-python-harness.py builds
# it, exports it and packs it into harness.ext4: it never runs as a container.
# The base is pinned by digest; the harness runs chrooted in this filesystem as
# an unprivileged user, read-only, with /dev, /proc, /run, /tmp and
# /var/lib/agent provided by the guest.
FROM ghcr.io/arnaudguiovanna/agentcapsule/runtime:python-3.13-20261121@sha256:7ab5ef55aca5b0ff15aa71935f3fa577f2b047781923929278c690e55e880fc5
COPY agentcapsule_harness.py harness.py /opt/harness/
RUN python3 -m compileall -q /opt/harness && chmod -R a+rX /opt/harness && mkdir -p /var/lib/agent
