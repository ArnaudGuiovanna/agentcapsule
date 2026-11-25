# An ordinary agent image: Python, the official OpenAI SDK and agent.py. It
# contains nothing of Agent Capsule. scripts/build-adapted-harness.py builds it,
# adds the adapter (/agentcapsule/capsule-adapter and adapter.json) to its
# filesystem and packs it into harness.ext4: it never runs as a container.
FROM ghcr.io/arnaudguiovanna/agentcapsule/runtime:python-3.13-20261125@sha256:c6211d5110e5afb9b1282a13d9cc429a16c65b2e4a6f4dd1237be17f46d4bf82
COPY requirements.txt agent.py /opt/agent/
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /opt/agent/requirements.txt \
 && python3 -m compileall -q /opt/agent && chmod -R a+rX /opt/agent
