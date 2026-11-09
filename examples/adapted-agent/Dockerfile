# An ordinary agent image: Python, the official OpenAI SDK and agent.py. It
# contains nothing of Agent Capsule. scripts/build-adapted-harness.py builds it,
# adds the adapter (/agentcapsule/capsule-adapter and adapter.json) to its
# filesystem and packs it into harness.ext4: it never runs as a container.
FROM python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca
COPY requirements.txt agent.py /opt/agent/
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /opt/agent/requirements.txt \
 && python3 -m compileall -q /opt/agent && chmod -R a+rX /opt/agent
