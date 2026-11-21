# An ordinary agent image: Python, the official OpenAI SDK and agent.py. It
# contains nothing of Agent Capsule. scripts/build-adapted-harness.py builds it,
# adds the adapter (/agentcapsule/capsule-adapter and adapter.json) to its
# filesystem and packs it into harness.ext4: it never runs as a container.
FROM ghcr.io/arnaudguiovanna/agentcapsule/runtime:python-3.13-20261121@sha256:7ab5ef55aca5b0ff15aa71935f3fa577f2b047781923929278c690e55e880fc5
COPY requirements.txt agent.py /opt/agent/
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: -r /opt/agent/requirements.txt \
 && python3 -m compileall -q /opt/agent && chmod -R a+rX /opt/agent
