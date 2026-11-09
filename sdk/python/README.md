# Python harness SDK

`agentcapsule_harness.py` lets you write an Agent Capsule harness in Python: the
program that runs an agent inside its microVM. It is one file with no dependency
beyond the Python standard library (3.9 or later), and it implements the guest side
of the private `capsule.v1` protocol, like the Go reference harness
(`cmd/capsule-echo`). [examples/python-echo](../../examples/python-echo) is a
complete harness built with it.

```python
from agentcapsule_harness import WORKING, Harness, text_result

harness = Harness()

@harness.on_invoke
def invoke(invocation, tx):
    tx.execute("CREATE TABLE IF NOT EXISTS seen (text TEXT)")
    tx.execute("INSERT INTO seen VALUES (?)", (invocation.text,))
    return text_result("echo: " + invocation.text)

harness.run()
```

## What the platform guarantees and expects

- **Start.** `capsule-init` starts the harness as an unprivileged user, chrooted in
  the harness image, with `PATH=/usr/bin:/bin`, `LANG=C` and `TMPDIR=/tmp`; stdout
  and stderr are discarded. File descriptor 3 carries the boot record (identity,
  data directory, platform socket), file descriptor 4 a bound Unix listener.
  `Harness()` reads both.
- **State.** The agent's private, encrypted data directory is
  `/var/lib/agent`; the SDK keeps its SQLite database (`harness.db`) there. Use
  it for everything the agent must remember: it survives sleep and wake, nothing
  else does. The image itself is read-only.
- **Exactly once.** `on_invoke(invocation, tx)` and `on_event(event, tx)` run inside
  the SQLite transaction that also records the event as handled and stores the
  result. The platform may deliver an event again (after a crash or a lost
  acknowledgment); the SDK then returns the stored result without calling your
  handler. A handler must only change the database through `tx`: no network call,
  no other file, no `COMMIT`, nothing in `capsule_*` tables.
- **Results.** An invocation returns JSON, usually `text_result("...")`
  (`{"content": [{"type": "text", "text": "..."}]}`), at most 512 KiB.
- **Deferred results.** The harness cannot call the platform while it is handling a
  delivery (that call would wait for the delivery to end). To use the model or read
  an attachment, record the work in `tx`, return `WORKING`, and finish in
  `on_background(harness)`, which runs in its own thread after each delivery and
  every few seconds: call `harness.platform.complete_llm(...)`, then
  `harness.platform.complete_invocation(key, operation_id, "completed", content)`.
  `harness.platform.find_agents([10302])` searches the organization's agents by
  OASF skill IDs in the private Directory the same way (`/find` in the example).
  Every platform call takes an idempotency key: a retry with the same key replays
  the outcome instead of doing it twice. Use keys derived from the event or
  operation ID.
- **Revocation.** `harness.store.fence(subject)` calls arrive from the platform when
  a participant is revoked; an event involving a fenced subject is refused before
  your handler runs. Background work goes through
  `harness.store.local(subjects, fn)`, which refuses fenced subjects the same way.
- **Stop.** The supervisor sends `SIGTERM` before the agent sleeps; `run()` stops
  accepting requests, lets those already admitted finish, and returns. Exit
  promptly: the volume is closed after the harness exits.
- **Peer check.** Only the supervisor's UID may call the harness; the SDK checks it
  with `SO_PEERCRED` on every connection.

## Packaging

A harness image must contain the interpreter and everything it imports, plus the
directories `/dev`, `/proc`, `/run`, `/tmp` and `/var/lib/agent`. The reference
build is the repository's Dagger module: it starts from an official Python image
pinned by digest, adds the SDK and the harness, and packs the container's
filesystem:

```bash
dagger call python-echo export --path=./build/python-echo
dagger call publish --pkg=./build/python-echo --registry=ghcr.io --repository=acme/python-echo \
  --tag=1.0.0 --username=<user> --password=env:GHCR_TOKEN
```

Without Dagger, [scripts/build-python-harness.py](../../scripts/build-python-harness.py)
does the same with plain Docker (`--output ./build/python-echo`, then
`agentcapsule-harness push --dir ./build/python-echo/package ...`).

The entrypoint in `harness.yaml` runs the interpreter in isolated mode
(`/usr/local/bin/python3 -I /opt/harness/harness.py`). See
[docs/registry.md](../../docs/registry.md) for signing and importing.

## Tests

`internal/capsuleprotocol/python_harness_test.go` runs `examples/python-echo` as a
real process and drives it with the Go client that `capsule-init` uses:
negotiation, health, replays and conflicts, fences, a deferred model answer through
the platform channel, a clean exit on `SIGTERM`, state across restarts and refusal of
other peers. The product KVM campaign then runs the packed image in a microVM.
