"""python-echo: a reference harness written in Python.

* A message is answered at once with "python echo #N: <text>". N counts the
  messages this agent has ever received; it lives in the agent's encrypted
  SQLite database, so it survives sleep and wake.
* "/llm <alias> <text>" asks the organization's model through its alias. The
  answer cannot be produced during the delivery (the platform channel waits for
  it to end), so the harness records the work, answers "working", and posts the
  model's answer afterwards.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agentcapsule_harness import WORKING, Harness, PlatformError, text_result  # noqa: E402

SCHEMA = """
CREATE TABLE IF NOT EXISTS echo_counter (id INTEGER PRIMARY KEY CHECK (id = 1), n INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS llm_work (
  event_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL, alias TEXT NOT NULL, prompt TEXT NOT NULL,
  answer TEXT, done INTEGER NOT NULL DEFAULT 0)
"""

# Codes after which retrying the same call cannot succeed.
PERMANENT = {"unauthorized", "not_found", "mandate", "conflict", "expired", "transition", "invalid", "quota_exceeded", "rejected"}

harness = Harness()


def schema(tx):
    for statement in SCHEMA.split(";"):
        if statement.strip():
            tx.execute(statement)


@harness.on_invoke
def invoke(invocation, tx):
    schema(tx)
    text = invocation.text.strip()
    if text.startswith("/llm "):
        alias, _, prompt = text[len("/llm "):].strip().partition(" ")
        if not alias or not prompt.strip():
            return text_result("Usage: /llm <alias> <text>.")
        if harness.platform is None:
            return text_result("The platform channel is unavailable; the model cannot be reached.")
        # The durable intent commits with the delivery; the call happens after.
        tx.execute("INSERT INTO llm_work(event_id, operation_id, alias, prompt) VALUES (?,?,?,?)",
                   (invocation.event_id, invocation.operation_id, alias, prompt.strip()))
        return WORKING
    tx.execute("INSERT INTO echo_counter(id, n) VALUES (1, 1) ON CONFLICT(id) DO UPDATE SET n = n + 1")
    n = tx.execute("SELECT n FROM echo_counter WHERE id = 1").fetchone()[0]
    return text_result("python echo #%d: %s" % (n, text))


@harness.on_event
def event(event, tx):
    # Peer requests and notifications are acknowledged and ignored.
    return b""


@harness.on_background
def background(h):
    def pending(tx):
        schema(tx)
        return tx.execute("SELECT event_id, operation_id, alias, prompt, answer FROM llm_work WHERE done = 0 "
                          "ORDER BY rowid LIMIT 1").fetchone()

    row = h.store.local(["agent/" + h.agent_id], pending)
    if row is None or h.platform is None:
        return False
    event_id, operation_id, alias, prompt, answer = row
    if answer is None:
        try:
            result = h.platform.complete_llm("llm-" + event_id, alias, [{"role": "user", "content": prompt}], max_tokens=512)
            answer = (result.get("text") or "").strip() or "(empty answer)"
        except PlatformError as error:
            if error.code not in PERMANENT:
                raise  # retried later with the same idempotency key
            answer = "The model call failed (%s)." % error.code
        h.store.local(["agent/" + h.agent_id],
                      lambda tx: tx.execute("UPDATE llm_work SET answer = ? WHERE event_id = ?", (answer, event_id)))
    try:
        h.platform.complete_invocation("done-" + operation_id, operation_id, "completed", [{"type": "text", "text": answer}])
    except PlatformError as error:
        if error.code not in PERMANENT:
            raise
        # Already closed by the platform (timeout, cancellation, deletion).
    h.store.local(["agent/" + h.agent_id], lambda tx: tx.execute("UPDATE llm_work SET done = 1 WHERE event_id = ?", (event_id,)))
    return True


if __name__ == "__main__":
    harness.run()
