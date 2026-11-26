import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { defaults, parseJob } from "./profile.mjs";

const control = (action, fields = {}) => ({ type: "json", json: { agentcapsule_pi: { action, ...fields } } });
const prompt = text => ({ type: "text", text });
const direct = (...content) => ({ kind: "invocation", content, text: content.map(p => p.text ?? JSON.stringify(p.json)).join("\n\n") });

test("profile hints require a typed direct invocation followed by a prompt", () => {
  const hint = control("invoke", defaults);
  assert.equal(parseJob(direct(hint, prompt("question"))).text, "question");
  assert.deepEqual(parseJob(direct(control("status"))), { status: true });
  assert.equal(parseJob(direct(prompt(JSON.stringify(hint.json)))).profile, defaults);
  assert.throws(() => parseJob(direct(hint)));
  assert.throws(() => parseJob({ ...direct(hint, prompt("answer")), kind: "request" }));
  assert.throws(() => parseJob({ ...direct(control("status")), kind: "request" }));
  for (const bad of [{ context_window: 8 }, { max_output_tokens: 32000 }, { alias: "a b" }, { provider: "own-url" }]) {
    assert.throws(() => parseJob(direct(control("invoke", { ...defaults, ...bad }), prompt("hi"))));
  }
});

// Use the locked Pi executable in a deterministic loopback lab. The publisher
// runs this against the npm installation that will actually enter its image.
test("real Pi takes tools, resumes a compacted session and isolates model profiles", { skip: !process.env.PI_TEST_BIN, timeout: 120000 }, async t => {
  const home = await mkdtemp(join(tmpdir(), "pi-acceptance-"));
  t.after(() => rm(home, { recursive: true, force: true }));
  const seen = [];
  const calls = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    if (req.url === "/agents/peer-2") {
      calls.push(body);
      const metadata = { agentcapsule: { request_state: body.method === "SendMessage" ? "PENDING_APPROVAL" : "REPLIED" } };
      const task = { id: "arq_123", status: { state: body.method === "SendMessage" ? "TASK_STATE_SUBMITTED" : "TASK_STATE_COMPLETED" }, metadata };
      if (body.method === "GetTask") task.artifacts = [{ parts: [{ text: "reviewed by peer" }] }];
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: body.method === "SendMessage" ? { task } : task }));
    }
    const messages = body.messages;
    const tools = body.tools?.map(t => t.function.name) ?? [];
    seen.push({ model: body.model, messages, tools });
    let text = "answer from fixture";
    let use;
    let reported = 400;
    const last = messages.at(-1);
    const lastText = JSON.stringify(last.content);
    if (!tools.length) {
      text = "compact summary from fixture";
    } else if (last.role === "tool" && JSON.stringify(messages.findLast(m => m.role === "user")?.content).includes("exercise the workspace")) {
      const first = messages.findLastIndex(m => m.role === "user");
      const history = messages.slice(first + 1).filter(m => m.role === "tool");
      const sequence = [
        ["edit", { path: "exercise.md", edits: [{oldText:"alpha", newText:"bravo"}] }],
        ["read", { path: "exercise.md" }],
        ["bash", { command: "rm -- exercise.md" }],
      ];
      if (history.length === 3) assert.match(lastText, /bravo/);
      const next = sequence[history.length - 1];
      if (next) use = { name: next[0], arguments: JSON.stringify(next[1]) };
      else text = "file created, edited, read and deleted";
    } else if (last.role === "tool") {
      text = lastText.includes("reviewed by peer") ? "received the review" : "waiting for consent";
    } else if (lastText.includes("exercise the workspace")) {
      use = { name: "write", arguments: JSON.stringify({path:"exercise.md", content:"alpha"}) };
    } else if (lastText.includes("ask peer now")) {
      use = { name: "agent_ask", arguments: JSON.stringify({ agent_id: "peer-2", question: "review the passage" }) };
    } else if (lastText.includes("look up the review")) {
      use = { name: "agent_request_status", arguments: JSON.stringify({ agent_id: "peer-2", request_id: "arq_123" }) };
    } else if (lastText.includes("long history")) {
      reported = 7500;
    }
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    const chunk = (delta, reason, usage) => res.write("data: " + JSON.stringify({
      id: "message", object: "chat.completion.chunk", created: 1, model: body.model,
      choices: [{ index: 0, delta, finish_reason: reason }], usage,
    }) + "\n\n");
    chunk({ role: "assistant" }, null);
    chunk(use ? { tool_calls: [{ index: 0, id: "call_" + seen.length, type: "function", function: use }] } : { content: text }, null);
    chunk({}, use ? "tool_calls" : "stop", { prompt_tokens: reported, completion_tokens: 10, total_tokens: reported + 10 });
    res.end("data: [DONE]\n\n");
  });
  await new Promise((ok, fail) => server.once("error", fail).listen(0, "127.0.0.1", ok));
  t.after(() => server.close());
  const base = "http://127.0.0.1:" + server.address().port;
  async function invoke(job) {
    const entry = new URL("./profile.mjs", import.meta.url).href;
    const source = 'import {runJob} from ' + JSON.stringify(entry)
      + '; const b=[]; for await (const x of process.stdin) b.push(x); process.exitCode=await runJob(JSON.parse(Buffer.concat(b)), {pi:process.env.PI_TEST_BIN});';
    const child = spawn(process.execPath, ["--input-type=module", "-e", source], { env: {
      ...process.env, HOME: home, AGENTCAPSULE_MODEL_URL: base, AGENTCAPSULE_A2A_URL: base,
      PI_OFFLINE: "1", PI_SKIP_VERSION_CHECK: "1", PI_TELEMETRY: "0",
    } });
    let output = "";
    let err = "";
    child.stdout.on("data", b => output += b);
    child.stderr.on("data", b => err += b);
    child.stdin.end(JSON.stringify(job));
    const code = await new Promise((ok, fail) => { child.once("error", fail); child.once("close", ok); });
    assert.equal(code, 0, err + " " + output);
    return output;
  }
  const profile = control("invoke", { ...defaults, context_window: 8192, max_output_tokens: 512 });
  assert.equal(await invoke(direct(profile, prompt("ask peer now"))), "waiting for consent");
  assert.deepEqual(calls.map(c => c.method), ["SendMessage"]);
  assert.equal(calls[0].params.message.parts[0].text, "review the passage");
  assert.equal(calls[0].params.configuration.returnImmediately, true);
  assert.equal(await invoke(direct(profile, prompt("look up the review"))), "received the review");
  assert.deepEqual(calls.map(c => c.method), ["SendMessage", "GetTask"]);
  assert.equal(await invoke(direct(profile, prompt("exercise the workspace"))), "file created, edited, read and deleted");
  await assert.rejects(readFile(join(home, "workspace", "exercise.md")), { code: "ENOENT" });
  const names = seen[0].tools;
  for (const tool of ["read", "write", "edit", "bash", "agent_discover", "agent_ask", "agent_request_status"]) assert.ok(names.includes(tool), tool);
  assert.equal(await invoke(direct(profile, prompt("long history " + "marker ".repeat(3500)))), "answer from fixture");
  assert.equal(await invoke(direct(profile, prompt("continue after compaction"))), "answer from fixture");
  const stats = JSON.parse(await invoke(direct(control("status"))));
  assert.equal(stats.last_compaction?.outcome, "completed");
  assert.ok(stats.last_compaction.tokens_before > 0);
  assert.ok(!JSON.stringify(stats).includes("summary from fixture"));
  assert.ok(seen.at(-1).messages.some(m => JSON.stringify(m).includes("compact summary from fixture")));
  const sessionDir = join(home, "pi-sessions");
  const session = (await readdir(sessionDir)).find(name => name.endsWith(".jsonl"));
  const entries = (await readFile(join(sessionDir, session), "utf8")).trim().split("\n").map(JSON.parse);
  assert.ok(entries.some(e => e.type === "compaction" && e.summary.includes("compact summary from fixture")));
  // A v0.1.5 example ran Pi with HOME as its cwd. Preserve that history
  // untouched and resume it in the writable workspace on the next invocation.
  const beforeUpgrade = await readFile(join(sessionDir, session), "utf8");
  const old = beforeUpgrade.split("\n");
  old[0] = JSON.stringify({ ...JSON.parse(old[0]), cwd: home });
  const legacy = old.join("\n");
  await writeFile(join(sessionDir, session), legacy);
  await invoke(direct(profile, prompt("resume v0.1.5")));
  assert.ok(seen.at(-1).messages.some(m => JSON.stringify(m).includes("compact summary from fixture")));
  assert.equal(await readFile(join(sessionDir, session), "utf8"), legacy);
  await invoke(direct(control("invoke", { ...defaults, alias: "other-profile" }), prompt("separate history")));
  assert.equal(seen.at(-1).model, "other-profile");
  assert.ok(!JSON.stringify(seen.at(-1).messages).includes("long history"));
  await invoke({ ...direct(prompt("inbound question")), kind: "request" });
  assert.ok(!JSON.stringify(seen.at(-1).messages).includes("long history"));
});
