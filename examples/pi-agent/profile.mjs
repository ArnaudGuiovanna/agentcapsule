// Entry point for a job-json adapter command. Only a typed control part from
// a direct invocation can select a model profile. Settings live for one run.
import { createHash } from "node:crypto";
import { access, mkdir, mkdtemp, readFile, realpath, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runPi } from "./stream.mjs";

const image = dirname(fileURLToPath(import.meta.url));
const template = JSON.parse(await readFile(join(image, "models.json"), "utf8"));
const defaultModel = template.providers["capsule-openai"].models[0];
export const defaults = {
  provider: "capsule-openai", alias: defaultModel.id,
  context_window: defaultModel.contextWindow, max_output_tokens: defaultModel.maxTokens,
};

function checkedProfile(value) {
  const { provider, alias, context_window, max_output_tokens } = value;
  if (!Object.hasOwn(template.providers, provider)
      || typeof alias !== "string" || !alias.length || Buffer.byteLength(alias) > 100
      || !alias.isWellFormed() || /[ \t\r\n\x00]/u.test(alias)
      || !Number.isInteger(context_window) || context_window < 1024 || context_window > 2147483647
      || !Number.isInteger(max_output_tokens) || max_output_tokens < 1
      || max_output_tokens > 1000000 || max_output_tokens >= context_window) {
    throw new Error("invalid Pi model profile");
  }
  return { provider, alias, context_window, max_output_tokens };
}

export function parseJob(job) {
  const parts = job.content ?? [];
  const first = parts[0];
  if (first?.type !== "json" || !Object.hasOwn(first.json ?? {}, "agentcapsule_pi")) {
    return { profile: defaults, text: job.text };
  }
  if (job.kind !== "invocation") throw new Error("peer cannot use Pi controls");
  const control = first.json.agentcapsule_pi;
  if (!control || typeof control !== "object" || Object.keys(first.json).length !== 1) {
    throw new Error("invalid Pi control");
  }
  if (control.action === "status" && Object.keys(control).length === 1 && parts.length === 1) {
    return { status: true };
  }
  if (control.action !== "invoke" || parts.length < 2 || Object.keys(control).length !== 5) {
    throw new Error("Pi invocation needs a model profile and a prompt");
  }
  const text = parts.slice(1).map(p => p.type === "text" ? p.text : JSON.stringify(p.json)).join("\n\n");
  return { profile: checkedProfile(control), text };
}

const reasonValues = ["manual", "threshold", "overflow"];
const outcomes = ["completed", "failed", "aborted"];

function publicCompaction(data) {
  if (!data || !outcomes.includes(data.outcome) || !reasonValues.includes(data.reason)) return null;
  const result = { outcome: data.outcome, reason: data.reason };
  for (const key of ["tokens_before", "estimated_tokens_after"]) {
    if (Number.isSafeInteger(data[key]) && data[key] >= 0) result[key] = data[key];
  }
  return result;
}

async function lastCompaction(path) {
  try {
    return publicCompaction(JSON.parse(await readFile(path, "utf8")));
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

export async function runJob(job, { home = process.env.HOME, pi = join(image, "release/node_modules/.bin/pi") } = {}) {
  const input = parseJob(job);
  const state = join(home, ".pi-agent");
  const last = join(state, "last-compaction.json");
  if (input.status) {
    process.stdout.write(JSON.stringify({ version: 1, last_compaction: await lastCompaction(last) }) + "\n");
    return 0;
  }
  const p = input.profile;
  const provider = { ...template.providers[p.provider], models: [{
    id: p.alias, contextWindow: p.context_window, maxTokens: p.max_output_tokens,
  }] };
  // The adapter may bind its model endpoint to another loopback port.
  if (process.env.AGENTCAPSULE_MODEL_URL) {
    const modelURL = new URL(process.env.AGENTCAPSULE_MODEL_URL);
    if (modelURL.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(modelURL.hostname)) {
      throw new Error("invalid loopback model endpoint");
    }
    provider.baseUrl = modelURL.origin + (p.provider === "capsule-openai" ? "/v1" : "");
  }
  const workspace = join(home, "workspace");
  const dir = await mkdtemp(join(tmpdir(), "capsule-pi-"));
  try {
    await mkdir(state, { recursive: true, mode: 0o700 });
    await mkdir(workspace, { recursive: true, mode: 0o700 });
    await writeFile(join(dir, "models.json"), JSON.stringify({ providers: { [p.provider]: provider } }));
    const reserveTokens = Math.min(16384, Math.floor(p.context_window / 4));
    const keepRecentTokens = Math.min(20000, Math.floor(p.context_window / 3));
    await writeFile(join(dir, "settings.json"), JSON.stringify({
      compaction: { enabled: true, reserveTokens, keepRecentTokens },
    }));
    const args = [pi, "--print", "--mode", "json", "--provider", p.provider,
      "--model", p.alias, "--no-extensions", "-e", join(image, "peers.mjs"),
      "--tools", "read,write,edit,bash,agent_discover,agent_ask,agent_request_status",
      "--append-system-prompt", "Your writable workspace is the current directory. Shared read-only corpora are under /corpus, with INDEX.md in each mount. For peer requests use agent_ask. If consent is pending, report the request ID and use agent_request_status to retrieve its reply."];
    if (job.kind === "invocation") {
      // Preserve v0.1.5 sessions for its default alias. Other provider/alias
      // pairs have separate histories, including when a caller switches back.
      let sessions = join(home, "pi-sessions");
      let fork;
      if (p.provider !== defaults.provider || p.alias !== defaults.alias) {
        const key = createHash("sha256").update(JSON.stringify([p.provider, p.alias])).digest("hex");
        sessions = join(home, "pi-model-sessions", key);
      } else if (await access(sessions).then(() => true, () => false)) {
        // The v0.1.5 developer image used HOME as its working directory. Pi
        // filters --continue by cwd. Fork its latest session once into the
        // new workspace using Pi's own session discovery and migration.
        const manager = join(dirname(await realpath(pi)), "../core/session-manager.js");
        const { findMostRecentSession } = await import(pathToFileURL(manager));
        if (!findMostRecentSession(sessions, workspace)) fork = findMostRecentSession(sessions, home);
      }
      args.push(...(fork ? ["--fork", fork] : ["--continue"]), "--session-dir", sessions);
    } else {
      args.push("--no-session");
    }
    return await runPi(process.execPath, args, {
      cwd: workspace, env: { ...process.env, PI_CODING_AGENT_DIR: dir },
      prompt: input.text, onCompaction: async event => {
        if (job.kind !== "invocation") return;
        const clean = publicCompaction({
          outcome: event.result ? "completed" : event.aborted ? "aborted" : "failed", reason: event.reason,
          tokens_before: event.result?.tokensBefore, estimated_tokens_after: event.result?.estimatedTokensAfter,
        });
        if (clean) {
          const writing = last + "." + process.pid;
          await writeFile(writing, JSON.stringify(clean), { mode: 0o600 });
          await rename(writing, last);
        }
      },
    });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    const job = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    process.exitCode = await runJob(job);
  } catch {
    process.exitCode = 1;
  }
}
