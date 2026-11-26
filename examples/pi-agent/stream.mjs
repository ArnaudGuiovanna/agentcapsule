// Only assistant text is public. Summaries, tool calls and provider errors stay
// in the guest. Split on LF, as other Unicode line separators are valid in JSON.
import { spawn } from "node:child_process";
import { once } from "node:events";
import { pathToFileURL } from "node:url";

async function* jsonEvents(stream) {
  stream.setEncoding("utf8");
  let rest = "";
  for await (const chunk of stream) {
    const parts = (rest + chunk).split("\n");
    rest = parts.pop();
    for (const line of parts) yield JSON.parse(line);
  }
  if (rest) yield JSON.parse(rest);
}

export async function runPi(program, args, { cwd, env, prompt, onCompaction } = {}) {
  const child = spawn(program, args, {
    cwd, env, stdio: [prompt === undefined ? "inherit" : "pipe", "pipe", "inherit"],
  });
  const result = new Promise(resolve => {
    child.once("error", () => resolve(1));
    child.once("close", code => resolve(code ?? 1));
  });
  if (prompt !== undefined) {
    // stdin keeps user text opaque, including initial @ or -- CLI syntax.
    child.stdin.on("error", () => {});
    child.stdin.end(prompt);
  }
  let hasDelta = false;
  let completed = false;
  async function text(fragment) {
    if (!process.stdout.write(fragment)) await once(process.stdout, "drain");
  }
  try {
    for await (const event of jsonEvents(child.stdout)) {
      if (event.type === "compaction_end") await onCompaction?.(event);
      if (event.type === "message_start") hasDelta = false;
      const delta = event.assistantMessageEvent;
      if (event.type === "message_update" && delta?.type === "text_delta") {
        await text(delta.delta);
        hasDelta = true;
      }
      if (event.type === "message_end" && event.message?.role === "assistant") {
        const message = event.message;
        if (!hasDelta) {
          for (const part of message.content ?? []) {
            if (part.type === "text") await text(part.text);
          }
        }
        completed = message.stopReason === "stop";
      }
      if (event.type === "agent_settled" && event.aborted) completed = false;
    }
  } catch {
    child.kill();
    await result;
    return 1;
  }
  const code = await result;
  return code || (completed ? 0 : 1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [program, ...args] = process.argv.slice(2);
  process.exitCode = await runPi(program, [...args, "--mode", "json"]);
}
