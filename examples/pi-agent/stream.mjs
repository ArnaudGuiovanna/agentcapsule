// Run unmodified Pi's JSON mode. Only assistant text is public invocation
// output. Pi's tool calls, tool results, thinking and session records stay local.
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";

const [program, ...args] = process.argv.slice(2);
const child = spawn(program, [...args, "--mode", "json"], {
  stdio: ["inherit", "pipe", "inherit"],
});
const result = new Promise((resolve) => {
  child.once("error", () => resolve(1));
  child.once("close", (code) => resolve(code ?? 1));
});

async function text(fragment) {
  if (!process.stdout.write(fragment)) await once(process.stdout, "drain");
}

let hasDelta = false;
let completed = false;
try {
  for await (const line of createInterface({ input: child.stdout, crlfDelay: Infinity })) {
    const event = JSON.parse(line);
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
  }
} catch {
  child.kill();
  process.exitCode = 1;
}
const code = await result;
if (code !== 0 || !completed) process.exitCode = code || 1;
