// All calls stay on the guest's adapter. Agent Cards are data, never addresses
// to follow. The platform authenticates the agent and enforces consent/mandates.
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

const peerID = { type: "string", pattern: "^[a-zA-Z0-9_-][a-zA-Z0-9._-]{0,99}$" };
const requestID = { type: "string", minLength: 1, maxLength: 200 };
const waitSeconds = { type: "integer", minimum: 0, maximum: 120, description: "Seconds to wait for a reply (default 0). Reuse the request ID to check later." };

function schema(properties, required) {
  return { type: "object", properties, required, additionalProperties: false };
}

async function request(path, signal, body) {
  const base = process.env.AGENTCAPSULE_A2A_URL;
  const url = new URL(base);
  if (url.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(url.hostname)) {
    throw new Error("A2A loopback adapter unavailable");
  }
  const response = await fetch(new URL(path, base), {
    method: body ? "POST" : "GET", redirect: "error",
    headers: { "Content-Type": "application/json", "A2A-Version": "1.0" },
    body: body && JSON.stringify(body),
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(35000)]) : AbortSignal.timeout(35000),
  });
  if (!response.ok) throw new Error("A2A adapter HTTP " + response.status);
  return response.json();
}

function peerPath(id) {
  if (!new RegExp(peerID.pattern).test(id)) throw new Error("Invalid agent ID");
  return "/agents/" + id;
}

async function rpc(agent, method, params, signal) {
  const id = randomUUID();
  const reply = await request(peerPath(agent), signal, { jsonrpc: "2.0", id, method, params });
  if (reply.id !== id || reply.jsonrpc !== "2.0") throw new Error("Invalid A2A response");
  if (reply.error) {
    const code = reply.error.code;
    throw new Error(code === -31403 ? "A2A permission denied (consent, capability or mandate)" : "A2A request failed (" + code + ")");
  }
  return method === "SendMessage" ? reply.result.task : reply.result;
}

function result(value) {
  return { content: [{ type: "text", text: JSON.stringify(value) }], details: {} };
}

async function taskResult(agent, task, seconds = 0, signal) {
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > 120) throw new Error("Invalid A2A wait");
  const deadline = Date.now() + seconds * 1000;
  while (["TASK_STATE_SUBMITTED", "TASK_STATE_WORKING"].includes(task.status.state) && Date.now() < deadline) {
    await delay(Math.min(1500, deadline - Date.now()), undefined, { signal });
    task = await rpc(agent, "GetTask", { id: task.id, historyLength: 0 }, signal);
  }
  const info = task.metadata?.agentcapsule;
  return result({
    request_id: task.id, state: info?.request_state ?? task.status.state,
    reason: info?.reason,
    reply: task.artifacts?.flatMap(a => a.parts?.map(p => p.text ?? p.data) ?? []),
  });
}

export default function register(pi) {
  pi.registerTool({
    name: "agent_discover", label: "Find agents", description: "Find visible agents in your organization offering an OASF skill. For example 10302 is summarization.",
    parameters: schema({ skill: { type: "integer", minimum: 1 } }, ["skill"]),
    async execute(_id, args, signal) {
      const { agents } = await request("/agents?skill=" + encodeURIComponent(args.skill), signal);
      return result(agents.map(card => ({ agent_id: card.name, description: card.description, skills: card.skills.map(s => s.id) })));
    },
  });
  pi.registerTool({
    name: "agent_ask", label: "Ask an agent", description: "Send one question to a visible agent through the current invocation's mandate. A request pending consent has not been answered. Report its ID and use agent_request_status; do not resend it.",
    parameters: schema({ agent_id: peerID, question: { type: "string", minLength: 1, maxLength: 32000 }, wait_seconds: waitSeconds }, ["agent_id", "question"]),
    async execute(callID, args, signal) {
      const task = await rpc(args.agent_id, "SendMessage", {
        message: { messageId: callID, role: "ROLE_USER", parts: [{ text: args.question }] },
        configuration: { returnImmediately: true },
      }, signal);
      return taskResult(args.agent_id, task, args.wait_seconds, signal);
    },
  });
  pi.registerTool({
    name: "agent_request_status", label: "Read agent reply", description: "Retrieve a previously sent request by its ID and recipient. Returns the reply, consent decision or pending state. Works in later invocations.",
    parameters: schema({ agent_id: peerID, request_id: requestID, wait_seconds: waitSeconds }, ["agent_id", "request_id"]),
    async execute(_id, args, signal) {
      const task = await rpc(args.agent_id, "GetTask", { id: args.request_id, historyLength: 0 }, signal);
      return taskResult(args.agent_id, task, args.wait_seconds, signal);
    },
  });
}
