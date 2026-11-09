"""A small tool-using agent written against the official OpenAI SDK.

It knows nothing about Agent Capsule: it reads a question on standard input,
lets the model call two tools (read a file, list a directory) and prints the
answer. The SDK finds its endpoint and key in OPENAI_BASE_URL and
OPENAI_API_KEY, as everywhere else.
"""

import json
import os
import sys

import openai

MODEL = os.environ.get("AGENT_MODEL", "gpt-4o")
TOOLS = [
    {"type": "function", "function": {"name": "read_file", "description": "Read a text file.",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
    {"type": "function", "function": {"name": "list_directory", "description": "List the entries of a directory.",
     "parameters": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}}},
]


def run_tool(name, args):
    path = args.get("path", "")
    try:
        if name == "read_file":
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read(20000)
        if name == "list_directory":
            return "\n".join(sorted(os.listdir(path)))
    except OSError as e:
        return "error: " + str(e)
    return "error: unknown tool " + name


def main():
    client = openai.OpenAI()
    messages = [
        {"role": "system", "content": "You are a helpful assistant. Use the tools to look at files when the user mentions them."},
        {"role": "user", "content": sys.stdin.read()},
    ]
    for _ in range(8):
        reply = client.chat.completions.create(model=MODEL, messages=messages, tools=TOOLS, max_tokens=1024)
        message = reply.choices[0].message
        if not message.tool_calls:
            print(message.content or "")
            return 0
        messages.append(message.model_dump(exclude_none=True))
        for call in message.tool_calls:
            args = json.loads(call.function.arguments or "{}")
            messages.append({"role": "tool", "tool_call_id": call.id, "content": run_tool(call.function.name, args)})
    print("I could not finish within the allowed number of steps.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
