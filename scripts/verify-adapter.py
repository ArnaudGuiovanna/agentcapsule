#!/usr/bin/env python3
"""Live qualification of capsule-adapter's model endpoint with unmodified clients.

The official OpenAI and Anthropic Python SDKs (pinned in
scripts/adapter-sdk-requirements.txt) talk to the adapter's model endpoint, with
and without streaming, with tools; the endpoint forwards through the platform's
real gateway code to a real provider. Then a delivered invocation runs an
unmodified Python agent (the OpenAI SDK in a tool loop) that reads an attached
file through a tool call. With --pi, Pi (the coding agent) runs the same way,
configured only through its own models.json and environment, through both
APIs: it reads the file with its read tool and keeps its session across
invocations. A local Ollama serves both APIs with no paid credential. No VM, no PostgreSQL: the metering of these calls and the guest
path are covered by the PostgreSQL and KVM campaigns.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {"TestLiveOfficialSDKsThroughTheModelEndpoint", "TestLiveUnmodifiedAgentAnswersAnInvocation"}
PI_TESTS = {"TestLivePiAnswersInvocations", "TestLivePiAnswersInvocations/capsule-anthropic", "TestLivePiAnswersInvocations/capsule-openai"}
SOURCES = ["go.mod", "go.sum", "internal/agentadapter", "internal/llmgateway", "internal/capsuleprotocol/llm.go",
           "scripts/verify-adapter.py", "scripts/adapter-sdk-requirements.txt"]


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def digests():
    out = {}
    for name in SOURCES:
        path = ROOT / name
        files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
        for f in files:
            if "__pycache__" not in f.parts:
                out[str(f.relative_to(ROOT))] = sha256(f)
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--provider-url", default="http://127.0.0.1:11434", help="provider serving /v1/chat/completions and /v1/messages")
    p.add_argument("--model", required=True, help="upstream model with tool calling")
    p.add_argument("--python", type=Path, required=True, help="Python with scripts/adapter-sdk-requirements.txt installed")
    p.add_argument("--pi", type=Path, help="pi executable: also qualify Pi, unmodified")
    p.add_argument("--node-dir", type=Path, help="directory holding the node that pi runs on (with --pi)")
    p.add_argument("--go", default="go")
    p.add_argument("--output", type=Path, required=True, help="new evidence directory")
    a = p.parse_args()
    if bool(a.pi) != bool(a.node_dir):
        p.error("--pi and --node-dir go together")
    required = REQUIRED | (PI_TESTS if a.pi else set())
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    versions = subprocess.run([str(a.python), "-I", "-c", "import json, sys, openai, anthropic; json.dump({'python': sys.version.split()[0], "
                               "'openai': openai.__version__, 'anthropic': anthropic.__version__}, sys.stdout)"],
                              check=True, capture_output=True, text=True).stdout
    provider = {"url": a.provider_url, "model": a.model}
    try:
        with urllib.request.urlopen(a.provider_url.rstrip("/") + "/api/version", timeout=5) as r:
            provider["ollama_version"] = json.load(r).get("version")
    except (OSError, ValueError):
        provider["ollama_version"] = None
    go_version = subprocess.run([a.go, "version"], check=True, capture_output=True, text=True).stdout.strip()
    pi = None
    if a.pi:
        node_env = dict(os.environ, PATH=os.path.abspath(a.node_dir) + os.pathsep + os.environ.get("PATH", ""), PI_OFFLINE="1",
                        PI_SKIP_VERSION_CHECK="1", PI_TELEMETRY="0")
        pi = {"path": os.path.abspath(a.pi), "version": subprocess.run([os.path.abspath(a.pi), "--version"], check=True, capture_output=True,
                                                                       text=True, env=node_env).stdout.strip(),
              "node": subprocess.run([os.path.join(os.path.abspath(a.node_dir), "node"), "--version"], check=True, capture_output=True,
                                     text=True).stdout.strip()}
    (out / "environment.json").write_text(json.dumps({"sdks": json.loads(versions), "provider": provider, "go": go_version, "pi": pi,
                                                      "source_sha256": digests(), "scope": __doc__}, indent=2) + "\n")
    env = dict(os.environ, CGO_ENABLED="1", GOFLAGS="-mod=readonly", AGENTCAPSULE_ADAPTER_PROVIDER_URL=a.provider_url,
               AGENTCAPSULE_ADAPTER_MODEL=a.model, AGENTCAPSULE_ADAPTER_PYTHON=os.path.abspath(a.python))  # a venv: never resolve its symlink
    if a.pi:
        env.update(AGENTCAPSULE_ADAPTER_PI=os.path.abspath(a.pi), AGENTCAPSULE_ADAPTER_NODE_DIR=os.path.abspath(a.node_dir))
    records = []

    def run(name, command, timeout):
        start = time.monotonic()
        print("RUN", name, flush=True)
        with (out / (name + ".log")).open("w") as log:
            rc = subprocess.run([str(c) for c in command], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout).returncode
        records.append({"phase": name, "returncode": rc, "seconds": round(time.monotonic() - start, 3)})
        (out / "summary.json").write_text(json.dumps(records, indent=2) + "\n")
        print("PASSED" if rc == 0 else "FAILED", name, flush=True)
        return rc

    status = "failed"
    passed = set()
    try:
        if run("compile", [a.go, "test", "-c", "-tags=adapter_live", "-o", out / "adapter.test", "./internal/agentadapter"], 600) == 0:
            run("live", [a.go, "tool", "test2json", "-p", "github.com/ArnaudGuiovanna/agentcapsule/internal/agentadapter",
                         out / "adapter.test", "-test.v", "-test.run=" + ("^TestLive" if a.pi else "^TestLive(OfficialSDKs|UnmodifiedAgent)"),
                         "-test.timeout=40m"], 2500)
            events = []
            for line in (out / "live.log").read_text().splitlines():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            passed = {e["Test"] for e in events if e.get("Action") == "pass" and "Test" in e}
            failed = {e["Test"] for e in events if e.get("Action") in ("fail", "skip") and "Test" in e}
            if required <= passed and not failed:
                status = "passed"
    finally:
        (out / "adapter.test").unlink(missing_ok=True)
        (out / "verification.json").write_text(json.dumps({"status": status, "passed_tests": sorted(passed),
                                                           "required_tests": sorted(required)}, indent=2) + "\n")
    print("Evidence:", out)
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
