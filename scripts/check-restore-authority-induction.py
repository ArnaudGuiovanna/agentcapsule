#!/usr/bin/env python3
"""Prove the safety of the restoreAuthorityTiny instance by symbolic induction."""
import argparse
import ctypes
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import zipfile

sys.dont_write_bytecode = True
repo = Path(__file__).resolve().parents[1]
proof = repo / "scripts" / "restore_authority_induction"
sys.path.insert(0, str(proof))
from assemble_certificate import assemble


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stripped(node):
    if isinstance(node, list):
        return [stripped(n) for n in node]
    if isinstance(node, dict):
        return {
            k: stripped(v) for k, v in node.items() if k not in ("id", "typeAnnotation", "depth")
        }
    return node


def select_solver(jar, work):
    system = platform.system()
    machine = platform.machine().lower()
    arch = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
        "i386": "x86",
        "i686": "x86",
    }.get(machine)
    target = {
        "Linux": ("linux", "libz3.so"),
        "Darwin": ("osx", "libz3.dylib"),
        "Windows": ("windows", "libz3.dll"),
    }.get(system)
    if not arch or not target:
        raise ValueError(f"Unsupported native Z3 platform {system}/{machine}")
    with zipfile.ZipFile(jar) as archive:
        data = archive.read(f"com/microsoft/z3/{target[0]}/{arch}/{target[1]}")
    lib = work / target[1]
    lib.write_bytes(data)
    dll = ctypes.CDLL(str(lib))
    dll.Z3_get_full_version.restype = ctypes.c_char_p
    return lib, dll.Z3_get_full_version().decode()


def compile_inputs(runtime, checker, work, out):
    model = "restore_authority.qnt"
    sliced = checker.isolate(repo / "spec", model, "restoreAuthorityTiny")
    if set(sliced) != {model}:
        raise ValueError("The source imports changed; review the proof compiler input")
    source = work / model
    source.write_text(sliced[model])
    output = work / "compiler.json"
    subprocess.run(
        [
            str(runtime["node"]),
            str(runtime["cli"]),
            "compile",
            "--target=json",
            "--main=restoreAuthorityTiny",
            "--invariant=safety",
            "--out=" + str(output),
            str(source),
        ],
        stdout=subprocess.DEVNULL,
        check=True,
    )
    result = json.loads(output.read_bytes())
    if result.get("errors") or [m["name"] for m in result["modules"]] != [
        "restoreAuthority",
        "restoreAuthorityTiny",
    ]:
        raise ValueError("Unexpected compiler modules")
    definitions, instance = result["modules"]
    overrides = instance["declarations"][0]
    if overrides["kind"] != "instance" or overrides["protoName"] != "restoreAuthority":
        raise ValueError("Unexpected instance")
    defs = {
        a["name"]: stripped(a["expr"]) for a in definitions["declarations"] if a["kind"] == "def"
    }
    assigned = {a["name"]: stripped(b) for a, b in overrides["overrides"]}
    consts = {a["name"] for a in definitions["declarations"] if a["kind"] == "const"}
    if set(assigned) != consts or defs.keys() & assigned.keys():
        raise ValueError("Incomplete or ambiguous instance parameters")
    roots = {d.get("name"): d.get("expr") for d in instance["declarations"][1:]}
    for n, original in [("q::init", "init"), ("q::step", "step"), ("q::inv", "safety")]:
        node = roots[n]
        if n == "q::inv" and node.get("opcode") == "and" and len(node["args"]) == 1:
            node = node["args"][0]
        if node["kind"] != "name" or node["name"] != original:
            raise ValueError("Unexpected checked operator " + n)
    (out / "rules.json").write_text(
        json.dumps(defs | assigned, sort_keys=True, separators=(",", ":")) + "\n"
    )
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tools", type=Path, default=Path.home() / ".local/share/agentcapsule-tools"
    )
    parser.add_argument(
        "--quint-dir",
        type=Path,
        default=repo / "spec",
        help="spec directory with its pinned npm installation",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="new or empty evidence directory (default: a unique directory under quint/results)",
    )
    args = parser.parse_args()
    spec = repo / "spec"
    deps = args.quint_dir.resolve()
    for f in ("package.json", "package-lock.json"):
        if sha(deps / f) != sha(spec / f):
            raise ValueError("Quint dependency inputs differ from this checkout: " + f)
    loader = importlib.util.spec_from_file_location(
        "model_checker", repo / "scripts/check-models.py"
    )
    checker = importlib.util.module_from_spec(loader)
    sys.modules[loader.name] = checker
    loader.loader.exec_module(checker)
    runtime = checker.find_tools(args.tools.expanduser().resolve(), deps)
    results = repo / "quint" / "results"
    if args.output:
        out = args.output.resolve()
        out.mkdir(parents=True, exist_ok=True)
        if any(out.iterdir()):
            raise ValueError(f"Existing proof evidence at {out}; choose an empty output directory")
    else:
        results.mkdir(parents=True, exist_ok=True)
        out = Path(tempfile.mkdtemp(prefix="restore-authority-induction-", dir=results))
    print("Evidence directory", out, flush=True)
    with tempfile.TemporaryDirectory() as d:
        work = Path(d)
        source = compile_inputs(runtime, checker, work, out)
        solver, version = select_solver(runtime["jar"], work)
        metadata = {
            "quint": runtime["versions"]["quint"],
            "entrypoint_sha256": sha(Path(__file__).resolve()),
            "source_isolation_runner_sha256": sha(repo / "scripts/check-models.py"),
            "npm_lock_sha256": sha(spec / "package-lock.json"),
            "input_sha256": sha(source),
            "full_source_sha256": sha(spec / "restore_authority.qnt"),
            "reduced_ir_sha256": sha(out / "rules.json"),
            "jar_sha256": runtime["versions"]["apalache_jar_sha256"],
            "libz3_sha256": sha(solver),
            "z3_version": version,
        }
        (out / "input-provenance.json").write_text(json.dumps(metadata, indent=2) + "\n")
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(proof / "prove_components.py"),
                str(out / "rules.json"),
                str(solver),
                str(out),
            ],
            check=True,
        )
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(proof / "check_projection_controls.py"),
                str(solver),
                "--evidence",
                str(out),
            ],
            check=True,
        )
        assemble(out, proof)


if __name__ == "__main__":
    main()
