"""agentcapsule-corpus-builder release entrypoint."""
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Isolated Python mode ignores PYTHONPATH. Modules come from the signed release.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from agentcapsule_harness import Harness, PlatformError, WORKING, json_part
from conversion import SCHEMA, convert, encode
from layout import build_layout

TOOL = "/opt/corpus-builder/corpus-guest-tool"
DEVICES = Path("/dev/corpus")
CLOSED = {"unauthorized","not_found","mandate","conflict","expired","transition","invalid","rejected"}
FIELDS = {
    "scan": ({"commit","name","builder","path","source"},{"cursor"}),
    "convert": ({"source"},{"lfs"}),
    "package": ({"uuid","output"},set())
}


def validate(req):
    if not isinstance(req,dict) or req.get("schema") != SCHEMA or not re.fullmatch(r"cbd_[a-f0-9]{32}",str(req.get("build_id"))):
        raise ValueError("invalid phase identity")
    required, optional = FIELDS[req["phase"]]
    required = required | {"schema","phase","build_id"}
    if not required <= req.keys() <= required | optional:
        raise ValueError("invalid phase fields")
    return req


def phase(req,data,devices,tool,platform,step=None):
    req = validate(req)
    if req["phase"] == "convert":
        return convert(req,data,devices,platform,step)
    if req["phase"] == "package":
        build_layout(data,req)
    result = subprocess.run([tool,req["phase"],data,devices],input=encode(req),stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,check=True)
    return json.loads(result.stdout)


@contextlib.contextmanager
def progress(h, op, enabled):
    if enabled and hasattr(h,"output_stream"):
        try:
            stream = h.output_stream(op)
            stream.__enter__()
        except (OSError,PlatformError):
            stream = None
    else:
        stream = None
    def step(name,state,label):
        if stream is not None:
            try:
                stream.step(name,state,label)
            except (PlatformError,OSError):
                pass
    try:
        yield step
    finally:
        if stream is not None:
            with contextlib.suppress(PlatformError,OSError):
                stream.__exit__(None,None,None)


def serve():
    os.environ["PATH"] = "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    h = Harness(database="builder.db",json_content=True)
    data = Path(h.boot.data_directory)/"builder"
    data.mkdir(mode=0o700,exist_ok=True)
    subjects = ["agent/"+h.agent_id]

    def schema(tx):
        tx.execute("CREATE TABLE IF NOT EXISTS phases (op TEXT PRIMARY KEY, request TEXT NOT NULL, result TEXT, outcome TEXT)")

    @h.on_invoke
    def invoke(invocation,tx):
        if len(invocation.values) != 1:
            raise ValueError("one builder phase required")
        req = validate(invocation.values[0])
        schema(tx)
        tx.execute("INSERT INTO phases(op,request) VALUES(?,?)",(invocation.operation_id,encode(req).decode()))
        return WORKING

    @h.on_background
    def background(h):
        def pending(tx):
            schema(tx)
            return tx.execute("SELECT op,request,result,outcome FROM phases ORDER BY rowid LIMIT 1").fetchone()
        row = h.store.local(subjects,pending)
        if not row or not h.platform:
            return False
        op,raw,result,outcome = row
        if not outcome:
            req = json.loads(raw)
            try:
                if req["phase"] == "scan" and not req.get("cursor"):
                    # Builds serialize per organization. Its conversion cache outlives these phase checkpoints.
                    for old in (data/"builds").glob("cbd_*"):
                        if re.fullmatch("cbd_[a-f0-9]{32}",old.name) and old.name != req["build_id"]:
                            shutil.rmtree(old)
                with progress(h,op,req["phase"]=="convert") as step:
                    reply = phase(req,data,DEVICES,TOOL,h.platform,step)
                result,outcome = encode(reply).decode(),"completed"
            except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
                result,outcome = None,"failed"
            h.store.local(subjects,lambda tx:tx.execute("UPDATE phases SET result=?,outcome=? WHERE op=?",(result,outcome,op)))
        try:
            h.platform.complete_invocation("builder-done-"+op,op,outcome,[json_part(json.loads(result))] if result else None)
        except PlatformError as error:
            if error.code not in CLOSED:
                raise
        h.store.local(subjects,lambda tx:tx.execute("DELETE FROM phases WHERE op=?",(op,)))
        return True
    h.run()


if __name__ == "__main__":
    serve()
