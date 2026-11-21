"""Assemble the read-only corpus layout from successful conversion checkpoints."""
import hashlib
import json
import re
import shutil
import sqlite3
import tempfile
from pathlib import Path

from conversion import encode, read_json, totals, write_json


def build_layout(data, request):
    if not re.fullmatch(r"cbd_[0-9a-f]{32}", request["build_id"]):
        raise ValueError("invalid build")
    seed = request["uuid"].replace("-","")
    if not re.fullmatch("[0-9a-f]{32}",seed):
        raise ValueError("invalid image UUID")
    build = data/"builds"/request["build_id"]
    destination = build/"layout"
    identity = "cbd_"+seed
    if destination.is_dir():
        if read_json(destination/"corpus.json")["build_id"] != identity:
            raise ValueError("package identity changed")
        return
    with tempfile.TemporaryDirectory(dir=build) as name:
        layout = Path(name)/"layout"
        layout.mkdir()
        for sub in ("docs","ext","search","topics"):
            (layout/sub).mkdir()
        scan = read_json(build/"scan.json")
        manifest, src = scan["Manifest"], scan["Request"]
        info = dict(schema="agentcapsule.corpus/v1", name=src["name"],title=manifest["Title"],
                    build_id=identity,commit=src["commit"],source_path=src["path"],builder=src["builder"],
                    languages=[manifest["Language"]],documents=[],modalities=[],tokens=0)
        report = read_json(build/"execution.json")
        report["build_id"] = identity
        for entry in report["files"]:
            if entry["status"] == "cached":
                entry["status"] = "converted"
        report["totals"] = totals(report["files"])
        write_json(layout/"report.json",report)
        index = "# "+info["title"]+"\n\n"
        topics, glossary, modalities = {}, {}, set()
        embedding = manifest["Processing"].get("Embeddings")
        db = sqlite3.connect(layout/"search/fts.sqlite")
        try:
            db.execute("CREATE VIRTUAL TABLE passages USING fts5(title, body, doc_id UNINDEXED, element_id UNINDEXED, part UNINDEXED, locator UNINDEXED, tokenize='unicode61')")
            for entry in read_json(build/"entries.json"):
                cache = data/"conversion-cache"/entry["key"]
                doc = read_json(cache/"doc.json")
                details = read_json(cache/"conversion.json")
                shutil.copytree(cache,layout/"docs"/doc["id"],ignore=shutil.ignore_patterns("conversion.json","embeddings.jsonl"))
                info["documents"].append({k:doc[k] for k in ("id","path","kind","title")} | {"tokens":details["tokens"]})
                info["tokens"] += details["tokens"]
                modalities.add({"image":"image","video":"video","audio":"audio"}.get(doc["kind"],"text"))
                prefix = "docs/"+doc["id"]+"/"
                link = "- [%s](%sREADME.md) — %s\n" % (doc["title"],prefix,details["summary"].replace("\n"," "))
                if len((index+link).encode()) <= 31600:
                    index += link
                for tag in doc["tags"]:
                    topics.setdefault(tag,[]).append(link)
                for element in doc["elements"]:
                    locator = {k:element[k] for k in ("page","box","sheet","range","start","end") if k in element}
                    db.execute("INSERT INTO passages VALUES(?,?,?,?,?,?)",(
                        doc["title"],element["text"],doc["id"],element["id"],element["part"],encode(locator).decode().strip()))
                    reference = "[%s](../%s%s#%s)" % (doc["title"],prefix,element["part"],element["id"])
                    if element["type"] == "heading":
                        topics.setdefault(element["text"][:120],[]).append("- "+reference+"\n")
                    match = re.match(r"^([^:\n]{2,70}?)\s*:\s+(\S.{4,300})$",element["text"])
                    if match:
                        glossary.setdefault(match[1],match[2]+" — "+reference.replace("(../","("))
                if embedding and (cache/"embeddings.jsonl").exists():
                    with (cache/"embeddings.jsonl").open("rb") as vf, (layout/"search/vectors.jsonl").open("ab") as out:
                        for raw in vf:
                            dimension = len(json.loads(raw)["embedding"])
                            spec = {"alias":embedding["Alias"],"dimensions":dimension}
                            if info.setdefault("embeddings",spec) != spec:
                                raise ValueError("embedding dimensions changed")
                            out.write(raw)
            db.execute("INSERT INTO passages(passages) VALUES('optimize')")
            db.commit()
        finally:
            db.close()
        info["modalities"] = sorted(modalities)
        write_json(layout/"corpus.json",info)
        for term,links in sorted(topics.items()):
            slug = hashlib.sha256(term.encode()).hexdigest()[:16]
            (layout/"topics"/(slug+".md")).write_text("# "+term+"\n\n"+"".join(line.replace("](docs/","](../docs/") for line in links))
        (layout/"glossary.md").write_text("# Glossary\n\n"+"".join("- "+k+" — "+v+"\n" for k,v in sorted(glossary.items())))
        (layout/"INDEX.md").write_text(index)
        layout.rename(destination)
