"""Durable file conversion within one organization's encrypted builder volume."""
import contextlib
import hashlib
import json
import os
import re
import shutil
import struct
import tempfile
from pathlib import Path
from xml.etree.ElementTree import ParseError
from zipfile import BadZipFile

from agentcapsule_harness import PlatformError, ProtocolError
from formats import ConversionError, MAX_TEXT, call_id, extract, paragraphs, read_bounded

SCHEMA = "agentcapsule.corpus-builder/v1"


def encode(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode()


def write_json(path, value):
    raw = encode(value)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        try:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
            f.close()
            os.replace(f.name, path)
        finally:
            Path(f.name).unlink(missing_ok=True)


def read_json(path):
    return json.loads(path.read_bytes())


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def copy_region(f, size, target=None):
    hasher = hashlib.sha256()
    while size:
        part = f.read(min(1 << 20,size))
        if not part:
            raise ValueError("incomplete drive")
        hasher.update(part)
        if target is not None:
            target.write(part)
        size -= len(part)
    return hasher.hexdigest()


def lfs_objects(device, drive, expected, temp):
    pointers = {p["oid"]:p["size"] for p in expected}
    if not drive:
        if pointers:
            raise ValueError("missing LFS drive")
        return {}
    with device.open("rb") as f:
        size = drive["bytes"]
        if type(size) is not int or not 16 <= size <= (1 << 41) or copy_region(f,size) != drive["sha256"]:
            raise ValueError("LFS drive integrity")
        f.seek(0)
        if f.read(8) != b"ACPLFS01":
            raise ValueError("LFS header")
        length = struct.unpack(">Q",f.read(8))[0]
        if not 0 < length <= min(size-16,4<<20):
            raise ValueError("LFS index length")
        index = json.loads(f.read(length))
        if index["schema"] != "agentcapsule.corpus-lfs/v1" or len(index["objects"]) != len(pointers):
            raise ValueError("LFS index")
        end = 16 + length
        paths = {}
        for item in index["objects"]:
            oid, offset, n = item["oid"], item["offset"], item["length"]
            if (oid not in pointers or oid in paths or not re.fullmatch("[a-f0-9]{64}",oid)
                    or n != pointers[oid] or offset < end or offset%4096 or offset+n > size):
                raise ValueError("invalid LFS object")
            f.seek(offset)
            dst = temp / oid
            with dst.open("xb") as obj:
                if copy_region(f,n,obj) != oid:
                    raise ValueError("LFS object integrity")
            paths[oid] = dst
            end = offset+n
        return paths


def document_id(path):
    source = b"agentcapsule.corpus-document.v1\0" + path.encode()
    return "d" + hashlib.sha256(source).hexdigest()[:16]


def write_readme(doc, summary, dest):
    outline = ["- [%s](%s#%s)" % (e["text"][:120],e["part"],e["id"])
               for e in doc["elements"] if e["type"] == "heading"]
    text = "# "+doc["title"]+"\n\n"+summary+"\n\nSource: "+doc["path"]+"\n\n"+"\n".join(outline[:120])
    (dest/"README.md").write_text(text+"\n", encoding="utf-8")


def migrate_cached_document(old, dest, path):
    # In-flight builds can still package their earlier cache entry. Publish an
    # independent corrected entry and retain all existing conversion results.
    shutil.copytree(old, dest)
    doc = read_json(dest/"doc.json")
    result = read_json(dest/"conversion.json")
    if doc["path"] != path or result["id"] != doc["id"]:
        raise ValueError("invalid conversion cache")
    doc["id"] = document_id(path)
    old_elements = [e.pop("id") for e in doc["elements"]]
    for element in doc["elements"]:
        element.pop("part")
    write_document(doc, dest)
    write_readme(doc, result["summary"], dest)
    vectors = dest/"embeddings.jsonl"
    if vectors.exists():
        anchors = dict(zip(old_elements, (e["id"] for e in doc["elements"]), strict=True))
        replacement = dest/"migrated-vectors"
        with vectors.open("rb") as src, replacement.open("wb") as out:
            for line in src:
                vector = json.loads(line)
                vector["doc_id"] = doc["id"]
                vector["element_id"] = anchors[vector["element_id"]]
                out.write(encode(vector))
        replacement.replace(vectors)
    result["id"] = doc["id"]
    write_json(dest/"conversion.json", result)


def write_document(doc, out):
    part, parts, used, ids = 0, [], 0, {}
    for element in doc["elements"]:
        text = element["text"]
        anchor = "e-" + hashlib.sha256(encode([doc["id"],element])).hexdigest()[:16]
        count = ids.get(anchor,0) + 1
        ids[anchor] = count
        element["id"] = anchor if count == 1 else anchor + "-%d" % count
        if part == 0 or (used and used+len(text.encode()) > 20000):
            part += 1
            parts.append([])
            used = 0
        element["part"] = "part-%03d.md" % part
        parts[-1].append('<a id="%s"></a>\n\n%s\n' % (element["id"],text))
        used += len(text.encode())
    for index, lines in enumerate(parts,1):
        (out / ("part-%03d.md" % index)).write_text("\n".join(lines),encoding="utf-8")
    write_json(out / "doc.json",doc)


def make_document(platform, src, f, manifest, meta, correction, key, scratch, dest):
    path = f["path"]
    doc = {"schema":"agentcapsule.corpus-document/v1","id":document_id(path),
           "path":path,"kind":f["kind"],"title":meta.get("Title") or Path(path).name[:200],
           "language":manifest["Language"],"tags":meta.get("Tags") or [],"elements":[]}
    proc = manifest["Processing"]
    warnings = []
    extract(src,doc,proc,platform,key,dest,scratch)
    if correction:
        doc["elements"] = list(paragraphs(read_bounded(correction,MAX_TEXT).decode("utf-8-sig"),"correction"))
        doc["corrected"] = True
        warnings.append("corrected")
    if not doc["elements"]:
        warnings.append("no_text")
    write_document(doc,dest)
    text = "\n".join(e["text"] for e in doc["elements"])
    tokens = (len(text.encode())+3)//4
    summary = " ".join(text.split())[:320]
    if proc.get("Summaries") and text:
        answer = platform.complete_llm(call_id(key,"summary"),proc["Summaries"]["Alias"],[
            {"role":"system","content":"Summarize this document in two or three sentences in "+doc["language"]+"."},
            {"role":"user","content":text[:16000]}],max_tokens=256,temperature=0.)
        summary = answer["text"].strip()[:1200]
    if proc.get("Embeddings") and doc["elements"]:
        with (dest/"embeddings.jsonl").open("wb") as vectors:
            for i in range(0,len(doc["elements"]),8):
                batch = doc["elements"][i:i+8]
                result = platform.embed_llm(call_id(key,"embedding",i),proc["Embeddings"]["Alias"],
                    [(doc["title"]+"\n"+e["text"])[:7200] for e in batch])
                for e,v in zip(batch,result["embeddings"],strict=True):
                    vectors.write(encode({"doc_id":doc["id"],"element_id":e["id"],"embedding":v}))
    write_readme(doc, summary, dest)
    return {"id":doc["id"],"tokens":tokens,"warnings":warnings,"summary":summary}


def totals(files):
    counts = dict(converted=0,cached=0,skipped=0,failed=0)
    for f in files:
        counts[f["status"]] += 1
    return dict(files=len(files),tokens=sum(f["tokens"] for f in files),**counts)


def convert(request, data, devices, platform, step=None):
    build_id = request["build_id"]
    if not re.fullmatch(r"cbd_[0-9a-f]{32}",build_id) or request["schema"] != SCHEMA or request["phase"] != "convert":
        raise ValueError("convert identity")
    build = data/"builds"/build_id
    scan = read_json(build/"scan.json")
    source = scan["Request"]
    if source["source"] != request["source"] or scan["Result"].get("errors") or not scan["Manifest"]:
        raise ValueError("invalid scan checkpoint")
    execution = build/"execution.json"
    if execution.exists():
        report = read_json(execution)
        return convert_reply(report)
    manifest = scan["Manifest"]
    metadata = {m["Path"]:m for m in manifest["Documents"] or []}
    corrections = {m["Path"]:build/"source"/m["Markdown"] for m in manifest["Corrections"] or []}
    cache = data/"conversion-cache"
    cache.mkdir(exist_ok=True)
    files, entries = [], []
    with tempfile.TemporaryDirectory(dir=build) as tmp:
        scratch = Path(tmp)
        objects = lfs_objects(devices/"lfs",request.get("lfs"),scan["Result"].get("lfs") or [],scratch)
        for ordinal,f in enumerate(scan["Result"]["files"] or [],1):
            path = f["path"]
            src = build/"source"/path
            if f.get("lfs"):
                # Preserve the extension for office import filters and text dialects.
                linked = scratch/("input-%d"%ordinal+src.suffix)
                os.link(objects[f["lfs"]["oid"]],linked)
                src = linked
            meta = metadata.get(path,{})
            correction = corrections.get(path)
            key = hashlib.sha256(encode([digest(src),source["builder"],path,manifest["Language"],
                                         manifest["Processing"],meta,digest(correction) if correction else ""])).hexdigest()
            old = cache/key
            key = hashlib.sha256(encode(["agentcapsule.corpus-document.v1", key])).hexdigest()
            cached = cache/key
            entry = {"path":path,"kind":f["kind"],"bytes":f["bytes"],"status":"failed",
                     "doc_id":"","tokens":0,"warnings":[],"error":"malformed"}
            step_name = "file-%d" % ordinal
            label = path.encode()[:240].decode("utf-8",errors="ignore")
            if step:
                step(step_name,"started",label)
            try:
                if not cached.is_dir():
                    with tempfile.TemporaryDirectory(dir=cache) as temp:
                        staged = Path(temp)/"document"
                        if old.is_dir():
                            migrate_cached_document(old, staged, path)
                        else:
                            staged.mkdir()
                            details = make_document(platform,src,f,manifest,meta,correction,old.name,scratch,staged)
                            write_json(staged/"conversion.json",dict(details,built_by=build_id))
                        os.rename(staged,cached)
                result = read_json(cached/"conversion.json")
                entry.update(doc_id=result["id"],tokens=result["tokens"],warnings=result["warnings"],error="",
                             status="converted" if result["built_by"]==build_id else "cached")
                entries.append({"key":key,"id":result["id"]})
            except ConversionError as e:
                entry["error"] = e.code
            except (PlatformError,ProtocolError):
                entry["error"] = "inference_failed"
            except (ValueError,KeyError,IndexError,ParseError,BadZipFile,UnicodeError):
                entry["error"] = "malformed"
            files.append(entry)
            if step:
                step(step_name,"failed" if entry["status"] == "failed" else "done",label)
    from pathlib import PurePosixPath
    for ignored in scan["Result"].get("ignored") or []:
        reason, path = ignored["reason"], ignored["path"]
        if reason in ("step_disabled","unsupported_type"):
            from_kind = {"audio":".mp3 .wav .m4a .flac .ogg .opus","video":".mp4 .m4v .mov .webm .mkv","image":".png .jpg .jpeg .webp .gif"}
            kind = next((k for k, exts in from_kind.items() if PurePosixPath(path).suffix.lower() in exts.split()),"other")
            files.append(dict(path=path,kind=kind,bytes=(build/"source"/path).stat().st_size,
                              status="skipped",doc_id="",tokens=0,warnings=[],error=reason))
    files.sort(key=lambda f:f["path"])
    report = {"schema":"agentcapsule.corpus-report/v1","build_id":build_id,"commit":source["commit"],
              "files":files,"totals":totals(files)}
    write_json(build/"entries.json",entries)
    write_json(execution,report)
    return convert_reply(report)


def convert_reply(report):
    counts = report["totals"]
    return {"schema":SCHEMA,"phase":"convert","files":{k:counts[k] for k in ("converted","cached","skipped","failed")},
            "tokens":counts["tokens"]}
