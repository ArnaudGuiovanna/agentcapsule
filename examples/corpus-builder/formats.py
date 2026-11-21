"""Source decoders used only inside the CPU-only builder microVM."""
import base64
import csv
import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

MAX_TEXT = 32 << 20
MAX_PAGES = 2048
MAX_MEDIA = 700 << 10


class ConversionError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def read_bounded(path, limit):
    if path.stat().st_size > limit:
        raise ConversionError("too_large")
    with path.open("rb") as src:
        data = src.read(limit + 1)
    if len(data) > limit:
        raise ConversionError("too_large")
    return data


def tool(args, directory, timeout=180):
    # All paths belong to this invocation's private working directory. Tools
    # never receive the original repository's name as an option.
    env = dict(os.environ, HOME=str(directory), TMPDIR=str(directory),
               SAL_USE_VCLPLUGIN="svp", LC_ALL="C", TZ="UTC")
    try:
        subprocess.run(args, cwd=directory, env=env, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise ConversionError("timeout") from e
    except subprocess.CalledProcessError as e:
        raise ConversionError("malformed") from e


def call_id(*parts):
    return "corpus-" + hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode()).hexdigest()


def preview(source, dest, temp):
    tool(["cwebp", "-quiet", "-resize", "1024", "0", "-q", "75", source, "-o", dest], temp)
    if dest.stat().st_size > MAX_MEDIA:
        tool(["cwebp", "-quiet", "-resize", "512", "0", "-q", "48", source, "-o", dest], temp)
    return read_bounded(dest, MAX_MEDIA)


def describe(platform, alias, data, language, key):
    body = {"model": alias, "max_tokens": 384, "messages": [{"role": "user", "content": [
        {"type": "text", "text": "Describe the visible figure and any labels. Language: " + language},
        {"type": "image_url", "image_url": {"url": "data:image/webp;base64," + base64.b64encode(data).decode()}}]}]}
    response = platform._call("/v1/llm/forward", {"idempotency_key": key, "forward": {
        "alias": alias, "dialect": "openai", "body": body}}, timeout=130)
    return response["forward_result"]["body"]["choices"][0]["message"]["content"]


def paragraphs(text, origin="native", **locator):
    for section in re.split(r"\n\s*\n", text.strip()):
        for pos in range(0, len(section), 6000):
            value = section[pos:pos + 6000].strip()
            if value:
                match = re.match(r"^(#{1,6})\s+([^\n]+)$", value)
                item = {"type": "heading" if match else "paragraph", "source": origin,
                        "text": match[2] if match else value, **locator}
                if match:
                    item["level"] = len(match[1])
                yield item


def pdf_document(path, record, processing, platform, key, out, temp):
    xml = temp / "text.xml"
    tool(["pdftotext", "-bbox-layout", path, xml], temp)
    tree = ET.fromstring(read_bounded(xml, MAX_TEXT))
    pages = tree.findall(".//{*}page")
    if not pages or len(pages) > MAX_PAGES:
        raise ConversionError("too_large" if pages else "malformed")
    record["pages"] = len(pages)
    for number, page in enumerate(pages, 1):
        width, height = float(page.get("width")), float(page.get("height"))
        native = []
        for block in page.findall(".//{*}block"):
            lines = [" ".join(w.text or "" for w in line.findall("{*}word")) for line in block.findall("{*}line")]
            rect = [float(block.attrib[k]) / (width if i % 2 == 0 else height)
                    for i, k in enumerate(("xMin", "yMin", "xMax", "yMax"))]
            native.extend(paragraphs("\n".join(lines), page=number, box=[max(0., min(1., f)) for f in rect]))
        tool(["pdftoppm", "-f", str(number), "-l", str(number), "-singlefile",
              "-scale-to", "1024", "-jpeg", path, temp / "render"], temp)
        data = preview(temp / "render.jpg", out / "pages" / ("page-%04d.webp" % number), temp)
        ocr = processing.get("OCR")
        if ocr and (ocr.get("Mode") == "always" or not native):
            result = platform.ocr_llm(call_id(key, "ocr", number), ocr["Alias"], data, "image/webp", 1)
            native = list(paragraphs("\n".join(p["markdown"] for p in result["pages"]), "ocr", page=number))
        record["elements"].extend(native)
        vision = processing.get("Vision")
        if vision and vision["DescribeFigures"]:
            description = describe(platform, vision["Alias"], data, record["language"], call_id(key, "figure", number))
            if description:
                record["elements"].append({"type":"caption", "source":"vision", "page":number, "text":description})


def col_name(number):
    name = ""
    while number:
        number, rest = divmod(number - 1, 26)
        name = chr(65 + rest) + name
    return name


def spreadsheet(path, record, out):
    kind = record["kind"]
    if kind == "xlsx":
        from openpyxl import load_workbook
        book = load_workbook(path, read_only=True, data_only=True, keep_links=False)
        sheets = ((s.title, s.values) for s in book)
    else:
        book = path.open(encoding="utf-8-sig", newline="")
        sheets = [(record["title"], csv.reader(book, delimiter="\t" if path.suffix.lower() == ".tsv" else ","))]
    try:
        for index, (sheet, rows) in enumerate(sheets, 1):
            name = "sheet-%03d" % index
            target = out / "data" / (name + ".csv")
            (target.with_suffix(".md")).write_text("# " + sheet + "\n\n[" + name + ".csv](" + name + ".csv)\n")
            with target.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f, lineterminator="\n")
                for rownum, row in enumerate(rows, 1):
                    if rownum > 100000 or len(row) > 16384 or f.tell() > MAX_TEXT:
                        raise ConversionError("too_large")
                    values = [str(value) if value is not None else "" for value in row]
                    writer.writerow(values)
                    if any(values):
                        record["elements"].append({"type":"table","source":"native","sheet":sheet,
                            "range":"A%d:%s%d" % (rownum,col_name(len(row)),rownum), "text":" | ".join(values)})
    finally:
        book.close()


def media_document(path, record, processing, platform, key, out, temp):
    probe = temp / "probe.json"
    tool(["ffprobe", "-v", "error", "-protocol_whitelist", "file,pipe", "-show_entries", "stream=codec_type:format=duration",
          "-of", "json", "-o", probe, path], temp)
    metadata = json.loads(read_bounded(probe, 65536))
    streams = {track["codec_type"] for track in metadata["streams"]}
    if record["kind"] not in streams:
        raise ConversionError("malformed")
    seconds = float(metadata["format"]["duration"])
    if not math.isfinite(seconds) or not 0 < seconds <= 86400:
        raise ConversionError("too_large")
    record["seconds"] = seconds
    end_seen = 0.
    alias = processing["Transcription"]["Alias"]
    language = record["language"].split("-")[0].lower()
    # Silent videos still contribute their timestamped key frames.
    for start in range(0, math.ceil(seconds) if "audio" in streams else 0, 118):
        length = min(120, seconds-start)
        audio = temp / "clip.mp3"
        tool(["ffmpeg","-nostdin","-v","error","-y","-protocol_whitelist","file,pipe","-ss",str(start),
              "-i",path,"-t",str(length),"-vn","-ar","16000","-ac","1","-b:a","32k",audio], temp)
        result = platform.transcribe_llm(call_id(key,"audio",start),alias,read_bounded(audio,MAX_MEDIA),
                                         "mp3",math.ceil(length),language if len(language)==2 else None)
        segments = result.get("segments") or [{"start":0, "end":length, "text":result["text"]}]
        for segment in segments:
            begin = max(end_seen, start + segment["start"])
            end = min(seconds, start + segment["end"])
            if end > begin and segment["text"].strip():
                record["elements"].append({"type":"transcript", "source":"transcription", "start":begin,
                                           "end":end, "text":segment["text"].strip()})
                end_seen = end
        if start+length >= seconds:
            break
    if record["kind"] == "video":
        # Filename is presentation time in milliseconds, including frame zero.
        tool(["ffmpeg","-nostdin","-v","error","-protocol_whitelist","file,pipe","-i",path,"-an",
              "-vf","select='eq(n,0)+gt(scene,0.35)',scale=640:-2","-fps_mode","vfr",
              "-enc_time_base","1/1000","-frame_pts","1","-frames:v","120",temp / "shot-%012d.jpg"],temp)
        for shot in sorted(temp.glob("shot-*.jpg")):
            stamp = int(shot.stem.split("-")[1])/1000
            data = preview(shot,out / "pages" / (shot.stem+".webp"),temp)
            vision = processing.get("Vision")
            if vision and vision["DescribeFigures"]:
                description = describe(platform,vision["Alias"],data,record["language"],call_id(key,"frame",stamp))
                record["elements"].append({"type":"figure","source":"vision","start":stamp,"end":stamp,"text":description})


def extract(path, record, processing, platform, key, out, scratch):
    for subdir in ("pages", "data"):
        (out / subdir).mkdir()
    with tempfile.TemporaryDirectory(dir=scratch) as name:
        temp = Path(name)
        kind = record["kind"]
        if kind in ("docx","pptx","odt"):
            tool(["soffice","-env:UserInstallation="+(temp / "profile").as_uri(),"--headless",
                  "--norestore","--convert-to","pdf","--outdir",temp,path],temp)
            path = temp / (path.stem+".pdf")
            if not path.is_file():
                raise ConversionError("malformed")
            kind = "pdf"
        if kind == "pdf":
            pdf_document(path,record,processing,platform,key,out,temp)
        elif kind in ("text","markdown"):
            record["elements"].extend(paragraphs(read_bounded(path,MAX_TEXT).decode("utf-8-sig")))
        elif kind in ("xlsx","csv"):
            spreadsheet(path,record,out)
        elif kind == "image":
            data = preview(path,out / "pages" / "page-0001.webp",temp)
            text = describe(platform,processing["Vision"]["Alias"],data,record["language"],call_id(key,"image"))
            record["pages"] = 1
            record["elements"].append({"type":"figure","source":"vision","page":1,"text":text})
        elif kind in ("video","audio"):
            media_document(path,record,processing,platform,key,out,temp)
        else:
            raise ConversionError("unsupported_type")
