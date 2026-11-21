"""Conversion regressions that run without LibreOffice, FFmpeg or a model service."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / "examples/corpus-builder"), str(REPO / "sdk/python")]
import conversion
import formats


class CorpusConversion(unittest.TestCase):
    def test_old_cached_document_keeps_results_under_the_published_identifier(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory)
            build_id = "cbd_" + "1" * 32
            build = data / "builds" / build_id
            src = build / "source" / "lesson.md"
            src.parent.mkdir(parents=True)
            src.write_text("# Orion\n\nOne entry")
            manifest = dict(Language="en", Processing={}, Documents=[], Corrections=[])
            request = dict(source={}, builder="builder@1", commit="a" * 40)
            file = dict(path=src.name, kind="markdown", bytes=src.stat().st_size)
            conversion.write_json(build / "scan.json", dict(Request=request, Manifest=manifest,
                                  Result=dict(files=[file])))
            oldkey = hashlib.sha256(conversion.encode([conversion.digest(src), request["builder"],
                                                     src.name, "en", {}, {}, ""])).hexdigest()
            cache = data / "conversion-cache"
            old = cache / oldkey
            old.mkdir(parents=True)
            result = conversion.make_document(None, src, file, manifest, {}, None, oldkey, data, old)
            # Reconstruct exactly what an earlier release cached, including its
            # original anchors and a vector addressing one of those anchors.
            doc = conversion.read_json(old / "doc.json")
            doc["id"] = "d-" + hashlib.sha256(src.name.encode()).hexdigest()[:20]
            for element in doc["elements"]:
                del element["id"], element["part"]
            conversion.write_document(doc, old)
            conversion.write_readme(doc, result["summary"], old)
            result.update(id=doc["id"], built_by="cbd_" + "0" * 32)
            conversion.write_json(old / "conversion.json", result)
            vector = dict(doc_id=doc["id"], element_id=doc["elements"][0]["id"], embedding=[0.25])
            (old / "embeddings.jsonl").write_bytes(conversion.encode(vector))
            before = {p.name: p.read_bytes() for p in old.iterdir() if p.is_file()}

            convert = dict(schema=conversion.SCHEMA, phase="convert", build_id=build_id, source={})
            with patch.object(conversion, "make_document", side_effect=AssertionError("recached through extraction")):
                receipt = conversion.convert(convert, data, data, None)
            self.assertEqual(receipt["files"], dict(cached=1, converted=0, skipped=0, failed=0))
            entry, = conversion.read_json(build / "entries.json")
            cold = data / "cold"
            cold.mkdir()
            fresh = conversion.make_document(None, src, file, manifest, {}, None, oldkey, data, cold)
            expected = "d" + hashlib.sha256(b"agentcapsule.corpus-document.v1\0lesson.md").hexdigest()[:16]
            self.assertEqual(entry["id"], expected)
            self.assertEqual(fresh["id"], expected)
            migrated = cache / entry["key"]
            for name in ("doc.json", "README.md", "part-001.md"):
                self.assertEqual((cold / name).read_bytes(), (migrated / name).read_bytes())
            heading = conversion.read_json(cold / "doc.json")["elements"][0]["id"]
            self.assertEqual(json.loads((migrated / "embeddings.jsonl").read_bytes()),
                             dict(doc_id=expected, element_id=heading, embedding=[0.25]))
            self.assertEqual(before, {p.name: p.read_bytes() for p in old.iterdir() if p.is_file()})

    def test_silent_video_extracts_timestamped_keyframes_without_transcription(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pages").mkdir()
            def tool(args, workspace, timeout=180):
                if args[0] == "ffprobe":
                    self.assertIn("stream=codec_type:format=duration", args)
                    (workspace / "probe.json").write_text('{"format":{"duration":"2"},"streams":[{"codec_type":"video"}]}')
                    return
                self.assertEqual(args[0], "ffmpeg")
                self.assertIn("-frame_pts", args)
                for stamp in [0, 1000]:
                    (workspace / ("shot-%012d.jpg" % stamp)).write_bytes(b"frame")

            doc = dict(kind="video", language="en", elements=[])
            processing = dict(Transcription={"Alias":"voice"}, Vision={"Alias":"vision", "DescribeFigures":True})
            with patch.object(formats, "tool", tool), patch.object(formats, "preview", return_value=b"preview"), \
                 patch.object(formats, "describe", return_value="key frame"):
                formats.media_document(root / "silent.mp4", doc, processing, None, "key", root, root)
            self.assertEqual(doc["seconds"], 2.0)
            self.assertEqual([(e["type"], e["start"], e["end"]) for e in doc["elements"]],
                             [("figure", 0.0, 0.0), ("figure", 1.0, 1.0)])
