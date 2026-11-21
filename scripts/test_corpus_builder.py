"""Integration tests for the guest release, including its persistent cache."""
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO/"examples/corpus-builder"), str(REPO/"sdk/python")]
from conversion import SCHEMA
from harness import phase


class CorpusBuild(unittest.TestCase):
    def test_cache_image_and_citations(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            dev = root/"dev"
            dev.mkdir()
            tool = root/"corpus-guest-tool"
            subprocess.run(["go","build","-o",tool,"./cmd/corpus-guest-tool"],cwd=REPO,check=True)
            workspace = root/"data"
            workspace.mkdir()
            src = {"agentcapsule-corpus.yaml":b"schema: agentcapsule.corpus-source/v1\ntitle: Skills\nlanguage: en\ninclude: ['docs/**']\n",
                   "docs/topics.md":b"# Stars\n\nA parsec is a distance.\n",
                   "docs/sample.csv":b"name,value\nlength,23\n"}
            hashes = []
            archive = None
            for run in range(3):
                if run == 2:
                    src["docs/sample.csv"] = b"name,value\nlength,29\n"
                if run != 1:
                    with tarfile.open(dev/"source",mode="w:gz") as tar:
                        for path, raw in src.items():
                            hdr = tarfile.TarInfo("forge-sha/"+path)
                            hdr.size = len(raw)
                            tar.addfile(hdr,io.BytesIO(raw))
                    archive = (dev/"source").read_bytes()
                spec = {"bytes":len(archive),"sha256":hashlib.sha256(archive).hexdigest()}
                common = {"schema":SCHEMA,"build_id":"cbd_"+("%032x" % (run+1))}
                scan = dict(common,phase="scan",name="stars",builder="corpus-builder@1",source=spec,path="",
                            commit=hashlib.sha1(archive,usedforsecurity=False).hexdigest())
                def execute(req):
                    return phase(req,workspace,dev,tool,None)
                self.assertEqual(execute(scan)["files"]["included"],2)
                conversion = dict(common,phase="convert",source=spec)
                stats = execute(conversion)
                self.assertEqual(execute(conversion),stats)
                self.assertEqual(stats["files"],{
                    "converted":[2,0,1][run],"cached":[0,2,1][run],"skipped":0,"failed":0})
                stage = workspace/"builds"/common["build_id"]
                capacity = 12<<20
                with (dev/"output").open("wb") as disk:
                    disk.truncate(capacity)
                info = execute(dict(common,phase="package",uuid=("1" if run!=2 else "2")*8+"-1234-1234-1234-123456789abc",
                                    output={"bytes":capacity}))
                self.assertEqual(info["documents"],2)
                hashes.append(hashlib.sha256((dev/"output").read_bytes()[:info["image_bytes"]]).digest())
                report = json.loads((stage/"layout/report.json").read_bytes())
                self.assertEqual(report["totals"]["cached"],0)
                self.assertTrue((stage/"layout/ext").is_dir())
                with sqlite3.connect((stage/"layout/search/fts.sqlite").as_uri()+"?immutable=1&mode=ro",uri=True) as db:
                    hit = db.execute("SELECT body,locator,doc_id,part,element_id FROM passages WHERE passages MATCH ?",
                                     ("29" if run==2 else "23",)).fetchone()
                    self.assertEqual(json.loads(hit[1])["range"],"A2:B2")
                    section = (stage/"layout/docs"/hit[2]/hit[3]).read_text()
                    self.assertIn('id="'+hit[4]+'"',section)
                self.assertNotEqual(report["build_id"],common["build_id"])
            self.assertEqual(hashes[0],hashes[1])
            self.assertNotEqual(hashes[1],hashes[2])


if __name__ == "__main__":
    unittest.main()
