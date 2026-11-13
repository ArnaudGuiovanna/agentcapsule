#!/usr/bin/env python3
"""Unit tests of deploy/backup/agentcapsule-archive-ship.py (REC-02).

A fake rclone stands for the stores: each is a local directory, and every
write is logged, so that the order of the uploads and removals can be
checked. scripts/verify-archive-shipping.py runs the script against rclone
1.60.1, an S3 store and an SFTP server.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile
import textwrap
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy/backup/agentcapsule-archive-ship.py"
SPEC = importlib.util.spec_from_file_location("archive_ship", SCRIPT)
SHIP = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(SHIP)

# The fake rclone: --config is a JSON file {"stores": {name: directory},
# "log": file, "fail": [stores], "cut": {store: bytes}}. A cut upload writes
# that many bytes, then fails, as an interrupted SFTP upload leaves a partial
# file under its final name.
FAKE_RCLONE = textwrap.dedent(f"""\
    #!{sys.executable}
    import datetime, json, os, shutil, sys
    args = sys.argv[1:]
    config = json.load(open(next(a.split("=", 1)[1] for a in args if a.startswith("--config="))))
    words = [a for a in args if not a.startswith("-")]
    action, target = words[0], words[-1]
    store, _, path = target.partition(":")
    if store in config.get("fail", []):
        sys.exit(1)
    base = config["stores"][store]
    full = os.path.join(base, path)
    def log(*entry):
        with open(config["log"], "a") as f:
            f.write(json.dumps([action, store, path, *entry]) + "\\n")
    if action == "lsjson":
        if not os.path.isdir(full):
            sys.exit(3)
        items = []
        for d, _, names in os.walk(full):
            for n in names:
                st = os.stat(os.path.join(d, n))
                when = datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).isoformat()
                items.append({{"Path": os.path.relpath(os.path.join(d, n), full), "Name": n, "Size": st.st_size,
                               "ModTime": when, "IsDir": False}})
        print(json.dumps(items))
    elif action == "rcat":
        os.makedirs(os.path.dirname(full), exist_ok=True)
        data = sys.stdin.buffer.read()
        cut = config.get("cut", {{}}).get(store)
        with open(full, "wb") as f:
            f.write(data[:cut] if cut is not None else data)
        log(len(data))
        if cut is not None:
            sys.exit(1)
    elif action == "cat":
        with open(full, "rb") as f:
            sys.stdout.buffer.write(f.read())
    elif action == "deletefile":
        os.unlink(full)
        log()
    elif action == "purge":
        shutil.rmtree(full)
        log()
    else:
        sys.exit(2)
""")


def archive(root, size=1000, agent=None, age=0):
    """A complete archive in root, in the worker's layout: {file: bytes}."""
    archive_id = "arc_" + secrets.token_hex(16)
    data = secrets.token_bytes(size)
    manifest = {"version": 1, "authority": "rstauth_" + "0" * 32, "id": archive_id,
                "binding": {"Store": agent or "agt_" + secrets.token_hex(16), "Volume": "vol_" + "1" * 32, "Incarnation": 1},
                "harness_digest": "sha256:" + "2" * 64, "size": size, "digest": list(hashlib.sha256(data).digest()), "mac": "AAAA"}
    directory = Path(root) / archive_id
    directory.mkdir(mode=0o700)
    (directory / "volume.luks").write_bytes(data)
    (directory / "manifest.json").write_text(json.dumps(manifest) + "\n")
    if age:
        past = time.time() - age
        for f in (directory / "volume.luks", directory / "manifest.json"):
            os.utime(f, (past, past))
    return archive_id


class Lab(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.root = self.dir / "root"
        self.root.mkdir(mode=0o700)
        self.textfile, self.state = self.dir / "textfile", self.dir / "state"
        self.textfile.mkdir()
        self.stores = {s: self.dir / s for s in SHIP.STORES}
        for d in self.stores.values():
            d.mkdir()
        self.rclone = self.dir / "rclone"
        self.rclone.write_text(FAKE_RCLONE)
        self.rclone.chmod(0o755)
        self.config = self.dir / "rclone.json"
        self.log = self.dir / "rclone.log"
        self.configure()

    def tearDown(self):
        self.tmp.cleanup()

    def configure(self, **extra):
        self.config.write_text(json.dumps({"stores": {s: str(d) for s, d in self.stores.items()}, "log": str(self.log), **extra}))

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def run_ship(self, *extra):
        argv = ["--archive-root", str(self.root), "--rclone", str(self.rclone), "--rclone-config", str(self.config),
                "ship", "--textfile-directory", str(self.textfile), "--state-directory", str(self.state), *extra]
        if os.geteuid() == 0:
            argv[:0] = ["--user", "nobody"]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = SHIP.main(argv)
        return code, self.metrics()

    def metrics(self):
        samples = {}
        for line in (self.textfile / SHIP.FILE_NAME).read_text().splitlines():
            if not line.startswith("#"):
                series, value = line.rsplit(" ", 1)
                samples[series.removeprefix("agentcapsule_archive_ship_")] = int(value)
        return samples

    def on_store(self, store, archive_id, name):
        return (self.stores[store] / archive_id / name).read_bytes()

    def local(self, archive_id, name):
        return (self.root / archive_id / name).read_bytes()


class Shipping(Lab):
    def test_first_ship_then_nothing_to_do(self):
        ids = [archive(self.root, 3000), archive(self.root, 10)]
        (self.root / ".pending-0123").mkdir()
        (self.root / ".pending-0123" / "volume.luks").write_bytes(b"capture in progress")
        (self.root / ".removed-4567").mkdir()
        (self.root / ".removed-4567" / "manifest.json").write_bytes(b"removal in progress")
        (self.root / ("arc_" + "9" * 32)).mkdir()  # no file at all: not an archive
        started = int(time.time())
        code, m = self.run_ship()
        self.assertEqual(code, 1, "an incomplete archive directory is reported")
        for store in SHIP.STORES:
            self.assertEqual(sorted(p.name for p in self.stores[store].iterdir()), sorted(ids))
            for i in ids:
                for name in SHIP.FILES:
                    self.assertEqual(self.on_store(store, i, name), self.local(i, name))
            self.assertEqual((m[f'pending_archives{{store="{store}"}}'], m[f'changed_archives{{store="{store}"}}'],
                              m[f'store_readable{{store="{store}"}}']), (0, 0, 1))
            self.assertGreaterEqual(m[f'last_success_timestamp_seconds{{store="{store}"}}'], started)
        # Per store and archive, the data first and the manifest last.
        for store in SHIP.STORES:
            for i in ids:
                order = [c[2].split("/")[1] for c in self.calls() if c[0] == "rcat" and c[1] == store and c[2].startswith(i)]
                self.assertEqual(order, ["volume.luks", "manifest.json"])
        uploads = len(self.calls())
        (self.root / ("arc_" + "9" * 32)).rmdir()
        code, _ = self.run_ship()
        self.assertEqual((code, len(self.calls())), (0, uploads), "a second run writes nothing")
        self.assertEqual(stat.S_IMODE((self.textfile / SHIP.FILE_NAME).stat().st_mode), 0o644)
        self.assertEqual(os.listdir(self.textfile), [SHIP.FILE_NAME])
        text = (self.textfile / SHIP.FILE_NAME).read_text()
        self.assertFalse(any(i in text for i in ids), "no archive ID in the metrics")

    def test_newest_archives_first(self):
        old, new = archive(self.root, age=3600), archive(self.root)
        self.run_ship()
        order = [c[2].split("/")[0] for c in self.calls() if c[0] == "rcat" and c[1] == "s3"]
        self.assertEqual(order, [new, new, old, old])

    def test_an_unreadable_store_keeps_its_last_success(self):
        archive(self.root)
        _, first = self.run_ship()
        self.configure(fail=["standby"])
        archive(self.root)
        code, m = self.run_ship()
        self.assertEqual(code, 1)
        self.assertEqual(m['store_readable{store="standby"}'], 0)
        self.assertNotIn('pending_archives{store="standby"}', m, "unknown, not zero")
        self.assertNotIn('changed_archives{store="standby"}', m)
        self.assertEqual(m['last_success_timestamp_seconds{store="standby"}'], first['last_success_timestamp_seconds{store="standby"}'])
        self.assertEqual((m['store_readable{store="s3"}'], m['pending_archives{store="s3"}']), (1, 0))

    def test_an_interrupted_upload_never_looks_complete_and_resumes(self):
        i = archive(self.root, 5000)
        self.configure(cut={"standby": 1234})
        code, m = self.run_ship()
        self.assertEqual((code, m['pending_archives{store="standby"}'], m['last_success_timestamp_seconds{store="standby"}']), (1, 1, 0))
        self.assertEqual(sorted(p.name for p in (self.stores["standby"] / i).iterdir()), ["volume.luks"], "no manifest: incomplete")
        self.assertEqual(len(self.on_store("standby", i, "volume.luks")), 1234)
        self.configure()
        code, m = self.run_ship()
        self.assertEqual((code, m['pending_archives{store="standby"}']), (0, 0))
        for name in SHIP.FILES:
            self.assertEqual(self.on_store("standby", i, name), self.local(i, name))

    def test_a_partial_manifest_is_uploaded_again(self):
        i = archive(self.root)
        self.run_ship()
        partial = self.local(i, "manifest.json")[:40]
        (self.stores["s3"] / i / "manifest.json").write_bytes(partial)
        code, m = self.run_ship()
        self.assertEqual((code, m['pending_archives{store="s3"}'], m['changed_archives{store="s3"}']), (0, 0, 0))
        self.assertEqual(self.on_store("s3", i, "manifest.json"), self.local(i, "manifest.json"))
        rewritten = [c for c in self.calls() if c[0] == "rcat" and c[1] == "s3" and c[2].startswith(i)]
        self.assertEqual([c[2] for c in rewritten][-1], f"{i}/manifest.json", "the whole data was not sent again")
        self.assertEqual(len(rewritten), 3)

    def test_a_changed_archive_is_reported_and_never_rewritten(self):
        grown, rewritten = archive(self.root), archive(self.root)
        self.run_ship()
        original = {i: self.local(i, "volume.luks") for i in (grown, rewritten)}
        uploads = len(self.calls())
        with open(self.root / grown / "volume.luks", "ab") as f:
            f.write(b"x")
        time.sleep(SHIP.CLOCK_MARGIN + 0.1)
        data = bytearray(original[rewritten])
        data[0] ^= 0xFF
        (self.root / rewritten / "volume.luks").write_bytes(data)  # same size, written after the upload
        code, m = self.run_ship()
        self.assertEqual(code, 1)
        for store in SHIP.STORES:
            self.assertEqual((m[f'changed_archives{{store="{store}"}}'], m[f'pending_archives{{store="{store}"}}']), (2, 0))
            for i in (grown, rewritten):
                self.assertEqual(self.on_store(store, i, "volume.luks"), original[i])
        self.assertEqual(len(self.calls()), uploads, "nothing written to a store")

    def test_an_archive_complete_on_a_store_that_differs_is_changed(self):
        i = archive(self.root)
        self.run_ship()
        # The host's copy grew; the store's manifest says the store's copy is whole.
        with open(self.root / i / "volume.luks", "ab") as f:
            f.write(b"more")
        self.assertEqual(SHIP.classify(i, {n: (len(self.local(i, n)), 0) for n in SHIP.FILES},
                                       {n: (len(self.on_store("s3", i, n)), time.time()) for n in SHIP.FILES},
                                       lambda: self.on_store("s3", i, "manifest.json")), "changed")


class Retention(Lab):
    def age_on_store(self, store, archive_id, seconds):
        past = time.time() - seconds
        for f in (self.stores[store] / archive_id).iterdir():
            os.utime(f, (past, past))

    def test_age_only_never_the_host_s_retention(self):
        kept, removed_here, expired = archive(self.root), archive(self.root), archive(self.root)
        self.run_ship()
        # The worker's retention removes an archive: its copies stay.
        os.rename(self.root / removed_here, self.root / (".removed-" + "a" * 32))
        code, m = self.run_ship()
        self.assertEqual(code, 0)
        for store in SHIP.STORES:
            self.assertTrue((self.stores[store] / removed_here / "manifest.json").exists())
        # Copies older than a store's retention go, from that store only.
        os.rename(self.root / expired, self.root / (".removed-" + "b" * 32))
        self.age_on_store("s3", expired, 31 * 86400)
        self.age_on_store("standby", expired, 8 * 86400)
        self.age_on_store("s3", removed_here, 29 * 86400)
        self.age_on_store("standby", removed_here, 6 * 86400)
        before = len(self.calls())
        code, m = self.run_ship()
        self.assertEqual(code, 0)
        for store in SHIP.STORES:
            self.assertFalse((self.stores[store] / expired).exists())
            self.assertTrue((self.stores[store] / removed_here / "manifest.json").exists())
            self.assertTrue((self.stores[store] / kept / "manifest.json").exists())
            removal = [c[0] for c in self.calls()[before:] if c[1] == store]
            self.assertEqual(removal, ["deletefile", "purge"], "the manifest goes first: never complete without its data")

    def test_an_archive_older_than_the_retention_is_not_shipped(self):
        old, new = archive(self.root, age=8 * 86400), archive(self.root)
        code, m = self.run_ship()
        self.assertEqual((code, m['pending_archives{store="standby"}']), (0, 0))
        self.assertEqual(sorted(p.name for p in self.stores["standby"].iterdir()), [new])
        self.assertEqual(sorted(p.name for p in self.stores["s3"].iterdir()), sorted([old, new]))

    def test_an_unfinished_copy_is_pruned_by_its_last_write(self):
        i = archive(self.root)
        self.configure(cut={"s3": 10})
        self.run_ship()
        self.configure()
        os.rename(self.root / i, self.root / (".removed-" + "c" * 32))
        self.age_on_store("s3", i, 31 * 86400)
        self.run_ship()
        self.assertFalse((self.stores["s3"] / i).exists())
        self.assertEqual([c[0] for c in self.calls() if c[0] in ("deletefile", "purge")], ["purge"])

    def test_durations(self):
        self.assertEqual([SHIP.duration(d) for d in ("30d", "7d", "12h", "45m", "90s")], [2592000, 604800, 43200, 2700, 90])
        for bad in ("0d", "30", "d", "1w", "-1d", " 1d"):
            with self.assertRaises(ValueError):
                SHIP.duration(bad)


class Pieces(unittest.TestCase):
    def test_rclone_times(self):
        self.assertEqual(SHIP.unix_time("2026-11-13T18:53:42Z"), 1794596022.0)
        self.assertAlmostEqual(SHIP.unix_time("2026-11-13T19:53:42.865980273+01:00"), 1794596022.865980273, places=6)
        self.assertEqual(SHIP.unix_time("2026-11-13T15:53:42-03:00"), 1794596022.0)
        for bad in ("2026-11-13 18:53:42Z", "2026-11-13T18:53:42", "yesterday"):
            with self.assertRaises(ValueError):
                SHIP.unix_time(bad)

    def test_manifest_size(self):
        i = "arc_" + "a" * 32
        self.assertEqual(SHIP.manifest_size(json.dumps({"id": i, "size": 5}).encode(), i), 5)
        for bad in (b"{", b"[]", json.dumps({"id": "arc_" + "b" * 32, "size": 5}).encode(), json.dumps({"id": i, "size": True}).encode(),
                    json.dumps({"id": i, "size": 5.0}).encode(), json.dumps({"id": i, "size": 0}).encode(),
                    json.dumps({"id": i, "size": (32 << 30) + 1}).encode(), b"\xff\xfe"):
            self.assertIsNone(SHIP.manifest_size(bad, i), bad[:40])

    def test_local_archives_take_only_complete_archive_directories(self):
        with tempfile.TemporaryDirectory() as d:
            good = archive(d)
            extra = archive(d)
            (Path(d) / extra / "notes").write_text("x")
            linked = archive(d)
            os.unlink(Path(d) / linked / "volume.luks")
            os.symlink(Path(d) / good / "volume.luks", Path(d) / linked / "volume.luks")
            big = archive(d)
            (Path(d) / big / "manifest.json").write_bytes(b" " * (SHIP.MANIFEST_LIMIT + 1))
            os.symlink(Path(d) / good, Path(d) / ("arc_" + "c" * 32))
            os.mkdir(Path(d) / ("ARC_" + "d" * 32))
            os.mkdir(Path(d) / (".pending-arc_" + "e" * 32))
            with contextlib.redirect_stderr(io.StringIO()) as reported:
                found, skipped = SHIP.local_archives(d)
            self.assertEqual((list(found), skipped), ([good], 3))
            self.assertEqual(len(reported.getvalue().splitlines()), 3)

    def test_remote_listing(self):
        i = "arc_" + "a" * 32
        listing = [{"Path": f"{i}/volume.luks", "Size": 10, "ModTime": "2026-11-13T18:53:42Z"},
                   {"Path": f"{i}/manifest.json", "Size": 2, "ModTime": "2026-11-13T18:53:43Z"},
                   {"Path": f"{i}/other", "Size": 1, "ModTime": "2026-11-13T18:53:43Z"},
                   {"Path": "volume.luks", "Size": 1, "ModTime": "2026-11-13T18:53:43Z"},
                   {"Path": f"nested/{i}/volume.luks", "Size": 1, "ModTime": "2026-11-13T18:53:43Z"}]
        self.assertEqual(SHIP.remote_archives(listing), {i: {"volume.luks": (10, 1794596022.0), "manifest.json": (2, 1794596023.0)}})
        with self.assertRaises(ValueError):
            SHIP.remote_archives([{"Path": f"{i}/volume.luks", "Size": "10", "ModTime": "2026-11-13T18:53:42Z"}])

    def test_classify(self):
        i = "arc_" + "a" * 32
        manifest = json.dumps({"id": i, "size": 100}).encode()
        local = {"volume.luks": (100, 1000.0), "manifest.json": (len(manifest), 1000.0)}
        same = {"volume.luks": (100, 1100.0), "manifest.json": (len(manifest), 1101.0)}
        never = lambda: self.fail("the store's manifest is not needed")  # noqa: E731
        self.assertEqual(SHIP.classify(i, local, None, never), "incomplete")
        self.assertEqual(SHIP.classify(i, local, {"volume.luks": (100, 1100.0)}, never), "incomplete")
        self.assertEqual(SHIP.classify(i, local, same, never), "complete")
        within = {n: (s, t + SHIP.CLOCK_MARGIN) for n, (s, t) in local.items()}
        self.assertEqual(SHIP.classify(i, within, same, never), "complete")
        later = {"volume.luks": (100, 1200.0), "manifest.json": local["manifest.json"]}
        self.assertEqual(SHIP.classify(i, later, same, never), "changed")
        grown = {"volume.luks": (101, 1000.0), "manifest.json": local["manifest.json"]}
        self.assertEqual(SHIP.classify(i, grown, same, lambda: manifest), "changed")
        partial = {"volume.luks": (100, 1100.0), "manifest.json": (5, 1101.0)}
        self.assertEqual(SHIP.classify(i, local, partial, lambda: manifest[:5]), "incomplete")
        self.assertEqual(SHIP.classify(i, local, partial, lambda: None), "incomplete")
        short = {"volume.luks": (40, 1100.0), "manifest.json": (len(manifest), 1101.0)}
        self.assertEqual(SHIP.classify(i, local, short, lambda: manifest), "incomplete", "the store's data is not whole")

    def test_render(self):
        results = {"s3": {"readable": True, "pending": 2, "changed": 0}, "standby": {"readable": False}}
        self.assertEqual(SHIP.render(results, {"s3": 1000}, 1234.9), "\n".join([
            "# HELP agentcapsule_archive_ship_changed_archives Archives complete on this store whose local copy changed after the upload; the store keeps the copy it received.",
            "# TYPE agentcapsule_archive_ship_changed_archives gauge",
            'agentcapsule_archive_ship_changed_archives{store="s3"} 0',
            "# HELP agentcapsule_archive_ship_collected_timestamp_seconds Unix time the shipper last wrote these metrics.",
            "# TYPE agentcapsule_archive_ship_collected_timestamp_seconds gauge",
            "agentcapsule_archive_ship_collected_timestamp_seconds 1234",
            "# HELP agentcapsule_archive_ship_last_success_timestamp_seconds Unix time of the last run that left every complete local archive within this store's retention complete on it; 0 when none did.",
            "# TYPE agentcapsule_archive_ship_last_success_timestamp_seconds gauge",
            'agentcapsule_archive_ship_last_success_timestamp_seconds{store="s3"} 1000',
            'agentcapsule_archive_ship_last_success_timestamp_seconds{store="standby"} 0',
            "# HELP agentcapsule_archive_ship_pending_archives Complete local archives within this store's retention that were not complete on it at the end of the last run.",
            "# TYPE agentcapsule_archive_ship_pending_archives gauge",
            'agentcapsule_archive_ship_pending_archives{store="s3"} 2',
            "# HELP agentcapsule_archive_ship_store_readable 1 when the last run could list this store.",
            "# TYPE agentcapsule_archive_ship_store_readable gauge",
            'agentcapsule_archive_ship_store_readable{store="s3"} 1',
            'agentcapsule_archive_ship_store_readable{store="standby"} 0',
        ]) + "\n")
        with self.assertRaises(ValueError):
            SHIP.render({"other": {"readable": True}}, {}, 0)


class Locking(Lab):
    def test_one_run_at_a_time(self):
        import fcntl
        self.state.mkdir(mode=0o700)
        with open(self.state / "lock", "a") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            argv = ["--archive-root", str(self.root), "--rclone", str(self.rclone), "--rclone-config", str(self.config),
                    "ship", "--textfile-directory", str(self.textfile), "--state-directory", str(self.state)]
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(SHIP.main(argv), 1)
        self.assertEqual(os.listdir(self.textfile), [], "the run that holds the lock writes the metrics")


class Fetching(Lab):
    def fetch(self, store, archive_id, root):
        argv = ["--archive-root", str(root), "--rclone", str(self.rclone), "--rclone-config", str(self.config),
                "fetch", "--store", store, "--archive", archive_id]
        with contextlib.redirect_stdout(io.StringIO()):
            return SHIP.main(argv)

    def test_fetch_from_each_store(self):
        i = archive(self.root, 4000)
        self.run_ship()
        for store in SHIP.STORES:
            restored = self.dir / f"restored-{store}"
            self.assertEqual(self.fetch(store, i, restored), 0)
            self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((restored / i).stat().st_mode), 0o700)
            self.assertEqual(sorted(os.listdir(restored)), [i], "no staging directory left")
            for name in SHIP.FILES:
                self.assertEqual((restored / i / name).read_bytes(), self.local(i, name))
                self.assertEqual(stat.S_IMODE((restored / i / name).stat().st_mode), 0o600)
                self.assertEqual(int((restored / i / name).stat().st_mtime), int((self.stores[store] / i / name).stat().st_mtime))
            with self.assertRaises(SystemExit):
                self.fetch(store, i, restored)  # never over an archive already there

    def test_fetch_refuses_an_incomplete_or_wrong_copy(self):
        i = archive(self.root, 4000)
        self.run_ship()
        os.unlink(self.stores["s3"] / i / "manifest.json")
        with self.assertRaises(SystemExit):
            self.fetch("s3", i, self.dir / "restored-s3")
        data = bytearray(self.on_store("standby", i, "volume.luks"))
        data[10] ^= 1
        (self.stores["standby"] / i / "volume.luks").write_bytes(data)
        with self.assertRaises(SystemExit):
            self.fetch("standby", i, self.dir / "restored-standby")
        self.assertEqual(os.listdir(self.dir / "restored-standby"), [], "the staging directory is removed")
        with self.assertRaises(SystemExit):
            self.fetch("standby", "arc_" + "f" * 32, self.dir / "restored-standby")


if __name__ == "__main__":
    unittest.main()
