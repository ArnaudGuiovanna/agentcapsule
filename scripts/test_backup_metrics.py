#!/usr/bin/env python3
"""Unit tests of deploy/backup/agentcapsule-backup-metrics.py (REC-03).

The fixtures follow the shape of `pgbackrest info --output=json` (2.58);
scripts/verify-backups.py runs the script against a real pgBackRest.
"""

import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy/backup/agentcapsule-backup-metrics.py"
SPEC = importlib.util.spec_from_file_location("backup_metrics", SCRIPT)
METRICS = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(METRICS)
SECRET = "label-path-host-or-message-never-copied"


def backup(repo, kind, stop):
    return {"label": f"{SECRET}-{stop}", "type": kind, "database": {"id": 1, "repo-key": repo},
            "timestamp": {"start": stop - 60, "stop": stop}, "error": False, "annotation": {"note": SECRET}}


def info(repos, backups, stanza="agentcapsule"):
    return [{"name": stanza, "status": {"code": 0, "message": SECRET},
             "repo": [{"key": key, "cipher": "aes-256-cbc", "status": {"code": code, "message": SECRET}} for key, code in repos],
             "backup": backups, "archive": [], "db": [], "cipher": "mixed"}]


class Freshness(unittest.TestCase):
    def test_newest_backup_of_each_type_in_each_repository(self):
        readable, finished = METRICS.freshness(info([(1, 0), (2, 0), (3, 0)], [
            backup(1, "full", 1000), backup(2, "full", 1100), backup(1, "diff", 2000), backup(1, "diff", 3000),
            backup(1, "incr", 9000),  # not a type the timers take
            backup(3, "full", 9000),  # not a repository of the vocabulary
        ]), "agentcapsule")
        self.assertEqual(readable, {"s3": True, "standby": True})
        self.assertEqual(finished, {("s3", "full"): 1000, ("s3", "diff"): 3000, ("standby", "full"): 1100, ("standby", "diff"): 0})

    def test_a_repository_without_backups_is_readable_and_says_zero(self):
        readable, finished = METRICS.freshness(info([(1, 2), (2, 2)], []), "agentcapsule")
        self.assertEqual(readable, {"s3": True, "standby": True})
        self.assertEqual(set(finished.values()), {0})

    def test_an_unreadable_repository_has_no_backup_times(self):
        for code in (1, 3, 99):
            readable, finished = METRICS.freshness(info([(1, 0), (2, code)], [backup(1, "full", 1000), backup(2, "full", 1100)]), "agentcapsule")
            self.assertEqual(readable, {"s3": True, "standby": False})
            self.assertEqual(finished, {("s3", "full"): 1000, ("s3", "diff"): 0})
        readable, finished = METRICS.freshness(info([(1, 0)], []), "agentcapsule")
        self.assertEqual((readable["standby"], ("standby", "full") in finished), (False, False), "a repository info does not list")

    def test_an_unexpected_shape_is_refused(self):
        for broken in ({"name": "agentcapsule"}, info([(1, 0)], [], stanza="other"), info([(1, 0)], []) * 2,
                       info([(1, "0")], []), info([(True, 0)], []), info([(1, 0)], [backup(1, "full", -5)]),
                       info([(1, 0)], [backup(1, "full", 1.5)]), info([(1, 0)], [{"type": "full"}])):
            with self.assertRaises((ValueError, KeyError, TypeError), msg=json.dumps(broken)[:80]):
                METRICS.freshness(broken, "agentcapsule")


class Rendering(unittest.TestCase):
    def test_text_format(self):
        text = METRICS.render({"s3": True, "standby": False}, {("s3", "full"): 1000, ("s3", "diff"): 0}, 1234.9)
        self.assertEqual(text, "\n".join([
            "# HELP agentcapsule_backup_collected_timestamp_seconds Unix time of the last collection of backup freshness.",
            "# TYPE agentcapsule_backup_collected_timestamp_seconds gauge",
            "agentcapsule_backup_collected_timestamp_seconds 1234",
            "# HELP agentcapsule_backup_last_success_timestamp_seconds Unix time the newest backup of this type in this repository finished; 0 when it holds none.",
            "# TYPE agentcapsule_backup_last_success_timestamp_seconds gauge",
            'agentcapsule_backup_last_success_timestamp_seconds{repo="s3",type="diff"} 0',
            'agentcapsule_backup_last_success_timestamp_seconds{repo="s3",type="full"} 1000',
            "# HELP agentcapsule_backup_repository_readable 1 when pgBackRest read this repository's list of backups at the last collection.",
            "# TYPE agentcapsule_backup_repository_readable gauge",
            'agentcapsule_backup_repository_readable{repo="s3"} 1',
            'agentcapsule_backup_repository_readable{repo="standby"} 0',
        ]) + "\n")

    def test_closed_vocabulary(self):
        with self.assertRaises(ValueError):
            METRICS.render({"s3": True}, {("s3", "incr"): 1}, 0)
        with self.assertRaises(ValueError):
            METRICS.render({"other": True}, {}, 0)


class Writing(unittest.TestCase):
    def test_atomic_replacement_mode_0644(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / METRICS.FILE_NAME
            path.write_text("old\n")
            path.chmod(0o600)
            old_umask = os.umask(0o077)
            try:
                METRICS.write_atomically(path, "new\n")
            finally:
                os.umask(old_umask)
            self.assertEqual(path.read_text(), "new\n")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            self.assertEqual(os.listdir(d), [METRICS.FILE_NAME], "no temporary file is left")

    def fake_pgbackrest(self, directory, body):
        fake = Path(directory) / "pgbackrest"
        fake.write_text("#!/bin/sh\n" + body)
        fake.chmod(0o755)
        return str(fake)

    def run_main(self, body):
        with tempfile.TemporaryDirectory() as d:
            argv = ["--pgbackrest", self.fake_pgbackrest(d, body), "--textfile-directory", d]
            code = METRICS.main(argv) if os.geteuid() else METRICS.main([*argv, "--user", "nobody"])
            return code, (Path(d) / METRICS.FILE_NAME).read_text()

    def test_main_writes_what_pgbackrest_lists(self):
        listed = json.dumps(info([(1, 0), (2, 0)], [backup(1, "full", 1000), backup(2, "diff", 2000)]))
        code, text = self.run_main(f"cat <<'EOF'\n{listed}\nEOF\n")
        self.assertEqual(code, 0)
        self.assertIn('agentcapsule_backup_last_success_timestamp_seconds{repo="standby",type="diff"} 2000\n', text)
        self.assertIn('agentcapsule_backup_repository_readable{repo="standby"} 1\n', text)
        self.assertNotIn(SECRET, text)

    def test_a_failed_info_marks_every_repository_unreadable(self):
        for body in ("echo 'ERROR: [055]: unable to load info file' >&2\nexit 55\n", "echo 'not json'\n"):
            code, text = self.run_main(body)
            self.assertEqual(code, 1)
            self.assertNotIn("last_success", text.replace("# HELP agentcapsule_backup_last_success", "").replace("# TYPE agentcapsule_backup_last_success", ""))
            self.assertIn('agentcapsule_backup_repository_readable{repo="s3"} 0\n', text)
            self.assertIn('agentcapsule_backup_repository_readable{repo="standby"} 0\n', text)
            self.assertNotIn("ERROR", text)


if __name__ == "__main__":
    unittest.main()
