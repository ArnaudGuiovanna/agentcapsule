#!/usr/bin/env python3
"""Unit tests of deploy/standby/agentcapsule-standby-metrics.py (REC-03).

A fake psql answers as PostgreSQL 18's psql does with -A -t -F ,;
scripts/verify-archive-shipping.py runs the script against a real standby.
"""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy/standby/agentcapsule-standby-metrics.py"
SPEC = importlib.util.spec_from_file_location("standby_metrics", SCRIPT)
METRICS = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(METRICS)


class Parsing(unittest.TestCase):
    def test_in_recovery_with_a_replayed_transaction(self):
        self.assertEqual(METRICS.parse("t,1794596432.123456,1794590000.5\n"), (True, 1794596432.123456))

    def test_nothing_replayed_since_the_start_counts_from_the_start(self):
        self.assertEqual(METRICS.parse("t,,1794590000.5\n"), (True, 1794590000.5))

    def test_promoted(self):
        self.assertEqual(METRICS.parse("f,1794596432,1794590000\n"), (False, 1794596432.0))

    def test_an_unexpected_answer_is_refused(self):
        for bad in ("", "t", "t,1,2,3", "x,1,2", "t,1,", "t,abc,2", "t,-5,2", "t,1,0", "t,inf,2", "t,nan,2", "ERROR: x"):
            with self.assertRaises(ValueError, msg=bad):
                METRICS.parse(bad)


class Rendering(unittest.TestCase):
    def test_text_format(self):
        self.assertEqual(METRICS.render((True, 1794596432.9), 1794596500.2), "\n".join([
            "# HELP agentcapsule_standby_collected_timestamp_seconds Unix time of the last collection of the standby's replay.",
            "# TYPE agentcapsule_standby_collected_timestamp_seconds gauge",
            "agentcapsule_standby_collected_timestamp_seconds 1794596500",
            "# HELP agentcapsule_standby_in_recovery 1 when the standby's PostgreSQL is in recovery, replaying the WAL archive; 0 once promoted.",
            "# TYPE agentcapsule_standby_in_recovery gauge",
            "agentcapsule_standby_in_recovery 1",
            "# HELP agentcapsule_standby_postgres_up 1 when the standby's PostgreSQL answered the last collection.",
            "# TYPE agentcapsule_standby_postgres_up gauge",
            "agentcapsule_standby_postgres_up 1",
            "# HELP agentcapsule_standby_replay_timestamp_seconds Unix time the last transaction the standby replayed was committed; the time it started, if it replayed none since.",
            "# TYPE agentcapsule_standby_replay_timestamp_seconds gauge",
            "agentcapsule_standby_replay_timestamp_seconds 1794596432",
        ]) + "\n")

    def test_down_has_no_replay_values(self):
        text = METRICS.render(None, 10)
        self.assertIn("agentcapsule_standby_postgres_up 0\n", text)
        self.assertNotIn("in_recovery ", text)
        self.assertNotIn("replay_timestamp_seconds ", text)


class Running(unittest.TestCase):
    def run_main(self, body):
        with tempfile.TemporaryDirectory() as d:
            psql = Path(d) / "psql"
            psql.write_text("#!/bin/sh\n" + body)
            psql.chmod(0o755)
            argv = ["--psql", str(psql), "--textfile-directory", d]
            if os.geteuid() == 0:
                argv += ["--user", "nobody"]
            with contextlib.redirect_stderr(io.StringIO()) as err:
                code = METRICS.main(argv)
            path = Path(d) / METRICS.FILE_NAME
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            self.assertEqual(sorted(os.listdir(d)), sorted([METRICS.FILE_NAME, "psql"]), "no temporary file is left")
            return code, path.read_text(), err.getvalue()

    def test_main_writes_what_postgresql_answers(self):
        code, text, _ = self.run_main("echo 't,1794596432.5,1794590000'\n")
        self.assertEqual(code, 0)
        self.assertIn("agentcapsule_standby_replay_timestamp_seconds 1794596432\n", text)
        self.assertIn("agentcapsule_standby_in_recovery 1\n", text)

    def test_the_query_and_the_connection(self):
        code, text, _ = self.run_main('for a in "$@"; do echo "$a"; done | grep -q "^SELECT pg_is_in_recovery()" && echo "f,1,2" || exit 9\n')
        self.assertEqual(code, 0)
        self.assertIn("agentcapsule_standby_in_recovery 0\n", text)

    def test_postgresql_down_or_a_strange_answer(self):
        for body in ("echo 'psql: error: connection to server failed: secret-host' >&2\nexit 2\n", "echo 'garbage'\n"):
            code, text, err = self.run_main(body)
            self.assertEqual(code, 1)
            self.assertIn("agentcapsule_standby_postgres_up 0\n", text)
            self.assertNotIn("secret-host", text + err, "no message from psql is copied")


if __name__ == "__main__":
    unittest.main()
