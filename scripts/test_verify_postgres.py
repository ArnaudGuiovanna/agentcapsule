"""The PostgreSQL campaign's stop (scripts/verify-postgres.py).

A fast stop that outlasted its wait on a loaded host left the campaign's
cluster running (FIX-2): stop_cluster falls back to an immediate stop, then
to SIGKILL, and checks that the postmaster is gone.
"""
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent


def load():
    spec = importlib.util.spec_from_file_location("verify_postgres", SCRIPTS / "verify-postgres.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFY = load()


class StopTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.data = Path(temp.name).resolve() / "data"
        self.data.mkdir()
        self.calls = []

    def postmaster(self):
        """A process working in the data directory, named by its PID file,
        as a running postmaster is."""
        proc = subprocess.Popen(["sleep", "60"], cwd=self.data)
        self.addCleanup(lambda: (proc.kill(), proc.wait()))
        (self.data / "postmaster.pid").write_text(f"{proc.pid}\n{self.data}\n")
        return proc

    def refuse_kill(self, pid, sig):
        self.fail(f"signal {sig} sent to {pid}")

    def run_failing(self, *failing):
        def run(label, command, timeout=60):
            self.calls.append((label, [str(c) for c in command], timeout))
            if label in failing:
                raise subprocess.TimeoutExpired(command, timeout)
        return run

    def test_a_fast_stop_that_does_not_end_falls_back_to_an_immediate_one(self):
        self.postmaster()
        VERIFY.stop_cluster(self.run_failing("stop"), Path("/pg/pg_ctl"), self.data, kill=self.refuse_kill)
        self.assertEqual([(label, command[command.index("-m") + 1]) for label, command, _ in self.calls],
                         [("stop", "fast"), ("stop-immediate", "immediate")])
        for _, command, timeout in self.calls:
            # pg_ctl's own wait ends before the runner's.
            self.assertLess(int(command[command.index("-t") + 1]), timeout)

    def test_a_cluster_that_outlives_both_stops_is_killed(self):
        proc = self.postmaster()
        self.assertEqual(VERIFY.postmaster(self.data), proc.pid)
        VERIFY.stop_cluster(self.run_failing("stop", "stop-immediate"), Path("/pg/pg_ctl"), self.data)
        self.assertEqual(proc.wait(timeout=10), -signal.SIGKILL)
        self.assertIsNone(VERIFY.postmaster(self.data))

    def test_a_cluster_that_stopped_needs_nothing_more(self):
        VERIFY.stop_cluster(self.run_failing(), Path("/pg/pg_ctl"), self.data, kill=self.refuse_kill)
        self.assertEqual([label for label, _, _ in self.calls], ["stop"])
        # A fast stop that failed on a cluster already gone: no other stop.
        self.calls.clear()
        VERIFY.stop_cluster(self.run_failing("stop"), Path("/pg/pg_ctl"), self.data, kill=self.refuse_kill)
        self.assertEqual([label for label, _, _ in self.calls], ["stop"])

    def test_a_reused_pid_is_never_killed(self):
        # The PID file names a process that works elsewhere: not the
        # postmaster, whatever its PID.
        other = subprocess.Popen(["sleep", "60"], cwd="/")
        self.addCleanup(lambda: (other.kill(), other.wait()))
        (self.data / "postmaster.pid").write_text(f"{other.pid}\n{self.data}\n")
        self.assertIsNone(VERIFY.postmaster(self.data))
        VERIFY.stop_cluster(self.run_failing("stop", "stop-immediate"), Path("/pg/pg_ctl"), self.data, kill=self.refuse_kill)
        self.assertIsNone(other.poll())


if __name__ == "__main__":
    unittest.main()
