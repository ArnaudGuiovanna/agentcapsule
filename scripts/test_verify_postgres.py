"""The PostgreSQL campaign's timeouts and shutdown (scripts/verify-postgres.py).

A fast stop that outlasted its wait on a loaded host left the campaign's
cluster running (FIX-2): stop_cluster falls back to an immediate stop, then
to SIGKILL, and checks that the postmaster is gone.
"""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent


def load():
    spec = importlib.util.spec_from_file_location("verify_postgres", SCRIPTS / "verify-postgres.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFY = load()


class IntegrationTimeoutTest(unittest.TestCase):
    def test_invalid_timeout_is_rejected_before_preparing_the_cluster(self):
        for value in ("0", "-1", "1.5", "abc"):
            with self.subTest(value=value):
                result = subprocess.run([sys.executable, SCRIPTS / "verify-postgres.py",
                                         "--integration-timeout-seconds", value],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("--integration-timeout-seconds", result.stderr.split("error:")[-1])

    def test_only_the_integration_phase_uses_the_configured_timeout(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            # Supply Go test events and the recovery marker expected by the
            # runner, so the CLI goes through every phase without a database.
            tool = directory / "test-tool"
            tool.write_text(f"""#!{sys.executable}
import sys
from pathlib import Path
name = Path(sys.argv[0]).name
if name == "go" and sys.argv[1] == "test":
    print('{{"Action":"pass","Test":"TestFixture"}}')
if name == "pg_ctl" and sys.argv[-1] == "start":
    Path(sys.argv[sys.argv.index("-l") + 1]).write_text("automatic recovery in progress")
""")
            tool.chmod(0o700)
            for name in ("go", "postgres", "pg_ctl", "psql", "initdb"):
                (directory / name).symlink_to(tool)
            env = dict(os.environ, PATH=temp + os.pathsep + os.environ["PATH"])
            for options, seconds in (([], 3600), (["--integration-timeout-seconds", "7200"], 7200)):
                with self.subTest(options=options):
                    output = directory / f"output-{seconds}"
                    result = subprocess.run([sys.executable, SCRIPTS / "verify-postgres.py",
                                             "--pg-bin", directory, "--output", output,
                                             "--llm-base-url", "http://unused.invalid", "--llm-model", "test", *options],
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    phases = {p["label"]: p for p in json.loads((output / "summary.json").read_text())}
                    self.assertEqual(phases["integration"]["command"],
                                     ["go", "test", "-race", "-json", "-count=1", f"-timeout={seconds}s",
                                      "-skip", "^TestInvocationEventsLoad$", "./..."])
                    self.assertEqual({label: p["timeout_seconds"] for label, p in phases.items()}, {
                        "initdb": 60, "start": 60, "settings": 60, "service-roles": 60,
                        "integration": seconds, "stream-load": 300, "llm-live": 300, "recovery-prepare": 120,
                        "database-crash": 60, "restart": 930, "recovery-verify": 120, "stop": 150,
                    })
                    for label, duration in (("stream-load", 180), ("llm-live", 3600),
                                            ("recovery-prepare", 3600), ("recovery-verify", 3600)):
                        flags = [arg for arg in phases[label]["command"] if arg.startswith("-timeout=")]
                        self.assertEqual(flags, [f"-timeout={duration}s"], label)


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
