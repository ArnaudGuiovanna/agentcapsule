#!/usr/bin/env python3
"""The scripts check their inputs with explicit tests, never assert.

python -O drops every assert statement: a pinned checksum checked by assert
would accept any Firecracker source, kernel source or kernel configuration.
build-firecracker.py and build-guest-kernel.py raise ValueError instead, and
these tests run their checks with bad inputs, also under python -O.
"""

import ast
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
# build-product-guest.py is one of the sources the pinned guest build records
# (source_sha256 in its artifacts.json): any change to it asks for a new guest
# image. Its one assert checks the build's own determinism, not an input;
# replace it with the next guest build.
GUEST_SOURCES = {"build-product-guest.py"}


def load(filename):
    spec = importlib.util.spec_from_file_location(filename.removesuffix(".py").replace("-", "_"), SCRIPTS / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FIRECRACKER = load("build-firecracker.py")
KERNEL = load("build-guest-kernel.py")


class NoAssertTest(unittest.TestCase):
    def test_no_script_checks_with_assert(self):
        found = []
        for path in sorted(SCRIPTS.glob("*.py")):
            if path.name.startswith("test_") or path.name in GUEST_SOURCES:
                continue
            tree = ast.parse(path.read_text(), filename=str(path))
            found += [f"{path.name}:{node.lineno}" for node in ast.walk(tree) if isinstance(node, ast.Assert)]
        self.assertEqual(found, [], "use an explicit check that raises: python -O drops assert")


class BuildInputsTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="build-inputs-test-"))
        self.addCleanup(shutil.rmtree, self.dir)
        self.file = self.dir / "input"
        self.file.write_bytes(b"pinned input")
        self.digest = hashlib.sha256(b"pinned input").hexdigest()

    def test_firecracker_refuses_a_patch_or_source_that_differs(self):
        FIRECRACKER.check_digest(self.file, self.digest, "patch")
        for what in ("patch", "upstream"):
            with self.assertRaisesRegex(ValueError, what + " checksum mismatch"):
                FIRECRACKER.check_digest(self.file, "0" * 64, what)

    def test_kernel_refuses_a_source_or_configuration_that_differs(self):
        KERNEL.check_digest(self.file, self.digest, "Linux source")
        for what in ("base config", "cached Linux source", "Linux source"):
            with self.assertRaisesRegex(ValueError, what + " checksum mismatch"):
                KERNEL.check_digest(self.file, "0" * 64, what)

    def test_kernel_refuses_an_option_that_is_not_built_in(self):
        options = ["CONFIG_DM_CRYPT=y", "CONFIG_EXT4_FS=m", "# CONFIG_VSOCKETS is not set"]
        KERNEL.check_builtins(options, ["DM_CRYPT"])
        with self.assertRaisesRegex(ValueError, "required built-in unavailable: EXT4_FS, VSOCKETS"):
            KERNEL.check_builtins(options, ["DM_CRYPT", "EXT4_FS", "VSOCKETS"])

    def test_the_checks_hold_under_python_O(self):
        code = (
            "import importlib.util, pathlib, sys\n"
            "for name in sys.argv[3:]:\n"
            "    spec = importlib.util.spec_from_file_location('m', pathlib.Path(sys.argv[1]) / name)\n"
            "    m = importlib.util.module_from_spec(spec)\n"
            "    spec.loader.exec_module(m)\n"
            "    try:\n"
            "        m.check_digest(pathlib.Path(sys.argv[2]), '0' * 64, 'input')\n"
            "    except ValueError:\n"
            "        print('refused', name)\n")
        result = subprocess.run([sys.executable, "-O", "-B", "-c", code, str(SCRIPTS), str(self.file),
                                 "build-firecracker.py", "build-guest-kernel.py"],
                                capture_output=True, text=True, timeout=60, check=True)
        self.assertEqual(result.stdout.split("\n")[:2], ["refused build-firecracker.py", "refused build-guest-kernel.py"])


if __name__ == "__main__":
    unittest.main()
