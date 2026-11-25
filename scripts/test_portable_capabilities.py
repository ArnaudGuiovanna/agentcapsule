#!/usr/bin/env python3
"""Portable preflight must fail before changing the host or launching services."""
from pathlib import Path
import os
import runpy
import stat
import tempfile
import types
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "internal/hostops/capabilities.py"
CHECK = runpy.run_path(str(MODULE))["portable_host_preflight"]


class PortablePreflight(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.controllers = "memory pids cpu"
        self.mountinfo = "100 80 8:1 / / rw - ext4 /dev/sda1 rw"
        self.patch("platform.machine", return_value="x86_64")
        self.patch("platform.release", return_value="6.18-test")
        self.patch("platform.system", return_value="Linux")
        self.patch("pathlib.Path.is_file", return_value=True)
        self.patch("pathlib.Path.is_dir", return_value=True)
        self.patch("pathlib.Path.exists", return_value=True)
        self.patch("pathlib.Path.read_text", autospec=True, side_effect=self.read_text)
        self.files = self.patch("builtins.open", mock.mock_open())
        self.patch("os.fstat", return_value=types.SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(10, 232)))
        self.patch("os.statvfs", return_value=types.SimpleNamespace(f_flag=0))
        self.ioctl = self.patch("fcntl.ioctl", side_effect=[12, 100, bytes([2, 0, 0, 0])])
        self.close = self.patch("os.close")

    def patch(self, target, *args, **kwargs):
        patch = mock.patch(target, *args, **kwargs)
        self.addCleanup(patch.stop)
        return patch.start()

    def read_text(self, path):
        return self.controllers if path.name == "cgroup.controllers" else self.mountinfo

    def test_independent_of_distribution_and_closes_transient_vm(self):
        CHECK(self.path)
        self.close.assert_called_once_with(100)

    def test_no_kvm(self):
        self.files.side_effect = FileNotFoundError("/dev/kvm")
        with self.assertRaisesRegex(ValueError, "enable virtualization"):
            CHECK(self.path)

    def test_kvm_open_but_vm_creation_denied(self):
        self.ioctl.side_effect = [12, PermissionError("blocked")]
        with self.assertRaisesRegex(ValueError, "VM creation failed"):
            CHECK(self.path)

    def test_tun_without_tap(self):
        self.ioctl.side_effect = [12, 100, bytes(4)]
        with self.assertRaisesRegex(ValueError, "TAP support"):
            CHECK(self.path)

    def test_controller_missing(self):
        self.controllers = "memory cpu"
        with self.assertRaisesRegex(ValueError, "pids"):
            CHECK(self.path)
        self.files.assert_not_called()

    def test_nested_ephemeral_mount_refused(self):
        self.mountinfo += "\n110 100 0:1 / " + self.path.as_posix() + " rw - tmpfs tmpfs rw"
        with self.assertRaisesRegex(ValueError, "tmpfs.*persistent"):
            CHECK(self.path)

    def test_nodev_storage_refused(self):
        self.patch("os.statvfs", return_value=types.SimpleNamespace(f_flag=os.ST_NODEV))
        with self.assertRaisesRegex(ValueError, "dev and exec"):
            CHECK(self.path)


if __name__ == "__main__":
    unittest.main()
