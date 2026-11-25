"""Kernel and storage requirements of the private systemd userspace."""
import fcntl
import os
from pathlib import Path
import platform
import re
import stat
import struct


def _portable_storage(storage):
    path = Path(storage).resolve()
    while not path.exists():
        path = path.parent
    flags = os.statvfs(path).f_flag
    if flags & (os.ST_RDONLY | os.ST_NODEV | os.ST_NOEXEC):
        raise ValueError(f"{path} must be mounted writable with dev and exec for the Firecracker jail")
    # Longest matching mount (last record for stacked mounts).
    fs = ""
    length = -1
    for row in Path("/proc/self/mountinfo").read_text().splitlines():
        left, right = row.split(" - ", 1)
        point = Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), left.split()[4]))
        if (point == path or point in path.parents) and len(point.parts) >= length:
            fs = right.split()[0]
            length = len(point.parts)
    if not fs or fs in {"tmpfs", "ramfs", "overlay", "nfs", "nfs4", "9p", "fuse", "fuseblk"} or fs.startswith("fuse."):
        raise ValueError(f"{path} uses {fs or 'an unidentified filesystem'}; choose persistent local ext4 or XFS storage")


def portable_host_preflight(storage=Path("/var/lib")):
    if platform.machine() != "x86_64" or platform.system() != "Linux":
        raise ValueError("run this release on x86-64 Linux")
    if not Path("/run/systemd/system").is_dir():
        raise ValueError("enable systemd as the host init system and restart the host")
    controllers = Path("/sys/fs/cgroup/cgroup.controllers")
    if not controllers.is_file() or not {"cpu", "memory", "pids"} <= set(controllers.read_text().split()):
        raise ValueError("enable the cpu, memory and pids controllers in the unified cgroup v2 hierarchy")
    release = re.match(r"(\d+)\.(\d+)", platform.release())
    if not release or tuple(map(int, release.groups())) < (5, 14):
        raise ValueError("install Linux 5.14 or later for cgroup.kill and clone3")
    for ns in ("pid", "mnt", "net", "cgroup"):
        if not Path("/proc/self/ns", ns).exists():
            raise ValueError(f"enable the {ns} namespace in the host kernel")
    try:
        with open("/dev/kvm", "rb+", buffering=0) as kvm:
            info = os.fstat(kvm.fileno())
            if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.makedev(10, 232):
                raise ValueError("/dev/kvm must be the KVM character device (10:232)")
            if fcntl.ioctl(kvm.fileno(), 0xAE00) != 12:  # KVM_GET_API_VERSION
                raise ValueError("KVM API 12 is required; enable virtualization on the host")
            os.close(fcntl.ioctl(kvm.fileno(), 0xAE01, 0))  # KVM_CREATE_VM, no vCPU or guest memory
    except OSError as error:
        raise ValueError(f"KVM VM creation failed ({error}); enable virtualization and expose /dev/kvm to the host") from error
    try:
        with open("/dev/net/tun", "rb+", buffering=0) as tun:
            features = struct.unpack("I", fcntl.ioctl(tun.fileno(), 0x800454CF, bytes(4)))[0]  # TUNGETFEATURES
            if not features & 2:  # IFF_TAP
                raise ValueError("enable TAP support in the host TUN driver")
    except OSError as error:
        raise ValueError(f"cannot query /dev/net/tun ({error}); enable the tun module and expose the device") from error
    _portable_storage(storage)
