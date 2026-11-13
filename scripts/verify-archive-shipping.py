#!/usr/bin/env python3
"""Qualify the shipping of the volume archives off the host, and the standby's replay metric (REC-02, REC-03).

deploy/backup/agentcapsule-archive-ship.py, with the rclone configuration of
deploy/backup and deploy/standby as shipped, against an S3 store (SeaweedFS
4.53, over TLS) and the standby's SFTP server (OpenSSH, with the Match block of
deploy/standby/sshd-archives.conf). Both images are those of
scripts/verify-backups.py, pinned by digest. The archives are captured with
the platform's own code (internal/volumearchive), signed by a real restore
authority: random bytes stand for the LUKS container, which needs root. The
run checks:
1. a first ship to both stores; an archive older than a store's retention is
   not shipped there; .pending-* and .removed-* directories never are;
2. a second run writes nothing;
3. a shipper killed in an upload, then a network cut (the SFTP server paused
   in an upload): the partial copy is never complete, a fetch refuses it, and
   the next run completes it; a truncated manifest on the standby's disk is
   uploaded again;
4. an archive changed on the host after its upload is reported, and neither
   store is written;
5. the metrics, with both stores, then with the standby's stopped;
6. a fetch from each store alone, the other one stopped, with the standby's
   configuration: every copy is byte-identical, and opens with the restore
   authority. The standby's S3 credential cannot write;
7. neither store holds an archive ID, agent ID, manifest, file name or marker
   in clear, in its own view (the S3 API, the standby's disk) or in
   SeaweedFS's data, while a copy sent in clear is found there: the control
   that the search works;
8. retention by age: an archive removed from the host stays on the stores;
   copies older than --keep go, newer ones stay, and the host keeps its own;
9. the standby's replay metric on a real standby replaying a WAL archive
   (PostgreSQL, archive_command and restore_command copying files): with the
   heartbeat of deploy/backup, on an idle primary without it, with archiving
   cut, once promoted, and stopped;
10. the units: systemd-analyze verify in a throwaway root, and sysusers.

Runs as an ordinary user with Docker and Go. Every secret is generated for the
run, removed with it, and searched for in the evidence.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("verify_backups", ROOT / "scripts/verify-backups.py")
BACKUPS = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(BACKUPS)
SEAWEED, SFTP = BACKUPS.SEAWEED, BACKUPS.SFTP  # the same pinned images
free_port, shipped, kill = BACKUPS.free_port, BACKUPS.shipped, BACKUPS.kill
SHIPPER = ROOT / "deploy/backup/agentcapsule-archive-ship.py"
SPEC = importlib.util.spec_from_file_location("archive_ship", SHIPPER)
SHIP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SHIP)  # for its parser of rclone's times only
STANDBY_METRICS = ROOT / "deploy/standby/agentcapsule-standby-metrics.py"
BUCKET = "agentcapsule-volume-archives"
SFTP_USER = "archives"
# atmoz/sftp chroots each user into its home under /home; /srv/backup/archives on the standby.
SFTP_HOME = "/home/" + SFTP_USER
FILES = ("volume.luks", "manifest.json")
MIB = 1 << 20
UNITS = ["deploy/backup/agentcapsule-archive-ship.service", "deploy/backup/agentcapsule-archive-ship.timer",
         "deploy/backup/agentcapsule-pg-heartbeat.service", "deploy/backup/agentcapsule-pg-heartbeat.timer",
         "deploy/standby/agentcapsule-standby-metrics.service", "deploy/standby/agentcapsule-standby-metrics.timer"]
# The standby phase, scaled down from production: archive_timeout 300 s and a
# heartbeat a minute, an alert at 900 s.
PG_ARCHIVE_TIMEOUT, HEARTBEAT = 10, 2
REPLAY_THRESHOLD = 900 * PG_ARCHIVE_TIMEOUT // 300

ARCHIVE_LAB = """\
// archivelab captures volume archives with the platform's own code
// (internal/volumearchive, internal/restoreauthority), and opens them back as
// a restore does: scripts/verify-archive-shipping.py builds it from a frozen
// copy of the sources.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/restoreauthority"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/volumearchive"
)

const keyIdentity = "keyauth_00000000000000000000000000000000"

func fail(err error) {
	fmt.Fprintln(os.Stderr, "archivelab:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: archivelab capture|open -authority DIR -root DIR -archive ID [...]"))
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	authorityRoot := flags.String("authority", "", "restore authority root")
	root := flags.String("root", "", "archive root")
	id := flags.String("archive", "", "archive ID")
	agent := flags.String("agent", "", "agent ID, to capture")
	volume := flags.String("volume", "", "volume ID, to capture")
	size := flags.Int64("size", 0, "volume bytes, to capture")
	marker := flags.String("marker", "", "text written at the volume's start, middle and end")
	_ = flags.Parse(os.Args[2:])
	ctx := context.Background()
	authority, err := restoreauthority.Initialize(ctx, *authorityRoot, keyIdentity)
	if err != nil {
		fail(err)
	}
	defer authority.Close()
	store, err := volumearchive.New(*root)
	if err != nil {
		fail(err)
	}
	out := json.NewEncoder(os.Stdout)
	switch os.Args[1] {
	case "capture":
		binding, err := authority.Register(ctx, *agent, *volume)
		if err != nil {
			fail(err)
		}
		data := make([]byte, *size)
		_, _ = rand.Read(data)
		for _, at := range []int64{0, *size / 2, *size - int64(len(*marker))} {
			copy(data[at:], *marker)
		}
		spec := volumearchive.Spec{ID: *id, Binding: binding, HarnessDigest: "sha256:" + hex.EncodeToString(make([]byte, 32)), Size: *size}
		a, err := store.Capture(ctx, spec, bytes.NewReader(data), authority)
		if err != nil {
			fail(err)
		}
		_ = out.Encode(map[string]any{"id": a.ID, "agent": a.Binding.Store, "size": a.Size})
	case "open":
		f, a, err := store.Open(ctx, *id, authority)
		if err != nil {
			fail(err)
		}
		defer f.Close()
		h := sha256.New()
		n, err := io.Copy(h, f)
		if err != nil {
			fail(err)
		}
		_ = out.Encode(map[string]any{"id": a.ID, "agent": a.Binding.Store, "size": n, "sha256": hex.EncodeToString(h.Sum(nil))})
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}
"""


def hex_id(prefix):
    return prefix + "_" + secrets.token_hex(16)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rclone", type=Path, required=True, help="rclone executable (the qualified version is 1.60.1)")
    p.add_argument("--go", type=Path, required=True, help="Go executable, to build the archive lab from the sources")
    p.add_argument("--pg-bin", type=Path, required=True, help="PostgreSQL bin directory (initdb, pg_ctl, psql, pg_basebackup)")
    p.add_argument("--pg-library-path", type=Path, help="library directory for PostgreSQL's programs")
    p.add_argument("--output", type=Path, required=True, help="new evidence directory")
    a = p.parse_args()
    for tool in ("docker", "openssl", "ssh-keygen", "systemd-analyze", "systemd-sysusers"):
        if not shutil.which(tool):
            p.error(tool + " is required")
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / "metrics").mkdir()
    report = {"status": "failed", "images": {"s3": SEAWEED, "sftp": SFTP}, "checks": {}}
    checks = report["checks"]
    work = Path(tempfile.mkdtemp(prefix="acpship-", dir="/tmp"))  # short: Unix socket paths
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PG", "RCLONE_"))}
    containers, paused, clusters, credentials = [], [], [], []
    tag = f"acpship-{os.getpid()}"
    rclone = a.rclone.resolve()

    def run(label, command, timeout=600, check=True, **kw):
        with (out / (label + ".log")).open("a") as log:
            log.write("$ " + " ".join(str(c) for c in command) + "\n")
            log.flush()
            r = subprocess.run([str(c) for c in command], env=kw.pop("environment", env), stdout=log, stderr=subprocess.STDOUT,
                               timeout=timeout, check=False, **kw)
        if check and r.returncode:
            raise RuntimeError(f"{label} failed ({r.returncode}); see {label}.log")
        return r.returncode

    def output(command, **kw):
        return subprocess.check_output([str(c) for c in command], env=kw.pop("environment", env), text=True, timeout=600, **kw)

    def expect(condition, message):
        if not condition:
            raise RuntimeError(message)

    try:
        report["rclone"] = output([rclone, "version"]).splitlines()[0]
        expect(report["rclone"].startswith("rclone v1.60.1"), "this run qualifies rclone 1.60.1")

        # ---- Secrets, certificates and keys, for this run only.
        certs = work / "certs"
        certs.mkdir()
        run("setup", ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
                      "-subj", "/CN=archive lab CA", "-keyout", certs / "ca.key", "-out", certs / "ca.pem"])
        run("setup", ["openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-subj", "/CN=127.0.0.1",
                      "-keyout", certs / "s3.key", "-out", certs / "s3.csr"])
        (certs / "san.ext").write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
        run("setup", ["openssl", "x509", "-req", "-in", certs / "s3.csr", "-CA", certs / "ca.pem", "-CAkey", certs / "ca.key",
                      "-CAcreateserial", "-days", "1", "-extfile", certs / "san.ext", "-out", certs / "s3.crt"])
        # The host's credential lists, reads, writes and deletes the bucket,
        # and sets the ACL rclone 1.60 sends with each upload; the standby's
        # only lists and reads it. Neither may create buckets.
        keys = {name: (name + secrets.token_hex(6), secrets.token_hex(24)) for name in ("ship", "standby")}
        actions = {"ship": [f"Read:{BUCKET}", f"Write:{BUCKET}", f"List:{BUCKET}", f"WriteAcp:{BUCKET}"],
                   "standby": [f"Read:{BUCKET}", f"List:{BUCKET}"]}
        (certs / "s3.json").write_text(json.dumps({"identities": [
            {"name": "admin", "credentials": [{"accessKey": "admin" + secrets.token_hex(6), "secretKey": secrets.token_hex(24)}], "actions": ["Admin"]},
            *({"name": n, "credentials": [{"accessKey": k, "secretKey": s}], "actions": actions[n]} for n, (k, s) in keys.items())]}))
        passes = {name: secrets.token_hex(32) for name in ("s3", "s3-2", "standby", "standby-2")}
        obscured = {name: output([rclone, "obscure", value]).strip() for name, value in passes.items()}
        for f in certs.iterdir():
            f.chmod(0o644)  # read by the containers' users
        run("setup", ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", certs / "host_key"])
        run("setup", ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", certs / "client_key"])
        (certs / "client_key").chmod(0o600)
        private_key = (certs / "client_key").read_text().splitlines()[1]
        credentials = [s for _, s in keys.values()] + list(passes.values()) + list(obscured.values()) + [private_key]

        # ---- The archive lab, built from a frozen copy of the sources.
        src = work / "src"
        src.mkdir()
        for name in ("go.mod", "go.sum"):
            shutil.copy2(ROOT / name, src / name)
        shutil.copytree(ROOT / "internal", src / "internal", ignore=shutil.ignore_patterns("*_test.go"))
        (src / "cmd/archivelab").mkdir(parents=True)
        (src / "cmd/archivelab/main.go").write_text(ARCHIVE_LAB)
        (out / "archivelab.go.txt").write_text(ARCHIVE_LAB)  # not a .go file: go vet ./... would pick it up
        go_env = {**env, "CGO_ENABLED": "1", "GOTOOLCHAIN": "local", "GOFLAGS": "-mod=readonly"}
        run("build", [a.go.resolve(), "build", "-trimpath", "-o", work / "archivelab", "./cmd/archivelab"], cwd=src, environment=go_env)
        authority, host_root = work / "authority", work / "host-root"

        def lab(command, root, archive_id, *extra):
            return json.loads(output([work / "archivelab", command, "-authority", authority, "-root", root, "-archive", archive_id, *extra]))

        archives, agents = {}, {}

        def capture(name, agent, size, age_days=0):
            agents.setdefault(agent, hex_id("vol"))
            archive_id, marker = hex_id("arc"), "acp-volume-marker-" + secrets.token_hex(8)
            got = lab("capture", host_root, archive_id, "-agent", agent, "-volume", agents[agent], "-size", str(size), "-marker", marker)
            expect(got["id"] == archive_id and got["agent"] == agent, "the lab did not capture " + name)
            if age_days:
                past = time.time() - age_days * 86400
                for f in FILES:
                    os.utime(host_root / archive_id / f, (past, past))
            archives[name] = {"id": archive_id, "agent": agent, "volume": agents[agent], "marker": marker, "size": size}
            return archive_id

        a_agent, b_agent, c_agent = hex_id("agt"), hex_id("agt"), hex_id("agt")
        capture("A-40-days", a_agent, 64 * 1024, age_days=40)  # beyond both stores' retention
        capture("D-10-days", a_agent, 64 * 1024, age_days=10)  # within S3's 30 days, beyond the standby's 7
        capture("A", a_agent, 1 * MIB)
        capture("B", b_agent, 12 * MIB)  # more than the S3 upload cutoff of the run: a multipart upload
        capture("C", c_agent, 256 * 1024)
        in_progress = {}
        for prefix in (".pending-", ".removed-"):
            directory = host_root / (prefix + secrets.token_hex(16))
            directory.mkdir(mode=0o700)
            in_progress[prefix] = "acp-" + prefix.strip(".-") + "-marker-" + secrets.token_hex(8)
            (directory / "volume.luks").write_text(in_progress[prefix] * 100)
            (directory / "manifest.json").write_text(json.dumps({"id": hex_id("arc"), "binding": {"Store": hex_id("agt")}, "note": in_progress[prefix]}))
        originals = {name: {f: (host_root / x["id"] / f).read_bytes() for f in FILES} for name, x in archives.items()}

        # ---- The stores. The SFTP server writes into a directory of this
        # host, as on the standby's disk; its user has this user's uid.
        s3_port, sftp_port = free_port(), free_port()
        sftp_dir = work / "standby-archives"
        sftp_dir.mkdir(mode=0o750)
        (certs / "sshd_config").write_text(output(["docker", "run", "--rm", "--network", "none", "--entrypoint", "cat", SFTP, "/etc/ssh/sshd_config"])
                                           + "\n" + (ROOT / "deploy/standby/sshd-archives.conf").read_text())
        (certs / "sshd_config").chmod(0o644)
        containers.append(f"{tag}-s3")
        run("services", ["docker", "run", "-d", "--name", f"{tag}-s3", "-p", f"127.0.0.1:{s3_port}:8333", "-v", f"{certs}:/etc/seaweed:ro",
                         SEAWEED, "server", "-dir=/data", "-s3", "-s3.port=8333", "-s3.config=/etc/seaweed/s3.json",
                         "-s3.cert.file=/etc/seaweed/s3.crt", "-s3.key.file=/etc/seaweed/s3.key"])
        containers.append(f"{tag}-sftp")
        run("services", ["docker", "run", "-d", "--name", f"{tag}-sftp", "-p", f"127.0.0.1:{sftp_port}:22",
                         "-v", f"{certs / 'sshd_config'}:/etc/ssh/sshd_config:ro",
                         "-v", f"{certs / 'host_key'}:/etc/ssh/ssh_host_ed25519_key:ro",
                         "-v", f"{certs / 'client_key.pub'}:/etc/ssh/authorized_keys/{SFTP_USER}:ro",
                         "-v", f"{sftp_dir}:{SFTP_HOME}/volumes", SFTP, f"{SFTP_USER}::{os.getuid()}:{os.getgid()}"])
        deadline = time.monotonic() + 120
        while True:
            if run("services", ["docker", "exec", f"{tag}-s3", "sh", "-c", f"echo 's3.bucket.create -name {BUCKET}' | weed shell"],
                   timeout=60, check=False) == 0 and BUCKET in output(["docker", "exec", f"{tag}-s3", "sh", "-c", "echo s3.bucket.list | weed shell"]):
                break
            expect(time.monotonic() < deadline, "the object store did not start; see services.log")
            time.sleep(2)
        # Every host key of the server, as docs/recovery.md has it written:
        # rclone 1.60's SSH client prefers the RSA key to the ed25519 one.
        deadline = time.monotonic() + 60
        while True:
            scanned = subprocess.run(["ssh-keyscan", "-p", str(sftp_port), "127.0.0.1"], capture_output=True, text=True, timeout=30, check=False)
            if scanned.stdout.strip():
                break
            expect(time.monotonic() < deadline, "the SFTP server did not answer ssh-keyscan; see services.log")
            time.sleep(1)
        (certs / "known_hosts").write_text(scanned.stdout)
        ed25519 = (certs / "host_key.pub").read_text().split()[1]
        keys_found = [line.split() for line in scanned.stdout.splitlines() if line.strip() and not line.startswith("#")]
        report["sftp_host_keys"] = sorted(k[1] for k in keys_found)
        expect(any(k[1:3] == ["ssh-ed25519", ed25519] for k in keys_found), "ssh-keyscan did not return the server's ed25519 key")

        # ---- rclone's configurations, as shipped, with only this
        # environment's addresses, paths and secrets replaced.
        s3_lines = {"endpoint = https://s3.example.net": f"endpoint = https://127.0.0.1:{s3_port}", "region = fr-par": "region = us-east-1"}
        host_conf, standby_conf = work / "host-rclone.conf", work / "standby-rclone.conf"
        host_conf.write_text(shipped("deploy/backup/rclone.conf.example", {
            **s3_lines,
            "access_key_id = <access key of a credential limited to this bucket>": f"access_key_id = {keys['ship'][0]}",
            "secret_access_key = <its secret>": f"secret_access_key = {keys['ship'][1]}",
            "password = <rclone obscure of the S3 store's first passphrase>": f"password = {obscured['s3']}",
            "password2 = <rclone obscure of the S3 store's second passphrase>": f"password2 = {obscured['s3-2']}",
            "host = standby.example.net": f"host = 127.0.0.1\nport = {sftp_port}",
            "key_file = /etc/agentcapsule-archive-ship/ssh_ed25519": f"key_file = {certs / 'client_key'}",
            "known_hosts_file = /etc/agentcapsule-archive-ship/known_hosts": f"known_hosts_file = {certs / 'known_hosts'}",
            "password = <rclone obscure of the standby store's first passphrase>": f"password = {obscured['standby']}",
            "password2 = <rclone obscure of the standby store's second passphrase>": f"password2 = {obscured['standby-2']}",
        }))
        standby_conf.write_text(shipped("deploy/standby/rclone.conf.example", {
            **s3_lines,
            "remote = /srv/backup/archives/volumes": f"remote = {sftp_dir}",
            "password = <the host's standby password, as rclone obscure prints it>": f"password = {obscured['standby']}",
            "password2 = <the host's standby password2>": f"password2 = {obscured['standby-2']}",
            "access_key_id = <access key of a read-only credential limited to this bucket>": f"access_key_id = {keys['standby'][0]}",
            "secret_access_key = <its secret>": f"secret_access_key = {keys['standby'][1]}",
            "password = <the host's s3 password>": f"password = {obscured['s3']}",
            "password2 = <the host's s3 password2>": f"password2 = {obscured['s3-2']}",
        }))
        for conf in (host_conf, standby_conf):
            conf.chmod(0o600)
        ca_flag = f"--ca-cert={certs / 'ca.pem'}"
        # The run's own flags: its CA, a multipart upload from 5 MiB, short connection timeouts.
        run_flags = [ca_flag, "--s3-upload-cutoff=5M", "--s3-chunk-size=5M", "--contimeout=10s"]

        def rc(conf, *args, check=True):
            command = [rclone, f"--config={conf}", ca_flag, "--use-server-modtime", "--contimeout=10s", *args]
            if check:
                return output(command)
            return subprocess.run([str(c) for c in command], env=env, capture_output=True, text=True, timeout=600, check=False)

        def listing(conf, remote):
            """{path: (size, time)} as rclone lists it."""
            return {i["Path"]: (i["Size"], i["ModTime"]) for i in json.loads(rc(conf, "lsjson", "-R", "--files-only", "--no-mimetype", remote))}

        def wait_store(conf, remote):
            """Until a store that was stopped or paused answers again."""
            deadline = time.monotonic() + 180
            while rc(conf, "lsjson", remote, check=False).returncode:
                expect(time.monotonic() < deadline, f"{remote} did not come back")
                time.sleep(2)
            return round(180 - (deadline - time.monotonic()), 1)

        def raw_view():
            """Each store as it sees itself: encrypted names, sizes and times."""
            return {"s3": listing(host_conf, f"s3-bucket:{BUCKET}"), "standby": listing(standby_conf, str(sftp_dir))}

        def complete_on(store):
            """The archives (by name) whose files are whole on a store, read through its crypt remote."""
            files = listing(host_conf, f"{store}:")
            return sorted(n for n, x in archives.items() if all(files.get(f"{x['id']}/{f}", (None,))[0] == len(originals[n][f]) for f in FILES))

        textfile, state = work / "textfile", work / "state"
        textfile.mkdir()

        def ship(label, flags=(), keep=(), background=False):
            command = [sys.executable, "-I", SHIPPER, f"--archive-root={host_root}", f"--rclone={rclone}", f"--rclone-config={host_conf}",
                       *(f"--rclone-flag={f}" for f in [*run_flags, *flags]), "ship", f"--textfile-directory={textfile}",
                       f"--state-directory={state}", *(f"--keep={k}" for k in keep)]
            log = (out / f"ship-{label}.log").open("w")
            log.write("$ " + " ".join(str(c) for c in command) + "\n")
            log.flush()
            proc = subprocess.Popen([str(c) for c in command], env=env, stdout=subprocess.PIPE, stderr=log, text=True, start_new_session=True)
            if background:
                return proc, log
            return finish(label, proc, log)

        def finish(label, proc, log, timeout=600):
            stdout, _ = proc.communicate(timeout=timeout)
            log.write(stdout)
            log.close()
            summary = json.loads(stdout.strip().splitlines()[-1]) if stdout.strip() else None
            metrics = read_metrics(label)
            checks.setdefault("runs", {})[label] = {"exit_code": proc.returncode, "summary": summary, "metrics": metrics}
            return proc.returncode, summary, metrics

        def read_metrics(label):
            path = textfile / "agentcapsule-archive-ship.prom"
            text = path.read_text()
            (out / "metrics" / f"{label}.prom").write_text(text)
            expect(path.stat().st_mode & 0o777 == 0o644 and sorted(os.listdir(textfile)) == [path.name],
                   f"{label}: the metrics file is not as written (mode or a leftover file)")
            leaked = [n for n, x in archives.items() if x["id"] in text or x["agent"] in text] + [i for i, s in enumerate(credentials) if s in text]
            expect(not leaked, f"{label}: the metrics file names an archive, an agent or a secret: {leaked}")
            samples = {}
            for line in text.splitlines():
                if not line.startswith("#"):
                    series, value = line.rsplit(" ", 1)
                    samples[series.removeprefix("agentcapsule_archive_ship_")] = int(value)
            return samples

        def m(samples, name, store):
            return samples.get(f'{name}{{store="{store}"}}')

        def uploaded(summary, store):
            return summary["stores"][store].get("uploaded")

        # ---- 1. The first ship.
        started = int(time.time())
        code, summary, first = ship("first")
        on_s3, on_standby = complete_on("s3"), complete_on("standby")
        checks["first_ship"] = {"exit_code": code, "complete_on_s3": on_s3, "complete_on_standby": on_standby}
        expect(code == 0, "the first ship failed; see ship-first.log")
        expect(on_s3 == ["A", "B", "C", "D-10-days"], "S3 does not hold exactly the archives within its 30 days")
        expect(on_standby == ["A", "B", "C"], "the standby does not hold exactly the archives within its 7 days")
        for store in ("s3", "standby"):
            expect((m(first, "pending_archives", store), m(first, "changed_archives", store), m(first, "store_readable", store)) == (0, 0, 1),
                   f"the first ship's metrics for {store} are wrong")
            expect(started <= m(first, "last_success_timestamp_seconds", store) <= time.time(), f"no last success for {store}")
            expect({p.split("/")[0] for p in listing(host_conf, f"{store}:")} <= {x["id"] for x in archives.values()},
                   f"{store} holds something other than the archives: a .pending- or .removed- directory?")

        # ---- 2. A second run writes nothing.
        before = raw_view()
        code, summary, second = ship("second")
        checks["second_ship"] = {"exit_code": code, "uploaded": {s: uploaded(summary, s) for s in ("s3", "standby")},
                                 "stores_unchanged": raw_view() == before}
        expect(code == 0 and checks["second_ship"]["uploaded"] == {"s3": 0, "standby": 0} and checks["second_ship"]["stores_unchanged"],
               "the second run wrote to a store")

        # ---- 3. A manifest cut short on the standby's disk, as an upload cut
        # in its last write leaves it: the ciphertext no longer authenticates.
        crash = checks["crash"] = {}
        plain, encrypted = rc(standby_conf, "cryptdecode", "--reverse", "standby:", f"{archives['C']['id']}/manifest.json").split("\t")
        expect(plain.strip() == f"{archives['C']['id']}/manifest.json", "cryptdecode did not map the manifest")
        with open(sftp_dir / encrypted.strip(), "r+b") as f:
            f.truncate(50)
        code, summary, _ = ship("partial-manifest")
        crash["partial_manifest"] = {"exit_code": code, "uploaded": {s: uploaded(summary, s) for s in ("s3", "standby")}}
        expect(code == 0 and uploaded(summary, "standby") == 1 and uploaded(summary, "s3") == 0 and "C" in complete_on("standby"),
               "a truncated manifest on the standby was not uploaded again")
        # A shipper killed in an upload, then a network cut.
        capture("E", c_agent, 48 * MIB)
        originals["E"] = {f: (host_root / archives["E"]["id"] / f).read_bytes() for f in FILES}
        e_id = archives["E"]["id"]

        def wait_for_upload(store, seconds=2.0):
            deadline = time.monotonic() + 120
            needle = f"{store}:{e_id}/volume.luks"
            while not any(needle in c for c in commands("rcat")):
                expect(time.monotonic() < deadline, f"the upload of E to {store} did not start")
                time.sleep(0.2)
            time.sleep(seconds)

        def commands(*needles):
            found = []
            for proc in Path("/proc").iterdir():
                if proc.name.isdigit():
                    try:
                        command = (proc / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
                    except OSError:
                        continue
                    if all(n in command for n in needles) and str(host_conf) in command:
                        found.append(command)
            return found

        proc, log = ship("killed", flags=["--bwlimit=8M"], background=True)
        wait_for_upload("s3")
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
        log.close()
        expect(not commands("rcat"), "an upload outlived the killed shipper")
        s3_files = listing(host_conf, "s3:")
        crash["e_files_on_s3_after_kill"] = sorted(f for f in s3_files if f.startswith(e_id))
        expect(f"{e_id}/manifest.json" not in s3_files, "a killed upload left E complete on S3")
        # Short timeouts, and one attempt per request: a silent server costs
        # a production run minutes, which this run does not need to wait.
        proc, log = ship("network-cut", flags=["--bwlimit=8M", "--timeout=10s", "--contimeout=5s", "--low-level-retries=1"], background=True)
        wait_for_upload("standby")
        run("services", ["docker", "pause", f"{tag}-sftp"])
        paused.append(f"{tag}-sftp")
        code, summary, cut = finish("network-cut", proc, log)
        on_disk = listing(standby_conf, "standby:")
        partial = {f: on_disk.get(f"{e_id}/{f}", (None,))[0] for f in FILES}
        fetch_partial = subprocess.run([sys.executable, "-I", SHIPPER, f"--archive-root={work / 'restore-partial'}", f"--rclone={rclone}",
                                        f"--rclone-config={standby_conf}", f"--rclone-flag={ca_flag}", "fetch", "--store=standby",
                                        f"--archive={e_id}"], env=env, capture_output=True, text=True, timeout=600, check=False)
        crash.update({"network_cut_exit_code": code, "network_cut_summary": summary, "e_on_standby_disk_during_cut": partial,
                      "fetch_of_partial_copy_exit_code": fetch_partial.returncode, "fetch_of_partial_copy_message": fetch_partial.stderr.strip()[-200:]})
        expect(code == 1 and uploaded(summary, "s3") == 1 and not summary["stores"]["standby"]["readable"],
               "the network cut did not end as expected: E shipped to S3, the standby unreadable")
        expect(m(cut, "store_readable", "standby") == 0 and m(cut, "pending_archives", "standby") is None,
               "with the network cut, the standby's metrics are wrong")
        expect(partial["manifest.json"] is None and partial["volume.luks"] is not None and 0 < partial["volume.luks"] < 48 * MIB,
               "the cut did not leave a partial data file without a manifest on the standby's disk")
        expect(fetch_partial.returncode != 0 and "no complete copy" in fetch_partial.stderr, "a fetch did not refuse the partial copy")
        run("services", ["docker", "unpause", f"{tag}-sftp"])
        paused.remove(f"{tag}-sftp")
        # Back from the cut, sshd first drops new connections while it works
        # through those queued meanwhile (MaxStartups): the next run waits.
        crash["standby_answers_again_after_seconds"] = wait_store(host_conf, "standby:")
        code, summary, resumed = ship("resumed")
        crash["resumed"] = {"exit_code": code, "uploaded": {s: uploaded(summary, s) for s in ("s3", "standby")}}
        expect(code == 0 and uploaded(summary, "s3") == 0 and uploaded(summary, "standby") == 1, "the resumed run did not complete E")
        expect("E" in complete_on("s3") and "E" in complete_on("standby"), "E is not complete on both stores")

        # ---- 4. Archives changed on the host after their upload.
        before, saved = raw_view(), {}
        time.sleep(3)  # beyond the shipper's clock margin
        for name in ("B", "C"):
            saved[name] = os.stat(host_root / archives[name]["id"] / "volume.luks")
        with open(host_root / archives["C"]["id"] / "volume.luks", "ab") as f:
            f.write(b"grown")
        with open(host_root / archives["B"]["id"] / "volume.luks", "r+b") as f:
            f.seek(1000)
            f.write(bytes(b ^ 0xFF for b in originals["B"]["volume.luks"][1000:1010]))  # same size
        code, summary, changed = ship("changed")
        checks["changed"] = {"exit_code": code, "changed": {s: m(changed, "changed_archives", s) for s in ("s3", "standby")},
                             "uploaded": {s: uploaded(summary, s) for s in ("s3", "standby")}, "stores_unchanged": raw_view() == before}
        expect(code == 1 and checks["changed"]["changed"] == {"s3": 2, "standby": 2} and checks["changed"]["uploaded"] == {"s3": 0, "standby": 0}
               and checks["changed"]["stores_unchanged"], "the changed archives were not reported, or a store was written")
        for name in ("B", "C"):
            path = host_root / archives[name]["id"] / "volume.luks"
            path.write_bytes(originals[name]["volume.luks"])
            os.utime(path, ns=(saved[name].st_atime_ns, saved[name].st_mtime_ns))
        code, summary, restored = ship("restored")
        expect(code == 0 and m(restored, "changed_archives", "s3") == 0 and m(restored, "changed_archives", "standby") == 0,
               "the archives, put back as they were, are still reported changed")

        # ---- 5. The metrics with the standby's store stopped.
        run("services", ["docker", "stop", f"{tag}-sftp"])
        code, summary, stopped = ship("standby-stopped")
        checks["standby_stopped"] = {"exit_code": code, "metrics": stopped}
        expect(code == 1 and m(stopped, "store_readable", "standby") == 0 and m(stopped, "pending_archives", "standby") is None
               and m(stopped, "changed_archives", "standby") is None
               and m(stopped, "last_success_timestamp_seconds", "standby") == m(restored, "last_success_timestamp_seconds", "standby")
               and m(stopped, "store_readable", "s3") == 1 and m(stopped, "pending_archives", "s3") == 0
               and m(stopped, "last_success_timestamp_seconds", "s3") >= m(restored, "last_success_timestamp_seconds", "s3"),
               "with the standby's store stopped, the metrics are wrong; see summary.json")
        run("services", ["docker", "start", f"{tag}-sftp"])
        wait_store(host_conf, "standby:")

        # ---- 6. A fetch from each store alone, with the standby's configuration.
        fetched = checks["fetch"] = {}

        def fetch_all(store, names):
            restore_root = work / f"restore-{store}"
            results = {}
            for name in names:
                x = archives[name]
                r = subprocess.run([sys.executable, "-I", SHIPPER, f"--archive-root={restore_root}", f"--rclone={rclone}",
                                    f"--rclone-config={standby_conf}", f"--rclone-flag={ca_flag}", "fetch", f"--store={store}",
                                    f"--archive={x['id']}"], env=env, capture_output=True, text=True, timeout=600, check=False)
                with (out / f"fetch-{store}.log").open("a") as log:
                    log.write(r.stdout + r.stderr)
                same = r.returncode == 0 and all((restore_root / x["id"] / f).read_bytes() == originals[name][f] for f in FILES)
                opened = lab("open", restore_root, x["id"]) if same else {}
                results[name] = {"exit_code": r.returncode, "byte_identical": same,
                                 "opens_with_the_restore_authority": opened.get("agent") == x["agent"] and opened.get("size") == x["size"]}
            return results

        run("services", ["docker", "stop", f"{tag}-sftp"])
        fetched["s3_alone"] = fetch_all("s3", ["A", "B", "C", "D-10-days", "E"])
        run("services", ["docker", "start", f"{tag}-sftp"])
        run("services", ["docker", "stop", f"{tag}-s3"])
        fetched["standby_alone"] = fetch_all("standby", ["A", "B", "C", "E"])
        run("services", ["docker", "start", f"{tag}-s3"])
        wait_store(host_conf, "s3:")
        wait_store(host_conf, "standby:")
        expect(all(r["byte_identical"] and r["opens_with_the_restore_authority"] for side in fetched.values() for r in side.values()),
               "a fetched archive differs or does not open; see summary.json")
        probe = work / "probe"
        probe.write_text("the standby must not write")
        write = rc(standby_conf, "copyto", "--retries=1", probe, f"s3:probe-{secrets.token_hex(4)}", check=False)
        delete = rc(standby_conf, "deletefile", "--retries=1", f"s3:{archives['A']['id']}/manifest.json", check=False)
        fetched["standby_s3_credential"] = {"write_refused": write.returncode != 0, "delete_refused": delete.returncode != 0}
        expect(write.returncode and delete.returncode and "A" in complete_on("s3"), "the standby's S3 credential could write or delete")

        # ---- 7. No clear text in either store; a copy in clear is found.
        decoy = {"agent": hex_id("agt"), "marker": "acp-decoy-marker-" + secrets.token_hex(8)}
        decoy_dir = work / "decoy" / ("decoy-" + decoy["agent"])
        decoy_dir.mkdir(parents=True)
        (decoy_dir / "decoy.bin").write_bytes(secrets.token_bytes(4096) + (decoy["marker"] + decoy["agent"]).encode() + secrets.token_bytes(4096))
        rc(host_conf, "copy", decoy_dir, f"s3-bucket:{BUCKET}/{decoy_dir.name}")
        rc(host_conf, "copy", decoy_dir, f"standby-sftp:volumes/{decoy_dir.name}")
        views = work / "views"
        rc(host_conf, "copy", f"s3-bucket:{BUCKET}", views / "s3-api")
        run("scan", ["docker", "cp", f"{tag}-s3:/data", views / "s3-data"])
        needles = {"marker": [x["marker"] for x in archives.values()], "agent_id": list(agents), "volume_id": list(agents.values()),
                   "archive_id": [x["id"] for x in archives.values()], "file_name": list(FILES), "manifest_field": ["harness_digest"],
                   "in_progress_marker": list(in_progress.values())}

        def found(root):
            """{kind: count} of needles in the names and contents under root."""
            hits = {}
            for f in root.rglob("*"):
                data = (str(f.relative_to(root)).encode() + b"\n" + (f.read_bytes() if f.is_file() and not f.is_symlink() else b""))
                for kind, values in needles.items():
                    hits[kind] = hits.get(kind, 0) + sum(1 for v in values if v.encode() in data)
            return {k: v for k, v in hits.items() if v}

        def has_decoy(root):
            blob = b"".join(str(f.relative_to(root)).encode() + (f.read_bytes() if f.is_file() and not f.is_symlink() else b"")
                            for f in root.rglob("*"))
            return decoy["marker"].encode() in blob and decoy["agent"].encode() in blob

        scan = checks["clear_text"] = {
            "s3_api_view": found(views / "s3-api"), "s3_data_directory": found(views / "s3-data"), "standby_disk": found(sftp_dir),
            "control_host_archive_root": found(host_root),
            "control_decoy_found": {"s3_api_view": has_decoy(views / "s3-api"), "s3_data_directory": has_decoy(views / "s3-data"),
                                    "standby_disk": has_decoy(sftp_dir)}}
        expect(all(scan["control_decoy_found"].values()), "the control failed: a copy in clear was not found in a store's view")
        expect({"marker", "agent_id", "archive_id", "file_name", "manifest_field", "in_progress_marker"} <= set(scan["control_host_archive_root"]),
               "the control failed: the host's own archive root does not hold the needles")
        expect(not scan["s3_api_view"] and not scan["s3_data_directory"] and not scan["standby_disk"],
               "a store holds an archive ID, agent ID, manifest, file name or marker in clear")
        rc(host_conf, "purge", f"s3-bucket:{BUCKET}/{decoy_dir.name}")
        rc(host_conf, "purge", f"standby-sftp:volumes/{decoy_dir.name}")
        modes = sorted({oct(f.stat().st_mode & 0o777) for f in sftp_dir.rglob("*")})
        scan["standby_disk_modes"] = modes
        expect(set(modes) <= {"0o640", "0o750"}, "the SFTP server's umask is not applied: files 0640, directories 0750")
        scan["objects"] = {"s3": len(raw_view()["s3"]), "standby": len(raw_view()["standby"])}

        # ---- 8. Retention by age only.
        retention = checks["retention"] = {}
        # The worker's own retention: renamed out of its ID, then deleted.
        removed = host_root / (".removed-" + secrets.token_hex(16))
        os.rename(host_root / archives["A"]["id"], removed)
        shutil.rmtree(removed)
        code, summary, _ = ship("host-removed-one")
        retention["removed_on_the_host_stays"] = {"exit_code": code, "on_s3": "A" in complete_on("s3"), "on_standby": "A" in complete_on("standby")}
        expect(code == 0 and retention["removed_on_the_host_stays"]["on_s3"] and retention["removed_on_the_host_stays"]["on_standby"],
               "an archive removed from the host was removed from a store")
        # E reached the stores last: a retention between the age of its copies
        # and that of the others removes those and keeps E.
        files = {s: listing(host_conf, f"{s}:") for s in ("s3", "standby")}

        def age(store, name):
            return time.time() - SHIP.unix_time(files[store][f"{archives[name]['id']}/manifest.json"][1])

        ages = {s: {n: round(age(s, n), 1) for n in archives if f"{archives[n]['id']}/manifest.json" in files[s]} for s in files}
        newest_other = min(v for s in ages for n, v in ages[s].items() if n != "E")
        oldest_e = max(ages[s]["E"] for s in ages)
        expect(newest_other - oldest_e >= 10, "E was not shipped well after the others")
        keep = int((newest_other + oldest_e) / 2)
        local_before = sorted(os.listdir(host_root))
        code, summary, pruned = ship("retention", keep=[f"s3={keep}s", f"standby={keep}s"])
        retention["by_age"] = {"keep_seconds": keep, "ages_on_stores_seconds": ages, "exit_code": code,
                               "pruned": {s: summary["stores"][s]["pruned"] for s in ("s3", "standby")},
                               "complete_on_s3": complete_on("s3"), "complete_on_standby": complete_on("standby"),
                               "host_unchanged": sorted(os.listdir(host_root)) == local_before}
        expect(code == 0 and retention["by_age"]["complete_on_s3"] == ["E"] and retention["by_age"]["complete_on_standby"] == ["E"]
               and retention["by_age"]["pruned"] == {"s3": 4, "standby": 3} and retention["by_age"]["host_unchanged"],
               "retention by age did not keep exactly E on each store, or touched the host")
        leftovers = {s: sorted({p.split("/")[0] for p in listing(host_conf, f"{s}:")} - {archives["E"]["id"]}) for s in ("s3", "standby")}
        expect(not any(leftovers.values()), "a pruned archive left files on a store")

        # ---- 9. The standby's replay metric, on a real standby.
        report["standby"] = standby_phase(a, out, work, env, run, output, expect, clusters)

        # ---- 10. The units.
        report["systemd"] = check_units(work, out)
        report["postgresql"] = output([a.pg_bin / "postgres", "--version"], environment=pg_env(a, env)).strip()
        report["status"] = "passed"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
    finally:
        for c in clusters:
            subprocess.run([str(a.pg_bin / "pg_ctl"), "-D", str(c), "-m", "immediate", "-w", "stop"], env=pg_env(a, env),
                           capture_output=True, check=False)
        kill(str(work))  # rclone, if any is left
        for c in paused:
            subprocess.run(["docker", "unpause", c], capture_output=True, check=False)
        for c in containers:
            with (out / "services.log").open("a") as log:
                subprocess.run(["docker", "logs", c], stdout=log, stderr=subprocess.STDOUT, check=False)
            subprocess.run(["docker", "rm", "-f", "-v", c], capture_output=True, check=False)
        shutil.rmtree(work, ignore_errors=True)
        leaks = sorted(str(f.relative_to(out)) for f in out.rglob("*") if f.is_file()
                       and any(c.encode() in f.read_bytes() for c in credentials))
        report["secrets_in_evidence"] = leaks
        if leaks and report["status"] == "passed":
            report["status"], report["error"] = "failed", "a secret of the run is in the evidence"
        (out / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k: report[k] for k in ("status", "error") if k in report}, indent=2))
    return 0 if report["status"] == "passed" else 1


def pg_env(a, env):
    return {**env, "LD_LIBRARY_PATH": str(a.pg_library_path)} if a.pg_library_path else env


def standby_phase(a, out, work, env, run, output, expect, clusters):
    """The replay metric on a primary and a standby that replays its WAL archive."""
    pgenv = pg_env(a, env)
    pg = lambda name: a.pg_bin / name  # noqa: E731
    result = {"archive_timeout_seconds": PG_ARCHIVE_TIMEOUT, "heartbeat_seconds": HEARTBEAT, "alert_threshold_seconds": REPLAY_THRESHOLD}
    archive, broken = work / "wal-archive", work / "archive-cut"
    archive.mkdir()
    primary, psock, standby, ssock = work / "pg-primary", work / "p", work / "pg-standby", work / "q"
    psock.mkdir()
    ssock.mkdir()
    timeouts = {"archive_timeout = 300": f"archive_timeout = {PG_ARCHIVE_TIMEOUT}", "checkpoint_timeout = 300": "checkpoint_timeout = 30"}
    run("standby", [pg("initdb"), "-D", primary, "--auth-local=trust", "--auth-host=reject", "--no-locale", "--encoding=UTF8"], environment=pgenv)
    command = f"test ! -e {broken} && test ! -f {archive}/%f && cp %p {archive}/%f"
    with (primary / "postgresql.conf").open("a") as f:
        f.write(f"listen_addresses = ''\nunix_socket_directories = '{psock}'\n" + shipped("deploy/backup/postgresql.conf", {
            "archive_command = 'pgbackrest --stanza=agentcapsule archive-push %p'": f"archive_command = '{command}'", **timeouts}))
    run("standby", [pg("pg_ctl"), "-D", primary, "-l", out / "pg-primary.log", "-w", "start"], environment=pgenv)
    clusters.append(primary)
    run("standby", [pg("pg_basebackup"), "-h", psock, "-D", standby, "-X", "none", "-c", "fast"], environment=pgenv)
    with (standby / "postgresql.conf").open("a") as f:
        f.write(shipped("deploy/standby/postgresql.conf", timeouts)
                + f"listen_addresses = ''\nunix_socket_directories = '{ssock}'\nrestore_command = 'cp {archive}/%f %p'\n")
    (standby / "standby.signal").touch()
    run("standby", [pg("pg_ctl"), "-D", standby, "-l", out / "pg-standby.log", "-t", "300", "-w", "start"], environment=pgenv)
    clusters.append(standby)

    # psql as the metrics script runs it, with this run's libraries.
    wrapper = work / "psql"
    wrapper.write_text(f"#!/bin/sh\nLD_LIBRARY_PATH={shlex.quote(str(a.pg_library_path or ''))} exec {shlex.quote(str(pg('psql')))} \"$@\"\n")
    wrapper.chmod(0o755)
    textfile = work / "standby-textfile"
    textfile.mkdir()

    def collect(label):
        code = run("standby-metrics", [sys.executable, "-I", STANDBY_METRICS, f"--psql={wrapper}", f"--host={ssock}",
                                       f"--textfile-directory={textfile}"], check=False)
        text = (textfile / "agentcapsule-standby.prom").read_text()
        (out / "metrics" / f"standby-{label}.prom").write_text(text)
        samples = {line.rsplit(" ", 1)[0].removeprefix("agentcapsule_standby_"): int(line.rsplit(" ", 1)[1])
                   for line in text.splitlines() if not line.startswith("#")}
        if "replay_timestamp_seconds" in samples:
            samples["age"] = samples["collected_timestamp_seconds"] - samples["replay_timestamp_seconds"]
        return code, samples

    # The heartbeat, as deploy/backup ships it, against the primary's socket.
    unit = (ROOT / "deploy/backup/agentcapsule-pg-heartbeat.service").read_text()
    beat = shlex.split(re.search(r"^ExecStart=(.*)$", unit, re.M)[1])
    expect(beat[0] == "/usr/bin/psql", "the heartbeat no longer runs psql")
    beat = [str(wrapper), "-h", str(psock), *beat[1:]]
    beating, stop = threading.Event(), threading.Event()
    beats = []

    def heart():
        while not stop.is_set():
            if beating.is_set():
                beats.append(subprocess.run(beat, env=env, capture_output=True, timeout=30, check=False).returncode)
            stop.wait(HEARTBEAT)

    thread = threading.Thread(target=heart, daemon=True)
    thread.start()

    def wait(predicate, limit, failure):
        start = time.monotonic()
        while True:
            code, samples = collect("wait")
            if predicate(samples):
                return round(time.monotonic() - start, 1), samples
            expect(time.monotonic() - start < limit, failure)
            time.sleep(1)

    try:
        beating.set()
        result["catch_up_seconds"], _ = wait(lambda s: s.get("age", 1e9) < REPLAY_THRESHOLD, 180,
                                             "the standby did not catch up with the heartbeat")
        # A minute with the heartbeat: the age stays well below the alert.
        segments_before = {f.name for f in archive.iterdir()}
        ages, end = [], time.monotonic() + 60
        while time.monotonic() < end:
            code, samples = collect("heartbeat")
            expect(code == 0 and samples["postgres_up"] == 1 and samples["in_recovery"] == 1, "the standby is not replaying")
            ages.append(samples["age"])
            time.sleep(2)
        result["with_heartbeat"] = {"samples": len(ages), "max_age_seconds": max(ages), "heartbeats": len(beats),
                                    "heartbeat_failures": sum(1 for b in beats if b)}
        expect(max(ages) <= PG_ARCHIVE_TIMEOUT + HEARTBEAT + 5 + 5 and not result["with_heartbeat"]["heartbeat_failures"],
               "with the heartbeat, the standby's age went beyond archive_timeout, the heartbeat and the poll")
        idle_segments = sorted(f for f in archive.iterdir() if f.name not in segments_before and re.fullmatch(r"[0-9A-F]{24}", f.name))
        result["with_heartbeat"]["segments_archived"] = len(idle_segments)
        if shutil.which("zstd") and idle_segments:
            sizes = [len(subprocess.run(["zstd", "-3", "-c", str(f)], capture_output=True, check=True).stdout) for f in idle_segments]
            result["with_heartbeat"]["segment_zstd_bytes"] = {"min": min(sizes), "max": max(sizes)}
        # An idle primary without the heartbeat: no transaction to replay,
        # the age grows past the alert although nothing is late.
        beating.clear()
        result["idle_without_heartbeat_seconds_to_alert"], samples = wait(
            lambda s: s.get("age", 0) > REPLAY_THRESHOLD, 180, "without the heartbeat, the idle standby's age did not grow")
        result["idle_without_heartbeat_age_seconds"] = samples["age"]
        # The heartbeat again, then archiving cut: the age passes the alert.
        beating.set()
        wait(lambda s: s.get("age", 1e9) < PG_ARCHIVE_TIMEOUT + HEARTBEAT + 10, 120, "the heartbeat did not refresh the standby")
        broken.touch()
        result["archiving_cut_seconds_to_alert"], samples = wait(
            lambda s: s.get("age", 0) > REPLAY_THRESHOLD, 180, "with archiving cut, the standby's age did not pass the alert")
        expect(samples["in_recovery"] == 1 and samples["postgres_up"] == 1, "with archiving cut, the standby is not up and in recovery")
        broken.unlink()
        result["archiving_back_seconds_to_recover"], _ = wait(lambda s: s.get("age", 1e9) < REPLAY_THRESHOLD, 240,
                                                              "once archiving was back, the standby did not catch up")
    finally:
        stop.set()
        thread.join(timeout=30)
    run("standby", [pg("pg_ctl"), "-D", standby, "-w", "promote"], environment=pgenv)
    _, samples = wait(lambda s: s.get("in_recovery") == 0, 60, "the promoted standby is still in recovery")
    result["promoted"] = {"in_recovery": samples["in_recovery"], "postgres_up": samples["postgres_up"]}
    run("standby", [pg("pg_ctl"), "-D", standby, "-m", "fast", "-w", "stop"], environment=pgenv)
    clusters.remove(standby)
    code, samples = collect("stopped")
    result["stopped"] = {"exit_code": code, "samples": sorted(samples)}
    expect(code == 1 and samples.get("postgres_up") == 0 and "in_recovery" not in samples and "replay_timestamp_seconds" not in samples,
           "with the standby stopped, its metrics are wrong")
    expect((textfile / "agentcapsule-standby.prom").stat().st_mode & 0o777 == 0o644, "the standby's metrics file is not 0644")
    return result


def check_units(work, out):
    """systemd-analyze verify in a throwaway root, with stand-ins for the programs; sysusers."""
    root = work / "systemd-root"
    shutil.copytree("/usr/lib/systemd/system", root / "usr/lib/systemd/system", symlinks=True)
    for stand_in in ("usr/bin/python3", "usr/bin/psql"):
        path = root / stand_in
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\n")
        path.chmod(0o755)
    system = root / "etc/systemd/system"
    system.mkdir(parents=True)
    for unit in UNITS:
        shutil.copy2(ROOT / unit, system / Path(unit).name)
    names = [f"/etc/systemd/system/{Path(u).name}" for u in UNITS]
    verify = subprocess.run(["systemd-analyze", "verify", "--man=no", f"--root={root}", *names], capture_output=True, text=True, timeout=120, check=False)
    (out / "systemd-verify.log").write_text(verify.stdout + verify.stderr)
    if verify.returncode or (verify.stdout + verify.stderr).strip():
        raise RuntimeError("systemd-analyze verify reported problems; see systemd-verify.log")
    exposure = {}
    for name in names:
        if name.endswith(".service"):
            r = subprocess.run(["systemd-analyze", "security", "--offline=yes", f"--root={root}", "--no-pager", name],
                               capture_output=True, text=True, timeout=120, check=False)
            score = re.search(r"Overall exposure level for \S+: ([0-9.]+)", r.stdout)
            exposure[Path(name).name] = float(score[1]) if score else None
    for name in ("passwd", "group", "shadow", "gshadow"):
        (root / "etc" / name).touch()
    sysusers = subprocess.run(["systemd-sysusers", f"--root={root}", str(ROOT / "deploy/backup/agentcapsule-archive-ship.sysusers")],
                              capture_output=True, text=True, timeout=120, check=False)
    created = (root / "etc/passwd").read_text().startswith("agentcapsule-ship:")
    if sysusers.returncode or not created:
        raise RuntimeError("the shipping user was not created: " + sysusers.stderr.strip())
    return {"systemd": subprocess.check_output(["systemd-analyze", "--version"], text=True).splitlines()[0], "units": [Path(u).name for u in UNITS],
            "verify_output": "", "exposure": exposure, "sysusers_created_user": created}


if __name__ == "__main__":
    raise SystemExit(main())
