"""The host may report a remote backup only after validating each independent copy."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


class BackupEvidenceTest(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        self.api = {"__name__": "backup_test"}
        for name in ("setup.py", "host.py"):
            source = ROOT / "internal/hostops" / name
            exec(compile(source.read_bytes(), str(source), "exec"), self.api)

    def test_remotes_must_be_encrypted_and_use_the_expected_backends(self):
        example = (ROOT / "deploy/backup/rclone.conf.example").read_text()
        conf = self.root / "rclone.conf"
        conf.write_text(example)
        self.assertEqual(self.api["volume_destinations"](conf), {
            "s3": "https://s3.example.net", "sftp": "standby.example.net"})
        for changed in (example.replace("type = sftp", "type = local"), example.replace("type = crypt", "type = alias"),
                        example.replace("filename_encryption = standard", "filename_encryption = off")):
            conf.write_text(changed)
            with self.assertRaisesRegex(ValueError, "encrypted rclone remotes"):
                self.api["volume_destinations"](conf)

    def test_no_off_host_claim_for_local_or_overlapping_addresses(self):
        with patch.dict(self.api, backup_peer_addresses=Mock(side_effect=[set(), {"198.51.100.1"}])):
            self.assertFalse(self.api["off_host_destinations"]({"s3": "a", "sftp": "b"}))
        for second, expected in (({"198.51.100.1"}, False), ({"203.0.113.1"}, True)):
            with patch.dict(self.api, backup_peer_addresses=Mock(side_effect=[{"198.51.100.1"}, second])):
                self.assertEqual(self.api["off_host_destinations"]({"s3": "a", "sftp": "b"}), expected)

    def test_stanza_override_and_plaintext_pg_repository_are_refused(self):
        conf = self.root / "pg.conf"
        example = (ROOT / "deploy/backup/pgbackrest.conf").read_text()
        conf.write_text(example)
        self.assertEqual(set(self.api["backup_destinations"](conf)), {"s3", "sftp"})
        for changed in (example + "\n[agentcapsule:backup]\nrepo1-type=posix\n",
                        example.replace("repo2-cipher-type=aes-256-cbc", "repo2-cipher-type=none")):
            conf.write_text(changed)
            with self.assertRaises(ValueError):
                self.api["backup_destinations"](conf)

    def test_receipt_requires_both_named_copies_and_authority_checks(self):
        archive, agent = "arc_" + "0" * 32, "agt_" + "1" * 32
        evidence = {"archive_id": archive, "agent_id": agent, "size": 123, "archive_store": "local",
                    "checked": ["manifest", "digest", "volume", "copy", "key"]}
        run, output = Mock(), Mock(return_value=json.dumps(evidence))
        with patch.dict(self.api, run=run, output=output, db_env=lambda _: {}):
            result = self.api["verify_volume_copies"]({}, agent, archive, self.root, "/etc/rclone.conf")
            self.assertEqual(set(result), {"s3", "standby"})
            self.assertEqual([call.args[call.args.index("--store") + 1] for call in run.call_args_list], ["s3", "standby"])
            roots = [call.args[call.args.index("-archive-root") + 1] for call in output.call_args_list]
            self.assertNotEqual(roots[0], roots[1])
            output.side_effect = [json.dumps(evidence), json.dumps(dict(evidence, checked=["digest"]))]
            with self.assertRaisesRegex(ValueError, "fetched probe archive"):
                self.api["verify_volume_copies"]({}, agent, archive, self.root, "/etc/rclone.conf")
