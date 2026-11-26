import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import pi_release


class PiDistributionTests(unittest.TestCase):
    def test_rejects_wrong_converter_before_publishing_pi(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = SimpleNamespace(tag="v0.1.6", tool="harness", packages=root, catalog=root/"catalog.json")
            digests = {name: "sha256:" + str(i)*64 for i, name in enumerate(pi_release.NAMES, 1)}
            args.catalog.write_text(json.dumps({
                "schema": "agentcapsule.pi/v1", "release": args.tag, "publisher_key": "test",
                "packages": {n: f"{pi_release.REGISTRY}/{pi_release.REPOSITORY}@{d}" for n, d in digests.items()},
            }))
            for field, changed, error in [("name", "different", "expected"),
                                          ("base", "agentcapsule-guest/1", "expected"),
                                          ("version", "0.1.5", "expected"),
                                          ("digest", "sha256:"+"3"*64, "differs")]:
                def inspect(tool, command, *flags):
                    self.assertEqual(command, "digest", "release attempted a write before checking both packages")
                    name = flags[flags.index("--dir")+1].name
                    report = dict(name=name, version="0.1.6", base="agentcapsule-guest/2", digest=digests[name])
                    if name == pi_release.NAMES[1]:
                        report[field] = changed
                    return json.dumps(report)

                with self.subTest(field=field), patch.object(pi_release, "output", side_effect=inspect):
                    with self.assertRaisesRegex(ValueError, error):
                        pi_release.publish(args)


if __name__ == "__main__":
    unittest.main()
