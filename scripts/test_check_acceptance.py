#!/usr/bin/env python3
"""Unit tests of scripts/check-acceptance.py (VAL-02).

The check must fail on a requirement of docs/product.md §4 without a row, on a
row for a requirement that no longer exists, on an unknown status, on a met
row without a test, and on a cited test or file that does not exist.
"""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name("check-acceptance.py")
SPEC = importlib.util.spec_from_file_location("check_acceptance", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
sys.dont_write_bytecode = True
SPEC.loader.exec_module(CHECK)

PRODUCT = """# Product
## 3. Concepts
| ID | Not a requirement | Here |
| ABC-999 | outside §4 | x |
## 4. MVP (P0) requirements
| ID | Requirement | Acceptance |
|---|---|---|
| TEN-001 | Create | Audited |
| TEN-002 | Tenant ID | Refused |
| A2A-001 | OASF record | Updated |
## 5. Out of scope
"""

GOOD = """# Acceptance
| ID | Acceptance | Status | Proof | Missing |
|---|---|---|---|---|
| TEN-001 | Audited | met | [`TestAudit`](../pkg/a_test.go) (PG) | — |
| TEN-002 | Refused | partial | [`TestAudit/case-one`](../pkg/a_test.go), [`test_refuses`](../scripts/test_x.py) | more |
| A2A-001 | Updated | not met | — | all |
| OUT-1 | a clause | met | [verify-x.py](../scripts/verify-x.py) | — |
| OPR-1 | a promise | needs KVM | `TestAudit` | a run |
"""


class Acceptance(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        (root / "docs").mkdir()
        (root / "pkg").mkdir()
        (root / "scripts").mkdir()
        (root / "pkg" / "a_test.go").write_text('package pkg\nfunc TestAudit(t *testing.T) { t.Run("case-one", nil) }\n')
        (root / "scripts" / "test_x.py").write_text("class T:\n    def test_refuses(self):\n        pass\n")
        (root / "scripts" / "verify-x.py").write_text("print('ok')\n")
        self.page = root / "docs" / "acceptance.md"
        self.ids = CHECK.requirements(PRODUCT)

    def tearDown(self):
        self.dir.cleanup()

    def errors(self, text):
        return CHECK.check(self.page, text, self.ids, {"TestAudit"})

    def test_reads_the_requirements_of_section_4_only(self):
        self.assertEqual(self.ids, ["TEN-001", "TEN-002", "A2A-001"])

    def test_a_complete_page_passes(self):
        self.assertEqual(self.errors(GOOD), [])

    def test_a_requirement_without_a_row_fails(self):
        text = GOOD.replace("| TEN-002 | Refused | partial", "| XYZ-1 | Refused | partial")
        self.assertEqual(self.errors(text), ["docs/product.md: TEN-002 has no row in docs/acceptance.md"])
        text = GOOD.replace("| A2A-001 | Updated | not met | — | all |\n", "")
        self.assertEqual(self.errors(text), ["docs/product.md: A2A-001 has no row in docs/acceptance.md"])

    def test_a_requirement_listed_twice_fails(self):
        text = GOOD + "| TEN-001 | again | met | [`TestAudit`](../pkg/a_test.go) | — |\n"
        self.assertEqual(self.errors(text), ["docs/acceptance.md:9: TEN-001 is already listed at line 4"])

    def test_a_requirement_the_product_no_longer_has_fails(self):
        text = GOOD + "| TEN-010 | gone | partial | — | — |\n"
        self.assertEqual(self.errors(text), ["docs/acceptance.md:9: TEN-010 is not a requirement of docs/product.md §4"])

    def test_an_unknown_status_fails(self):
        text = GOOD.replace("| needs KVM |", "| maybe |")
        self.assertEqual(self.errors(text),
                         ["docs/acceptance.md:8: unknown status 'maybe' (one of met, partial, not met, needs KVM)"])

    def test_a_met_row_without_a_test_fails(self):
        text = GOOD.replace("| met | [verify-x.py](../scripts/verify-x.py) |", "| met | [the docs](../pkg/a_test.go) |")
        self.assertEqual(self.errors(text), ["docs/acceptance.md:7: OUT-1 is met but cites no test or campaign script"])

    def test_a_link_to_a_missing_file_fails(self):
        text = GOOD.replace("../scripts/verify-x.py", "../scripts/verify-gone.py")
        self.assertEqual(self.errors(text), ["docs/acceptance.md:7: ../scripts/verify-gone.py does not exist"])

    def test_a_go_test_missing_from_its_file_fails(self):
        text = GOOD.replace("[`TestAudit`](../pkg/a_test.go) (PG)", "[`TestGone`](../pkg/a_test.go) (PG)")
        self.assertEqual(self.errors(text), ["docs/acceptance.md:4: ../pkg/a_test.go does not define TestGone",
                                             "docs/acceptance.md:4: Go test TestGone does not exist"])

    def test_a_missing_case_fails(self):
        text = GOOD.replace("TestAudit/case-one", "TestAudit/case-two")
        self.assertEqual(self.errors(text), ["docs/acceptance.md:5: ../pkg/a_test.go has no case 'case-two' of TestAudit"])

    def test_a_python_test_missing_from_its_file_fails(self):
        text = GOOD.replace("test_refuses", "test_accepts")
        self.assertEqual(self.errors(text), ["docs/acceptance.md:5: ../scripts/test_x.py does not define test_accepts"])

    def test_a_go_test_named_in_text_must_exist(self):
        text = GOOD.replace("| needs KVM | `TestAudit` |", "| needs KVM | `TestNeverWritten` |")
        self.assertEqual(self.errors(text), ["docs/acceptance.md:8: Go test TestNeverWritten does not exist"])


if __name__ == "__main__":
    unittest.main()
