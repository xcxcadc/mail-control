"""Focused tests for Mailu password policy overrides; no Mailu/Flask required."""
import ast
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from tools.configure_password_policy import CUSTOM_VALIDATOR, UPSTREAM_VALIDATOR, configure, patch_source


class PasswordPolicyTests(unittest.TestCase):
    def test_accepts_short_breached_unicode_and_symbol_passwords(self):
        namespace = {}
        exec(CUSTOM_VALIDATOR, namespace)
        validator = namespace["isBadOrPwned"]
        for value in ("1", "password", "密碼", "!@#$%^&*()", "a" * 1000):
            with self.subTest(password_kind=len(value)):
                form = SimpleNamespace(pw=SimpleNamespace(data=value), pwned=SimpleNamespace(data=5000000))
                self.assertIsNone(validator(form))
        for value in ("", None):
            self.assertEqual(validator(SimpleNamespace(pw=SimpleNamespace(data=value))), "Password cannot be empty.")

    def test_only_known_function_changes(self):
        prefix = "# untouched before\nimport os\n\ndef preserve_hash(password):\n    return password.encode('utf-8')\n\n"
        suffix = "\n# untouched after\ndef authentication():\n    return False\n"
        original = prefix + UPSTREAM_VALIDATOR + suffix
        prepared, changed = patch_source(original)
        self.assertTrue(changed)
        self.assertEqual(prepared, prefix + CUSTOM_VALIDATOR + suffix)
        before = ast.parse(original).body
        after = ast.parse(prepared).body
        for a, b in zip(before, after):
            if not isinstance(a, ast.FunctionDef) or a.name != "isBadOrPwned":
                self.assertEqual(ast.dump(a), ast.dump(b))

    def test_idempotent_and_preserves_crlf(self):
        prepared, changed = patch_source(UPSTREAM_VALIDATOR.replace("\n", "\r\n"))
        self.assertTrue(changed)
        self.assertNotIn("\n", prepared.replace("\r\n", ""))
        self.assertEqual(patch_source(prepared), (prepared, False))

    def test_unknown_duplicate_and_decorated_validators_refused(self):
        for source in ("def isBadOrPwned(form):\n    return False\n", UPSTREAM_VALIDATOR * 2,
                       "@authorization\n" + UPSTREAM_VALIDATOR, "def other(): pass\n"):
            with self.subTest(source=source[:40]):
                with self.assertRaises(ValueError):
                    patch_source(source)

    def test_backup_and_rerun_preserve_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "utils.py"
            source.write_text(UPSTREAM_VALIDATOR, encoding="utf-8")
            original = source.read_bytes()
            report = configure(source, source, root / "backup")
            self.assertTrue(report["written"])
            self.assertEqual(Path(report["backup"]).read_bytes(), original)
            second = configure(source, source, root / "backup")
            self.assertFalse(second["written"])
            self.assertEqual(len(list((root / "backup").iterdir())), 1)
            self.assertTrue(configure(source, check=True)["active_in_source"])

    def test_check_does_not_write_and_inplace_requires_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "utils.py"
            source.write_text(UPSTREAM_VALIDATOR, encoding="utf-8")
            original = source.read_bytes()
            self.assertFalse(configure(source, check=True)["active_in_source"])
            self.assertEqual(source.read_bytes(), original)
            with self.assertRaises(ValueError):
                configure(source, source)
            self.assertEqual(source.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
