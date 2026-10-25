import importlib.util
import json
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('configure_webmail_upload', ROOT / 'tools/configure_webmail_upload.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WebmailUploadTests(unittest.TestCase):
    def test_policy_rejects_bypass_values(self):
        for item in ({'single_mb': True}, {'total_mb': 101}, {'max_count': 0}, {'single_mb': 1.5},
                     {'single_mb': 30, 'total_mb': 24}, {'message_mb': 201}):
            with self.subTest(item=item), self.assertRaises(ValueError):
                MODULE.validate_policy(item)
        self.assertEqual(MODULE.validate_policy({'single_mb': 100, 'total_mb': 100, 'max_count': 100})['single_mb'], 100)

    def test_configure_preserves_other_business_settings_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ini = root / '_data_/_default_/configs/application.ini'
            ini.parent.mkdir(parents=True)
            original = ('; untouched comment\n[webmail]\ntitle = "Existing title"\nattachment_size_limit = 31\n'
                        '[plugins]\nenable = Off\nenabled_list = "proxy-auth,other-plugin"\n'
                        '[security]\ncsrf_protection = On\n')
            ini.write_text(original, encoding='utf-8')
            result = MODULE.configure(root, ROOT / 'webmail/mail-control-upload',
                                      {'single_mb': 25, 'total_mb': 80, 'max_count': 40})
            first = ini.read_text(encoding='utf-8')
            self.assertIn('title = "Existing title"', first)
            self.assertIn('csrf_protection = On', first)
            self.assertIn('attachment_size_limit = 25', first)
            self.assertIn('proxy-auth,other-plugin,mail-control-upload', first)
            self.assertIn('enable = On', first)
            self.assertEqual(ini.with_name('application.ini.before-mail-control-upload').read_text(encoding='utf-8'), original)
            MODULE.configure(root, ROOT / 'webmail/mail-control-upload')
            self.assertEqual(first, ini.read_text(encoding='utf-8'))
            self.assertEqual(json.loads(Path(result['policy']).read_text())['total_mb'], 80)
            for name in MODULE.PLUGIN_FILES:
                self.assertEqual((Path(result['plugin']) / name).read_bytes(), (ROOT / 'webmail/mail-control-upload' / name).read_bytes())

    def test_missing_ini_does_not_create_synthetic_webmail(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                MODULE.configure(folder, ROOT / 'webmail/mail-control-upload')
            self.assertEqual(list(Path(folder).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
