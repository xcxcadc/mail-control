import importlib.util
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('upload_policy', Path(__file__).parent / 'src' / 'upload_policy.py')
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class UploadPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.app = self.base / 'app' / 'upload-policy.json'
        self.webmail = self.base / 'webmail' / 'mail-control-upload-policy.json'
        self.webmail.parent.mkdir()
        self.db = self.base / 'app' / 'uploads.db'
        self.env = patch.dict(os.environ, {'MAIL_CONTROL_UPLOAD_POLICY': str(self.app),
                                         'MAIL_CONTROL_WEBMAIL_POLICY': str(self.webmail),
                                         'MAIL_CONTROL_UPLOAD_DB': str(self.db)})
        self.env.start()
        policy._UP_ACTIVE.clear()
        policy._UP_AUDIT_SCHEMA.clear()

    def tearDown(self):
        policy._UP_ACTIVE.clear()
        self.env.stop()
        self.temp.cleanup()

    def test_defaults_and_dual_save(self):
        self.assertEqual(policy.upload_policy(), dict(policy._UP_DEFAULT))
        saved = policy.save_upload_policy({'single_mb': 20, 'total_mb': 80, 'max_count': 30})
        self.assertEqual(saved['message_mb'], 200)
        self.assertEqual(saved['hard_max_mb'], 100)
        self.assertEqual(json.loads(self.app.read_text()), saved)
        self.assertEqual(self.app.read_bytes(), self.webmail.read_bytes())
        self.assertEqual(policy.upload_policy(), saved)
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(self.app.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(self.webmail.stat().st_mode), 0o644)

    def test_bounds_bool_and_unknown_setting_are_rejected(self):
        values = ({'single_mb': 0}, {'total_mb': 101}, {'max_count': True},
                  {'single_mb': '12'}, {'single_mb': 13.0},
                  {'single_mb': 30, 'total_mb': 20}, {'surprise': 1},
                  {'message_mb': 300}, {'hard_max_mb': False})
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                policy.save_upload_policy(value)
        self.assertFalse(self.app.exists())

    def test_corrupt_existing_file_does_not_fallback(self):
        self.app.parent.mkdir()
        self.app.write_text('{bad')
        with self.assertRaisesRegex(ValueError, '文件无效'):
            policy.upload_policy()
        with self.assertRaises(ValueError):
            policy.save_upload_policy({'single_mb': 50})
        self.assertEqual(self.app.read_text(), '{bad')

    def test_webmail_parent_not_implicitly_created(self):
        missing = self.base / 'missing-business' / 'policy.json'
        with patch.dict(os.environ, {'MAIL_CONTROL_WEBMAIL_POLICY': str(missing)}), self.assertRaisesRegex(ValueError, '目录不存在'):
            policy.save_upload_policy({'single_mb': 13})
        self.assertFalse(missing.parent.exists())
        self.assertFalse(self.app.exists())

    def test_second_replace_failure_rolls_back_both_existing_and_absent_files(self):
        policy.save_upload_policy({'single_mb': 12, 'total_mb': 24})
        original_app, original_web = self.app.read_bytes(), self.webmail.read_bytes()
        original_replace = policy._up_os.replace
        def fail_web(source, destination):
            if Path(destination) == self.webmail:
                raise PermissionError('fixture permission failure')
            return original_replace(source, destination)
        with patch.object(policy._up_os, 'replace', side_effect=fail_web), self.assertRaisesRegex(ValueError, '原设置已保留'):
            policy.save_upload_policy({'single_mb': 20, 'total_mb': 40})
        self.assertEqual(self.app.read_bytes(), original_app)
        self.assertEqual(self.webmail.read_bytes(), original_web)
        self.assertEqual(list(self.app.parent.glob('*.tmp')), [])
        self.app.unlink()
        with patch.object(policy._up_os, 'replace', side_effect=fail_web), self.assertRaises(ValueError):
            policy.save_upload_policy({'single_mb': 20, 'total_mb': 40})
        self.assertFalse(self.app.exists())
        self.assertEqual(self.webmail.read_bytes(), original_web)

    def test_permission_failure_before_commit_preserves_both(self):
        policy.save_upload_policy({})
        before = self.app.read_bytes()
        with patch.object(policy, '_up_stage', side_effect=PermissionError('fixture denied')), self.assertRaises(ValueError):
            policy.save_upload_policy({'total_mb': 60})
        self.assertEqual(self.app.read_bytes(), before)
        self.assertEqual(self.webmail.read_bytes(), before)

    def test_progress_realtime_in_memory_and_database_throttled(self):
        with patch.object(policy._up_time, 'monotonic', return_value=10):
            event_id = policy.upload_request_start('custom-send', 'admin@example.com', 100)
        with patch.object(policy._up_time, 'monotonic', return_value=10.1):
            policy.upload_request_progress(event_id, 35)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT received FROM upload_events').fetchone()[0], 0)
        self.assertEqual(policy.upload_request_snapshot()[0]['received'], 35)
        with patch.object(policy._up_time, 'monotonic', return_value=10.6):
            policy.upload_request_progress(event_id, 75)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT received FROM upload_events').fetchone()[0], 75)
        policy.upload_request_progress(event_id, 70)
        self.assertEqual(policy.upload_request_snapshot()[0]['received'], 75)
        policy.upload_request_finish(event_id, 'sent', [{'filename': '../private/附件.txt', 'size': 13, 'content': 'DO NOT STORE'}])
        row = policy.upload_request_snapshot()[0]
        self.assertEqual(row['status'], 'sent')
        self.assertEqual(row['files'], [{'name': '附件.txt', 'size': 13}])
        self.assertNotIn('_last_write', row)
        self.assertFalse(policy._UP_ACTIVE)
        policy.upload_request_progress(event_id, 100)
        self.assertEqual(policy.upload_request_snapshot()[0]['received'], 75)

    def test_finish_preserves_error_and_handles_unknown_event(self):
        event_id = policy.upload_request_start('webmail', 'user@example.com', 10)
        policy.upload_request_progress(event_id, 1000)
        policy.upload_request_finish(event_id, 'failed', error='network failed')
        row = policy.upload_request_snapshot()[0]
        self.assertEqual(row['error'], 'network failed')
        self.assertEqual(row['received'], 10)
        policy.upload_request_finish('missing', 'failed')
        with self.assertRaises(ValueError):
            policy.upload_request_start('webmail', 'user', True)
        with self.assertRaises(ValueError):
            policy.upload_request_finish(event_id, '<invalid>')

    def test_snapshot_100_and_retention_1000_and_cached_schema(self):
        event_id = policy.upload_request_start('fixture', 'admin', 1)
        policy.upload_request_finish(event_id, 'sent')
        with closing(sqlite3.connect(self.db)) as db:
            db.executemany('INSERT INTO upload_events VALUES(?,?,?,?,?,?,?,?,?,?)',
                           [(str(i), 'fixture', 'admin', 1, 1, 'sent', '[]', '', i, i) for i in range(1100)])
            db.commit()
        newest = policy.upload_request_start('fixture', 'admin', 1)
        policy.upload_request_finish(newest, 'sent')
        self.assertEqual(len(policy.upload_request_snapshot()), 100)
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM upload_events').fetchone()[0], 1000)
        with patch.object(policy._UPPath, 'chmod', side_effect=AssertionError('schema unexpectedly recreated')):
            policy.upload_request_snapshot()
        self.db.unlink()
        self.assertEqual(policy.upload_request_snapshot(), [])


if __name__ == '__main__':
    unittest.main()
