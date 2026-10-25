import importlib.util
import os
import tempfile
import time
import unittest
from email.message import EmailMessage
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('storage_manager', Path(__file__).parent / 'src' / 'storage_manager.py')
storage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(storage)


class StorageManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.mail = self.base / 'mail'
        self.uploads = self.base / 'snappy-upload'
        self.mail.mkdir()
        self.uploads.mkdir()
        storage.CONFIG = SimpleNamespace(mail_root=self.mail)
        self.webmail_storage = self.base / 'webmail' / 'storage'
        self.environment = patch.dict(os.environ, {'MAIL_CONTROL_UPLOAD_ROOTS': storage._sm_json.dumps([str(self.uploads)]),
                                                 'MAIL_CONTROL_WEBMAIL_STORAGE_ROOT': str(self.webmail_storage)})
        self.environment.start()
        self.started = time.time()
        with storage._SM_LOCK:
            storage._SM_STATE.update(key=None, items=[], summary={}, updated_at=None, scanning=False, error='', partial=False, started_at=None)
        storage._sm_metadata.cache_clear()
        storage._SM_DISCOVERY.update(key=None, time=0, roots=[], partial=False)

    def tearDown(self):
        deadline = time.monotonic() + 5
        while storage._SM_STATE['scanning'] and time.monotonic() < deadline:
            time.sleep(.01)
        self.environment.stop()
        self.temp.cleanup()

    def snapshot(self, **query):
        page = storage.storage_snapshot(query)
        deadline = time.monotonic() + 5
        while page['scanning'] and time.monotonic() < deadline:
            time.sleep(.01)
            page = storage.storage_snapshot({key: value for key, value in query.items() if key != 'refresh'})
        self.assertFalse(page['scanning'])
        self.assertEqual(page['error'], '')
        return page

    def message(self, mailbox='support@example.com', folder='INBOX', filename='first-message'):
        directory = self.mail / mailbox / ('' if folder == 'INBOX' else folder) / 'new'
        directory.mkdir(parents=True, exist_ok=True)
        msg = EmailMessage()
        msg['Subject'] = '附件存储测试'
        msg['From'] = 'sender@example.net'
        msg.set_content('body')
        msg.add_attachment(b'abc', maintype='application', subtype='octet-stream', filename='附件.txt')
        path = directory / filename
        path.write_bytes(msg.as_bytes())
        return path

    def test_inventory_keeps_message_identity_and_paginates_filters(self):
        message = self.message()
        self.message('other@example.com', '.Sent', 'second-message')
        upload = self.uploads / 'image.png'
        upload.write_bytes(b'PNG')
        page = self.snapshot()
        self.assertEqual(page['total'], 3)
        self.assertEqual(page['summary']['sources']['mail']['files'], 2)
        self.assertEqual(page['summary']['sources']['temp']['bytes'], 3)
        self.assertTrue(page['summary']['disks'][0]['free'] > 0)
        page = self.snapshot(source='mail', mailbox='support@example.com', limit=1)
        self.assertEqual(page['total'], 1)
        item = page['items'][0]
        self.assertEqual((item['mailbox'], item['folder'], item['id']), ('support@example.com', 'INBOX', message.name))
        self.assertEqual(item['attachments'][0]['filename'], '附件.txt')
        self.assertEqual(item['attachment_state'], 'complete')
        self.assertNotIn('_path', item)
        self.assertNotIn('token', item)
        page = self.snapshot(source='temp', q='image', offset=1, limit=1)
        self.assertEqual(page['total'], 1)
        self.assertEqual(page['items'], [])

    def test_recent_upload_cannot_be_deleted(self):
        path = self.uploads / 'recent.bin'
        path.write_bytes(b'upload')
        item = self.snapshot(source='temp')['items'][0]
        self.assertFalse(item['deletable'])
        result = storage.delete_storage_temp({'confirm': True, 'tokens': [item['token']]})
        self.assertFalse(result['deleted'])
        self.assertIn('保护期', result['errors'][0]['error'])
        self.assertTrue(path.exists())

    def test_old_unchanged_inactive_upload_deletes_without_touching_message(self):
        message = self.message()
        path = self.uploads / 'old.bin'
        path.write_bytes(b'old upload')
        item = self.snapshot(source='temp')['items'][0]
        with patch.object(storage._sm_time, 'time', return_value=self.started + 601), patch.object(storage, '_sm_is_open', return_value=False):
            result = storage.delete_storage_temp({'confirm': True, 'tokens': [item['token']]})
        self.assertEqual(len(result['deleted']), 1)
        self.assertFalse(result['errors'])
        self.assertFalse(path.exists())
        self.assertTrue(message.exists())

    def test_changed_or_active_upload_cannot_be_deleted(self):
        path = self.uploads / 'changed.bin'
        path.write_bytes(b'first')
        token = self.snapshot(source='temp')['items'][0]['token']
        path.write_bytes(b'changed')
        with patch.object(storage._sm_time, 'time', return_value=self.started + 601):
            result = storage.delete_storage_temp({'confirm': True, 'tokens': [token]})
        self.assertIn('变化', result['errors'][0]['error'])
        token = storage._sm_token(self.uploads, path.name, path.stat())
        with patch.object(storage._sm_time, 'time', return_value=self.started + 601), patch.object(storage, '_sm_is_open', return_value=True):
            result = storage.delete_storage_temp({'confirm': True, 'tokens': [token]})
        self.assertIn('正在使用', result['errors'][0]['error'])
        self.assertTrue(path.exists())

    def test_tampering_expiry_unconfigured_root_and_confirmation_rejected(self):
        path = self.uploads / 'test.bin'
        path.write_bytes(b'test')
        token = self.snapshot(source='temp')['items'][0]['token']
        for payload in ({'tokens': [token]}, {'confirm': True, 'tokens': [token + 'x']}, {'confirm': True, 'tokens': [{}]}):
            with self.assertRaises(ValueError):
                storage.delete_storage_temp(payload)
        with patch.object(storage._sm_time, 'time', return_value=self.started + 7200):
            with self.assertRaises(ValueError):
                storage.delete_storage_temp({'confirm': True, 'tokens': [token]})
        with patch.dict(os.environ, {'MAIL_CONTROL_UPLOAD_ROOTS': '[]'}):
            with self.assertRaises(ValueError):
                storage.delete_storage_temp({'confirm': True, 'tokens': [token]})
        self.assertTrue(path.exists())

    def test_symlink_and_parent_traversal_are_rejected(self):
        outside = self.base / 'unmanaged.bin'
        outside.write_bytes(b'important')
        token = storage._sm_token(self.uploads, '../unmanaged.bin', outside.stat())
        with self.assertRaises(ValueError):
            storage.delete_storage_temp({'confirm': True, 'tokens': [token]})
        try:
            (self.uploads / 'linked.bin').symlink_to(outside)
        except OSError:
            return
        self.assertEqual(self.snapshot(source='temp')['total'], 0)
        token = storage._sm_token(self.uploads, 'linked.bin', outside.stat())
        result = storage.delete_storage_temp({'confirm': True, 'tokens': [token]})
        self.assertFalse(result['deleted'])
        self.assertTrue(outside.exists())

    def test_mail_root_system_root_and_nested_roots_cannot_be_allowlisted(self):
        cases = ([str(self.mail)], [str(self.base)], [str(Path(self.base.anchor))],
                 [str(self.uploads), str(self.uploads / 'child')])
        for roots in cases:
            with self.subTest(roots=roots), patch.dict(os.environ, {'MAIL_CONTROL_UPLOAD_ROOTS': storage._sm_json.dumps(roots)}):
                with self.assertRaises(ValueError):
                    storage.storage_snapshot()

    def test_first_request_returns_while_scan_runs_and_refresh_is_deduplicated(self):
        entered = storage._sm_threading.Event()
        release = storage._sm_threading.Event()
        original = storage._sm_scan
        def slow(*args):
            entered.set()
            release.wait(2)
            original(*args)
        with patch.object(storage, '_sm_scan', side_effect=slow) as scan:
            page = storage.storage_snapshot({'refresh': '1'})
            self.assertTrue(page['scanning'])
            self.assertTrue(entered.wait(1))
            storage.storage_snapshot({'refresh': '1'})
            self.assertEqual(scan.call_count, 1)
            release.set()
            self.snapshot()

    def test_large_message_metadata_is_bounded_and_marked_partial(self):
        message = self.message()
        with message.open('ab') as stream:
            stream.write(b'x' * (storage._SM_METADATA_BYTES + 100))
        page = self.snapshot(source='mail')
        self.assertEqual(page['items'][0]['attachment_state'], 'partial')
        self.assertIsNone(page['items'][0]['attachments'][0]['size'])

    def test_webmail_only_discovers_files_leaves_and_associates_mailbox(self):
        account = self.webmail_storage / 'example.com' / 'support'
        for directory in (account / '.files', account / '.sessions', account / '.gnupg',
                          account / 'extra@example.net' / '.files',
                          account / 'one' / 'two' / '.files'):
            directory.mkdir(parents=True)
            (directory / 'abc123').write_bytes(b'upload or private data')
        page = self.snapshot(source='temp')
        self.assertEqual(page['total'], 2)
        self.assertEqual({item['mailbox'] for item in page['items']}, {'support@example.com', 'extra@example.net'})
        self.assertTrue(all('标识' in item['filename_note'] for item in page['items']))
        self.assertTrue(page['webmail_storage']['exists'])
        self.assertFalse(page['webmail_storage']['discovery_partial'])
        token = page['items'][0]['token']
        with patch.object(storage._sm_time, 'time', return_value=self.started + 601), patch.object(storage, '_sm_is_open', return_value=False):
            result = storage.delete_storage_temp({'confirm': True, 'tokens': [token]})
        self.assertEqual(len(result['deleted']), 1)
        self.assertTrue((account / '.sessions' / 'abc123').exists())
        self.assertTrue((account / '.gnupg' / 'abc123').exists())

    def test_new_webmail_files_directory_automatically_discovered_after_cache_expiry(self):
        page = self.snapshot(source='temp')
        self.assertFalse(page['webmail_storage']['exists'])
        directory = self.webmail_storage / 'example.org' / 'new' / '.files'
        directory.mkdir(parents=True)
        (directory / 'newhash').write_bytes(b'new')
        storage._SM_DISCOVERY['time'] = 0
        page = self.snapshot(source='temp')
        self.assertEqual(page['total'], 1)
        self.assertEqual(page['items'][0]['mailbox'], 'new@example.org')

    def test_webmail_metadata_labels_only_matching_file_and_keeps_delete_identity(self):
        data = self.base / 'webmail'
        storage_root = data / '_data_' / '_default_' / 'storage'
        directory = storage_root / 'example.com' / 'support' / '.files'
        directory.mkdir(parents=True)
        path = directory / 'opaquehash'
        path.write_bytes(b'upload')
        events = data / 'mail-control-upload-events'
        events.mkdir()
        container_path = '/data/' + path.relative_to(data).as_posix()
        metadata = events / (storage._sm_hashlib.sha256(container_path.encode()).hexdigest() + '.json')
        value = {'path': container_path, 'filename': '../folder/原附件\x00.txt',
                 'size': path.stat().st_size, 'mtime': int(path.stat().st_mtime), 'mailbox': 'other@example.net'}
        metadata.write_text(storage._sm_json.dumps(value), encoding='utf-8')
        with patch.dict(os.environ, {'MAIL_CONTROL_WEBMAIL_STORAGE_ROOT': str(storage_root)}):
            item = self.snapshot(source='temp')['items'][0]
            self.assertEqual(item['filename'], '原附件.txt')
            self.assertEqual(item['temporary_id'], 'opaquehash')
            self.assertEqual(item['mailbox'], 'support@example.com')
            self.assertEqual(storage._sm_decode_token(item['token'])['path'], 'opaquehash')
            value['size'] += 1
            metadata.write_text(storage._sm_json.dumps(value), encoding='utf-8')
            item = self.snapshot(source='temp')['items'][0]
            self.assertEqual(item['filename'], 'opaquehash')
            self.assertIn('未映射', item['filename_note'])

    def test_webmail_progress_events_bounded_validated_and_display_only(self):
        events = self.base / 'upload-events'
        events.mkdir()
        def write(digit, **changes):
            digest = digit * 64
            value = {'id': 'webmail-' + digest, 'source': 'webmail', 'actor': 'support@example.com',
                     'total': 100, 'received': 50, 'status': 'uploading',
                     'files': [{'filename': '../附件\x00.txt', 'size': 80}], 'error': '',
                     'created_at': self.started - 10, 'updated_at': self.started, 'reported_by': 'client'}
            value.update(changes)
            path = events / ('progress-' + digest + '.json')
            path.write_text(storage._sm_json.dumps(value), encoding='utf-8')
            return path
        valid = write('a')
        write('b', received=True)
        write('c', received=101)
        write('d', status='untrusted-status')
        write('e', updated_at=self.started - 86401, created_at=self.started - 86402)
        write('f', updated_at=self.started + 3600)
        write('0', actor='not-an-email')
        write('1', id='webmail-other')
        write('2', updated_at=self.started - 7201, created_at=self.started - 7202)
        (events / ('progress-' + '3' * 64 + '.json')).write_bytes(b'x' * 8193)
        try:
            (events / ('progress-' + '4' * 64 + '.json')).symlink_to(valid)
        except OSError:
            pass
        with patch.dict(os.environ, {'MAIL_CONTROL_WEBMAIL_EVENTS_ROOT': str(events)}):
            rows = storage.storage_webmail_upload_events()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['files'], [{'name': '附件.txt', 'size': 80}])
        self.assertEqual(rows[0]['reported_by'], 'client')
        self.assertNotIn('token', rows[0])
        self.assertNotIn('path', rows[0])


if __name__ == '__main__':
    unittest.main()
