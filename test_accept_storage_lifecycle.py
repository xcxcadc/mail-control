import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('accept_storage_lifecycle', Path(__file__).parent / 'tools' / 'accept_storage_lifecycle.py')
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class StorageLifecycleAcceptanceTests(unittest.TestCase):
    def test_rejects_production_and_non_loopback_urls(self):
        for url in ('https://postal.qnns.de/', 'http://127.0.0.1:18080/',
                    'http://localhost:18082/', 'http://127.0.0.1/',
                    'http://user:password@127.0.0.1:18082/', 'http://127.0.0.1:18082/?x=1'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                acceptance.candidate_url(url)
        self.assertEqual(acceptance.candidate_url('http://127.0.0.1:18082'), 'http://127.0.0.1:18082/')

    def test_redirect_is_rejected_before_destination_is_opened(self):
        with self.assertRaises(ValueError):
            acceptance.NoRedirect().redirect_request(None, None, 302, 'Moved', {}, 'https://postal.qnns.de/')

    def test_fixture_validation_rejects_unrelated_or_changed_files(self):
        with tempfile.TemporaryDirectory(prefix='candidate-') as folder:
            root = acceptance.fixture_root(Path(folder))
            run_id = 'a' * 24
            record = acceptance.create_fixture(root, acceptance.PREFIX + run_id + '-mature.txt', run_id)
            self.assertEqual(acceptance.validate_fixture(root, record).name, record['filename'])
            unrelated = root / 'customer-upload.txt'
            unrelated.write_text('valuable data')
            with self.assertRaises(ValueError):
                acceptance.create_fixture(root, unrelated.name, run_id)
            Path(record['path']).write_text('changed')
            with self.assertRaises(ValueError):
                acceptance.validate_fixture(root, record)
            self.assertEqual(unrelated.read_text(), 'valuable data')

    def test_protected_check_deletes_only_matching_fixture_token(self):
        with tempfile.TemporaryDirectory(prefix='candidate-') as folder:
            root = acceptance.fixture_root(Path(folder))
            run_id = 'b' * 24
            record = acceptance.create_fixture(root, acceptance.PREFIX + run_id + '-recent.txt', run_id)
            class API:
                def request(self, route, method, payload):
                    self.call = (route, method, payload)
                    return {'deleted': [], 'errors': [{'token': 'fixture-token', 'error': 'protected'}]}
            api = API()
            row = dict(source='temp', path=record['filename'], filename=record['filename'],
                       size=record['size'], token='fixture-token', deletable=False)
            acceptance.expect_protected(api, root, record, row)
            self.assertEqual(api.call, ('api/storage/temp', 'DELETE', {'confirm': True, 'tokens': ['fixture-token']}))
            self.assertTrue(Path(record['path']).exists())
            row['path'] = 'other-file'
            with self.assertRaises(ValueError):
                acceptance.expect_protected(api, root, record, row)

    def test_verify_returns_waiting_without_touching_fixture(self):
        with tempfile.TemporaryDirectory(prefix='candidate-') as folder:
            root = acceptance.fixture_root(Path(folder))
            run_id = 'c' * 24
            record = acceptance.create_fixture(root, acceptance.PREFIX + run_id + '-mature.txt', run_id)
            api = acceptance.CandidateAPI('http://127.0.0.1:18082/')
            manifest = root / (acceptance.PREFIX + run_id + '.json')
            acceptance.write_manifest(manifest, {'version': 1, 'base_url': api.base, 'fixture_root': str(root),
                                                'run_id': run_id, 'record': record, 'ready_at': acceptance.time.time() + 300,
                                                'recent_protection_passed': True})
            with patch.object(api, 'request', side_effect=AssertionError('HTTP should not be called before age is ready')):
                self.assertEqual(acceptance.verify(api, root, manifest, 0), 3)
            self.assertTrue(Path(record['path']).exists())
            self.assertTrue(manifest.exists())


if __name__ == '__main__':
    unittest.main()
