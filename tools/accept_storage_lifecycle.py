#!/usr/bin/env python3
"""Verify only self-created disposable uploads through a running candidate API.

Run on the candidate host; this tool never opens SSH or starts a server. The
prepare/verify split lets the real five-minute ctime protection elapse while
other acceptance work continues. No clock manipulation or user-file deletion.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PREFIX = 'mail-control-acceptance-'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, target):
        raise ValueError('Candidate API unexpectedly redirected; refusing the new destination')


def candidate_url(value):
    parsed = urllib.parse.urlsplit(value)
    try:
        address = ipaddress.ip_address(parsed.hostname or '')
    except ValueError:
        raise ValueError('Candidate URL must use an explicit loopback IP address')
    if (not address.is_loopback or parsed.scheme not in {'http', 'https'}
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.port in {None, 80, 443, 18080}):
        raise ValueError('Use a dedicated loopback candidate port, never the production Mail Control port')
    return value.rstrip('/') + '/'


def fixture_root(value):
    path = Path(value)
    if not path.is_absolute() or not path.is_dir():
        raise ValueError('Fixture root must be an existing absolute candidate upload directory')
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('Fixture root must not contain symlinks')
    resolved = path.resolve()
    if not any('staging' in part.lower() or 'candidate' in part.lower() for part in resolved.parts):
        raise ValueError('Fixture root must be under an explicitly named staging/candidate directory')
    return resolved


class CandidateAPI:
    def __init__(self, base):
        self.base = candidate_url(base)
        # Loopback requests must not pass through inherited system proxies.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, route, method='GET', payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(self.base + route, data=body, method=method,
                                         headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
        try:
            with self.opener.open(request, timeout=15) as response:
                if response.geturl() != request.full_url:
                    raise ValueError('Candidate API unexpectedly redirected')
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise ValueError('Candidate response exceeded the bounded acceptance size')
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise ValueError('Expected a candidate API JSON object')
                return result
        except urllib.error.HTTPError as error:
            raise ValueError('Candidate API returned HTTP ' + str(error.code)) from error

    def find(self, run_id, expected, timeout=45):
        deadline = time.monotonic() + timeout
        route = 'api/storage?' + urllib.parse.urlencode({'source': 'temp', 'q': run_id, 'limit': 100, 'attachments': 0})
        first = True
        while time.monotonic() < deadline:
            page = self.request(route + ('&refresh=1' if first else ''))
            first = False
            if page.get('error'):
                raise ValueError('Candidate storage scan failed')
            if page.get('partial'):
                raise ValueError('Candidate inventory is partial; cannot prove a complete acceptance result')
            rows = page.get('items')
            if not isinstance(rows, list):
                raise ValueError('Candidate storage items are invalid')
            found = {item.get('filename'): item for item in rows if isinstance(item, dict)}
            if not page.get('scanning') and all(name in found for name in expected):
                return page, found
            time.sleep(.4)
        raise ValueError('Timed out locating only the generated acceptance fixture files')


def create_fixture(root, name, run_id):
    if not name.startswith(PREFIX + run_id + '-') or Path(name).name != name:
        raise ValueError('Refusing a non-fixture filename')
    path = root / name
    content = ('Mail Control disposable upload acceptance fixture\nrun=' + run_id + '\n').encode()
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    info = path.lstat()
    return {'filename': name, 'path': str(path), 'size': info.st_size, 'sha256': hashlib.sha256(content).hexdigest(),
            'device': info.st_dev, 'inode': info.st_ino, 'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def validate_fixture(root, record):
    name = record['filename']
    match = re.fullmatch(re.escape(PREFIX) + r'([a-f0-9]{24})-(?:mature|recent)\.txt', name)
    if not match or Path(name).name != name:
        raise ValueError('Invalid acceptance fixture manifest name')
    path = root / name
    if str(path) != record['path'] or path.is_symlink() or not path.is_file():
        raise ValueError('Acceptance fixture path changed')
    info = path.lstat()
    expected = ('Mail Control disposable upload acceptance fixture\nrun=' + match.group(1) + '\n').encode()
    if (info.st_size != len(expected) or info.st_size != record['size']
            or path.read_bytes() != expected or info.st_dev != record['device'] or info.st_ino != record['inode']
            or info.st_mtime_ns != record['mtime_ns'] or info.st_ctime_ns != record['ctime_ns']
            or hashlib.sha256(path.read_bytes()).hexdigest() != record['sha256']):
        raise ValueError('Acceptance fixture content or filesystem identity changed')
    return path


def row_token(row, record):
    if (row.get('source') != 'temp' or row.get('path') != record['filename']
            or row.get('filename') != record['filename'] or row.get('size') != record['size']
            or not isinstance(row.get('token'), str)):
        raise ValueError('Candidate API row does not match the generated fixture')
    return row['token']


def expect_protected(api, root, record, row):
    path = validate_fixture(root, record)
    token = row_token(row, record)
    if row.get('deletable') is not False:
        raise ValueError('New fixture unexpectedly appears deletable')
    result = api.request('api/storage/temp', 'DELETE', {'confirm': True, 'tokens': [token]})
    errors = result.get('errors')
    if (result.get('deleted') or not isinstance(errors, list) or len(errors) != 1
            or errors[0].get('token') != token or not path.exists()):
        raise ValueError('Recent-file deletion protection failed')
    validate_fixture(root, record)


def write_manifest(path, value):
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write('\n')
    path.chmod(0o600)


def prepare(api, root):
    run_id = secrets.token_hex(12)
    record = create_fixture(root, PREFIX + run_id + '-mature.txt', run_id)
    page, rows = api.find(run_id, [record['filename']])
    expect_protected(api, root, record, rows[record['filename']])
    age = page.get('delete_min_age')
    if isinstance(age, bool) or not isinstance(age, int) or not 300 <= age <= 31536000:
        raise ValueError('Candidate API returned an invalid deletion protection age')
    ready = max(record['mtime_ns'], record['ctime_ns']) / 1000000000 + age + 2
    manifest = root / (PREFIX + run_id + '.json')
    value = {'version': 1, 'run_id': run_id, 'base_url': api.base, 'fixture_root': str(root),
             'record': record, 'ready_at': ready, 'recent_protection_passed': True}
    write_manifest(manifest, value)
    print(json.dumps({'status': 'prepared', 'manifest': str(manifest), 'recent_protection': 'passed',
                      'ready_at': ready, 'wait_seconds': max(0, int(ready - time.time()) + 1)}, ensure_ascii=False))


def verify(api, root, manifest_path, max_wait):
    if (manifest_path.parent.resolve() != root or manifest_path.is_symlink()
            or not manifest_path.is_file() or manifest_path.stat().st_size > 8192):
        raise ValueError('Manifest must be a regular file directly inside the candidate fixture directory')
    value = json.loads(manifest_path.read_text(encoding='utf-8'))
    if (value.get('version') != 1 or value.get('base_url') != api.base or value.get('fixture_root') != str(root)
            or not value.get('recent_protection_passed')):
        raise ValueError('Acceptance manifest does not match this candidate')
    record, run_id = value['record'], value['run_id']
    if (not isinstance(run_id, str) or not re.fullmatch(r'[a-f0-9]{24}', run_id)
            or record['filename'] != PREFIX + run_id + '-mature.txt'
            or manifest_path.name != PREFIX + run_id + '.json'):
        raise ValueError('Acceptance manifest fixture identity is invalid')
    validate_fixture(root, record)
    wait = max(0, value['ready_at'] - time.time())
    if wait > max_wait:
        print(json.dumps({'status': 'waiting_for_real_protection_age', 'wait_seconds': int(wait) + 1,
                          'manifest': str(manifest_path)}))
        return 3
    if wait:
        print('Waiting ' + str(int(wait) + 1) + ' seconds for the actual candidate protection period.', flush=True)
        time.sleep(wait)
    # Prove the protection remains active for a second fresh upload while the
    # matured file is deleted. Both files are unique to this acceptance run.
    fresh = create_fixture(root, PREFIX + run_id + '-recent.txt', run_id)
    page, rows = api.find(run_id, [record['filename'], fresh['filename']])
    expect_protected(api, root, fresh, rows[fresh['filename']])
    mature = validate_fixture(root, record)
    row = rows[record['filename']]
    if row.get('deletable') is not True:
        raise ValueError('Mature fixture still protected; inspect actual protection settings')
    token = row_token(row, record)
    result = api.request('api/storage/temp', 'DELETE', {'confirm': True, 'tokens': [token]})
    if result.get('errors') or len(result.get('deleted', [])) != 1 or mature.exists():
        raise ValueError('Mature disposable fixture was not removed through the real API')
    validate_fixture(root, fresh)
    # Cleanup is limited to this exact script-generated, unchanged fresh file
    # and manifest. The mature file was removed only by the HTTP endpoint.
    (root / fresh['filename']).unlink()
    manifest_path.unlink()
    print(json.dumps({'status': 'passed', 'real_http_recent_protection': True,
                      'real_http_mature_deletion': True, 'fresh_upload_survived_mature_delete': True,
                      'fixture_cleanup': True, 'user_files_touched': False}, ensure_ascii=False))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', required=True, help='Existing loopback candidate app URL, e.g. http://127.0.0.1:18082/')
    parser.add_argument('--fixture-root', required=True, type=Path, help='Existing candidate temp upload root on this host')
    parser.add_argument('--phase', choices=('prepare', 'verify'), required=True)
    parser.add_argument('--manifest', type=Path, help='prepare output manifest, required for verify')
    parser.add_argument('--max-wait', type=int, default=0, help='At most 60 seconds of waiting during verify; default returns ready time')
    args = parser.parse_args()
    if not 0 <= args.max_wait <= 60:
        parser.error('--max-wait must be between 0 and 60')
    api, root = CandidateAPI(args.base_url), fixture_root(args.fixture_root)
    if args.phase == 'prepare':
        if args.manifest:
            parser.error('--manifest is produced by prepare, not supplied to it')
        prepare(api, root)
        return 0
    if not args.manifest:
        parser.error('--manifest is required for verify')
    return verify(api, root, args.manifest.absolute(), args.max_wait)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError, urllib.error.URLError) as error:
        raise SystemExit('storage acceptance: ' + str(error))
