"""Bounded, asynchronous inventory of Maildir messages and allowlisted uploads.

Embedded by build_ui.py into mail_control.py; CONFIG is the application's config.
This module never removes Maildir files. Message deletion stays in Dovecot.
"""
import base64 as _sm_b64
import email.parser as _sm_parser
import email.policy as _sm_policy
import hashlib as _sm_hashlib
import hmac as _sm_hmac
import json as _sm_json
import math as _sm_math
import logging as _sm_logging
import os as _sm_os
import re as _sm_re
import secrets as _sm_secrets
import shutil as _sm_shutil
import stat as _sm_stat
import threading as _sm_threading
import time as _sm_time
from functools import lru_cache as _sm_lru_cache
from pathlib import Path as _SMPath

_SM_LOCK = _sm_threading.Lock()
_SM_DELETE_LOCK = _sm_threading.Lock()
_SM_SECRET = _sm_secrets.token_bytes(32)
_SM_STATE = {'key': None, 'items': [], 'summary': {}, 'updated_at': None,
             'scanning': False, 'error': '', 'partial': False, 'started_at': None}
_SM_MAILBOX = _sm_re.compile(r'^[^\s@/\\]+@[^\s@/\\]+\.[^\s@/\\]+$')
_SM_REFRESH_SECONDS = 10
_SM_METADATA_BYTES = 256 * 1024
_SM_DISCOVERY_LOCK = _sm_threading.Lock()
_SM_DISCOVERY = {'key': None, 'time': 0, 'roots': [], 'partial': False}


def _sm_int(value, name, minimum, maximum):
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(name + '无效')
    if not minimum <= number <= maximum:
        raise ValueError(name + '超出范围')
    return number


def _sm_has_symlink(path):
    path = _SMPath(path)
    for current in (path, *path.parents):
        try:
            if _sm_stat.S_ISLNK(current.lstat().st_mode):
                return True
        except FileNotFoundError:
            continue
    return False


def _sm_roots():
    mail = _SMPath(CONFIG.mail_root).absolute()
    if _sm_has_symlink(mail):
        raise ValueError('邮件存储根目录不能是符号链接')
    mail = mail.resolve()
    raw = _sm_os.environ.get('MAIL_CONTROL_UPLOAD_ROOTS', '[]')
    try:
        entries = _sm_json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError('MAIL_CONTROL_UPLOAD_ROOTS 必须为目录的 JSON 数组')
    if not isinstance(entries, list) or len(entries) > 16:
        raise ValueError('上传目录配置无效，最多允许 16 个专用目录')
    roots = []
    forbidden = {'/', '/tmp', '/var', '/var/tmp', '/opt', '/opt/mailu',
                 '/opt/mailu/data', '/home', '/root', str(_SMPath.home())}
    for value in entries:
        if not isinstance(value, str) or not value or not _SMPath(value).is_absolute():
            raise ValueError('上传目录必须使用绝对路径')
        path = _SMPath(value)
        if _sm_has_symlink(path):
            raise ValueError('上传目录不能包含符号链接')
        path = path.resolve()
        if (str(path) in forbidden or path == _SMPath(path.anchor)
                or path == mail or path in mail.parents or mail in path.parents):
            raise ValueError('只能配置专用临时上传目录，不能使用邮件目录或宽泛的系统目录')
        if any(path == other or path in other.parents or other in path.parents for other in roots):
            raise ValueError('上传目录不能重复或嵌套')
        roots.append(path)
    webmail, _ = _sm_webmail_roots()
    for path in webmail:
        if path == mail or path in mail.parents or mail in path.parents:
            continue
        if not any(path == other or path in other.parents or other in path.parents for other in roots):
            roots.append(path)
    return mail, roots


def _sm_webmail_storage():
    path = _SMPath(_sm_os.environ.get('MAIL_CONTROL_WEBMAIL_STORAGE_ROOT',
                                    '/opt/mailu/data/webmail/_data_/_default_/storage'))
    if not path.is_absolute() or _sm_has_symlink(path):
        raise ValueError('网页邮箱存储目录必须是无符号链接的绝对路径')
    return path.resolve()


def _sm_webmail_roots():
    """Discover only SnappyMail .files leaves, never the account storage itself."""
    root = _sm_webmail_storage()
    key = str(root)
    with _SM_DISCOVERY_LOCK:
        if _SM_DISCOVERY['key'] == key and _sm_time.monotonic() - _SM_DISCOVERY['time'] < 10:
            return list(_SM_DISCOVERY['roots']), _SM_DISCOVERY['partial']
        found, partial = [], False
        stack, count = [(root, 0)], 0
        deadline = _sm_time.monotonic() + .5
        while stack:
            directory, depth = stack.pop()
            if depth >= 4 or not directory.is_dir() or _sm_has_symlink(directory):
                continue
            try:
                with _sm_os.scandir(directory) as entries:
                    for entry in entries:
                        count += 1
                        if count > 20000 or len(found) >= 2000 or _sm_time.monotonic() > deadline:
                            partial = True
                            break
                        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                            continue
                        path = _SMPath(entry.path)
                        if entry.name == '.files':
                            if not _sm_has_symlink(path) and root in path.resolve().parents:
                                found.append(path.resolve())
                        elif not entry.name.startswith('.'):
                            stack.append((path, depth + 1))
            except (FileNotFoundError, PermissionError, NotADirectoryError):
                continue
            if partial:
                break
        _SM_DISCOVERY.update(key=key, time=_sm_time.monotonic(), roots=found, partial=partial)
        return list(found), partial


def _sm_temp_mailbox(root):
    try:
        parts = root.relative_to(_sm_webmail_storage()).parts
    except ValueError:
        return ''
    if 3 <= len(parts) <= 4 and parts[-1] == '.files':
        if len(parts) == 4 and _SM_MAILBOX.fullmatch(parts[2]):
            return parts[2]
        mailbox = parts[1] + '@' + parts[0]
        return mailbox if _SM_MAILBOX.fullmatch(mailbox) else ''
    return ''


def _sm_webmail_filename(path, identity):
    """Use plugin metadata only as a display label, never as a file authority."""
    try:
        storage = _sm_webmail_storage()
        if storage not in path.parents or path.parent.name != '.files':
            return None
        # Production storage is <data>/_data_/_default_/storage. Container
        # paths are what the plugin hashes; the host mount may live elsewhere.
        host_data = storage.parents[2]
        relative = path.relative_to(host_data).as_posix()
        container_root = _sm_os.environ.get('MAIL_CONTROL_WEBMAIL_CONTAINER_DATA_ROOT', '/data').rstrip('/')
        if not container_root.startswith('/') or '\\' in container_root:
            return None
        container_path = container_root + '/' + relative
        events = _SMPath(_sm_os.environ.get('MAIL_CONTROL_WEBMAIL_EVENTS_ROOT',
                                           str(host_data / 'mail-control-upload-events')))
        if not events.is_absolute() or _sm_has_symlink(events):
            return None
        metadata = events / (_sm_hashlib.sha256(container_path.encode()).hexdigest() + '.json')
        st = metadata.lstat()
        if not _sm_stat.S_ISREG(st.st_mode) or st.st_size > 8192 or _sm_has_symlink(metadata):
            return None
        with metadata.open('rb') as stream:
            raw = stream.read(8193)
        if len(raw) > 8192:
            return None
        value = _sm_json.loads(raw)
        if (not isinstance(value, dict) or value.get('path') != container_path
                or isinstance(value.get('size'), bool) or value.get('size') != identity[2]
                or isinstance(value.get('mtime'), bool)
                or not isinstance(value.get('mtime'), (int, float))):
            return None
        # PHP filemtime records whole seconds; reject metadata for any different
        # second and retain the actual filesystem identity for deletion tokens.
        if int(value['mtime']) != identity[3] // 1000000000:
            return None
        name = value.get('filename')
        if not isinstance(name, str):
            return None
        name = name.replace('\\', '/').rsplit('/', 1)[-1]
        name = ''.join(char for char in name if ord(char) >= 32 and not 127 <= ord(char) < 160)[:255].strip()
        if not name or name in {'.', '..'}:
            return None
        return name
    except (OSError, ValueError, TypeError, IndexError, OverflowError):
        return None


def storage_webmail_upload_events():
    """Read bounded, authenticated-plugin progress reports for display only.

    These are browser-reported upload observations, not SMTP delivery receipts.
    Their filenames/metadata never confer temporary-file deletion authority.
    """
    storage = _sm_webmail_storage()
    try:
        default = storage.parents[2] / 'mail-control-upload-events'
    except IndexError:
        return []
    root = _SMPath(_sm_os.environ.get('MAIL_CONTROL_WEBMAIL_EVENTS_ROOT', str(default)))
    if not root.is_absolute() or _sm_has_symlink(root) or not root.is_dir():
        return []
    now, deadline = _sm_time.time(), _sm_time.monotonic() + .5
    candidates = []
    try:
        with _sm_os.scandir(root) as entries:
            for count, entry in enumerate(entries):
                if count >= 10000 or _sm_time.monotonic() > deadline:
                    break
                match = _sm_re.fullmatch(r'progress-([a-f0-9]{64})\.json', entry.name)
                if not match or entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                    continue
                path = _SMPath(entry.path)
                st = path.lstat()
                if not _sm_stat.S_ISREG(st.st_mode) or st.st_size > 8192 or st.st_mtime < now - 86400:
                    continue
                candidates.append((st.st_mtime, path, match.group(1), _sm_identity(st)))
    except OSError:
        return []
    candidates.sort(key=lambda item: item[0], reverse=True)
    result = []
    statuses = {'uploading', 'processing', 'completed', 'failed', 'cancelled'}
    for _, path, digest, identity in candidates[:1000]:
        if len(result) >= 100 or _sm_time.monotonic() > deadline:
            break
        try:
            if _sm_has_symlink(path) or _sm_identity(path.lstat()) != identity:
                continue
            with path.open('rb') as stream:
                raw = stream.read(8193)
            if len(raw) > 8192:
                continue
            value = _sm_json.loads(raw)
            if (not isinstance(value, dict) or value.get('id') != 'webmail-' + digest
                    or value.get('source') != 'webmail' or value.get('reported_by') != 'client'
                    or value.get('status') not in statuses
                    or not isinstance(value.get('actor'), str) or not _SM_MAILBOX.fullmatch(value['actor'])):
                continue
            total, received = value.get('total'), value.get('received')
            if any(isinstance(number, bool) or not isinstance(number, int) or not 0 <= number <= 1024 * 1024 * 1024
                   for number in (total, received)) or received > total:
                continue
            created, updated = value.get('created_at'), value.get('updated_at')
            if any(isinstance(number, bool) or not isinstance(number, (int, float))
                   or not _sm_math.isfinite(number) for number in (created, updated)):
                continue
            if not 0 < created <= updated <= now + 300 or updated < now - 86400:
                continue
            if value['status'] in {'uploading', 'processing'} and updated < now - 7200:
                continue
            files = value.get('files')
            if not isinstance(files, list) or len(files) > 100:
                continue
            sanitized = []
            for item in files:
                if not isinstance(item, dict) or not isinstance(item.get('filename'), str):
                    raise ValueError('invalid file metadata')
                size = item.get('size')
                if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= 1024 * 1024 * 1024:
                    raise ValueError('invalid size')
                name = item['filename'].replace('\\', '/').rsplit('/', 1)[-1]
                name = ''.join(c for c in name if ord(c) >= 32 and not 127 <= ord(c) < 160).strip()[:255]
                if not name or name in {'.', '..'}:
                    raise ValueError('invalid filename')
                sanitized.append({'name': name, 'size': size})
            error = value.get('error', '')
            if not isinstance(error, str):
                continue
            result.append({'id': value['id'], 'source': 'webmail', 'actor': value['actor'][:255],
                           'total': total, 'received': received, 'status': value['status'],
                           'files': sanitized, 'error': error[:1024], 'created_at': created,
                           'updated_at': updated, 'reported_by': 'client'})
        except (OSError, ValueError, TypeError):
            continue
    return sorted(result, key=lambda item: item['updated_at'], reverse=True)[:100]


def _sm_root_id(root):
    return _sm_hashlib.sha256(str(root).encode()).hexdigest()[:20]


def _sm_identity(st):
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def _sm_token(root, relative, st):
    payload = _sm_json.dumps({'root': _sm_root_id(root), 'path': relative,
                             'file': _sm_identity(st), 'expires': int(_sm_time.time()) + 3600},
                            separators=(',', ':'), ensure_ascii=True).encode()
    value = _sm_b64.urlsafe_b64encode(payload).rstrip(b'=')
    signature = _sm_hmac.new(_SM_SECRET, value, _sm_hashlib.sha256).hexdigest().encode()
    return (value + b'.' + signature).decode()


def _sm_decode_token(token):
    try:
        if not isinstance(token, str) or len(token) > 8192:
            raise ValueError()
        value, signature = token.encode('ascii').split(b'.', 1)
        expected = _sm_hmac.new(_SM_SECRET, value, _sm_hashlib.sha256).hexdigest().encode()
        if not _sm_hmac.compare_digest(signature, expected):
            raise ValueError()
        item = _sm_json.loads(_sm_b64.urlsafe_b64decode(value + b'=' * (-len(value) % 4)))
        if int(item.get('expires', 0)) < _sm_time.time():
            raise ValueError()
        relative = item['path']
        if (not isinstance(relative, str) or not relative or '\\' in relative
                or _SMPath(relative).is_absolute() or any(p in {'', '.', '..'} for p in relative.split('/'))):
            raise ValueError()
        return item
    except (ValueError, TypeError, KeyError, UnicodeError):
        raise ValueError('文件标识无效或已过期，请刷新后重新选择')


def _sm_walk(root, deadline, budget):
    if not root.is_dir():
        return
    stack = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        if depth > 32 or _sm_time.monotonic() > deadline or budget[0] <= 0:
            budget[1] = True
            return
        if _sm_has_symlink(directory) or (directory != root and root not in directory.resolve().parents):
            continue
        try:
            with _sm_os.scandir(directory) as entries:
                for entry in entries:
                    budget[0] -= 1
                    if budget[0] < 0 or _sm_time.monotonic() > deadline:
                        budget[1] = True
                        return
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        stack.append((_SMPath(entry.path), depth + 1))
                    elif entry.is_file(follow_symlinks=False):
                        # Path.lstat supplies the inode/device identity on Windows
                        # too; DirEntry.stat may report both as zero there.
                        path = _SMPath(entry.path)
                        current = path.lstat()
                        if _sm_stat.S_ISREG(current.st_mode):
                            yield path, current
        except (FileNotFoundError, PermissionError, NotADirectoryError):
            continue


def _sm_summary(items, roots):
    sources = {name: {'bytes': 0, 'files': 0} for name in ('mail', 'temp')}
    for item in items:
        sources[item['source']]['bytes'] += item['size']
        sources[item['source']]['files'] += 1
    disks = []
    seen = set()
    for source, root in roots:
        current = root
        while not current.exists() and current != current.parent:
            current = current.parent
        try:
            device = current.stat().st_dev
            if device in seen:
                continue
            seen.add(device)
            usage = _sm_shutil.disk_usage(current)
            disks.append({'source': source, 'total': usage.total, 'used': usage.used,
                          'free': usage.free, 'used_percent': round(usage.used * 100 / usage.total, 1) if usage.total else 0})
        except OSError:
            continue
    return {'sources': sources, 'disks': disks,
            'bytes': sum(v['bytes'] for v in sources.values()), 'files': len(items)}


def _sm_scan(key, mail, uploads):
    items, error, partial = [], '', False
    deadline = _sm_time.monotonic() + 30
    budget = [250000, False]
    try:
        if mail.is_dir():
            with _sm_os.scandir(mail) as boxes:
                for box in boxes:
                    if not _SM_MAILBOX.fullmatch(box.name) or not box.is_dir(follow_symlinks=False) or box.is_symlink():
                        continue
                    root = _SMPath(box.path)
                    for path, st in _sm_walk(root, deadline, budget):
                        relative = path.relative_to(root).as_posix()
                        parts = relative.split('/')
                        if len(parts) < 2 or parts[-2] not in {'new', 'cur'}:
                            continue
                        folder = '/'.join(parts[:-2]) or 'INBOX'
                        items.append({'source': 'mail', 'root_id': _sm_root_id(mail), 'mailbox': box.name,
                                      'id': path.name.split(':2,', 1)[0], 'folder': folder,
                                      'path': relative, 'filename': path.name, 'size': st.st_size,
                                      'mtime': st.st_mtime, 'attachment_state': 'not_loaded',
                                      'delete_mode': 'message', '_path': str(path), '_file': _sm_identity(st)})
                    if budget[1]:
                        break
        for root in uploads:
            mailbox = _sm_temp_mailbox(root)
            for path, st in _sm_walk(root, deadline, budget):
                items.append({'source': 'temp', 'root_id': _sm_root_id(root), 'mailbox': mailbox,
                              'path': path.relative_to(root).as_posix(), 'filename': path.name,
                              'size': st.st_size, 'mtime': st.st_mtime, 'delete_mode': 'temp',
                              'filename_note': '网页邮箱临时文件标识（原附件名未映射）' if root.name == '.files' else '',
                              '_path': str(path), '_file': _sm_identity(st)})
        partial = bool(budget[1])
        items.sort(key=lambda item: (item['mtime'], item['filename']), reverse=True)
    except Exception:
        _sm_logging.exception('Storage inventory failed')
        error = '存储扫描失败，请检查目录权限及后台日志'
    summary = _sm_summary(items, [('mail', mail)] + [('temp', p) for p in uploads])
    with _SM_LOCK:
        if _SM_STATE['key'] == key:
            _SM_STATE.update(items=items, summary=summary, updated_at=_sm_time.time(),
                             scanning=False, error=error, partial=partial)


@_sm_lru_cache(maxsize=512)
def _sm_metadata(path, identity):
    try:
        candidate = _SMPath(path)
        st = candidate.lstat()
        if _sm_stat.S_ISLNK(st.st_mode) or tuple(_sm_identity(st)) != identity or _sm_has_symlink(candidate):
            return {'attachment_state': 'changed'}
        with candidate.open('rb') as stream:
            raw = stream.read(_SM_METADATA_BYTES)
        msg = _sm_parser.BytesParser(policy=_sm_policy.default).parsebytes(raw)
        attachments = []
        for part in msg.walk():
            filename = part.get_filename()
            if filename or part.get_content_disposition() == 'attachment':
                attachments.append({'filename': str(filename or '(未命名附件)'),
                                    'content_type': part.get_content_type(), 'size': None,
                                    'inline': part.get_content_disposition() == 'inline'})
        return {'subject': str(msg.get('subject', '')), 'from': str(msg.get('from', '')),
                'date': str(msg.get('date', '')), 'attachments': attachments,
                'attachment_state': 'partial' if st.st_size > len(raw) else 'complete',
                'attachments_note': '附件属于邮件 MIME 内容，删除邮件会同时删除其全部附件。附件字节数不作截断估算。'}
    except (OSError, ValueError):
        return {'attachment_state': 'unavailable'}


def storage_snapshot(query=None):
    """Return a cached page immediately; at most one background scan per config."""
    query = query or {}
    def value(name, default=''):
        result = query.get(name, default)
        return result[0] if isinstance(result, list) and result else result
    source = str(value('source', 'all'))
    if source not in {'all', 'mail', 'temp'}:
        raise ValueError('存储来源无效')
    mailbox = str(value('mailbox')).strip().lower()
    if mailbox and not _SM_MAILBOX.fullmatch(mailbox):
        raise ValueError('邮箱地址无效')
    search = str(value('q')).strip().lower()[:255]
    offset = _sm_int(value('offset', 0), '偏移量', 0, 1000000)
    limit = _sm_int(value('limit', 25), '每页数量', 1, 100)
    min_age = max(300, _sm_int(_sm_os.environ.get('MAIL_CONTROL_UPLOAD_DELETE_MIN_AGE', 300), '清理保护时长', 0, 31536000))
    mail, uploads = _sm_roots()
    key = (str(mail), tuple(str(root) for root in uploads))
    with _SM_LOCK:
        if _SM_STATE['key'] != key:
            _SM_STATE.update(key=key, items=[], summary={}, updated_at=None,
                             scanning=False, error='', partial=False, started_at=None)
        stale = not _SM_STATE['updated_at'] or _sm_time.time() - _SM_STATE['updated_at'] >= _SM_REFRESH_SECONDS
        if not _SM_STATE['scanning'] and (stale or str(value('refresh', '0')) == '1'):
            _SM_STATE.update(scanning=True, started_at=_sm_time.time())
            _sm_threading.Thread(target=_sm_scan, args=(key, mail, uploads), daemon=True,
                                 name='mail-storage-inventory').start()
        state = {key: value for key, value in _SM_STATE.items() if key != 'items'}
        selected = [item for item in _SM_STATE['items'] if
                    (source == 'all' or item['source'] == source) and
                    (not mailbox or item['mailbox'].lower() == mailbox) and
                    (not search or search in (item['filename'] + ' ' + item['path'] + ' ' + item['mailbox']).lower())]
        page = [dict(item) for item in selected[offset:offset + limit]]
    roots = {_sm_root_id(root): root for root in uploads}
    for item in page:
        if item['source'] == 'temp':
            root = roots.get(item['root_id'])
            latest_change = max(item['mtime'], item['_file'][4] / 1000000000)
            item['deletable'] = _sm_time.time() - latest_change >= min_age
            item['delete_reason'] = '' if item['deletable'] else '正在保护最近上传的文件，请至少等待 ' + str(min_age // 60) + ' 分钟'
            try:
                path = _SMPath(item['_path'])
                st = path.lstat()
                if not root or _sm_has_symlink(path) or _sm_identity(st) != item['_file']:
                    raise ValueError()
                item['token'] = _sm_token(root, item['path'], st)
                filename = _sm_webmail_filename(path, item['_file'])
                if filename:
                    item['temporary_id'] = item['filename']
                    item['filename'] = filename
                    item['filename_note'] = '来自网页邮箱上传记录的原文件名；删除仅作用于对应临时文件'
            except (OSError, ValueError):
                item['deletable'] = False
                item['delete_reason'] = '文件位置或内容已变化，请刷新'
        elif str(value('attachments', '1')) == '1':
            item.update(_sm_metadata(item['_path'], tuple(item['_file'])))
        item.pop('_path', None)
        item.pop('_file', None)
    state.pop('key', None)
    webmail_storage = _sm_webmail_storage()
    _, discovery_partial = _sm_webmail_roots()
    state['partial'] = state['partial'] or discovery_partial
    state.update(items=page, total=len(selected), offset=offset, limit=limit,
                 refresh_seconds=_SM_REFRESH_SECONDS, delete_min_age=min_age,
                 webmail_storage={'path': str(webmail_storage), 'exists': webmail_storage.is_dir(),
                                  'discovery_partial': discovery_partial},
                 roots=[{'id': _sm_root_id(root), 'label': root.name, 'source': 'temp', 'exists': root.is_dir()} for root in uploads])
    return state


def _sm_is_open(st):
    """Refuse active Linux uploads, including files with old modification times."""
    proc = _SMPath('/proc')
    if _sm_os.name != 'posix' or not proc.is_dir():
        return False
    deadline, count = _sm_time.monotonic() + 3, 0
    try:
        with _sm_os.scandir(proc) as processes:
            for process in processes:
                if not process.name.isdigit():
                    continue
                try:
                    with _sm_os.scandir(_SMPath(process.path) / 'fd') as fds:
                        for fd in fds:
                            count += 1
                            if count > 50000 or _sm_time.monotonic() > deadline:
                                raise ValueError('无法及时确认文件是否正在使用，请稍后重试')
                            try:
                                current = fd.stat(follow_symlinks=True)
                                if current.st_dev == st.st_dev and current.st_ino == st.st_ino:
                                    return True
                            except FileNotFoundError:
                                pass
                except (FileNotFoundError, ProcessLookupError):
                    pass
                except PermissionError:
                    raise ValueError('无法确认文件是否正在使用，请检查存储服务权限')
    except OSError as exc:
        raise ValueError('无法确认文件是否正在使用，请稍后重试') from exc
    return False


def _sm_remove_temp(root, item, min_age):
    path = root / item['path']
    if _sm_has_symlink(path) or root not in path.resolve().parents:
        raise ValueError('文件路径不再有效，请刷新')
    st = path.lstat()
    if not _sm_stat.S_ISREG(st.st_mode) or _sm_identity(st) != item['file']:
        raise ValueError('文件内容已变化，请刷新')
    if _sm_time.time() - max(st.st_mtime, st.st_ctime) < min_age:
        raise ValueError('文件正在上传或处于最近上传保护期')
    if _sm_is_open(st):
        raise ValueError('文件正在使用，不能删除')
    # dir_fd + O_NOFOLLOW prevents a renamed intermediate directory escaping the
    # allowlist between validation and unlink. No Maildir path reaches this branch.
    if _sm_os.name == 'posix' and _sm_os.unlink in _sm_os.supports_dir_fd:
        descriptor = _sm_os.open(root, _sm_os.O_RDONLY | _sm_os.O_DIRECTORY | _sm_os.O_NOFOLLOW)
        try:
            parts = item['path'].split('/')
            for part in parts[:-1]:
                child = _sm_os.open(part, _sm_os.O_RDONLY | _sm_os.O_DIRECTORY | _sm_os.O_NOFOLLOW, dir_fd=descriptor)
                _sm_os.close(descriptor)
                descriptor = child
            current = _sm_os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
            if not _sm_stat.S_ISREG(current.st_mode) or _sm_identity(current) != item['file']:
                raise ValueError('文件内容已变化，请刷新')
            _sm_os.unlink(parts[-1], dir_fd=descriptor)
        finally:
            _sm_os.close(descriptor)
    else:
        if _sm_identity(path.lstat()) != item['file'] or _sm_has_symlink(path):
            raise ValueError('文件内容已变化，请刷新')
        path.unlink()
    return str(path)


def delete_storage_temp(payload):
    """Delete only signed, unchanged, old, inactive files in configured roots."""
    if not isinstance(payload, dict) or payload.get('confirm') is not True:
        raise ValueError('请明确确认删除选中的临时文件')
    tokens = payload.get('tokens')
    if not isinstance(tokens, list) or not 1 <= len(tokens) <= 100 or any(not isinstance(token, str) for token in tokens):
        raise ValueError('每次请选择 1 到 100 个临时文件')
    _, configured = _sm_roots()
    roots = {_sm_root_id(root): root for root in configured}
    plans = []
    for token in dict.fromkeys(tokens):
        item = _sm_decode_token(token)
        root = roots.get(item['root'])
        if root is None:
            raise ValueError('文件目录已不在允许清理的范围内')
        plans.append((token, root, item))
    min_age = max(300, _sm_int(_sm_os.environ.get('MAIL_CONTROL_UPLOAD_DELETE_MIN_AGE', 300), '清理保护时长', 0, 31536000))
    deleted, errors = [], []
    with _SM_DELETE_LOCK:
        for token, root, item in plans:
            try:
                path = _sm_remove_temp(root, item, min_age)
                deleted.append({'token': token, 'filename': _SMPath(item['path']).name, 'size': item['file'][2]})
                with _SM_LOCK:
                    _SM_STATE['items'] = [row for row in _SM_STATE['items'] if row['_path'] != path]
                    _SM_STATE['updated_at'] = None
                _sm_logging.warning('Global admin deleted expired temporary upload: root=%s filename=%r size=%s',
                                    _sm_root_id(root), _SMPath(item['path']).name, item['file'][2])
            except (OSError, ValueError) as exc:
                errors.append({'token': token, 'error': str(exc)})
    return {'deleted': deleted, 'errors': errors}
