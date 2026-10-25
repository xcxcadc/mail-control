"""Shared upload policy and metadata-only, throttled upload audit."""
import json as _up_json
import os as _up_os
import re as _up_re
import sqlite3 as _up_sqlite
import stat as _up_stat
import tempfile as _up_tempfile
import threading as _up_threading
import time as _up_time
import uuid as _up_uuid
from pathlib import Path as _UPPath
from contextlib import contextmanager as _up_contextmanager

_UP_DEFAULT = {'single_mb': 12, 'total_mb': 24, 'max_count': 12,
               'message_mb': 200, 'hard_max_mb': 100}
_UP_POLICY_LOCK = _up_threading.RLock()
_UP_EVENT_LOCK = _up_threading.RLock()
_UP_AUDIT_SCHEMA = {}
_UP_ACTIVE = {}


def _up_int(value, name, lower, upper):
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ValueError(name + '必须为 ' + str(lower) + ' 到 ' + str(upper) + ' 的整数')
    return value


def _up_validate(value, current=None):
    if not isinstance(value, dict):
        raise ValueError('附件设置必须为 JSON 对象')
    if set(value) - set(_UP_DEFAULT):
        raise ValueError('包含未知的附件设置')
    result = dict(current or _UP_DEFAULT)
    for key, number in value.items():
        if key in {'single_mb', 'total_mb', 'max_count'}:
            result[key] = _up_int(number, key, 1, 100)
        elif isinstance(number, bool) or not isinstance(number, int) or number != _UP_DEFAULT[key]:
            raise ValueError(key + '为只读的服务器限制')
    if result['total_mb'] < result['single_mb']:
        raise ValueError('附件总大小不能小于单文件大小')
    return result


def _up_paths():
    return (_UPPath(_up_os.environ.get('MAIL_CONTROL_UPLOAD_POLICY', '/opt/mail-control/upload-policy.json')),
            _UPPath(_up_os.environ.get('MAIL_CONTROL_WEBMAIL_POLICY', '/opt/mailu/data/webmail/mail-control-upload-policy.json')))


def _up_no_links(path):
    for component in (path, *path.parents):
        try:
            if _up_stat.S_ISLNK(component.lstat().st_mode):
                raise ValueError('附件配置路径不能包含符号链接')
        except FileNotFoundError:
            continue


def upload_policy():
    """Return the effective policy; a corrupt file fails explicitly."""
    with _UP_POLICY_LOCK:
        path, _ = _up_paths()
        _up_no_links(path)
        try:
            data = path.read_text(encoding='utf-8')
        except FileNotFoundError:
            return dict(_UP_DEFAULT)
        except OSError as exc:
            raise ValueError('无法读取附件设置，请检查配置权限') from exc
        if len(data) > 8192:
            raise ValueError('附件设置文件异常，请修复后重试')
        try:
            return _up_validate(_up_json.loads(data))
        except (ValueError, TypeError) as exc:
            raise ValueError('附件设置文件无效：' + str(exc)) from exc


def _up_stage(path, content, mode=0o644):
    fd, name = _up_tempfile.mkstemp(prefix='.' + path.name + '.', suffix='.tmp', dir=str(path.parent))
    temporary = _UPPath(name)
    try:
        with _up_os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            _up_os.fsync(stream.fileno())
        temporary.chmod(mode)
        return temporary
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _up_sync_parent(path):
    if _up_os.name == 'posix':
        fd = _up_os.open(path.parent, _up_os.O_RDONLY | _up_os.O_DIRECTORY)
        try:
            _up_os.fsync(fd)
        finally:
            _up_os.close(fd)


def save_upload_policy(payload):
    """Commit app/webmail copies together, rolling back either replacement failure."""
    with _UP_POLICY_LOCK:
        policy = _up_validate(payload, upload_policy())
        paths = _up_paths()
        if paths[0].absolute() == paths[1].absolute():
            raise ValueError('应用和网页邮箱的附件配置必须是两个独立文件')
        for path in paths:
            _up_no_links(path)
        paths[0].parent.mkdir(parents=True, exist_ok=True)
        if not paths[1].parent.is_dir():
            raise ValueError('网页邮箱配置目录不存在，请先确认实际部署路径')
        staged, originals, committed, recovery = {}, {}, [], set()
        body = (_up_json.dumps(policy, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
        try:
            # Prepare both new copies and rollback images before mutating either.
            for path in paths:
                if path.exists():
                    if not path.is_file():
                        raise ValueError('附件配置目标不是普通文件')
                    original = path.read_bytes()
                    originals[path] = _up_stage(path, original, _up_stat.S_IMODE(path.stat().st_mode))
                else:
                    originals[path] = None
                staged[path] = _up_stage(path, body)
            for path in paths:
                _up_os.replace(staged[path], path)
                committed.append(path)
                _up_sync_parent(path)
        except Exception as exc:
            failures = []
            for path in reversed(committed):
                try:
                    if originals[path] is None:
                        path.unlink(missing_ok=True)
                    else:
                        _up_os.replace(originals[path], path)
                    _up_sync_parent(path)
                except OSError:
                    failures.append(str(path))
                    if originals[path] is not None:
                        recovery.add(originals[path])
            if failures:
                locations = '、'.join(str(path) for path in recovery)
                raise ValueError('附件设置保存失败，回滚未完成，请检查：' + '、'.join(failures)
                                 + ('；原文件保留于：' + locations if locations else '')) from exc
            raise ValueError('附件设置保存失败，原设置已保留：' + str(exc)) from exc
        finally:
            for path in list(staged.values()) + [p for p in originals.values() if p is not None]:
                if path not in recovery:
                    path.unlink(missing_ok=True)
        return policy


def _up_db_path():
    return _UPPath(_up_os.environ.get('MAIL_CONTROL_UPLOAD_DB', '/opt/mail-control/uploads.db'))


def _up_connect():
    path = _up_db_path()
    _up_no_links(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = _up_sqlite.connect(path, timeout=3)
    db.row_factory = _up_sqlite.Row
    identity = (path.stat().st_dev, path.stat().st_ino)
    key = str(path.absolute())
    if _UP_AUDIT_SCHEMA.get(key) != identity:
        try:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('''CREATE TABLE IF NOT EXISTS upload_events (
                id TEXT PRIMARY KEY, source TEXT NOT NULL, actor TEXT NOT NULL,
                total INTEGER NOT NULL, received INTEGER NOT NULL, status TEXT NOT NULL,
                files TEXT NOT NULL, error TEXT NOT NULL,
                created_at REAL NOT NULL, updated_at REAL NOT NULL)''')
            db.execute('CREATE INDEX IF NOT EXISTS upload_events_updated ON upload_events(updated_at DESC)')
            db.commit()
            path.chmod(0o600)
            _UP_AUDIT_SCHEMA[key] = identity
        except BaseException:
            db.close()
            raise
    return db


@_up_contextmanager
def _up_db():
    db = _up_connect()
    try:
        with db:
            yield db
    finally:
        db.close()


def _up_event_key(event_id):
    return str(_up_db_path().absolute()), str(event_id)


def _up_public_event(event):
    return {key: value for key, value in event.items() if not key.startswith('_')}


def _up_trim(db):
    db.execute('DELETE FROM upload_events WHERE id NOT IN (SELECT id FROM upload_events ORDER BY updated_at DESC, rowid DESC LIMIT 1000)')


def upload_request_start(source, actor, total):
    total = _up_int(total, '上传总大小', 0, 9223372036854775807)
    source = str(source or 'unknown').strip()[:64]
    actor = str(actor or '').strip()[:255]
    event_id = str(_up_uuid.uuid4())
    now = _up_time.time()
    event = {'id': event_id, 'source': source, 'actor': actor, 'total': total,
             'received': 0, 'status': 'uploading', 'files': [], 'error': '',
             'created_at': now, 'updated_at': now, '_last_write': _up_time.monotonic()}
    with _UP_EVENT_LOCK:
        with _up_db() as db:
            db.execute('INSERT INTO upload_events VALUES(?,?,?,?,?,?,?,?,?,?)',
                       (event_id, source, actor, total, 0, 'uploading', '[]', '', now, now))
            _up_trim(db)
        _UP_ACTIVE[_up_event_key(event_id)] = event
        # The persistent audit is limited to 1000; avoid a failed request leaking
        # an unbounded in-memory progress record too.
        if len(_UP_ACTIVE) > 1000:
            oldest = min(_UP_ACTIVE, key=lambda key: _UP_ACTIVE[key]['updated_at'])
            del _UP_ACTIVE[oldest]
    return event_id


def _up_load_event(db, event_id):
    row = db.execute('SELECT * FROM upload_events WHERE id=?', (str(event_id),)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result['files'] = _up_json.loads(result['files'])
    result['_last_write'] = 0
    return result


def upload_request_progress(event_id, received):
    received = _up_int(received, '已上传大小', 0, 9223372036854775807)
    with _UP_EVENT_LOCK:
        key = _up_event_key(event_id)
        event = _UP_ACTIVE.get(key)
        if event is None:
            with _up_db() as db:
                event = _up_load_event(db, event_id)
            if event is None or event['status'] != 'uploading':
                return
            _UP_ACTIVE[key] = event
        event['received'] = min(event['total'], max(event['received'], received)) if event['total'] else max(event['received'], received)
        event['updated_at'] = _up_time.time()
        monotonic = _up_time.monotonic()
        if monotonic - event['_last_write'] < .5:
            return
        with _up_db() as db:
            db.execute('UPDATE upload_events SET received=?, updated_at=? WHERE id=?',
                       (event['received'], event['updated_at'], str(event_id)))
        event['_last_write'] = monotonic


def _up_files(files):
    if files is None:
        return None
    if not isinstance(files, list) or len(files) > 100:
        raise ValueError('附件审计元信息无效')
    result = []
    for item in files:
        if not isinstance(item, dict):
            raise ValueError('附件审计元信息无效')
        name = str(item.get('name', item.get('filename', ''))).replace('\\', '/').rsplit('/', 1)[-1]
        name = ''.join(character for character in name if ord(character) >= 32)[:255]
        result.append({'name': name, 'size': _up_int(item.get('size', 0), '附件大小', 0, 9223372036854775807)})
    return result


def upload_request_finish(event_id, status, files=None, error=''):
    status = str(status or '').strip()
    if not _up_re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', status):
        raise ValueError('上传状态无效')
    prepared_files = _up_files(files)
    with _UP_EVENT_LOCK:
        key = _up_event_key(event_id)
        with _up_db() as db:
            event = _UP_ACTIVE.get(key) or _up_load_event(db, event_id)
            if event is None:
                return
            event.update(status=status, error=str(error or '')[:1024], updated_at=_up_time.time())
            if prepared_files is not None:
                event['files'] = prepared_files
            db.execute('UPDATE upload_events SET received=?, status=?, files=?, error=?, updated_at=? WHERE id=?',
                       (event['received'], event['status'], _up_json.dumps(event['files'], ensure_ascii=False),
                        event['error'], event['updated_at'], str(event_id)))
            _up_trim(db)
        _UP_ACTIVE.pop(key, None)


def upload_request_snapshot():
    with _UP_EVENT_LOCK:
        with _up_db() as db:
            rows = db.execute('SELECT * FROM upload_events ORDER BY updated_at DESC, rowid DESC LIMIT 100').fetchall()
        events = {}
        for row in rows:
            event = dict(row)
            event['files'] = _up_json.loads(event['files'])
            events[event['id']] = event
        path = str(_up_db_path().absolute())
        for (database, event_id), event in _UP_ACTIVE.items():
            if database == path:
                events[event_id] = _up_public_event(event)
        return sorted(events.values(), key=lambda event: (event['updated_at'], event['created_at']), reverse=True)[:100]
