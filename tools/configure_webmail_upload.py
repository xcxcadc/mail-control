#!/usr/bin/env python3
"""Install the shared-policy SnappyMail plugin without modifying upstream code."""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile

DEFAULT_POLICY = dict(single_mb=12, total_mb=24, max_count=12, message_mb=200)
PLUGIN_FILES = ('index.php', 'upload.js', 'upload.css')


def validate_policy(data):
    result = {}
    if not isinstance(data, dict):
        raise ValueError('upload policy must be a JSON object')
    for key, default in DEFAULT_POLICY.items():
        value = data.get(key, default)
        maximum = 200 if key == 'message_mb' else 100
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise ValueError(f'{key} must be an integer between 1 and {maximum}')
        result[key] = value
    if result['single_mb'] > result['total_mb']:
        raise ValueError('single_mb cannot exceed total_mb')
    return result


def replace_ini_value(text, section, key, value):
    """Keep unrelated settings and comments; never round-trip all INI sections."""
    header = re.search(r'^\[' + re.escape(section) + r'\][ \t]*\r?$', text, re.M)
    if not header:
        return text.rstrip() + '\n\n[' + section + ']\n' + key + ' = ' + value + '\n'
    after = text[header.end():]
    end = re.search(r'^\[', after, re.M)
    block_end = header.end() + (end.start() if end else len(after))
    block = text[header.end():block_end]
    pattern = r'^' + re.escape(key) + r'[ \t]*=.*$'
    if re.search(pattern, block, re.M):
        block = re.sub(pattern, lambda match: key + ' = ' + value, block, count=1, flags=re.M)
    else:
        block = block.rstrip() + '\n' + key + ' = ' + value + '\n\n'
    return text[:header.end()] + block + text[block_end:]


def atomic_write(path, content, owner=None, mode=None):
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f'refusing symlink target: {path}')
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = path.stat() if path.exists() else None
    fd, temp = tempfile.mkstemp(prefix='.' + path.name + '-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(content if isinstance(content, bytes) else content.encode('utf-8'))
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp, mode or (previous.st_mode & 0o777 if previous else 0o640))
        if hasattr(os, 'chown'):
            own = owner or ((previous.st_uid, previous.st_gid) if previous else None)
            if own:
                os.chown(temp, *own)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def configure(data_root, plugin_source, policy=None, php_ini=None):
    data_root = Path(data_root).resolve(strict=True)
    private = data_root / '_data_' / '_default_'
    config = private / 'configs' / 'application.ini'
    if not config.is_file() or config.is_symlink():
        raise ValueError('existing SnappyMail application.ini is required')
    existing = config.read_text(encoding='utf-8')
    stat = config.stat()
    owner = (stat.st_uid, stat.st_gid)
    source = Path(plugin_source).resolve(strict=True)
    for name in PLUGIN_FILES:
        if not (source / name).is_file():
            raise ValueError('missing plugin file: ' + name)
    enabled_match = re.search(r'^\[plugins\][\s\S]*?(?=^\[|\Z)', existing, re.M)
    enabled = []
    if enabled_match:
        match = re.search(r'^enabled_list\s*=\s*(.*?)\s*$', enabled_match.group(), re.M)
        if match:
            enabled = [x.strip() for x in match.group(1).strip('"\'').split(',') if x.strip()]
    if 'mail-control-upload' not in enabled:
        enabled.append('mail-control-upload')
    text = replace_ini_value(existing, 'plugins', 'enable', 'On')
    text = replace_ini_value(text, 'plugins', 'enabled_list', '"' + ','.join(enabled) + '"')
    policy_path = data_root / 'mail-control-upload-policy.json'
    data = validate_policy(policy if policy is not None else (
        json.loads(policy_path.read_text(encoding='utf-8')) if policy_path.exists() else DEFAULT_POLICY))
    text = replace_ini_value(text, 'webmail', 'attachment_size_limit', str(data['single_mb']))
    destination = private / 'plugins' / 'mail-control-upload'
    if destination.is_symlink() or destination.parent.is_symlink():
        raise ValueError('refusing symlink plugin directory')
    destination.mkdir(parents=True, exist_ok=True)
    for name in PLUGIN_FILES:
        atomic_write(destination / name, (source / name).read_bytes(), owner, 0o640)
    if hasattr(os, 'chown'):
        os.chown(destination, *owner)
        os.chmod(destination, 0o750)
    atomic_write(policy_path, json.dumps(data, ensure_ascii=False) + '\n', owner, 0o640)
    events = data_root / 'mail-control-upload-events'
    if events.is_symlink():
        raise ValueError('refusing symlink events directory')
    events.mkdir(mode=0o700, exist_ok=True)
    if hasattr(os, 'chown'):
        os.chown(events, *owner)
        os.chmod(events, 0o700)
    if text != existing:
        backup = config.with_name('application.ini.before-mail-control-upload')
        if not backup.exists():
            atomic_write(backup, existing, owner, 0o600)
        atomic_write(config, text, owner)
    if php_ini:
        atomic_write(Path(php_ini), '; Mail Control transport ceiling; business limits are live in plugin\n'
                     'upload_max_filesize = 128M\npost_max_size = 128M\nmax_file_uploads = 100\nmemory_limit = 512M\n', mode=0o644)
    return {'plugin': str(destination), 'policy': str(policy_path), 'events': str(events),
            'enabled_plugins': enabled, 'limits': data}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-root', required=True, help='Host path mounted at webmail /data')
    parser.add_argument('--plugin-source', default=str(Path(__file__).resolve().parent.parent / 'webmail' / 'mail-control-upload'))
    parser.add_argument('--policy', help='Canonical JSON policy file to mirror into webmail /data')
    parser.add_argument('--php-ini', help='Optional dedicated host PHP INI override (mount into conf.d)')
    args = parser.parse_args()
    policy = json.loads(Path(args.policy).read_text(encoding='utf-8')) if args.policy else None
    print(json.dumps(configure(args.data_root, args.plugin_source, policy, args.php_ini), ensure_ascii=False))


if __name__ == '__main__':
    main()
