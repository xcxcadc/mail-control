#!/usr/bin/env python3
"""Directed Mailu rollout. Read-only without --apply; never runs install.sh."""
import argparse
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    raise SystemExit('PyYAML is required; use the existing server Python environment with yaml installed')

COMPOSE = Path('/opt/mailu/docker-compose.yml')
APP = Path('/opt/mail-control/mail_control.py')
ADMIN_CONF = Path('/opt/mailu/nginx-overrides/mail-control-admin.conf')
CONTROL_CONF = Path('/opt/mailu/nginx-overrides/mail-control.conf')
POSTFIX = Path('/opt/mailu/data/overrides/postfix/postfix.cf')
OVERRIDES = Path('/opt/mail-control/overrides')
CONTAINERS = dict(admin='mailu-admin-1', webmail='mailu-webmail-1',
                  smtp='mailu-smtp-1', front='mailu-front-1')
PRODUCTION_INITIAL_POLICY = dict(single_mb=12, total_mb=24, max_count=12,
                                 message_mb=200, hard_max_mb=100)


def command(args, input=None):
    result = subprocess.run([str(arg) for arg in args], input=input, text=True,
                            capture_output=True, timeout=180)
    if result.returncode:
        # Config dumps may contain credentials. Do not replay arbitrary stdout.
        detail = result.stderr.strip()[-2000:]
        raise RuntimeError('Command failed: ' + shlex.join([str(a) for a in args])
                           + ('\n' + detail if detail else ''))
    return result.stdout


def regular(path):
    path = Path(path)
    if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Expected an existing regular, non-symlink file: ' + str(path))
    return path


def module(path, name):
    regular(path)
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    before = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(result)
    finally:
        sys.dont_write_bytecode = before
    return result


def write(path, data, mode=None):
    path = Path(path)
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise ValueError('Refusing symlink target: ' + str(path))
    previous = path.stat() if path.exists() else None
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data.encode() if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode if mode is not None else (stat.S_IMODE(previous.st_mode) if previous else 0o644))
        if previous and hasattr(os, 'chown'):
            os.chown(temporary, previous.st_uid, previous.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def mount_target(volume):
    if isinstance(volume, str):
        parts = volume.split(':')
        if len(parts) in (2, 3):
            return parts[1], parts[0]
    elif isinstance(volume, dict):
        return volume.get('target'), volume.get('source')
    return None, None


def add_mount(service, source, target):
    volumes = service.setdefault('volumes', [])
    if not isinstance(volumes, list):
        raise ValueError('Unsupported Compose volumes structure')
    for index, volume in enumerate(volumes):
        existing_target, existing_source = mount_target(volume)
        if existing_target == target:
            if existing_source != str(source):
                raise ValueError('Existing custom mount conflicts at ' + target + ': ' + str(existing_source))
            volumes[index] = str(source) + ':' + target + ':ro'
            return
    volumes.append(str(source) + ':' + target + ':ro')


def proxy_upload_config(text):
    lines = []
    active = False
    depth = 0
    blocks = 0
    settings = {'client_max_body_size': '300m', 'proxy_read_timeout': '300s',
                'proxy_send_timeout': '300s', 'client_body_timeout': '300s',
                'proxy_request_buffering': 'off'}
    found = set()
    for line in text.splitlines():
        if re.match(r'\s*location\s+\^~\s+/(?:admin/)?mail-control/\s*\{', line):
            if active:
                raise ValueError('Unexpected nested Mail Control location')
            active, depth, found = True, 0, set()
            blocks += 1
        if active:
            match = re.match(r'\s*(' + '|'.join(settings) + r')\s+[^;]+;\s*$', line)
            if match:
                key = match.group(1)
                if key in found:
                    continue
                line = '    ' + key + ' ' + settings[key] + ';'
                found.add(key)
            closing = depth + line.count('{') - line.count('}')
            if closing == 0:
                for key, value in settings.items():
                    if key not in found:
                        lines.append('    ' + key + ' ' + value + ';')
                active = False
            depth = closing
        lines.append(line)
    if blocks != 2 or active:
        raise ValueError('Expected exactly two existing Mail Control proxy locations')
    return '\n'.join(lines) + '\n'


def webmail_nginx_config(text):
    pattern = r'(?m)^([ \t]*)client_max_body_size\s+[^;]+;'
    if not re.search(pattern, text):
        raise ValueError('No client_max_body_size found in the actual webmail Nginx template')
    result = re.sub(pattern, r'\g<1>client_max_body_size 128m;', text)
    timeout = r'(?m)^([ \t]*)fastcgi_read_timeout\s+[^;]+;'
    if re.search(timeout, result):
        result = re.sub(timeout, r'\g<1>fastcgi_read_timeout 300s;', result)
    else:
        match = re.search(r'(?m)^([ \t]*)fastcgi_pass\s+[^;]+;.*$', result)
        if not match:
            raise ValueError('No fastcgi_pass found in the actual webmail Nginx template')
        result = result[:match.end()] + '\n' + match.group(1) + 'fastcgi_read_timeout 300s;' + result[match.end():]
    return result


class Backup:
    def __init__(self, root):
        self.root = root
        root.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.items = []
        self.extra = {}

    def capture(self, path):
        path = Path(path)
        if any(item['path'] == str(path) for item in self.items):
            return
        if path.is_symlink():
            raise ValueError('Refusing to back up symlink target: ' + str(path))
        item = {'path': str(path), 'existed': path.exists()}
        if path.exists():
            regular(path)
            name = 'files/' + str(len(self.items)).zfill(3) + '-' + path.name
            destination = self.root / name
            destination.parent.mkdir(exist_ok=True)
            shutil.copy2(path, destination)
            st = path.stat()
            item.update(backup=name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid)
        self.items.append(item)
        self.save()

    def capture_directory(self, path):
        path = Path(path)
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise ValueError('Refusing symlink plugin directory: ' + str(path))
        item = {'path': str(path), 'existed': path.exists()}
        if path.exists():
            if not path.is_dir():
                raise ValueError('Plugin target must be a directory: ' + str(path))
            info = path.stat()
            item.update(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
        self.extra.setdefault('directories', []).append(item)
        self.save()

    def save(self):
        value = dict(self.extra, files=self.items, version=1)
        write(self.root / 'manifest.json', json.dumps(value, ensure_ascii=False, indent=2) + '\n', 0o600)


def restore(backup):
    manifest = json.loads(regular(backup / 'manifest.json').read_text())
    for item in reversed(manifest['files']):
        path = Path(item['path'])
        if item['existed']:
            source = regular(backup / item['backup'])
            if hashlib.sha256(source.read_bytes()).hexdigest() != item['sha256']:
                raise ValueError('Backup digest mismatch: ' + str(source))
            write(path, source.read_bytes(), item['mode'])
            if hasattr(os, 'chown'):
                os.chown(path, item['uid'], item['gid'])
        elif path.exists():
            regular(path).unlink()
    for item in reversed(manifest.get('directories', [])):
        path = Path(item['path'])
        if path.is_symlink():
            raise ValueError('Refusing symlink directory during rollback: ' + str(path))
        if item['existed']:
            if not path.is_dir():
                raise ValueError('Original plugin directory disappeared: ' + str(path))
            os.chmod(path, item['mode'])
            if hasattr(os, 'chown'):
                os.chown(path, item['uid'], item['gid'])
        elif path.is_dir():
            # Remove only a newly created directory that is now empty; never
            # recursively remove a directory possibly populated by a user.
            try:
                path.rmdir()
            except OSError:
                pass
    return manifest


def compose_command(compose):
    return ['docker', 'compose', '--project-directory', str(compose.parent), '-f', str(compose)]


def activate(compose, admin_service, webmail_service, smtp_limit=209715200):
    if isinstance(smtp_limit, bool) or not isinstance(smtp_limit, int) or smtp_limit < 0:
        raise ValueError('Invalid restored SMTP message_size_limit')
    base = compose_command(compose)
    command(base + ['config', '--quiet'])
    command(['docker', 'exec', CONTAINERS['front'], 'nginx', '-t'])
    command(base + ['up', '-d', '--no-deps', '--force-recreate', '--pull', 'never', '--no-build',
                    admin_service, webmail_service])
    command(['systemctl', 'restart', 'mail-control'])
    command(['docker', 'exec', CONTAINERS['smtp'], 'postconf', '-e', 'message_size_limit=' + str(smtp_limit)])
    command(['docker', 'exec', CONTAINERS['smtp'], 'postfix', 'reload'])
    command(['docker', 'exec', CONTAINERS['front'], 'nginx', '-t'])
    command(['docker', 'exec', CONTAINERS['front'], 'nginx', '-s', 'reload'])


def inspect_production(release):
    for path in (COMPOSE, APP, ADMIN_CONF, CONTROL_CONF, POSTFIX,
                 release / 'mail_control.py', release / 'nginx' / 'mail-control-admin.conf',
                 release / 'tools' / 'configure_password_policy.py',
                 release / 'tools' / 'configure_webmail_upload.py', release / 'src' / 'upload_policy.py'):
        regular(path)
    compose = yaml.safe_load(COMPOSE.read_text())
    if not isinstance(compose, dict) or not isinstance(compose.get('services'), dict):
        raise ValueError('Invalid existing Compose service map')
    inspections = {}
    for role, name in CONTAINERS.items():
        info = json.loads(command(['docker', 'inspect', name]))
        if len(info) != 1 or not info[0].get('State', {}).get('Running'):
            raise ValueError('Expected a running Mailu container: ' + name)
        inspections[role] = info[0]
    services = {}
    for role in ('admin', 'webmail'):
        labels = inspections[role].get('Config', {}).get('Labels', {})
        service = labels.get('com.docker.compose.service')
        if service not in compose['services']:
            raise ValueError('Container service does not match the existing Compose file: ' + role)
        config_files = labels.get('com.docker.compose.project.config_files', '')
        if config_files.split(',') != [str(COMPOSE)]:
            raise ValueError('Container is not managed by the expected Compose file: ' + role)
        services[role] = service
    mounts = [item for item in inspections['webmail']['Mounts'] if item['Destination'] == '/data' and item['Type'] == 'bind']
    if len(mounts) != 1:
        raise ValueError('Expected exactly one existing bind mount for webmail /data')
    data = Path(mounts[0]['Source'])
    if data.resolve() != Path('/opt/mailu/data/webmail'):
        raise ValueError('Unexpected webmail data root; review the rollout configuration explicitly: ' + str(data))
    application = regular(data / '_data_' / '_default_' / 'configs' / 'application.ini')
    sources = {}
    for role, path, key in (('admin', '/app/mailu/utils.py', 'utils'),
                            ('webmail', '/defaults/application.ini', 'defaults'),
                            ('webmail', '/conf/nginx-webmail.conf', 'nginx')):
        command(['docker', 'exec', CONTAINERS[role], 'test', '-f', path])
        sources[key] = command(['docker', 'exec', CONTAINERS[role], 'cat', path])
    ini = command(['docker', 'exec', CONTAINERS['webmail'], 'php', '--ini'])
    match = re.search(r'^Scan for additional \.ini files in:\s*(/[^\r\n]+)\s*$', ini, re.M)
    if not match or match.group(1).strip() in {'/', '(none)'}:
        raise ValueError('Could not determine the actual PHP conf.d directory')
    php_dir = match.group(1).strip()
    command(['docker', 'exec', CONTAINERS['webmail'], 'test', '-d', php_dir])
    smtp_limit = command(['docker', 'exec', CONTAINERS['smtp'], 'postconf', '-h', 'message_size_limit']).strip()
    if not smtp_limit.isdigit():
        raise ValueError('Could not read the existing SMTP message_size_limit')
    return compose, services, data, application, sources, php_dir, int(smtp_limit)


def rollout(release, apply):
    compose, services, data, application, sources, php_dir, old_smtp_limit = inspect_production(release)
    password = module(release / 'tools' / 'configure_password_policy.py', 'rollout_password')
    webmail = module(release / 'tools' / 'configure_webmail_upload.py', 'rollout_webmail')
    policy = module(release / 'src' / 'upload_policy.py', 'rollout_policy')
    if policy._up_paths() != (Path('/opt/mail-control/upload-policy.json'), data / 'mail-control-upload-policy.json'):
        raise ValueError('Upload policy environment overrides do not match the backed-up production paths')
    compile((release / 'mail_control.py').read_text(encoding='utf-8'), str(release / 'mail_control.py'), 'exec')
    prepared_utils, _ = password.patch_source(sources['utils'])
    prepared_nginx = webmail_nginx_config(sources['nginx'])
    prepared_control = proxy_upload_config(CONTROL_CONF.read_text())
    existing_postfix = POSTFIX.read_text()
    new_postfix = re.sub(r'(?m)^\s*message_size_limit\s*=.*$', 'message_size_limit = 209715200', existing_postfix)
    if not re.search(r'(?m)^message_size_limit\s*=', new_postfix):
        new_postfix = new_postfix.rstrip() + '\nmessage_size_limit = 209715200\n'
    # The domain-copy socketmap and every unrelated Postfix parameter are retained.
    target_utils = OVERRIDES / 'mailu-utils.py'
    target_php = OVERRIDES / '99-mail-control-upload.ini'
    target_defaults = OVERRIDES / 'webmail-application.ini'
    target_nginx = OVERRIDES / 'nginx-webmail.conf'
    plugin_destination = data / '_data_' / '_default_' / 'plugins' / 'mail-control-upload'
    prepared_compose = copy.deepcopy(compose)
    add_mount(prepared_compose['services'][services['admin']], target_utils, '/app/mailu/utils.py')
    for source, target in ((target_php, php_dir + '/99-mail-control-upload.ini'),
                           (target_defaults, '/defaults/application.ini'),
                           (target_nginx, '/conf/nginx-webmail.conf'),
                           (plugin_destination, '/data/_data_/_default_/plugins/mail-control-upload')):
        add_mount(prepared_compose['services'][services['webmail']], source, target)
    if set(prepared_compose['services']) != set(compose['services']):
        raise ValueError('Refusing any Compose service-set change')
    for name in compose['services']:
        if name not in services.values() and prepared_compose['services'][name] != compose['services'][name]:
            raise ValueError('Refusing changes to an unrelated Compose service')
    plugin_source = release / 'webmail' / 'mail-control-upload'
    for name in webmail.PLUGIN_FILES:
        regular(plugin_source / name)
    # Read the production policy only to validate its current health. Candidate
    # acceptance values such as 1/2/2 must never become release defaults.
    previous_policy = policy.upload_policy()
    current_policy = dict(PRODUCTION_INITIAL_POLICY)
    print(json.dumps({'mode': 'apply' if apply else 'read-only', 'services_to_recreate': list(services.values()),
                      'compose': str(COMPOSE), 'webmail_data': str(data), 'php_conf_d': php_dir,
                      'smtp_message_bytes': 209715200, 'mail_control_http_mib': 300,
                      'webmail_http_mib': 128, 'policy_to_apply': current_policy}, ensure_ascii=False))
    if not apply:
        return
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
    backup = Backup(Path('/opt/mail-control/backups') / ('upload-features-' + timestamp))
    backup.extra.update(compose=str(COMPOSE), services=services, release_root=str(release),
                        old_smtp_limit=old_smtp_limit, previous_policy=previous_policy,
                        applied_policy=current_policy, state='preparing')
    backup.capture_directory(plugin_destination)
    paths = [APP, COMPOSE, ADMIN_CONF, CONTROL_CONF, POSTFIX, application,
             target_utils, target_php, target_defaults, target_nginx,
             Path('/opt/mail-control/upload-policy.json'), data / 'mail-control-upload-policy.json',
             application.with_name('application.ini.before-mail-control-upload')]
    paths += [plugin_destination / name for name in webmail.PLUGIN_FILES]
    for path in paths:
        backup.capture(path)
    write(backup.root / 'container-utils.py', sources['utils'], 0o600)
    write(backup.root / 'container-application.ini', sources['defaults'], 0o600)
    write(backup.root / 'container-nginx-webmail.conf', sources['nginx'], 0o600)
    rollback_command = shlex.join([sys.executable, str(release / 'tools' / 'rollout_upload_features.py'),
                                  '--release-root', str(release), '--rollback', str(backup.root), '--apply'])
    backup.extra.update(rollback_command=rollback_command, state='applying')
    backup.save()
    print('BACKUP=' + str(backup.root), flush=True)
    print('ROLLBACK=' + rollback_command, flush=True)
    try:
        write(target_utils, prepared_utils, 0o644)
        write(target_nginx, prepared_nginx, 0o644)
        # Render the original default template independently of the current
        # generated config, preserving all Mailu variables and SSO settings.
        enabled = re.search(r'^\[plugins\][\s\S]*?(?=^\[|\Z)', sources['defaults'], re.M)
        names = []
        if enabled:
            found = re.search(r'^enabled_list\s*=\s*(.*?)\s*$', enabled.group(), re.M)
            if found:
                names = [item.strip() for item in found.group(1).strip('"\'').split(',') if item.strip()]
        if 'mail-control-upload' not in names:
            names.append('mail-control-upload')
        defaults = webmail.replace_ini_value(sources['defaults'], 'plugins', 'enable', 'On')
        defaults = webmail.replace_ini_value(defaults, 'plugins', 'enabled_list', '"' + ','.join(names) + '"')
        defaults = webmail.replace_ini_value(defaults, 'webmail', 'attachment_size_limit', str(current_policy['single_mb']))
        write(target_defaults, defaults, 0o644)
        webmail.configure(data, plugin_source, current_policy, target_php)
        # Snuffleupagus requires executable PHP to be immutable and owned by a
        # different account from the PHP worker. Keep the plugin root-owned,
        # readable by mailu, and additionally bind it read-only inside /data.
        os.chown(plugin_destination, 0, 0)
        os.chmod(plugin_destination, 0o755)
        for name in webmail.PLUGIN_FILES:
            asset = regular(plugin_destination / name)
            os.chown(asset, 0, 0)
            os.chmod(asset, 0o644)
        # configure() retains existing plugins; merge their list into the boot
        # template too so recreation does not disable a previously enabled plugin.
        configured = application.read_text()
        section = re.search(r'^\[plugins\][\s\S]*?(?=^\[|\Z)', configured, re.M)
        if section:
            match = re.search(r'^enabled_list\s*=\s*(.*?)\s*$', section.group(), re.M)
            if match:
                extra = [item.strip() for item in match.group(1).strip('"\'').split(',') if item.strip()]
                names = list(dict.fromkeys(names + extra))
                write(target_defaults, webmail.replace_ini_value(defaults, 'plugins', 'enabled_list', '"' + ','.join(names) + '"'), 0o644)
        policy.save_upload_policy(current_policy)
        command(['docker', 'exec', '-i', CONTAINERS['webmail'], 'php', '-l'], input=(plugin_source / 'index.php').read_text())
        write(APP, (release / 'mail_control.py').read_bytes())
        write(ADMIN_CONF, (release / 'nginx' / 'mail-control-admin.conf').read_bytes())
        write(CONTROL_CONF, prepared_control)
        write(POSTFIX, new_postfix)
        write(COMPOSE, yaml.safe_dump(prepared_compose, sort_keys=False, allow_unicode=True))
        activate(COMPOSE, services['admin'], services['webmail'])
        backup.extra['state'] = 'applied'
        backup.save()
        print('Directed rollout completed; only admin/webmail recreated and mail-control restarted.')
    except Exception as exc:
        print('Rollout failed; restoring manifest files: ' + str(exc), file=sys.stderr, flush=True)
        try:
            restore(backup.root)
            activate(COMPOSE, services['admin'], services['webmail'], old_smtp_limit)
            backup.extra['state'] = 'rolled-back'
            backup.save()
        except Exception as rollback_error:
            backup.extra.update(state='rollback-needs-attention', rollback_error=str(rollback_error))
            backup.save()
            raise RuntimeError('Automatic rollback needs attention. Use: ' + rollback_command) from rollback_error
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-root', required=True, type=Path)
    parser.add_argument('--apply', action='store_true', help='Explicitly apply the directed rollout or rollback')
    parser.add_argument('--rollback', type=Path, help='Restore one timestamped backup manifest')
    args = parser.parse_args()
    release = args.release_root.resolve(strict=True)
    if args.rollback:
        backup = args.rollback.resolve(strict=True)
        manifest = json.loads(regular(backup / 'manifest.json').read_text())
        if not args.apply:
            print(json.dumps({'mode': 'read-only', 'rollback': str(backup),
                              'files': [item['path'] for item in manifest['files']],
                              'services': manifest['services']}, ensure_ascii=False))
            return
        restore(backup)
        activate(Path(manifest['compose']), manifest['services']['admin'], manifest['services']['webmail'],
                 manifest['old_smtp_limit'])
        print('Directed rollback completed: ' + str(backup))
    else:
        rollout(release, args.apply)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit('upload rollout: ' + str(error))
