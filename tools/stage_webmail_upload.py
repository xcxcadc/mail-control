#!/usr/bin/env python3
"""Create a loopback-only SnappyMail candidate with isolated data, never deploy it.

Run on the Docker host as root. Existing candidate containers/directories are never
reused. No production volume, session, storage, or database is mounted or copied.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from configure_webmail_upload import (DEFAULT_POLICY, atomic_write, configure,
                                      replace_ini_value, validate_policy)

CANDIDATE = 'mail-control-webmail-candidate'
LABEL = 'mail-control.stage'
PORT = '18888'
EXPECTED_VERSION = '2.38.2'
CONFIG_PATH = '/data/_data_/_default_/configs/application.ini'


def docker(*arguments, allow_failure=False):
    result = subprocess.run(['docker', *map(str, arguments)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode and not allow_failure:
        # Never surface env, config, credentials, or startup logs in an exception.
        raise RuntimeError('Docker operation failed: ' + arguments[0])
    return result


def inspect(container, required=True):
    result = docker('container', 'inspect', container, allow_failure=True)
    if result.returncode:
        if required:
            raise ValueError('source container does not exist or cannot be inspected')
        return None
    rows = json.loads(result.stdout)
    if len(rows) != 1:
        raise ValueError('ambiguous container inspection')
    return rows[0]


def read_container(container, path):
    data = docker('exec', container, 'cat', path).stdout
    if not data or len(data) > 2 * 1024 * 1024:
        raise ValueError('missing or unexpectedly large configuration: ' + path)
    return data


def environment_from(container):
    values = {}
    for line in container.get('Config', {}).get('Env', []):
        key, separator, value = line.partition('=')
        if not separator or key in values or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key):
            raise ValueError('invalid or ambiguous source environment')
        if '\n' in value or '\r' in value or '\x00' in value:
            raise ValueError('multiline source environment is unsupported')
        values[key] = value
    if values.get('WEBMAIL') != 'snappymail':
        raise ValueError('source must explicitly use WEBMAIL=snappymail')
    # Mailu initializes the Roundcube DB even when running SnappyMail.
    values.update(WEB_WEBMAIL='/', ROUNDCUBE_DB_FLAVOR='sqlite',
                  SQLALCHEMY_DATABASE_URI_ROUNDCUBE='sqlite:////data/roundcube.db',
                  MESSAGE_SIZE_LIMIT=str(200 * 1024 * 1024))
    for key in ('ROUNDCUBE_DB_PW', 'ROUNDCUBE_DB_USER', 'ROUNDCUBE_DB_HOST',
                'ROUNDCUBE_DB_NAME'):
        values.pop(key, None)
    return values


def candidate_application(content):
    if '{{' in content or '{%' in content or '[webmail]' not in content:
        raise ValueError('source application.ini must be a rendered SnappyMail configuration')
    for section, key, value in (
        ('labs', 'custom_login_link', '""'),
        ('labs', 'custom_logout_link', '""'),
        ('labs', 'cookie_default_path', '"/"'),
        ('labs', 'cookie_default_secure', 'Off'),
        ('security', 'cookie_samesite', '"Strict"'),
        ('security', 'allow_admin_panel', 'Off'),
        ('plugins', 'enable', 'On'),
        ('plugins', 'enabled_list', '"mail-control-upload"'),
    ):
        content = replace_ini_value(content, section, key, value)
    return content


def candidate_nginx(content):
    pattern = r'(?m)^([ \t]*)client_max_body_size[ \t]+[^;\r\n]+;'
    if len(re.findall(pattern, content)) != 1:
        raise ValueError('nginx template must have exactly one upload-size directive')
    if re.search(r'fastcgi_param\s+HTTPS\s+', content):
        raise ValueError('custom HTTPS FastCGI configuration needs explicit review')
    if '/var/www/' not in content or not re.search(r'listen\s+80\b', content):
        raise ValueError('unsupported webmail nginx layout')
    return re.sub(pattern, lambda match: match.group(1) + 'client_max_body_size 128m;', content)


def selected_network(container, requested):
    networks = container.get('NetworkSettings', {}).get('Networks', {})
    if requested:
        if requested not in networks:
            raise ValueError('requested network is not attached to source container')
        return requested
    if len(networks) != 1:
        raise ValueError('source has zero or multiple networks; specify --network explicitly')
    return next(iter(networks))


def safe_cleanup(root):
    current = inspect(CANDIDATE, required=False)
    if current and current.get('Config', {}).get('Labels', {}).get(LABEL) == str(root):
        docker('rm', '-f', '-v', CANDIDATE, allow_failure=True)


def stage(args):
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('run this script as root on the Linux Docker host')
    if inspect(CANDIDATE, required=False):
        raise ValueError('candidate already exists; inspect/remove it explicitly before staging again')
    source = inspect(args.source)
    if not source.get('State', {}).get('Running'):
        raise ValueError('source container must be running')
    image = source.get('Image', '')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise ValueError('source image is not an immutable image ID')
    network = selected_network(source, args.network)
    env = environment_from(source)
    code_root = '/var/www/snappymail/snappymail/v/' + EXPECTED_VERSION
    docker('exec', args.source, 'test', '-f', code_root + '/app/libraries/RainLoop/Actions.php')
    docker('exec', args.source, 'test', '-f', '/start.py')
    docker('exec', args.source, 'test', '-d', '/etc/php83/conf.d')
    snapshots = {
        'production.application.ini': read_container(args.source, CONFIG_PATH),
        'production.application-template.ini': read_container(args.source, '/defaults/application.ini'),
        'production.default-template.json': read_container(args.source, '/defaults/default.json'),
        'production.nginx-template.conf': read_container(args.source, '/conf/nginx-webmail.conf'),
    }
    default_template = snapshots['production.default-template.json'].decode('utf-8')
    if '{{ FRONT_ADDRESS }}' not in default_template or '10143' not in default_template or '10025' not in default_template:
        raise ValueError('unsupported default domain template; expected original Mailu backend settings')
    application = candidate_application(snapshots['production.application.ini'].decode('utf-8'))
    nginx = candidate_nginx(snapshots['production.nginx-template.conf'].decode('utf-8'))
    policy = validate_policy(json.loads(Path(args.policy).read_text(encoding='utf-8'))
                             if args.policy else DEFAULT_POLICY)
    parent = Path(args.staging_parent).resolve(strict=True)
    if not parent.is_dir() or ',' in str(parent):
        raise ValueError('staging parent must be an existing directory without commas')
    root = Path(tempfile.mkdtemp(prefix='webmail-candidate-', dir=parent))
    os.chmod(root, 0o700)
    try:
        secrets = root / 'snapshots'
        secrets.mkdir(mode=0o700)
        for name, data in snapshots.items():
            atomic_write(secrets / name, data, mode=0o600)
        data_root = root / 'data'
        config = data_root / '_data_' / '_default_' / 'configs' / 'application.ini'
        atomic_write(config, application, mode=0o640)
        php_override = root / 'mail-control-upload.ini'
        configure(data_root, args.plugin_source, policy, php_override)
        templates = root / 'templates'
        # Startup renders these into the candidate data only. Original backend domain template stays unchanged.
        atomic_write(templates / 'application.ini', config.read_bytes(), mode=0o600)
        atomic_write(templates / 'default.json', snapshots['production.default-template.json'], mode=0o600)
        atomic_write(templates / 'nginx-webmail.conf', nginx, mode=0o600)
        env_file = root / 'candidate.env'
        atomic_write(env_file, ''.join(key + '=' + value + '\n' for key, value in sorted(env.items())), mode=0o600)
        overrides = root / 'overrides'
        overrides.mkdir(mode=0o700)
        manifest = dict(container=CANDIDATE, source_id=source['Id'], image=image,
                        network=network, root=str(root), data=str(data_root),
                        listen='127.0.0.1:' + PORT, version=EXPECTED_VERSION,
                        policy=policy, configuration_only=True,
                        candidate_plugins=['mail-control-upload'],
                        plugin_readonly=True,
                        snapshot_sha256={key: hashlib.sha256(value).hexdigest() for key, value in snapshots.items()})
        atomic_write(root / 'manifest.json', json.dumps(manifest, indent=2) + '\n', mode=0o600)
        plugin_directory = data_root / '_data_' / '_default_' / 'plugins' / 'mail-control-upload'
        # Snuffleupagus forbids both writable PHP and PHP owned by its runtime
        # process. Keep code root-owned/read-only and readable by the PHP user.
        # Mailu startup's recursive chown cannot alter this nested read-only mount.
        os.chown(plugin_directory, 0, 0)
        os.chmod(plugin_directory, 0o755)
        for plugin_file in plugin_directory.iterdir():
            if not plugin_file.is_file() or plugin_file.is_symlink():
                raise ValueError('unexpected file in isolated plugin directory')
            os.chown(plugin_file, 0, 0)
            os.chmod(plugin_file, 0o644)
        mounts = ((data_root, '/data'), (overrides, '/overrides'),
                  # Snuffleupagus readonly_exec requires plugin PHP to be on a
                  # read-only mount even though the surrounding /data is writable.
                  (plugin_directory, '/data/_data_/_default_/plugins/mail-control-upload'),
                  (templates / 'application.ini', '/defaults/application.ini'),
                  (templates / 'default.json', '/defaults/default.json'),
                  (templates / 'nginx-webmail.conf', '/conf/nginx-webmail.conf'),
                  (php_override, '/etc/php83/conf.d/zz-mail-control-upload.ini'))
        command = ['create', '--name', CANDIDATE, '--label', LABEL + '=' + str(root),
                   '--network', network, '--env-file', str(env_file), '--restart', 'no',
                   '--publish', '127.0.0.1:' + PORT + ':80', '--memory', '768m', '--cpus', '1',
                   '--pids-limit', '256', '--log-opt', 'max-size=5m', '--log-opt', 'max-file=2']
        # Mailu often uses its private resolver instead of Docker's default DNS.
        host_config = source.get('HostConfig', {})
        for key, option in (('Dns', '--dns'), ('DnsOptions', '--dns-option'),
                            ('DnsSearch', '--dns-search')):
            for value in host_config.get(key) or []:
                command += [option, str(value)]
        for host, target in mounts:
            command += ['--mount', 'type=bind,src=' + str(host) + ',dst=' + target + (',readonly' if target not in ('/data', '/overrides') else '')]
        command.append(image)
        docker(*command)
        docker('start', CANDIDATE)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            candidate = inspect(CANDIDATE)
            if not candidate.get('State', {}).get('Running'):
                raise RuntimeError('candidate stopped during startup; inspect its private Docker logs')
            response = docker('exec', CANDIDATE, 'curl', '--fail', '--silent',
                              '--max-time', '2', 'http://127.0.0.1/ping', allow_failure=True)
            if response.returncode == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('candidate startup timed out')
        docker('exec', CANDIDATE, 'nginx', '-t')
        docker('exec', CANDIDATE, 'php83', '-l',
               '/data/_data_/_default_/plugins/mail-control-upload/index.php')
        candidate = inspect(CANDIDATE)
        binding = candidate.get('NetworkSettings', {}).get('Ports', {}).get('80/tcp')
        if binding != [{'HostIp': '127.0.0.1', 'HostPort': PORT}]:
            raise RuntimeError('candidate port binding is not loopback-only')
        if candidate['Image'] != image:
            raise RuntimeError('candidate image differs from production image ID')
        plugin_mounts = [entry for entry in candidate.get('Mounts', [])
                         if entry.get('Destination') == '/data/_data_/_default_/plugins/mail-control-upload']
        if len(plugin_mounts) != 1 or plugin_mounts[0].get('RW') is not False:
            raise RuntimeError('candidate plugin mount must be read-only for Snuffleupagus')
        manifest['candidate_id'] = candidate['Id']
        manifest['ready'] = True
        atomic_write(root / 'manifest.json', json.dumps(manifest, indent=2) + '\n', mode=0o600)
        return {key: manifest[key] for key in ('container', 'image', 'network', 'root', 'listen', 'ready')}
    except Exception:
        safe_cleanup(root)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, help='Existing production SnappyMail container name or ID')
    parser.add_argument('--network', help='Required if source is attached to multiple networks')
    parser.add_argument('--staging-parent', default='/opt/mail-control/staging', help='Existing private host directory')
    parser.add_argument('--plugin-source', default=str(Path(__file__).resolve().parent.parent / 'webmail' / 'mail-control-upload'))
    parser.add_argument('--policy', help='Canonical upload-policy JSON file; values are never printed')
    args = parser.parse_args()
    try:
        result = stage(args)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print('Staging failed: ' + str(error), file=sys.stderr)
        return 1
    print(json.dumps(result))
    print('SSH tunnel: ssh -N -L 18888:127.0.0.1:18888 <server>')
    print('Preview: http://127.0.0.1:18888/ (use a dedicated test mailbox; production sessions are not copied)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
