#!/usr/bin/env python3
"""Prepare/start an isolated Mailu admin for real password-form acceptance.

Run on the Docker host. No SSH, production writes, container restarts, or public
port exposure. The only new account is written to a private SQLite backup.
Default is prepare-only; --start creates one uniquely named candidate container.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import time
import urllib.parse


BOOTSTRAP = r'''import ipaddress, json, socket, sys
sys.path.insert(0, '/app')
from pathlib import Path

# Fail closed for accidental mail, Redis, webhook, or other outbound requests.
# Gunicorn receives traffic but this process cannot initiate TCP connections.
def denied_connect(*args, **kwargs):
    raise OSError('Candidate admin outbound connections are disabled')
socket.socket.connect = denied_connect
socket.socket.connect_ex = denied_connect
socket.create_connection = denied_connect

from mailu import create_app, models
app = create_app()
app.config.update(SESSION_COOKIE_NAME='mail_control_candidate', SESSION_COOKIE_SECURE=False)
credentials = json.loads(Path('/candidate/credentials.json').read_text())
with app.app_context():
    domain = models.Domain.query.get(credentials['domain'])
    if domain is None:
        raise RuntimeError('QA domain must already exist in the copied candidate database')
    if models.User.query.get(credentials['email']) is not None:
        raise RuntimeError('Candidate QA account already exists; do not overwrite')
    user = models.User(localpart=credentials['localpart'], domain=domain,
                       global_admin=True, enabled=True, change_pw_next_login=False,
                       displayed_name='Mail Control Candidate QA')
    user.set_password(credentials['password'], keep_sessions=True)
    models.db.session.add(user)
    models.db.session.commit()
del credentials

# Deny mail-affecting operations even though outbound TCP is already blocked.
@app.before_request
def candidate_write_scope():
    import flask
    if flask.request.method in {'POST','PUT','PATCH','DELETE'}:
        allowed = ('/sso/login', '/sso/pw_change', '/sso/logout',
                   '/admin/user/create/', '/admin/user/edit/',
                   '/admin/user/password', '/admin/language')
        if not flask.request.path.startswith(allowed):
            flask.abort(403)

from gunicorn.app.base import BaseApplication
class Candidate(BaseApplication):
    def load_config(self):
        for key, value in {'bind':'0.0.0.0:80','workers':1,'threads':1,
                           'accesslog':None,'errorlog':'-','preload_app':True,
                           'worker_tmp_dir':'/tmp','timeout':60}.items():
            self.cfg.set(key, value)
    def load(self):
        return app
Candidate().run()
'''


def docker(*arguments):
    result = subprocess.run(['docker', *arguments], text=True, capture_output=True)
    if result.returncode:
        # Do not echo an environment, command, credential, or arbitrary logs.
        raise RuntimeError('Docker command failed: ' + arguments[0])
    return result.stdout


def private_write(path, content, mode=0o600):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
        stream.write(content)
    os.chmod(path, mode)


def resolve_database(info, env, explicit):
    data_mounts = [item for item in info.get('Mounts', []) if item.get('Destination') == '/data']
    if len(data_mounts) != 1:
        raise ValueError('Expected one production /data mount')
    root = Path(data_mounts[0]['Source']).resolve(strict=True)
    if explicit:
        source = Path(explicit).resolve(strict=True)
    else:
        uri = env.get('SQLALCHEMY_DATABASE_URI', 'sqlite:////data/main.db')
        if not uri.startswith('sqlite:///'):
            raise ValueError('Only SQLite production databases are supported')
        relative = uri[len('sqlite:///'):]
        if not relative.startswith('/data/'):
            configured = env.get('SQLITE_DATABASE_FILE', '/data/main.db')
            relative = '/' + configured.lstrip('/')
        if not relative.startswith('/data/'):
            raise ValueError('Database is not under the production /data mount; pass --source-db')
        source = (root / relative[len('/data/'):]).resolve(strict=True)
    if not source.is_file() or root not in source.parents:
        raise ValueError('Source database must be a regular file within the production /data mount')
    return source


def stage(args):
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Run on the Linux Docker host as root')
    info = json.loads(docker('inspect', args.production))[0]
    env = dict(value.split('=', 1) for value in info['Config'].get('Env', []) if '=' in value)
    source = resolve_database(info, env, args.source_db)
    patch = Path(args.patched_utils).resolve(strict=True)
    if patch.is_symlink() or not patch.is_file():
        raise ValueError('Patched utils must be a regular file')
    from configure_password_policy import patch_source
    prepared, changed = patch_source(patch.read_text(encoding='utf-8'))
    if changed:
        raise ValueError('Provided utils.py does not yet contain the non-empty policy')
    networks = info.get('NetworkSettings', {}).get('Networks', {})
    network = args.network or (next(iter(networks)) if len(networks) == 1 else None)
    if not network or network not in networks:
        raise ValueError('Choose --network from the production admin networks')
    root = Path(args.root).absolute()
    if root.exists() or root.is_symlink():
        raise ValueError('Candidate root already exists; choose a new unique directory')
    for ancestor in (root.parent, *root.parent.parents):
        if ancestor.is_symlink():
            raise ValueError('Candidate root cannot contain symlink directories')
    production_roots = [Path(item['Source']).resolve() for item in info.get('Mounts', [])
                        if item.get('Source') and Path(item['Source']).exists()]
    if any(root == item or item in root.parents for item in production_roots):
        raise ValueError('Candidate root must not be inside any production mounted path')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{1,80}', args.name):
        raise ValueError('Invalid candidate container name')
    # Avoid creating a directory and sensitive snapshot if the port is occupied.
    import socket
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', args.port))
    root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.mkdir(mode=0o700)
    data = root / 'data'; data.mkdir(mode=0o700)
    (root / 'dkim').mkdir(mode=0o700)
    target = data / 'main.db'
    uri = 'file:' + urllib.parse.quote(str(source), safe='/') + '?mode=ro'
    with sqlite3.connect(uri, uri=True) as src, sqlite3.connect(target) as dst:
        src.backup(dst)
    os.chmod(target, 0o600)
    qa_id = secrets.token_hex(5)
    qa_domain = args.qa_domain.strip().lower()
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', qa_domain) or '.' not in qa_domain:
        raise ValueError('QA domain must be a valid existing production domain')
    with sqlite3.connect(target) as candidate_db:
        if not candidate_db.execute('SELECT 1 FROM domain WHERE name=?', (qa_domain,)).fetchone():
            raise ValueError('QA domain does not exist in the copied database')
    qa_localpart = 'candidate-admin-' + qa_id
    credentials = {'email': qa_localpart + '@' + qa_domain, 'localpart':qa_localpart,
                   'domain':qa_domain, 'password':secrets.token_urlsafe(28),
                   'url':'http://127.0.0.1:' + str(args.port) + '/sso/login?noproxyauth=1',
                   'container':args.name}
    private_write(root / 'credentials.json', json.dumps(credentials, indent=2) + '\n')
    private_write(root / 'bootstrap.py', BOOTSTRAP)
    private_write(root / 'utils.py', prepared, 0o644)
    # Copy runtime settings, never production writable volumes or SECRET_* files.
    env = {key:value for key,value in env.items() if not key.endswith('_FILE')
           and not key.startswith('INITIAL_ADMIN_')}
    for key in list(env):
        if key.endswith('_ADDRESS'):
            env[key] = '127.0.0.1'
    env.update(SECRET_KEY=secrets.token_urlsafe(48), SECRET='', MEMORY_SESSIONS='True',
               RATELIMIT_STORAGE_URL='memory://', SESSION_COOKIE_SECURE='False',
               DB_FLAVOR='', SQLITE_DATABASE_FILE='/data/main.db',
               SQLALCHEMY_DATABASE_URI='sqlite:////data/main.db',
               DOMAIN=qa_domain, HOSTNAMES='localhost', TLS_FLAVOR='notls',
               WEB_ADMIN='/admin', WEBMAIL='none', WEB_WEBMAIL='/webmail',
               WELCOME='False', FETCHMAIL_ENABLED='False', DISABLE_STATISTICS='True',
               API='False', API_TOKEN='', DOMAIN_REGISTRATION='False',
               RECAPTCHA_PUBLIC_KEY='', RECAPTCHA_PRIVATE_KEY='',
               PROXY_AUTH_WHITELIST='', PROXY_AUTH_HEADER='X-Candidate-Disabled-Auth',
               PROXY_AUTH_CREATE='False', AUTH_REQUIRE_TOKENS='False',
               LOG_LEVEL='WARNING', DKIM_PATH='/dkim/{domain}.{selector}.key')
    if any('\n' in key or '\r' in key or '\n' in value or '\r' in value for key,value in env.items()):
        raise ValueError('Multiline environment values are unsupported')
    private_write(root / 'candidate.env', ''.join(key + '=' + value + '\n' for key,value in sorted(env.items())))
    create = ['create','--name',args.name,'--label','mail-control.candidate=password-policy',
              '--network',network,'--publish','127.0.0.1:' + str(args.port) + ':80',
              '--restart','no','--read-only','--cap-drop','ALL',
              '--security-opt','no-new-privileges','--tmpfs','/tmp:rw,nosuid,nodev,size=64m',
              '--tmpfs','/run:rw,nosuid,nodev,size=16m',
              '--env-file',str(root / 'candidate.env'), '--workdir',info['Config'].get('WorkingDir') or '/app',
              '--mount','type=bind,src=' + str(data) + ',dst=/data',
              '--mount','type=bind,src=' + str(root / 'dkim') + ',dst=/dkim',
              '--mount','type=bind,src=' + str(root) + ',dst=/candidate,readonly',
              '--mount','type=bind,src=' + str(root / 'utils.py') + ',dst=' + args.utils_target + ',readonly',
              '--entrypoint',args.python, info['Image'], '/candidate/bootstrap.py']
    report = {'status':'prepared','candidate_root':str(root),'credentials_file':str(root / 'credentials.json'),
              'container':args.name,'url':credentials['url'],'image_id':info['Image'],
              'source_database_read_only':str(source),'candidate_database':str(target),
              'patched_utils_sha256':hashlib.sha256(prepared.encode()).hexdigest(),
              'production_containers_modified':False, 'outbound_connections':'disabled in candidate Python process'}
    private_write(root / 'create-arguments.json', json.dumps(create, indent=2) + '\n')
    if args.start:
        docker(*create)
        docker('start', args.name)
        report['status'] = 'started-not-yet-browser-verified'
    private_write(root / 'stage-report.json', json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--production', default='mailu-admin-1')
    parser.add_argument('--source-db', help='Explicit database path within production /data mount')
    parser.add_argument('--qa-domain', default='99765.my.id', help='Existing domain in the copied candidate database; no production domain writes')
    parser.add_argument('--patched-utils', required=True)
    parser.add_argument('--utils-target', default='/app/mailu/utils.py')
    parser.add_argument('--python', default='python3')
    parser.add_argument('--network')
    parser.add_argument('--port', type=int, default=18889)
    parser.add_argument('--name', default='mail-control-password-candidate')
    parser.add_argument('--root', default='/opt/mail-control-candidates/password-' + time.strftime('%Y%m%d-%H%M%S'))
    parser.add_argument('--start', action='store_true', help='Create and start only the new candidate container')
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('--port must be 1024–65535')
    try:
        print(json.dumps(stage(args), indent=2))
    except Exception as error:
        parser.exit(2, 'candidate staging failed: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
