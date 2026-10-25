#!/usr/bin/env python3
"""Submit actual Mailu password forms against the isolated loopback candidate.

No database writes, credential output, production URLs, or third-party requests.
Uses the candidate QA administrator, creates one random qa-short-* account by
the real new-user form, checks short/common passwords and negative cases, then
replaces the temporary weak password through the real password form.
"""
import argparse
from datetime import datetime, timezone
from html.parser import HTMLParser
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = 'http://127.0.0.1:18889'
PHASE = 'initializing'


def check_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.port != 18889 or parsed.username or parsed.password:
        raise ValueError('Only the isolated candidate at http://127.0.0.1:18889 is permitted')
    return url


class LocalRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        if code in {307, 308}:
            # Flask canonical routes may preserve POST. urllib otherwise rejects
            # these redirects instead of replaying the actual form submission.
            forwarded = {key:value for key,value in req.headers.items()
                         if key.lower() not in {'content-length', 'host'}}
            return urllib.request.Request(newurl, data=req.data, headers=forwarded,
                                          origin_req_host=req.origin_req_host,
                                          unverifiable=True, method=req.get_method())
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    http_error_307 = urllib.request.HTTPRedirectHandler.http_error_302
    http_error_308 = urllib.request.HTTPRedirectHandler.http_error_302


class Forms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.current = {'action':attrs.get('action', ''), 'fields':{}, 'names':set()}
            self.forms.append(self.current)
        elif tag == 'input' and self.current is not None and attrs.get('name'):
            name, kind = attrs['name'], attrs.get('type', 'text').lower()
            self.current['names'].add(name)
            if 'disabled' in attrs or kind in {'file','button','reset'}:
                return
            if kind in {'checkbox','radio'} and 'checked' not in attrs:
                return
            self.current['fields'][name] = attrs.get('value', 'y' if kind == 'checkbox' else '')

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None


class BrowserSession:
    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                    urllib.request.HTTPCookieProcessor(self.jar), LocalRedirect())

    def request(self, path, fields=None):
        url = check_url(urllib.parse.urljoin(BASE + '/', path))
        data = urllib.parse.urlencode(fields).encode() if fields is not None else None
        request = urllib.request.Request(url, data=data, headers={
            'User-Agent':'MailControlCandidatePasswordAcceptance',
            'Accept-Language':'en', 'Referer':url,
            **({'Content-Type':'application/x-www-form-urlencoded'} if data is not None else {})})
        try:
            with self.opener.open(request, timeout=25) as response:
                final = check_url(response.geturl())
                markup = response.read(4 * 1024 * 1024).decode('utf-8', 'replace')
                return final, markup
        except urllib.error.HTTPError as error:
            # Status and path diagnose canonical routing without response bodies,
            # POST data, query credentials, or session cookies.
            raise RuntimeError('HTTP ' + str(error.code) + ' at ' + urllib.parse.urlsplit(error.url).path) from None

    def form(self, path, required):
        url, markup = self.request(path)
        parser = Forms(); parser.feed(markup)
        matches = [form for form in parser.forms if set(required) <= form['names']]
        if len(matches) != 1:
            raise RuntimeError('Expected one candidate form for ' + urllib.parse.urlsplit(path).path)
        form = matches[0]
        action = check_url(urllib.parse.urljoin(url, form['action'] or url))
        return action, dict(form['fields'])

    def login(self, email, password, pwned='-1'):
        action, fields = self.form('/sso/login?noproxyauth=1', {'email','pw'})
        fields.update(email=email, pw=password, pwned=pwned, submitAdmin='Sign in')
        self.request(action, fields)
        final, markup = self.request('/admin/user/settings')
        if urllib.parse.urlsplit(final).path != '/admin/user/settings':
            raise RuntimeError('Candidate login did not reach authenticated settings')
        if 'data breaches!' in markup or 'This password is too short.' in markup:
            raise RuntimeError('Password policy warning remains after candidate login')
        return self

    def logout(self):
        self.request('/sso/logout')
        self.jar.clear()


def credentials(root):
    root = Path(root)
    if root.is_symlink():
        raise ValueError('Candidate root cannot be a symlink')
    resolved = root.resolve(strict=True)
    base = Path('/opt/mail-control-candidates').resolve(strict=True)
    if resolved.parent != base or not resolved.name.startswith('password-'):
        raise ValueError('Credentials must belong to a dedicated password candidate directory')
    path = resolved / 'credentials.json'
    if path.is_symlink() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError('Candidate credentials must be a private regular file')
    value = json.loads(path.read_text())
    if not value.get('localpart','').startswith('candidate-admin-') or value.get('email') != value.get('localpart') + '@' + value.get('domain',''):
        raise ValueError('Expected an isolated randomly named QA administrator')
    check_url(value['url'])
    return resolved, value


def write_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2); stream.write('\n')


def change_password(admin, email, password, confirmation=None, pwned='-1', expect_success=True):
    route = '/admin/user/password/' + urllib.parse.quote(email, safe='@')
    action, fields = admin.form(route, {'pw','pw2','csrf_token'})
    fields.update(pw=password, pw2=password if confirmation is None else confirmation, pwned=pwned)
    final, markup = admin.request(action, fields)
    successful = urllib.parse.urlsplit(final).path.startswith('/admin/user/list/')
    if successful != expect_success:
        raise RuntimeError('Candidate password form result did not match expected ' + ('acceptance' if expect_success else 'rejection'))
    if expect_success and ('data breaches!' in markup or 'This password is too short.' in markup):
        raise RuntimeError('Password form still reports a policy warning')


def accept(root):
    global PHASE
    PHASE = 'validate_candidate_credentials'
    root, qa = credentials(root)
    report = {'target':BASE, 'candidate_root':str(root), 'started_at':datetime.now(timezone.utc).isoformat(),
              'method':'actual HTTP form submission with CSRF and cookie sessions; no direct database writes',
              'checks':[], 'status':'running', 'production_touched':False}
    token = secrets.token_hex(5)
    account = 'qa-short-' + token + '@' + qa['domain']
    report['test_email'] = account
    PHASE = 'qa_admin_login'
    admin = BrowserSession().login(qa['email'], qa['password'])
    report['checks'].append('qa_admin_login')
    creation = '/admin/user/create/' + urllib.parse.quote(qa['domain'], safe='')
    PHASE = 'load_new_user_form'
    action, fields = admin.form(creation, {'localpart','pw','pw2','csrf_token'})
    fields.update(localpart=account.split('@')[0], pw='1', pw2='1', pwned='2',
                  displayed_name='Temporary Password Acceptance', comment='Candidate acceptance only ' + token,
                  enabled='y', enable_imap='y', enable_pop='y')
    fields.pop('change_pw_next_login', None)
    fields.pop('allow_spoofing', None)
    PHASE = 'submit_one_character_new_user_form'
    final, markup = admin.request(action, fields)
    if not urllib.parse.urlsplit(final).path.startswith('/admin/user/list/') or account not in markup:
        raise RuntimeError('Actual new-user form did not create the isolated short-password account')
    if 'data breaches!' in markup or 'This password is too short.' in markup:
        raise RuntimeError('New-user form still reports a policy warning')
    report['checks'].append('create_one_character_password_with_pwned_2')
    PHASE = 'one_character_password_login_and_logout'
    user = BrowserSession().login(account, '1', '2'); user.logout()
    report['checks'].append('one_character_password_login')
    # Form validation must retain required values and matching confirmation.
    PHASE = 'empty_password_rejection'
    change_password(admin, account, '', expect_success=False)
    report['checks'].append('empty_password_form_rejected')
    PHASE = 'mismatched_confirmation_rejection'
    change_password(admin, account, 'candidate-mismatch', confirmation='different', expect_success=False)
    report['checks'].append('mismatched_confirmation_rejected')
    PHASE = 'previous_password_preserved_after_rejection'
    user = BrowserSession().login(account, '1'); user.logout()
    report['checks'].append('negative_changes_preserved_previous_password')
    PHASE = 'common_password_form_acceptance'
    change_password(admin, account, 'password', pwned='2000000')
    report['checks'].append('common_password_with_pwned_2000000_accepted')
    PHASE = 'common_password_login_and_logout'
    user = BrowserSession().login(account, 'password', '2000000'); user.logout()
    report['checks'].append('common_password_login')
    # Retain the test account for browser-list verification, with no weak secret.
    final_password = secrets.token_urlsafe(32)
    PHASE = 'restore_random_test_account_password'
    change_password(admin, account, final_password)
    user = BrowserSession().login(account, final_password); user.logout()
    admin.logout()
    report['checks'].append('test_account_restored_to_random_password')
    PHASE = 'write_acceptance_receipt'
    write_private(root / ('acceptance-account-' + token + '.json'), {'email':account, 'password':final_password, 'candidate_only':True})
    report.update(status='passed-actual-http-forms', completed_at=datetime.now(timezone.utc).isoformat(),
                  browser_visual_review='Must be recorded separately; this tool does not claim a browser UI pass')
    receipt = root / ('password-acceptance-' + token + '.json')
    write_private(receipt, report)
    return {'status':report['status'], 'test_email':account, 'checks':report['checks'], 'receipt':str(receipt),
            'weak_password_remains':False, 'production_touched':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, help='Existing /opt/mail-control-candidates/password-* directory')
    args = parser.parse_args()
    try:
        print(json.dumps(accept(args.root), indent=2))
    except Exception as error:
        # Do not print response bodies, credential fields or request data.
        parser.exit(2, 'candidate form acceptance failed [' + PHASE + ']: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
