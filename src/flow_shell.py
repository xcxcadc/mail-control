"""Server-rendered shell for already-authorized mail-control tool pages."""

def flow_shell_identity(headers):
    trusted = headers.get('X-Mail-Control-Proxy-Secret', '')
    if CONFIG.proxy_secret and trusted and hmac.compare_digest(trusted, CONFIG.proxy_secret):
        return headers.get('X-Remote-User', '').strip().lower()
    value = headers.get('Authorization', '')
    if value.startswith('Basic '):
        try:
            return base64.b64decode(value[6:], validate=True).decode('utf-8').split(':', 1)[0].strip().lower()
        except (ValueError, UnicodeError):
            pass
    return ''


def flow_shell_display_name(username):
    if not username:
        return '管理员'
    # Match Mailu's existing displayed_name where the field is available. A
    # schema/version without that field simply uses the authenticated address.
    try:
        db_uri = 'file:' + urllib.parse.quote(str(CONFIG.db_path), safe='/:') + '?mode=ro'
        db = sqlite3.connect(db_uri, uri=True)
        try:
            columns = {row[1] for row in db.execute('PRAGMA table_info(user)')}
            name_column = next((name for name in ('displayed_name', 'display_name') if name in columns), None)
            if name_column:
                row = db.execute('SELECT "' + name_column + '" FROM user WHERE email = ?', (username,)).fetchone()
                if row and row[0] and str(row[0]).strip():
                    return str(row[0]).strip()
        finally:
            db.close()
    except (OSError, sqlite3.Error, AttributeError):
        pass
    return username


def flow_shell_markup(username, request_path='', request_query=''):
    root = '/admin/mail-control/'
    pathname = request_path or root
    if not pathname.startswith('/admin/'):
        pathname = root + pathname.lstrip('/')
    current = pathname.rstrip('/') or '/'
    query = urllib.parse.parse_qs(request_query)
    groups = (
        ('邮件工作台', (
            ('全局邮件查询', root + 'global/', 'fa-search'),
            ('邮件控制', root, 'fa-envelope'),
            ('自定义发件', root + 'custom-send/', 'fa-paper-plane'),
            ('批量邮箱', root + 'accounts/', 'fa-users'),
            ('邮件营销', root + 'marketing/', 'fa-bullhorn'),
            ('发件 API', root + 'marketing/?tab=api', 'fa-code'),
        )),
        ('我的账户', (
            ('设置', '/admin/user/settings', 'fa-wrench'),
            ('更新密码', '/admin/user/password', 'fa-lock'),
            ('自动回复', '/admin/user/reply', 'fa-plane'),
            ('认证令牌', '/admin/token/list', 'fa-ticket-alt'),
            ('客户端设置', '/admin/client', 'fa-laptop'),
        )),
        ('管理', (
            ('公告', '/admin/announcement', 'fa-bullhorn'),
            ('管理员', '/admin/admin/list', 'fa-user'),
            ('中继域', '/admin/relay', 'fa-reply-all'),
            ('反垃圾邮件', '/admin/antispam/', 'fa-trash-alt'),
            ('邮件域', '/admin/domain', 'fa-envelope'),
        )),
        ('转到', (
            ('网页邮箱', '/webmail', 'fa-envelope'),
            ('网站', 'https://mailu.io', 'fa-globe'),
            ('帮助', 'https://mailu.io', 'fa-life-ring'),
            ('登出', '/sso/logout', 'fa-sign-out-alt'),
        )),
    )
    def selected(href):
        target = urllib.parse.urlsplit(href)
        if target.scheme or target.netloc:
            return False
        target_path = target.path.rstrip('/') or '/'
        if target_path == (root + 'marketing').rstrip('/'):
            api = query.get('tab', [''])[0] == 'api'
            return current.startswith(target_path) and (api if target.query else not api)
        return current == target_path
    items = []
    for heading, links in groups:
        items.append('<li class="nav-header" role="none">' + heading + '</li>')
        for label, href, icon in links:
            active = selected(href)
            external = href.startswith('https://')
            attrs = (' aria-current="page"' if active else '') + (' target="_blank" rel="noreferrer noopener"' if external else '')
            items.append('<li class="nav-item" role="none"><a class="nav-link' + (' active' if active else '') + '" href="' + html.escape(href, quote=True) + '" role="menuitem"' + attrs + '><i class="nav-icon fas ' + icon + '" aria-hidden="true"></i><p>' + label + (' <i class="fas fa-external-link-alt text-xs" aria-hidden="true"></i>' if external else '') + '</p></a></li>')
    name = html.escape(flow_shell_display_name(username), quote=True)
    address = html.escape(username, quote=True)
    return ('<aside id="mail-control-side-nav" class="flow-server-sidebar flow-sidebar-surface" aria-label="Mailu 导航">'
            '<a class="brand-link" href="/admin/domain"><img class="brand-image" src="/static/mailu.png" width="25" height="25" alt=""><span class="brand-text">Mailu</span></a>'
            '<button id="flow-shell-close" class="flow-shell-close" type="button" aria-label="关闭导航">×</button>'
            '<div class="sidebar"><div class="user-panel" title="' + address + '"><div class="image"><div><i class="fas fa-user" aria-hidden="true"></i></div></div>'
            '<div class="info"><a href="/admin/user/settings">' + name + '</a></div></div>'
            '<nav><ul class="nav-sidebar" role="menu">' + ''.join(items) + '</ul></nav></div></aside>'
            '<button id="mail-control-nav-toggle" type="button" aria-label="打开导航" aria-controls="mail-control-side-nav" aria-expanded="false"><i class="fas fa-bars" aria-hidden="true"></i><span>Mailu</span></button>'
            '<button id="mail-control-nav-backdrop" type="button" aria-label="关闭导航" tabindex="-1"></button>'
            '<script>' + FLOW_UI_ASSETS['flow-shell.js'] + '</script>')
