#!/usr/bin/env python3
"""Build the deployable app and Nginx override from maintained source assets."""
import ast
import hashlib
import html
import pathlib
import re
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
HERE = ROOT / 'ui'
BASE = ROOT / 'src/mail_control.py'


def replace_constant(source, name, value):
    tree = ast.parse(source)
    node = next(n for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
    lines = source.splitlines(keepends=True)
    lines[node.lineno-1:node.end_lineno] = [name + ' = ' + repr(value) + '\n']
    return ''.join(lines)


def main():
    source = BASE.read_text(encoding='utf-8')
    assets = {name: (HERE / name).read_text(encoding='utf-8') for name in
              ('flow-tools.css', 'flow-tools.js', 'flow-admin.css', 'flow-admin.js', 'flow-sidebar.css', 'flow-surfaces.css', 'flow-surfaces.js', 'flow-bootstrap.js', 'flow-shell.css', 'flow-shell.js', 'flow-help.css', 'flow-help.js')}
    for name, value in assets.items():
        if name.endswith('.js') and '</script' in value.lower():
            raise ValueError('Unsafe script delimiter in ' + name)
    tree = ast.parse(source)
    nav = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == 'NAVIGATION_JS' for t in n.targets))
    nav = nav.replace('    shadow.appendChild(style);\n',
                      '    shadow.appendChild(style);\n'
                      '    var flowStyle = document.createElement("style");\n'
                      '    flowStyle.dataset.flowSidebar = "true";\n'
                      '    flowStyle.textContent = ' + repr(assets['flow-sidebar.css']) + ';\n'
                      '    shadow.appendChild(flowStyle);\n', 1)
    if 'flowStyle.textContent' not in nav:
        raise ValueError('Sidebar theme anchor missing')
    nav = nav.replace("if (location.pathname.indexOf(rootPath) !== 0) return;", "if (location.pathname.indexOf(rootPath) !== 0 && location.pathname.indexOf('/admin/antispam/') !== 0) return;")
    nav = nav.replace("var sidebar = document.querySelector('.sidebar');", "var sidebar = document.querySelector('.main-sidebar .sidebar');")
    # A Mailu wrapper may embed Rspamd. Its child frame must not mount a second
    # Mailu navigation or reserve another sidebar width.
    nav = nav.replace("    if (new URLSearchParams(location.search).get('embedded') === '1') return;", "    if (window.self !== window.top || new URLSearchParams(location.search).get('embedded') === '1') return;")
    nav = nav.replace("  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);", "  if (document.querySelector('.main-sidebar .sidebar') || document.querySelector('body > main') || document.getElementById('mainUI')) init();\n  else if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);")
    nav = nav.replace("var response = await fetch('/admin/domain', {cache: 'no-store', credentials: 'same-origin'});", "var response = await (window.flowNavigationResponse || fetch('/admin/domain', {cache: 'no-store', credentials: 'same-origin'}));\n    if (!response) response = await fetch('/admin/domain', {cache: 'no-store', credentials: 'same-origin'});")
    nav = nav.replace("body.mail-control-shell{margin-left:250px;min-width:0}", "body.mail-control-shell{margin-left:194px;min-width:0}").replace("width:250px;height:100dvh", "width:194px;height:100dvh")
    # Native theme CSS is already supplied to the main document. Re-fetching it
    # into every shadow shell adds latency and can briefly show framework colours.
    nav = nav.replace("      var url = new URL(link.getAttribute('href'), location.origin);", "      var url = new URL(link.getAttribute('href'), location.origin);\n      if (url.pathname.indexOf('/admin/mail-control/ui/') === 0) return;")
    nav = nav.replace("    var sidebar = source.cloneNode(true);", "    var sidebar = source.cloneNode(true);\n    sidebar.querySelectorAll('a[href]').forEach(function(link){\n      var url=new URL(link.getAttribute('href'),location.origin);\n      if(url.origin===location.origin && url.pathname.indexOf('/admin/antispam')===0){link.href='/admin/antispam/';link.removeAttribute('target');link.removeAttribute('data-clicked');}\n    });")
    nav_version = hashlib.sha256(nav.encode()).hexdigest()[:12]
    # Navigation code is static and checks only the menu already returned by
    # Mailu. Expose a signed-in asset copy for native non-admin users; no account
    # HTML or API response is placed in the asset map.
    assets['flow-navigation.js'] = nav
    source = replace_constant(source, 'NAVIGATION_JS', nav)
    constant = '\nFLOW_UI_ASSETS = ' + repr(assets) + '\nFLOW_NAVIGATION_VERSION = ' + repr(nav_version) + '\n\n'
    shell_helpers = (ROOT / 'src/flow_shell.py').read_text(encoding='utf-8')
    source = source.replace('def html_bytes(template, embedded=False):\n', constant + shell_helpers + '\n\ndef html_bytes(template, embedded=False, username="", request_path="", request_query=""):\n', 1)
    anchor = '    return template.encode("utf-8")\n'
    if source.count(anchor) != 1:
        raise ValueError('html return anchor missing')
    replacement = '''    # Theme the server-rendered body before any content can paint. The page
    # class also applies list/compose/etc. rules before asynchronous data arrives.
    page_class = next((name for marker, name in (
        ('id="rows"', 'flow-global'), ('id="compose"', 'flow-compose'),
        ('id="localparts"', 'flow-accounts'), ('id="api-form"', 'flow-api'),
        ('id="sender-domain"', 'flow-marketing-task'), ('id="task-list"', 'flow-marketing-list'),
        ('id="tab-campaigns"', 'flow-marketing-manage'), ('id="message-modal"', 'flow-control'),
        ('id="subject"', 'flow-view')) if marker in template), '')
    classes = 'flow-tools ' + page_class + (' embedded' if embedded else ' mail-control-shell')
    template = template.replace('<body class="embedded">', '<body class="' + classes + '">', 1) if embedded else template.replace('<body>', '<body class="' + classes + '">', 1)
    preload = '<script>if(self!==top)document.documentElement.classList.add("flow-embedded-surface");</script>'
    theme_css = FLOW_UI_ASSETS["flow-tools.css"] + FLOW_UI_ASSETS['flow-help.css'] + ('' if embedded else FLOW_UI_ASSETS['flow-shell.css'])
    template = template.replace("</head>", "<style>" + theme_css + "</style>" + preload + "</head>", 1)
    if not embedded:
        body_start = template.index('>', template.index('<body')) + 1
        template = template[:body_start] + flow_shell_markup(username, request_path, request_query) + template[body_start:]
    # Dialog markup follows main on some pages. Run after it has parsed but
    # before the existing page script starts requests and handlers.
    theme_pos = template.find('<script', template.index('</main>') + len('</main>'))
    theme_script = '<script>' + FLOW_UI_ASSETS['flow-tools.js'] + '</script><script>' + FLOW_UI_ASSETS['flow-help.js'] + '</script>'
    template = template[:theme_pos] + theme_script + template[theme_pos:] if theme_pos >= 0 else template.replace('</body>', theme_script + '</body>', 1)
    template = template.replace('<script defer src="/admin/mail-control/navigation.js"></script>', '', 1)
    template = template.replace("</body>", "<script>" + FLOW_UI_ASSETS["flow-admin.js"] + "</script></body>", 1)
    return template.encode("utf-8")
'''
    source = source.replace(anchor, replacement, 1)
    anchor = '        if not self.require_auth():\n            return\n        try:\n            if parsed.path == "/navigation.js":\n'
    replacement = '''        # These fixed assets contain only theme code. The front proxy still requires
        # a signed-in Mailu user; all mail, settings and API routes retain their guards.
        def send_theme_asset(body, content_type):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "private, max-age=86400" if "v" in query else "private, max-age=300")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        if parsed.path.startswith("/ui/"):
            name = parsed.path[4:]
            if name in FLOW_UI_ASSETS:
                content_type = "text/css; charset=utf-8" if name.endswith(".css") else "application/javascript; charset=utf-8"
                body = FLOW_UI_ASSETS[name].encode("utf-8")
                # Assets are versioned by content digest, include no user data,
                # and remain behind the front proxy's existing login check.
                send_theme_asset(body, content_type)
            else:
                self.send_json({"error": "不存在的资源"}, HTTPStatus.NOT_FOUND)
            return
        if not self.require_auth():
            return
        try:
            if parsed.path == "/navigation.js":
'''
    if source.count(anchor) != 1:
        raise ValueError('GET anchor missing')
    source = source.replace(anchor, replacement, 1)
    source = source.replace('self.send_content(NAVIGATION_JS.encode("utf-8"), "application/javascript; charset=utf-8")', 'send_theme_asset(NAVIGATION_JS.encode("utf-8"), "application/javascript; charset=utf-8")', 1)
    source = source.replace('''            if parsed.path == "/navigation.js":
''', '''            if parsed.path == "/sidebar":
                fragment = '<style>' + FLOW_UI_ASSETS['flow-shell.css'] + '</style>' + flow_shell_markup(flow_shell_identity(self.headers), query.get('request_path', ['/admin/antispam/'])[0], '')
                self.send_content(fragment.encode('utf-8'), 'text/html; charset=utf-8')
            elif parsed.path == "/navigation.js":
''', 1)
    source, html_hooks = re.subn(r'(body = html_bytes\([^\n]+query.get\("embedded", \["0"\]\)\[0\] == "1")\)', r'\1, username=flow_shell_identity(self.headers), request_path=parsed.path, request_query=parsed.query)', source)
    if html_hooks != 8:
        raise ValueError('Unexpected HTML response hooks: ' + str(html_hooks))
    compile(source, 'mail_control.flow.py', 'exec')
    # Compare all original functions and methods except the two deliberate UI hooks.
    old = ast.parse(BASE.read_text(encoding='utf-8'))
    new = ast.parse(source)
    for before in old.body:
        if isinstance(before, (ast.FunctionDef, ast.AsyncFunctionDef)) and before.name != 'html_bytes':
            after = next(n for n in new.body if type(n) == type(before) and n.name == before.name)
            assert ast.dump(before) == ast.dump(after), before.name
        elif isinstance(before, ast.ClassDef):
            after = next(n for n in new.body if isinstance(n, ast.ClassDef) and n.name == before.name)
            for method in before.body:
                if isinstance(method, ast.FunctionDef) and not (before.name == 'Handler' and method.name == 'do_GET'):
                    newer = next(n for n in after.body if isinstance(n, ast.FunctionDef) and n.name == method.name)
                    assert ast.dump(method) == ast.dump(newer), before.name + '.' + method.name
    (ROOT / 'mail_control.py').write_text(source, encoding='utf-8', newline='\n')

    conf = (ROOT / 'nginx/mail-control-admin.base.conf').read_text(encoding='utf-8')
    conf = re.sub(r'^    sub_filter "</body>".*\n', '', conf, flags=re.MULTILINE)
    def asset_url(name):
        return '/admin/mail-control/ui/' + name + '?v=' + hashlib.sha256(assets[name].encode()).hexdigest()[:12]
    head = '<link rel="stylesheet" href="' + asset_url('flow-admin.css') + '"><link data-flow-native-sidebar="true" rel="stylesheet" href="' + asset_url('flow-sidebar.css') + '"><link rel="stylesheet" href="' + asset_url('flow-help.css') + '"><script>' + assets['flow-bootstrap.js'] + '</script></head>'
    nav_url = '/admin/mail-control/navigation.js?v=' + nav_version
    # Fixed theme scripts contain no account data. Keep them as authenticated
    # assets so Nginx replacement stays a single-line, syntax-safe directive.
    body = '<script src="' + asset_url('flow-navigation.js') + '"></script><script src="' + asset_url('flow-admin.js') + '"></script><script defer src="' + asset_url('flow-help.js') + '"></script></body>'
    def quote(value):
        return value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')
    theme_filters = '    proxy_set_header Accept-Encoding "";\n    sub_filter_once on;\n    sub_filter "</head>" "' + quote(head) + '";\n'
    for marker in ('location = /admin/client {', 'location ^~ /admin/ {'):
        start = conf.index(marker)
        end = conf.index('\n}', start)
        block = conf[start:end]
        block = re.sub(r'^    (proxy_set_header Accept-Encoding|sub_filter_once).*(?:\n|$)', '', block, flags=re.MULTILINE)
        block += '\n' + theme_filters.rstrip('\n')
        block += '\n    sub_filter \'<body class="\' \'<body class="mailu-flow-admin \';'
        block += '\n    sub_filter \'<aside class="main-sidebar\' \'<aside class="flow-sidebar-surface main-sidebar\';'
        block += '\n    sub_filter \'href="/admin/antispam/" data-clicked="/admin/webui_antispam" target="_blank"\' \'href="/admin/antispam/"\';'
        block += '\n    sub_filter "' + quote('<script src="/static/vendor.js"></script>') + '" "' + quote(body.replace('</body>', '') + '<script src="/static/vendor.js"></script>') + '";'
        block += '\n    sub_filter \'lang="None"\' \'lang="en"\';\n    sub_filter \'>None</span>\' \'>en</span>\';'
        conf = conf[:start] + block + conf[end:]
    head_surface = '<link rel="stylesheet" href="' + asset_url('flow-surfaces.css') + '"><link rel="stylesheet" href="' + asset_url('flow-shell.css') + '"><link rel="stylesheet" href="' + asset_url('flow-help.css') + '"><script>' + assets['flow-bootstrap.js'] + '</script></head>'
    # Rspamd's Bootstrap jQuery plugins register at DOMContentLoaded. Theme
    # scripts must not hold that event behind a slow network navigation asset.
    body_surface = '<script async src="' + asset_url('flow-admin.js') + '"></script><script async src="' + asset_url('flow-help.js') + '"></script></body>'
    # The production Mailu auth handler permits this upstream only when the
    # current user is enabled and global_admin. The same fixed navigation is
    # therefore valid here; no account HTML is fetched/cached in the browser.
    shell_namespace = {'html': html, 'urllib': __import__('urllib'), 'FLOW_UI_ASSETS': assets}
    exec(compile(shell_helpers, '<Rspamd shell builder>', 'exec'), shell_namespace)
    rspamd_shell = shell_namespace['flow_shell_markup']('', '/admin/antispam/', '').replace('<script>' + assets['flow-shell.js'] + '</script>', '<script src="' + asset_url('flow-shell.js') + '"></script>')
    # Keep the first-frame Nginx replacement below its 4 KiB argument limit.
    # The native shell CSS already styles these structural elements, so omit
    # redundant ARIA roles and per-item wrapper classes from this static menu.
    rspamd_shell = re.sub(r'\s(?:role="(?:none|menuitem)"|aria-hidden="true")', '', rspamd_shell)
    rspamd_shell = rspamd_shell.replace(' class="nav-item"', '')
    marker = 'location ^~ /admin/antispam/ {'
    start = conf.index(marker)
    end = conf.index('\n}', start)
    conf = conf[:end] + '\n    sub_filter "</head>" "' + quote(head_surface) + '";\n    sub_filter "<body>" "' + quote('<body>' + rspamd_shell) + '";\n    sub_filter "</body>" "' + quote(body_surface) + '";' + conf[end:]
    # Only these Rspamd directories contain code/images. Authenticated /stat,
    # /neighbours and all other controller responses retain their upstream policy.
    for static_dir in ('js', 'css', 'fonts', 'img'):
        conf += '\nlocation ^~ /admin/antispam/' + static_dir + '/ {\n' + '''    # Set the cache variable before rewrite break ends this rewrite phase.
    set $flow_rspamd_asset_cache "no-store";
    if ($request_method ~ ^(GET|HEAD)$) {
        set $flow_rspamd_asset_cache "private, max-age=86400";
    }
    if ($uri !~* \\.(js|css|woff2?|ttf|otf|svg|png|jpe?g|gif|ico)$) {
        set $flow_rspamd_asset_cache "no-store";
    }
    rewrite ^/admin/antispam/(.*) /$1 break;
    auth_request /internal/auth/admin;
    error_page 401 403 = @sso_login;
    proxy_set_header X-Real-IP "";
    proxy_set_header X-Forwarded-For "";
    proxy_set_header X-Forwarded-By "";
    proxy_pass http://$antispam;
    proxy_hide_header Cache-Control;
    proxy_hide_header Pragma;
    proxy_hide_header Expires;
    add_header Cache-Control $flow_rspamd_asset_cache;
}\n'''
    conf += '''

# Existing SnappyMail upstream and authentication, with theme-only response filters.
location ^~ /webmail/ {
    rewrite ^/webmail/(.*) /$1 break;
    include /etc/nginx/proxy.conf;
    auth_request /internal/auth/user;
    error_page 403 @sso_login;
    proxy_pass http://$webmail;
    proxy_set_header Accept-Encoding "";
    sub_filter_once on;
    sub_filter "</head>" "<link rel=\\"stylesheet\\" href=\\"/admin/mail-control/ui/flow-surfaces.css?v=20261013\\"></head>";
}
location = /webmail/sso.php {
    rewrite ^/webmail/(.*) /$1 break;
    include /etc/nginx/proxy.conf;
    auth_request /internal/auth/user;
    auth_request_set $user $upstream_http_x_user;
    auth_request_set $token $upstream_http_x_user_token;
    proxy_set_header X-Remote-User $user;
    proxy_set_header X-Remote-User-Token $token;
    error_page 403 @sso_login;
    proxy_pass http://$webmail;
}
# A missing locale in the original UI previously requested a nonexistent file.
location = /static/None.json {
    rewrite ^ /static/en.json break;
    include /etc/nginx/proxy.conf;
    proxy_pass http://$admin;
}
'''
    conf = conf.replace('/admin/mail-control/ui/flow-surfaces.css?v=20261013', asset_url('flow-surfaces.css'))
    (ROOT / 'nginx/mail-control-admin.conf').write_text(conf, encoding='utf-8', newline='\n')
    print('Flow integration compiles; original business functions and methods unchanged.')


if __name__ == '__main__':
    main()
