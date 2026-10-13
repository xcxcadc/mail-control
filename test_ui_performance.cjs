// Tools must render complete navigation in their first content frame. Rspamd
// keeps its authenticated upstream page with a shell injected at body parsing.
// Generated pages and real theme code, with every browser request handled locally.
// No production account, SMTP connection, or mailbox is used by this test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {spawnSync} = require('node:child_process');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const templateNames = ['HTML', 'GLOBAL_HTML', 'CUSTOM_SEND_HTML', 'ACCOUNTS_HTML',
  'API_HTML', 'MARKETING_LIST_HTML', 'MARKETING_TASK_HTML', 'MARKETING_HTML', 'VIEW_HTML'];
const toolPages = [
  {name: 'HTML', route: ''}, {name: 'GLOBAL_HTML', route: 'global/'},
  {name: 'CUSTOM_SEND_HTML', route: 'custom-send/'}, {name: 'ACCOUNTS_HTML', route: 'accounts/'},
  {name: 'API_HTML', route: 'marketing/?tab=api'}, {name: 'MARKETING_LIST_HTML', route: 'marketing/'},
  {name: 'MARKETING_TASK_HTML', route: 'marketing/task/'}, {name: 'MARKETING_HTML', route: 'marketing/?tab=templates'},
  {name: 'VIEW_HTML', route: 'view?mailbox=support%40example.com&path=new%2Ffixture'},
];
const exported = spawnSync(process.env.PYTHON || 'python', ['-c', [
  'import json,tempfile,pathlib,mail_control as m',
  'fixture=tempfile.TemporaryDirectory()',
  'm.CONFIG.db_path=pathlib.Path(fixture.name)/"fixture.db"',
  `specs=${JSON.stringify(toolPages)}`,
  'from urllib.parse import urlsplit',
  'render=lambda s,embedded: m.html_bytes(getattr(m,s["name"]),embedded,username="admin@example.com",request_path="/admin/mail-control/"+urlsplit(s["route"]).path,request_query=urlsplit(s["route"]).query).decode()',
  'print(json.dumps({"pages":{s["name"]:render(s,False) for s in specs},"embeddedPages":{s["name"]:render(s,True) for s in specs},"assets":m.FLOW_UI_ASSETS,"navigation":m.NAVIGATION_JS}))',
].join(';')], {cwd: __dirname, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024});
assert.equal(exported.status, 0, exported.stderr);
const {pages, embeddedPages, assets, navigation} = JSON.parse(exported.stdout);

function rspamdProxyFilters() {
  const config = fs.readFileSync(path.join(__dirname, 'nginx/mail-control-admin.conf'), 'utf8');
  const start = config.indexOf('location ^~ /admin/antispam/ {');
  assert.notEqual(start, -1, 'Rspamd location exists in the generated Nginx configuration');
  const end = config.indexOf('\nlocation ^~ /admin/ {', start);
  assert.notEqual(end, -1, 'Rspamd location ends before the native admin location');
  const block = config.slice(start, end);
  assert.match(block, /auth_request \/internal\/auth\/admin;/, 'Rspamd retains administrator authentication');
  assert.doesNotMatch(block, /\bssi\s+on;|include\s+virtual/i, 'Rspamd rendering does not rely on SSI');
  const directives = [...block.matchAll(/^\s*sub_filter\s+("(?:\\.|[^"\\])*")\s+("(?:\\.|[^"\\])*");\s*$/gm)];
  const unquote = value => value.slice(1, -1).replace(/\\(["\\$])/g, '$1');
  const filters = directives.map(match => ({source: unquote(match[1]), replacement: unquote(match[2])}));
  for (const source of ['</head>', '<body>', '</body>']) {
    assert.ok(filters.some(filter => filter.source === source), 'generated Rspamd config has a real ' + source + ' filter');
  }
  return upstream => filters.reduce((html, filter) => {
    assert.ok(html.includes(filter.source), 'fixture includes actual sub_filter target ' + filter.source);
    return html.replace(filter.source, filter.replacement);
  }, upstream);
}
const applyRspamdFilters = rspamdProxyFilters();
for (const [name, html] of [...Object.entries(pages), ...Object.entries(embeddedPages)]) {
  for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
    new vm.Script(match[1], {filename: name + '.inline.js'});
  }
}
for (const [name, source] of Object.entries(assets)) {
  if (name.endsWith('.js')) new vm.Script(source, {filename: name});
}
new vm.Script(navigation, {filename: 'navigation.js'});

const origin = 'http://mail-control.test';
const basePath = '/admin/mail-control/';
const requiredLinks = ['', 'global/', 'custom-send/', 'accounts/', 'marketing/', 'marketing/?tab=api']
  .map(route => basePath + route).concat(['/admin/domain', '/admin/admin/list', '/admin/antispam/']);
const fixtureMessage = {subject: 'Detail test', from: 'sender@example.net',
  to: 'support@example.com', cc: '', date: '2026-10-13', text: 'Plain fixture body',
  html: '<p>Complete fixture body</p>', attachments: []};
const globalRow = {mailbox: 'support@example.com', id: 'fixture', folder: 'INBOX',
  unread: true, received_at: 1791849600, size: 100, ...fixtureMessage};
const adminDocument = `<!doctype html><html><head><meta charset="utf-8">
  <link rel="stylesheet" href="/static/vendor.css">
  <link rel="stylesheet" href="${basePath}ui/flow-admin.css">
  <link data-flow-native-sidebar="true" rel="stylesheet" href="${basePath}ui/flow-sidebar.css">
  <script>${assets['flow-bootstrap.js']}</script></head>
  <body class="mailu-flow-admin"><aside class="flow-sidebar-surface main-sidebar"><div class="sidebar">
  <ul class="nav-sidebar"><li class="nav-item"><a class="nav-link" href="/admin/admin/list">管理员</a></li>
  <li class="nav-item"><a class="nav-link" href="/admin/domain">域名</a></li>
  <li class="nav-item"><a class="nav-link" href="/admin/antispam/" data-clicked="/admin/webui_antispam" target="_blank">反垃圾邮件</a></li></ul>
  </div></aside><main>Local admin fixture</main>
  <script src="${basePath}ui/flow-navigation.js"></script>
  <script src="${basePath}ui/flow-admin.js"></script></body></html>`;
const rspamdUpstream = `<!doctype html><html><head><meta charset="utf-8">
  <link rel="stylesheet" href="css/main.css"></head>
  <body><div id="mainUI"><nav id="navBar">Rspamd fixture</nav></div>
  <script src="js/main.js"></script></body></html>`;
const rspamdDocument = applyRspamdFilters(rspamdUpstream);

function templateFor(url) {
  const route = url.pathname.slice(basePath.length).replace(/\/$/, '');
  if (!route) return 'HTML';
  if (route === 'global') return 'GLOBAL_HTML';
  if (route === 'custom-send') return 'CUSTOM_SEND_HTML';
  if (route === 'accounts') return 'ACCOUNTS_HTML';
  if (route === 'view') return 'VIEW_HTML';
  if (route === 'marketing/task') return 'MARKETING_TASK_HTML';
  if (route === 'marketing') {
    const tab = url.searchParams.get('tab');
    return tab === 'api' ? 'API_HTML' : ['templates', 'contacts'].includes(tab) ? 'MARKETING_HTML' : 'MARKETING_LIST_HTML';
  }
}

async function afterPaint(page) {
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
}

async function assertNoOldMenuFrames(page) {
  assert.equal(await page.locator('#mail-control-rspamd-panel, #mail-control-rspamd-nav, iframe[data-menu], iframe[src*="embedded=1"]').count(), 0,
    'tools must use document navigation instead of the old embedded menu');
  assert.equal(await page.locator('#mail-control-side-nav').count(), 1, 'one standalone navigation shell');
}

function recordFirstContentFrame() {
  window.__firstMainFrame = null;
  function inspect() {
    const main = document.querySelector('body > main, body > #mainUI');
    const mainRect = main && main.getBoundingClientRect();
    if (!main || !main.textContent.trim() || !mainRect.width || !mainRect.height) {
      requestAnimationFrame(inspect);
      return;
    }
    const hosts = document.querySelectorAll('#mail-control-side-nav');
    const host = hosts[0];
    const surface = host && (host.shadowRoot || host);
    const links = surface ? [...surface.querySelectorAll('a[href]')].map(link => {
      const url = new URL(link.getAttribute('href'), location.href);
      return url.pathname + url.search;
    }) : [];
    const activeLinks = surface ? [...surface.querySelectorAll('a[aria-current="page"], a.active')].map(link => {
      const url = new URL(link.getAttribute('href'), location.href);
      return url.pathname + url.search;
    }) : [];
    const rect = host && host.getBoundingClientRect();
    const toggle = document.getElementById('mail-control-nav-toggle');
    const toggleRect = toggle && toggle.getBoundingClientRect();
    window.__firstMainFrame = {atMs: performance.now(), mainWidth: mainRect.width,
      mainHeight: mainRect.height, sidebarCount: hosts.length, linkCount: links.length, links, activeLinks,
      sidebarWidth: rect?.width || 0, sidebarHeight: rect?.height || 0,
      toggleWidth: toggleRect?.width || 0, toggleHeight: toggleRect?.height || 0,
      toggleEnabled: !!toggle && !toggle.disabled,
      apiResponses: performance.getEntriesByType('resource').filter(entry => entry.name.includes('/api/')).length};
  }
  requestAnimationFrame(inspect);
}

async function runViewport(browser, viewport) {
  const context = await browser.newContext({viewport, serviceWorkers: 'block'});
  const page = await context.newPage();
  page.setDefaultTimeout(7000);
  const errors = [], unexpected = [], requests = [];
  const state = {detailGate: null, apiBarrier: null};
  const firstFrames = [];
  await context.addInitScript(recordFirstContentFrame);
  page.on('pageerror', error => errors.push(error.message));
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== origin || route.request().method() !== 'GET') {
      unexpected.push(route.request().method() + ' ' + url.href);
      return route.abort();
    }
    requests.push(url.pathname + url.search);
    if (url.pathname === '/admin/domain') {
      await new Promise(resolve => setTimeout(resolve, 2000));
      return route.fulfill({contentType: 'text/html; charset=utf-8', body: adminDocument});
    }
    if (url.pathname === '/admin/antispam/') return route.fulfill({contentType: 'text/html; charset=utf-8', body: rspamdDocument});
    if (url.pathname === '/admin/antispam/css/main.css') return route.fulfill({contentType: 'text/css', body: '#mainUI{min-height:100px}'});
    if (url.pathname === '/admin/antispam/js/main.js') return route.fulfill({contentType: 'application/javascript', body: '/* Local Rspamd application fixture. */'});
    if (url.pathname === '/static/vendor.css') return route.fulfill({contentType: 'text/css', body: '.nav-sidebar{list-style:none}'});
    if (url.pathname === '/static/mailu.png') return route.fulfill({contentType: 'image/png',
      body: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==', 'base64')});
    if (url.pathname === '/static/fa-solid-900.woff2') {
      // Typography is intentionally late and unavailable; it must not hold the
      // complete navigation or change its dimensions while account APIs wait.
      await new Promise(resolve => setTimeout(resolve, 1200));
      return route.fulfill({status: 404, body: 'Local font deliberately unavailable'});
    }
    if (url.pathname === basePath + 'navigation.js') return route.fulfill({contentType: 'application/javascript', body: navigation});
    if (url.pathname.startsWith(basePath + 'ui/')) {
      const name = url.pathname.slice((basePath + 'ui/').length);
      if (assets[name] !== undefined) return route.fulfill({contentType: name.endsWith('.css') ? 'text/css' : 'application/javascript', body: assets[name]});
    }
    if (url.pathname.startsWith(basePath + 'api/')) {
      if (state.apiBarrier) await state.apiBarrier;
      const endpoint = url.pathname.slice((basePath + 'api/').length);
      if (endpoint === 'body') return route.fulfill({contentType: 'text/html; charset=utf-8', body: '<!doctype html><style>body{margin:0;padding:16px}p{margin:0}</style><p>Complete fixture body</p>'});
      if (endpoint === 'message' || endpoint === 'global/message') {
        if (state.detailGate) {
          const gate = state.detailGate;
          state.detailGate = null;
          gate.release = () => route.fulfill({json: {message: gate.message}});
          gate.started();
          return;
        }
        return route.fulfill({json: {message: fixtureMessage}});
      }
      const bodies = {
        messages: {total: 1, folders: ['INBOX', '.Sent'], messages: [{path: 'new/fixture', ...fixtureMessage, folder: 'INBOX'}]},
        'global/messages': {total: 1, mailboxes: 1, folders: ['INBOX'], messages: [globalRow]},
        mailboxes: {mailboxes: ['support@example.com']},
        lists: {blacklist: [], whitelist: []},
        domains: {domains: [{name: 'example.com', used: 1, max_users: 100, remaining: 99}]},
        accounts: {accounts: []},
        'marketing/campaigns': {campaigns: []},
        'marketing/templates': {templates: []},
        'marketing/groups': {groups: []},
        'marketing/contacts': {contacts: []},
        'marketing/api-keys': {api_keys: [], list: [], total: 0},
        'marketing/api-overview': {total: 0, send_count: 0, success_count: 0, failure_count: 0, open_rate: 0, click_rate: 0},
        'marketing/summary': {campaigns: 0, contacts: 0, templates: 0, sent: 0, failed: 0},
      };
      if (bodies[endpoint]) return route.fulfill({json: bodies[endpoint]});
    }
    const template = url.pathname.startsWith(basePath) && templateFor(url);
    if (template) return route.fulfill({contentType: 'text/html; charset=utf-8', body: url.searchParams.get('embedded') === '1' ? embeddedPages[template] : pages[template]});
    unexpected.push(route.request().method() + ' ' + url.pathname);
    return route.fulfill({status: 404, body: 'Unmapped local fixture'});
  });

  function holdDetail(message = fixtureMessage) {
    let started;
    const gate = {message, start: new Promise(resolve => { started = resolve; }), started: () => started()};
    state.detailGate = gate;
    return gate;
  }
  async function waitForDetail(gate) {
    let timer;
    try {
      await Promise.race([gate.start, new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error('fixture detail request did not start')), 7000);
      })]);
    } finally { clearTimeout(timer); }
  }
  async function releaseDetail(gate, endpoint) {
    const response = page.waitForResponse(res => new URL(res.url()).pathname === basePath + 'api/' + endpoint);
    await gate.release();
    await response;
    await afterPaint(page);
  }
  async function navigate(route) {
    requests.length = 0;
    let releaseApis;
    state.apiBarrier = new Promise(resolve => { releaseApis = resolve; });
    try {
      await page.goto(origin + basePath + route, {waitUntil: 'domcontentloaded'});
      await page.waitForFunction(() => window.__firstMainFrame);
      const snapshot = await page.evaluate(() => window.__firstMainFrame);
      firstFrames.push({route, ...snapshot});
      assert.equal(snapshot.sidebarCount, 1, route + ': complete navigation exists in first content frame');
      assert.ok(snapshot.sidebarWidth >= 180 && snapshot.sidebarHeight >= viewport.height - 1, route + ': navigation has its final dimensions');
      for (const link of requiredLinks) assert.ok(snapshot.links.includes(link), route + ': first-frame navigation includes ' + link);
      const current = new URL(origin + basePath + route);
      if (!current.pathname.endsWith('/view')) {
        const selected = current.pathname.startsWith(basePath + 'marketing') ?
          basePath + 'marketing/' + (current.searchParams.get('tab') === 'api' ? '?tab=api' : '') : current.pathname;
        assert.ok(snapshot.activeLinks.includes(selected), route + ': current menu is highlighted in the first content frame');
      }
      assert.equal(snapshot.apiResponses, 0, route + ': complete navigation precedes slow API responses');
      assert.equal(requests.filter(url => url === '/admin/domain').length, 0, route + ': tool navigation has no admin/domain dependency');
      if (viewport.width < 900) {
        assert.ok(snapshot.toggleEnabled && snapshot.toggleWidth > 0 && snapshot.toggleHeight > 0, route + ': mobile navigation button is available immediately');
        await page.locator('#mail-control-nav-toggle').click();
        assert.equal(await page.locator('#mail-control-nav-toggle').getAttribute('aria-expanded'), 'true');
        await page.locator('#mail-control-side-nav a[href="/admin/domain"]').last().waitFor({state: 'visible'});
        await page.locator('#mail-control-side-nav .close-nav, #flow-shell-close').click();
        assert.equal(await page.locator('#mail-control-nav-toggle').getAttribute('aria-expanded'), 'false');
      }
    } finally {
      state.apiBarrier = null;
      releaseApis();
    }
    await page.waitForLoadState('networkidle');
    await page.locator('#mail-control-side-nav').waitFor({state: 'attached'});
    assert.equal(requests.filter(url => url === '/admin/domain').length, 0, 'tools never fetch the native domain page for navigation');
    await assertNoOldMenuFrames(page);
  }

  try {
    await navigate('');
    await page.locator('.view-link').waitFor();
    assert.equal(requests.filter(url => url.startsWith(basePath + 'api/messages?')).length, 1, 'one initial mailbox listing');
    const held = holdDetail();
    await page.locator('.view-link').click();
    await waitForDetail(held);
    await page.locator('#close-message').click();
    await releaseDetail(held, 'message');
    assert.equal(await page.locator('#message-modal').isVisible(), false, 'late mailbox detail must not reopen its dialog');
    await page.locator('.view-link').click();
    await page.locator('#message-subject').filter({hasText: 'Detail test'}).waitFor();
    await page.frameLocator('#modal-html').getByText('Complete fixture body').waitFor();
    await page.locator('#close-message').click();

    await navigate('global/');
    await page.locator('[data-view]').waitFor();
    assert.equal(requests.filter(url => url.startsWith(basePath + 'api/global/messages?')).length, 1, 'one initial global listing');
    await page.locator('[data-view]').click();
    await page.locator('#detail[open]').waitFor();
    await page.frameLocator('#html-view').getByText('Complete fixture body').waitFor();
    const geometry = await page.locator('#detail').evaluate(detail => {
      const rect = detail.getBoundingClientRect();
      const list = document.querySelector('.flow-global-list').getBoundingClientRect();
      return {x: rect.x, y: rect.y, width: rect.width, height: rect.height, rightOfList: rect.x >= list.right - 1,
        modal: detail.matches(':modal'), inside: rect.x >= 0 && rect.y >= 0 && rect.right <= innerWidth + 1 && rect.bottom <= innerHeight + 1,
        centered: Math.abs(rect.x + rect.width / 2 - innerWidth / 2) < 2 && Math.abs(rect.y + rect.height / 2 - innerHeight / 2) < 2};
    });
    if (viewport.width >= 1100) {
      assert.equal(geometry.rightOfList, true, 'desktop reads mail beside the message list');
      assert.equal(geometry.modal, false, 'desktop reader keeps the inbox interactive');
      // Changing responsive mode closes and reopens the native dialog internally.
      // It must keep an intentional selection and its in-flight response alive.
      const heldResize = holdDetail({...fixtureMessage, subject: 'Detail after resize'});
      await page.locator('[data-view]').click();
      await waitForDetail(heldResize);
      await page.setViewportSize({width: 390, height: 844});
      await page.waitForFunction(() => document.getElementById('detail').matches(':modal'));
      await releaseDetail(heldResize, 'global/message');
      assert.equal(await page.locator('#subject').textContent(), 'Detail after resize', 'responsive conversion preserves pending detail');
      await page.setViewportSize(viewport);
      await page.waitForFunction(() => document.body.classList.contains('flow-reader-layout') &&
        document.getElementById('detail').open && !document.getElementById('detail').matches(':modal'));
      const heldGlobal = holdDetail();
      await page.locator('[data-view]').click();
      await waitForDetail(heldGlobal);
      await page.locator('#close').click();
      await releaseDetail(heldGlobal, 'global/message');
      assert.equal(await page.locator('#detail').evaluate(detail => detail.open), false, 'late global detail must not reopen its reader');
    } else {
      assert.equal(geometry.modal, true, 'mobile uses a dialog');
      assert.equal(geometry.inside, true, 'mobile dialog stays within viewport');
      assert.equal(geometry.centered, true, 'mobile dialog is centered and fits its content');
      await page.locator('#close').click();
    }

    // Every exported business page runs its generated scripts and assets. Message
    // and marketing preview iframes are permitted; obsolete menu frames are not.
    for (const route of ['custom-send/', 'accounts/', 'marketing/', 'marketing/?tab=api',
      'marketing/task/', 'marketing/?tab=templates', 'view?mailbox=support%40example.com&path=new%2Ffixture']) {
      await navigate(route);
    }
    // Embedded exports reserve no sidebar space and render no duplicate shell.
    for (const spec of toolPages) {
      const url = new URL(origin + basePath + spec.route);
      url.searchParams.set('embedded', '1');
      requests.length = 0;
      await page.goto(url.href, {waitUntil: 'networkidle'});
      const embedded = await page.evaluate(() => {
        const shell = document.getElementById('mail-control-side-nav');
        return {shellVisible: !!shell && getComputedStyle(shell).display !== 'none',
          toggleVisible: !!document.getElementById('mail-control-nav-toggle') &&
            getComputedStyle(document.getElementById('mail-control-nav-toggle')).display !== 'none',
          marginLeft: getComputedStyle(document.body).marginLeft,
          hiddenSurface: document.body.classList.contains('embedded')};
      });
      assert.equal(embedded.shellVisible, false, spec.name + ': embedded sidebar stays hidden');
      assert.equal(embedded.toggleVisible, false, spec.name + ': embedded navigation toggle stays hidden');
      assert.equal(embedded.hiddenSurface, true, spec.name + ': embedded class retained');
      assert.ok(parseFloat(embedded.marginLeft) < 20, spec.name + ': embedded page reserves no sidebar width');
      assert.equal(requests.filter(url => url === '/admin/domain').length, 0, spec.name + ': embedded navigation makes no domain request');
    }
    requests.length = 0;
    await page.goto(origin + '/admin/antispam/', {waitUntil: 'domcontentloaded'});
    await page.waitForFunction(() => window.__firstMainFrame);
    const rspamdFirstFrame = await page.evaluate(() => window.__firstMainFrame);
    firstFrames.push({route: '/admin/antispam/', ...rspamdFirstFrame});
    assert.equal(rspamdFirstFrame.sidebarCount, 1, 'generated Rspamd body filter puts its shell in the first content frame');
    assert.equal(rspamdFirstFrame.linkCount, 22, 'Rspamd body filter includes all 22 authorized navigation links');
    assert.ok(rspamdFirstFrame.sidebarWidth >= 180 && rspamdFirstFrame.sidebarHeight >= viewport.height - 1,
      'Rspamd first-frame navigation has its final desktop/mobile dimensions');
    for (const link of requiredLinks) assert.ok(rspamdFirstFrame.links.includes(link), 'Rspamd first-frame shell includes ' + link);
    assert.equal(requests.filter(url => url === '/admin/domain').length, 0, 'Rspamd SSR shell requires no admin/domain fetch');
    await page.waitForLoadState('networkidle');
    await assertNoOldMenuFrames(page);
    const antispam = page.locator('#mail-control-side-nav a[href="/admin/antispam/"]');
    assert.equal(await antispam.getAttribute('target'), null, 'navigation opens antispam in the current tab');
    assert.equal(await antispam.getAttribute('data-clicked'), null, 'old Mailu popup interception is removed');
    requests.length = 0;
    await page.goto(origin + '/admin/antispam/?embedded=1', {waitUntil: 'networkidle'});
    const rspamdEmbedded = await page.evaluate(() => ({
      shellCount: document.querySelectorAll('#mail-control-side-nav').length,
      visibleShells: [...document.querySelectorAll('#mail-control-side-nav')].filter(node => getComputedStyle(node).display !== 'none').length,
      visibleToggles: [...document.querySelectorAll('#mail-control-nav-toggle')].filter(node => getComputedStyle(node).display !== 'none').length,
      marginLeft: getComputedStyle(document.body).marginLeft,
    }));
    assert.equal(rspamdEmbedded.shellCount, 1, 'embedded Rspamd retains one fixed shell in the document');
    assert.equal(rspamdEmbedded.visibleShells, 0, 'embedded Rspamd hides the fixed shell');
    assert.equal(rspamdEmbedded.visibleToggles, 0, 'embedded Rspamd hides the navigation toggle');
    assert.ok(parseFloat(rspamdEmbedded.marginLeft) < 20,
      'embedded Rspamd reserves no sidebar width beyond the fixture body margin');
    assert.equal(requests.filter(url => url === '/admin/domain').length, 0, 'embedded Rspamd has no native-navigation fetch');
    await page.goto(origin + '/admin/antispam/', {waitUntil: 'networkidle'});
    if (viewport.width < 900) await page.locator('#mail-control-nav-toggle').click();
    const globalLink = page.locator('#mail-control-side-nav a[href="/admin/mail-control/global/"]');
    await globalLink.click();
    await page.waitForURL(origin + basePath + 'global/');
    await page.locator('[data-view]').waitFor();
    await assertNoOldMenuFrames(page);
    assert.deepEqual(unexpected, [], 'all requests must use known local fixtures');
    assert.deepEqual(errors, [], 'all tool pages must run without JavaScript errors');
    console.log(JSON.stringify({viewport, result: 'passed', scriptTemplates: templateNames.length,
      initialMailboxListings: 1, initialGlobalListings: 1, standaloneNavigation: 'passed',
      reader: viewport.width >= 1100 ? 'desktop right pane' : 'mobile centered dialog',
      lateMailboxDetail: 'passed', lateGlobalDetail: viewport.width >= 1100 ? 'passed' : 'desktop interaction',
      responsiveDetailTransition: viewport.width >= 1100 ? 'passed' : 'covered in desktop case', productionRequests: 0}));
    console.log(JSON.stringify({viewport, firstFrames: firstFrames.map(({route, atMs, sidebarCount, linkCount,
      sidebarWidth, sidebarHeight, toggleEnabled, apiResponses}) => ({route, atMs, sidebarCount,
      linkCount, sidebarWidth, sidebarHeight, toggleEnabled, apiResponses})), embeddedPages: toolPages.length,
      rspamdFirstFrame: {sidebarCount: rspamdFirstFrame.sidebarCount, linkCount: rspamdFirstFrame.linkCount,
        sidebarWidth: rspamdFirstFrame.sidebarWidth, embeddedVisible: rspamdEmbedded.visibleShells},
    }));
  } finally {
    await context.close();
  }
}

(async () => {
  const launch = {headless: true};
  if (process.env.CHROME_PATH) launch.executablePath = process.env.CHROME_PATH;
  else if (process.env.PLAYWRIGHT_CHANNEL) launch.channel = process.env.PLAYWRIGHT_CHANNEL;
  const browser = await chromium.launch(launch);
  const failures = [];
  try {
    for (const viewport of [{width: 1440, height: 1000}, {width: 390, height: 844}]) {
      try { await runViewport(browser, viewport); }
      catch (error) { failures.push({viewport, error: error.message}); }
    }
  } finally {
    await browser.close();
  }
  assert.deepEqual(failures, [], 'all viewport regressions must pass');
})().catch(error => {console.error(error); process.exitCode = 1;});
