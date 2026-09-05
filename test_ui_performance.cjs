const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const {spawnSync} = require('node:child_process');
const {chromium} = require('playwright');

const exported = spawnSync(process.env.PYTHON || 'python', ['-c',
  'import json,mail_control as m; print(json.dumps({k:m.html_bytes(getattr(m,k),True).decode() for k in ["HTML","ACCOUNTS_HTML","API_HTML","MARKETING_LIST_HTML","MARKETING_TASK_HTML","MARKETING_HTML","VIEW_HTML"]}))'
], {cwd: __dirname, encoding: 'utf8'});
assert.equal(exported.status, 0, exported.stderr);
const pages = JSON.parse(exported.stdout);
for (const html of Object.values(pages)) {
  for (const match of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) new vm.Script(match[1]);
}
const installer = fs.readFileSync(path.join(__dirname, 'install.sh'), 'utf8');
const nav = installer.match(/sub_filter "<\/body>" "(.*)";/)[1].replace(/\\"/g, '"');
const style = installer.match(/sub_filter "<\/head>" "(.*)";/)[1].replace(/\\"/g, '"');
new vm.Script(nav.match(/<script>([\s\S]*?)<\/script>/)[1]);

(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.PLAYWRIGHT_CHANNEL ? {channel: process.env.PLAYWRIGHT_CHANNEL} : {})});
  try {
    for (const viewport of [{width: 1440, height: 1000}, {width: 390, height: 844}]) {
      const context = await browser.newContext({viewport});
      const page = await context.newPage();
      const errors = [];
      page.on('pageerror', e => errors.push(e.message));
      const requests = [];
      let authenticated = true;
      await context.route('http://mail-control.test/**', async route => {
        const url = new URL(route.request().url());
        requests.push(url.pathname + url.search);
        let body;
        if (url.pathname === '/admin/antispam/') {
          return route.fulfill({contentType: 'text/html; charset=utf-8', body: '<html><head><meta charset="utf-8">' + style + '<body><div><div id="tablist"></div></div>' + nav + '</html>'});
        }
        if (url.pathname === '/sso/login') return route.fulfill({contentType: 'text/html', body: 'Login'});
        if (!url.pathname.includes('/api/')) {
          const template = url.pathname.endsWith('/accounts/') ? 'ACCOUNTS_HTML' : url.pathname.endsWith('/marketing/') ? (url.searchParams.get('tab') === 'api' ? 'API_HTML' : 'MARKETING_LIST_HTML') : 'HTML';
          return route.fulfill({contentType: 'text/html', body: pages[template]});
        }
        const endpoint = url.pathname.split('/api/')[1];
        if (endpoint === 'status' && !authenticated) return route.fulfill({status: 401, json: {error: 'login required'}});
        if (endpoint === 'messages') body = {total: 1, folders: ['INBOX', '.Sent'], messages: [{path: 'new/test', folder: 'INBOX', subject: 'Inbox test', from: 'sender@example.net', date: '2026-09-05'}]};
        else if (endpoint === 'message') {
          await new Promise(resolve => setTimeout(resolve, 250));
          body = {message: {subject: 'Detail test', from: 'sender@example.net', text: 'plain', html: '<p>HTML test</p>', attachments: []}};
        } else if (endpoint === 'mailboxes') body = {mailboxes: ['support@example.com']};
        else if (endpoint === 'lists') body = {blacklist: [], whitelist: []};
        else if (endpoint === 'domains') body = {domains: [{name: 'example.com', used: 1, max_users: 100, remaining: 99}]};
        else if (endpoint === 'accounts') body = {accounts: []};
        else if (endpoint.endsWith('campaigns')) body = {campaigns: []};
        else if (endpoint.endsWith('templates')) body = {templates: []};
        else if (endpoint.endsWith('groups')) body = {groups: []};
        else if (endpoint.endsWith('api-keys')) body = {api_keys: [], total: 0};
        else body = {ok: true};
        return route.fulfill({json: body});
      });
      await page.goto('http://mail-control.test/admin/antispam/');
      const menu = page.locator('#mail-control-rspamd-nav');
      await menu.getByRole('button', {name: '\u90ae\u4ef6\u63a7\u5236', exact: true}).click();
      const mail = page.frameLocator('iframe[data-menu="/admin/mail-control/"]');
      await mail.locator('.view-link').waitFor();
      assert.equal(requests.filter(u => u.includes('/api/messages?')).length, 1, 'only one initial message listing');
      await mail.locator('.view-link').click();
      await mail.locator('#close-message').click();
      await page.waitForTimeout(350);
      assert.equal(await mail.locator('#message-modal').isVisible(), false, 'late detail response must not reopen modal');
      await mail.locator('.view-link').click();
      await mail.locator('#message-subject').filter({hasText: 'Detail test'}).waitFor();
      await mail.locator('#close-message').click();
      for (const name of ['\u6279\u91cf\u90ae\u7bb1', '\u90ae\u4ef6\u8425\u9500', '\u53d1\u4ef6 API']) {
        await page.locator('.mail-control-panel-close').click();
        await menu.getByRole('button', {name, exact: true}).click();
        await page.locator('#mail-control-rspamd-panel iframe:not([hidden])').waitFor();
      }
      await page.locator('.mail-control-panel-close').click();
      await menu.getByRole('button', {name: '\u90ae\u4ef6\u63a7\u5236', exact: true}).click();
      await mail.locator('.view-link').waitFor();
      assert.equal(await page.locator('#mail-control-rspamd-panel iframe').count(), 4);
      assert.equal(requests.filter(u => u === '/admin/mail-control/?embedded=1').length, 1, 'reuse mail page');
      await page.screenshot({path: path.join(os.tmpdir(), 'mail-control-speed-' + viewport.width + '.png')});
      authenticated = false;
      await page.locator('.mail-control-panel-close').click();
      await menu.getByRole('button', {name: '\u6279\u91cf\u90ae\u7bb1', exact: true}).click();
      await page.waitForURL('**/sso/login');
      assert.deepEqual(errors, []);
      console.log(JSON.stringify({viewport, result: 'passed', initialListRequests: 1, retainedMenus: 4, authExpiry: 'passed'}));
      await context.close();
    }
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error); process.exitCode = 1;});
