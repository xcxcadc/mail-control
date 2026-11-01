// Real Chromium interactions against generated production HTML and local-only API fixtures.
// No production mailbox, SMTP connection, account, or NekoPass service is touched.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const origin = 'http://mail-query.test';
const base = '/admin/mail-control/';
const evidence = process.env.QUERY_EVIDENCE_DIR || path.join(os.tmpdir(), 'mail-control-query-acceptance');
fs.mkdirSync(evidence, {recursive: true});
const exported = spawnSync(process.env.PYTHON || 'python', ['-c', [
  'import json,tempfile,pathlib,mail_control as m',
  'fixture=tempfile.TemporaryDirectory()',
  'm.CONFIG.db_path=pathlib.Path(fixture.name)/"fixture.db"',
  'print(json.dumps({"html":m.html_bytes(m.GLOBAL_HTML,False,username="admin@example.com",request_path="/admin/mail-control/global/").decode(),"assets":m.FLOW_UI_ASSETS}))',
].join(';')], {cwd: __dirname, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024});
assert.equal(exported.status, 0, exported.stderr);
const {html, assets} = JSON.parse(exported.stdout);

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}

function message(subject = 'INITIAL RESULT') {
  return {mailbox: 'support@example.com', id: 'fixture', folder: 'INBOX', unread: true,
    received_at: 1791849600, size: 120, subject, from: 'sender@example.net',
    to: 'support@example.com', cc: '', date: '2026-11-01', text: 'Visible plain body fixture',
    html: '<p>Visible complete HTML body fixture</p>', attachments: []};
}

async function run(browser, viewport) {
  const context = await browser.newContext({viewport, serviceWorkers: 'block'});
  const page = await context.newPage();
  page.setDefaultTimeout(7000);
  const unexpected = [], errors = [], requests = [], gates = [];
  const state = {nextGate: null, active: 0, maxAutoActive: 0};
  // Speed up only the application's real 5/15-second refresh cadence; all I/O,
  // AbortController behavior, rendering, and clicks remain genuine browser work.
  await context.addInitScript(() => {
    const timeout = window.setTimeout.bind(window), interval = window.setInterval.bind(window);
    window.setTimeout = (callback, delay, ...args) => timeout(callback, delay === 15000 || delay === 5000 ? 100 : delay, ...args);
    window.setInterval = (callback, delay, ...args) => interval(callback, delay === 15000 || delay === 5000 ? 100 : delay, ...args);
  });
  page.on('pageerror', error => errors.push(error.message));
  function holdNext() {
    const gate = {started: deferred(), release: deferred(), request: null};
    assert.equal(state.nextGate, null, 'no unconsumed fixture gate');
    state.nextGate = gate;
    gates.push(gate);
    return gate;
  }
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== origin || route.request().method() !== 'GET') {
      unexpected.push(route.request().method() + ' ' + url.href);
      return route.abort();
    }
    if (url.pathname === base + 'global/') return route.fulfill({contentType: 'text/html; charset=utf-8', body: html});
    if (url.pathname.startsWith(base + 'ui/')) {
      const name = url.pathname.slice((base + 'ui/').length);
      if (assets[name] !== undefined) return route.fulfill({contentType: name.endsWith('.css') ? 'text/css' : 'application/javascript', body: assets[name]});
    }
    if (url.pathname === base + 'api/domains') return route.fulfill({json: {domains: [{name: 'example.com'}]}});
    if (url.pathname === base + 'api/global/messages') {
      const request = Object.fromEntries(url.searchParams);
      requests.push(request);
      state.active++;
      state.maxAutoActive = Math.max(state.maxAutoActive, state.active);
      const gate = state.nextGate;
      if (gate) {
        state.nextGate = null;
        gate.request = request;
        gate.started.resolve();
        await gate.release.promise;
      }
      try {
        if (request.q === 'fixture-error') return await route.fulfill({status: 503, json: {error: 'Fixture query failed; retry is available'}});
        const subject = request.q === 'stale' ? 'STALE RESULT' : request.q === 'newest' ? 'LATEST RESULT' :
          request.q ? 'MATCH ' + request.search_field + ' ' + request.q : 'INITIAL RESULT';
        await route.fulfill({json: {total: 1, mailboxes: 2, folders: ['INBOX', '.Sent'],
          offset: Number(request.offset || 0), limit: Number(request.limit || 50),
          search_field: request.search_field || 'all', messages: [message(subject)]}});
      } catch (error) {
        // A replaced search legitimately aborts its old HTTP request.
        if (!/closed|handled|abort|Target|interception/i.test(error.message)) throw error;
      } finally { state.active--; }
      return;
    }
    if (url.pathname === base + 'api/global/message') return route.fulfill({json: {message: message('DETAIL BODY FIXTURE')}});
    if (url.pathname === base + 'api/body') return route.fulfill({contentType: 'text/html; charset=utf-8', body: '<!doctype html><p>Visible complete HTML body fixture</p>'});
    if (url.pathname === '/static/mailu.png') return route.fulfill({contentType: 'image/png', body: Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLbtAAAAABJRU5ErkJggg==', 'base64')});
    if (url.pathname === '/static/fa-solid-900.woff2') return route.fulfill({status: 404, body: 'Local fixture uses fallback icons'});
    if (url.pathname === '/favicon.ico') return route.fulfill({status: 204});
    unexpected.push(url.pathname);
    return route.fulfill({status: 404, body: 'Unmapped local fixture'});
  });

  const progress = page.locator('#query-progress');
  const rows = page.locator('#rows');
  async function release(gate) {
    gate.release.resolve();
    await progress.waitFor({state: 'hidden'});
  }
  async function clickSearch(keyword, field = 'all') {
    await page.locator('#search-field').selectOption(field);
    await page.locator('#query').fill(keyword);
    await page.locator('#search').click();
  }
  async function waitStarted(gate) {
    let timer;
    try {
      await Promise.race([gate.started.promise, new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error('query fixture did not receive request')), 7000);
      })]);
    } finally { clearTimeout(timer); }
  }
  try {
    const initial = holdNext();
    await page.goto(origin + base + 'global/', {waitUntil: 'domcontentloaded'});
    await waitStarted(initial);
    await progress.waitFor({state: 'visible'});
    assert.equal(await page.locator('#query-progress-bar').getAttribute('value'), null, 'server work uses genuine indeterminate progress');
    assert.equal(await page.locator('#query-results').getAttribute('aria-busy'), 'true');
    await page.locator('#auto').uncheck();
    if (viewport.width < 900 && await page.locator('.flow-filter-toggle').count()) await page.locator('.flow-filter-toggle').click();
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({path: path.join(evidence, `query-loading-${viewport.width}.png`), fullPage: true});
    await release(initial);
    await rows.getByText('INITIAL RESULT', {exact: true}).waitFor();
    assert.equal(await page.locator('#query-results').getAttribute('aria-busy'), 'false');
    const options = await page.locator('#search-field option').evaluateAll(nodes => nodes.map(node => node.value));
    for (const value of ['all', 'subject', 'body', 'from', 'to']) assert.ok(options.includes(value), 'search field exists: ' + value);

    const subject = holdNext();
    await clickSearch('invoice', 'subject');
    await waitStarted(subject);
    await progress.waitFor({state: 'visible'});
    assert.equal(subject.request.search_field, 'subject');
    assert.equal(subject.request.q, 'invoice');
    assert.match(await rows.textContent(), /INITIAL RESULT/, 'old results remain while a new query runs');
    await release(subject);
    await rows.getByText('MATCH subject invoice', {exact: true}).waitFor();
    const body = holdNext();
    await clickSearch('正文关键字', 'body');
    await waitStarted(body);
    assert.equal(body.request.search_field, 'body');
    assert.equal(body.request.q, '正文关键字');
    await release(body);
    await rows.getByText('MATCH body 正文关键字', {exact: true}).waitFor();

    await clickSearch('fixture-error');
    await page.locator('#status').filter({hasText: 'Fixture query failed'}).waitFor();
    await progress.waitFor({state: 'hidden'});
    assert.match(await rows.textContent(), /MATCH body 正文关键字/, 'failure preserves previous usable results');
    const recovery = holdNext();
    await page.locator('#query').fill('recovered');
    await page.locator('#refresh').click();
    await waitStarted(recovery);
    await progress.waitFor({state: 'visible'});
    await release(recovery);
    await rows.getByText('MATCH all recovered', {exact: true}).waitFor();

    const stale = holdNext();
    await clickSearch('stale');
    await waitStarted(stale);
    const newest = holdNext();
    await clickSearch('newest');
    const queuedCount = requests.length;
    await page.waitForTimeout(100);
    assert.equal(requests.length, queuedCount, 'replacement query waits for current server work rather than starting another scan');
    stale.release.resolve();
    await waitStarted(newest);
    assert.doesNotMatch(await rows.textContent(), /STALE RESULT/, 'superseded response is ignored before next search completes');
    await release(newest);
    await rows.getByText('LATEST RESULT', {exact: true}).waitFor();
    await page.waitForTimeout(80);
    assert.doesNotMatch(await rows.textContent(), /STALE RESULT/, 'late old search cannot overwrite the newest query');

    // Automatic refresh remains serial while its API is slow, and does not run
    // when the document is hidden. A manual replacement is checked separately.
    state.maxAutoActive = 0;
    const auto = holdNext();
    const beforeAuto = requests.length;
    await page.locator('#auto').check();
    await waitStarted(auto);
    await page.waitForTimeout(330);
    assert.equal(requests.length, beforeAuto + 1, 'automatic refresh never overlaps a slow request');
    await page.evaluate(() => { Object.defineProperty(document, 'hidden', {configurable: true, get: () => true}); document.dispatchEvent(new Event('visibilitychange')); });
    auto.release.resolve();
    await progress.waitFor({state: 'hidden'});
    const hiddenCount = requests.length;
    await page.waitForTimeout(330);
    assert.equal(requests.length, hiddenCount, 'hidden tabs do not query');
    await page.locator('#auto').uncheck();
    await page.evaluate(() => { Object.defineProperty(document, 'hidden', {configurable: true, get: () => false}); document.dispatchEvent(new Event('visibilitychange')); });
    await progress.waitFor({state: 'hidden'});

    await page.locator('[data-view]').first().click();
    await page.locator('#detail[open]').waitFor();
    await page.frameLocator('#html-view').getByText('Visible complete HTML body fixture').waitFor();
    if (viewport.width < 1100) {
      const geometry = await page.locator('#detail').evaluate(node => {
        const r = node.getBoundingClientRect();
        return {fits: r.x >= 0 && r.y >= 0 && r.right <= innerWidth + 1 && r.bottom <= innerHeight + 1,
          centered: Math.abs(r.x + r.width / 2 - innerWidth / 2) < 2 && Math.abs(r.y + r.height / 2 - innerHeight / 2) < 2};
      });
      assert.ok(geometry.fits && geometry.centered, 'mobile message remains centered within the viewport');
    }
    await page.locator('#close').click();
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({path: path.join(evidence, `query-complete-${viewport.width}.png`), fullPage: true});
    assert.deepEqual(unexpected, [], 'all network calls use local fixtures');
    assert.deepEqual(errors, [], 'no browser script errors');
    console.log(JSON.stringify({viewport, result: 'passed', requests: requests.length,
      cases: ['initial progress', 'subject/body parameters', 'preserved results', 'error/retry',
        'newest query wins', 'serial auto-refresh', 'hidden pause', 'complete message body', 'responsive layout'],
      productionRequests: 0, evidence}));
  } finally {
    gates.forEach(gate => gate.release.resolve());
    await context.close();
  }
}

(async () => {
  const launch = {headless: true};
  if (process.env.CHROME_PATH) launch.executablePath = process.env.CHROME_PATH;
  else if (process.env.PLAYWRIGHT_CHANNEL) launch.channel = process.env.PLAYWRIGHT_CHANNEL;
  const browser = await chromium.launch(launch);
  try {
    for (const viewport of [{width: 1440, height: 1000}, {width: 390, height: 844}]) await run(browser, viewport);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
