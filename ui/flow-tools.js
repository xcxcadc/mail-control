/* Progressive visual enhancement. Existing mail-control APIs own all data/actions. */
(function () {
  'use strict';
  function init() {
    if (!document.body || document.body.dataset.flowToolsReady) return;
    var body = document.body;
    var main = document.querySelector('body > main');
    if (!main) return;
    body.dataset.flowToolsReady = '1';
    body.classList.add('flow-tools');

    var pages = [
      ['flow-global', '#rows', '#detail'],
      ['flow-compose', '#compose'],
      ['flow-accounts', '#localparts'],
      ['flow-api', '#api-form'],
      ['flow-marketing-task', '#sender-domain'],
      ['flow-marketing-list', '#task-list'],
      ['flow-marketing-manage', '#tab-campaigns'],
      ['flow-control', '#message-modal'],
      ['flow-view', 'body > header #subject']
    ];
    pages.some(function (page) {
      if (page.slice(1).every(function (selector) { return document.querySelector(selector); })) {
        body.classList.add(page[0]);
        return true;
      }
      return false;
    });
    if (body.classList.contains('flow-global')) {
      try { enhanceGlobal(main); }
      catch (error) { console.warn('Mailu theme enhancement: ' + error.message); }
    }
  }

  function enhanceGlobal(main) {
    var detail = document.getElementById('detail');
    var rows = document.getElementById('rows');
    var list = rows && rows.closest('section.panel');
    var filters = main.querySelector('section.panel');
    if (!detail || !list || !filters || detail === list || typeof detail.showModal !== 'function' || typeof detail.show !== 'function') return;

    var body = document.body;
    var desktop = window.matchMedia('(min-width: 1100px)');
    var originalShowModal = detail.showModal;
    var originalShow = detail.show;
    var originalClose = detail.close;
    var anchor = document.createComment('flow-detail-original-position');
    var layout = document.createElement('div');
    var reader = document.createElement('section');
    var placeholder = document.createElement('div');
    var mobileFilters = document.createElement('button');
    var selectLabel = document.createElement('span');
    var switching = false;
    var observer;
    var rowsObserver;
    var refreshTimer;
    var pendingRow = null;
    var activeKey = '';

    function rowKey(row) {
      if (!row || row.cells.length < 7) return '';
      return [row.cells[1].firstChild ? row.cells[1].firstChild.textContent : '', row.cells[2].textContent, row.cells[3].textContent, row.cells[5].textContent, row.cells[6].textContent].join('\u001f');
    }
    function markCurrent() {
      Array.from(rows.querySelectorAll('tr')).forEach(function (row) {
        var current = detail.open && activeKey && rowKey(row) === activeKey;
        row.classList.toggle('flow-current-message', !!current);
        var link = row.querySelector('[data-view]');
        if (link) {
          if (current) link.setAttribute('aria-current', 'true');
          else link.removeAttribute('aria-current');
        }
      });
    }
    function syncReader() {
      placeholder.hidden = !!detail.open;
      var frame = document.getElementById('html-view');
      var text = document.getElementById('text-view');
      var htmlTab = document.getElementById('html-tab');
      var textTab = document.getElementById('text-tab');
      var htmlActive = frame && !frame.classList.contains('hidden');
      if (htmlTab) {
        htmlTab.classList.toggle('flow-active-tab', !!htmlActive);
        htmlTab.setAttribute('aria-pressed', String(!!htmlActive));
      }
      if (textTab) {
        textTab.classList.toggle('flow-active-tab', !htmlActive && !!text);
        textTab.setAttribute('aria-pressed', String(!htmlActive && !!text));
      }
      markCurrent();
    }
    function notifyResize() {
      var frame = document.getElementById('html-view');
      if (frame && window.MailViewer) {
        // The existing viewer owns measurement through its window resize listener.
        requestAnimationFrame(function () { window.dispatchEvent(new Event('resize')); });
      }
    }
    function showWithMode() {
      if (desktop.matches && body.classList.contains('flow-reader-layout')) {
        originalShow.call(detail);
      } else originalShowModal.call(detail);
      syncReader();
      notifyResize();
    }
    function switchMode() {
      if (switching) return;
      switching = true;
      try {
        var isOpen = detail.open;
        if (isOpen) originalClose.call(detail);
        if (desktop.matches) {
          reader.appendChild(detail);
          detail.classList.add('flow-reader-detail');
          body.classList.add('flow-reader-layout');
        } else {
          anchor.parentNode.insertBefore(detail, anchor.nextSibling);
          detail.classList.remove('flow-reader-detail');
          body.classList.remove('flow-reader-layout');
        }
        if (isOpen) showWithMode();
        syncReader();
        notifyResize();
      } finally { switching = false; }
    }
    function rowClicked(event) {
      var link = event.target.closest('[data-view]');
      if (link && rows.contains(link)) pendingRow = link.closest('tr');
    }
    function detailUpdated(records) {
      if (pendingRow && records.some(function (record) {
        return record.type === 'childList' && (record.target.id === 'subject' || record.target.id === 'meta');
      })) {
        activeKey = rowKey(pendingRow);
        pendingRow = null;
      }
      syncReader();
    }
    function filterToggle() {
      var collapsed = filters.classList.toggle('flow-filters-collapsed');
      mobileFilters.textContent = collapsed ? '展开筛选' : '收起筛选';
      mobileFilters.setAttribute('aria-expanded', String(!collapsed));
    }
    function rollback(error) {
      if (observer) observer.disconnect();
      if (rowsObserver) rowsObserver.disconnect();
      if (refreshTimer) clearInterval(refreshTimer);
      rows.removeEventListener('click', rowClicked, true);
      detail.removeEventListener('close', syncReader);
      if (desktop.removeEventListener) desktop.removeEventListener('change', switchMode);
      else if (desktop.removeListener) desktop.removeListener(switchMode);
      detail.showModal = originalShowModal;
      var isOpen = detail.open;
      if (isOpen) originalClose.call(detail);
      if (anchor.parentNode) anchor.parentNode.insertBefore(detail, anchor.nextSibling);
      detail.classList.remove('flow-reader-detail');
      if (layout.parentNode) layout.parentNode.insertBefore(list, layout);
      layout.remove();
      anchor.remove(); mobileFilters.remove(); selectLabel.remove();
      list.classList.remove('flow-global-list');
      filters.classList.remove('flow-global-filters', 'flow-filters-collapsed');
      body.classList.remove('flow-reader-layout');
      if (isOpen) originalShowModal.call(detail);
      console.warn('Mailu theme fallback: ' + error.message);
    }

    try {
      detail.parentNode.insertBefore(anchor, detail);
      layout.className = 'flow-inbox-layout';
      reader.className = 'flow-reader';
      reader.setAttribute('aria-label', '邮件阅读区');
      placeholder.className = 'flow-reader-placeholder';
      var title = document.createElement('strong');
      title.textContent = '选择一封邮件';
      placeholder.append(title, document.createTextNode('点击左侧邮件主题，在此查看完整正文和附件。'));
      reader.appendChild(placeholder);
      list.parentNode.insertBefore(layout, list);
      layout.append(list, reader);
      list.classList.add('flow-global-list');
      filters.classList.add('flow-global-filters', 'flow-filters-collapsed');
      var fields = filters.querySelector('.fields');
      if (fields) {
        if (!fields.id) fields.id = 'flow-global-filter-fields';
        mobileFilters.type = 'button';
        mobileFilters.className = 'flow-filter-toggle';
        mobileFilters.textContent = '展开筛选';
        mobileFilters.setAttribute('aria-expanded', 'false');
        mobileFilters.setAttribute('aria-controls', fields.id);
        mobileFilters.addEventListener('click', filterToggle);
        filters.insertBefore(mobileFilters, fields);
      }
      var selectAll = document.getElementById('select-all');
      if (selectAll && selectAll.parentNode) {
        selectLabel.className = 'flow-select-label';
        selectLabel.textContent = '选择当前页全部邮件';
        selectAll.parentNode.appendChild(selectLabel);
      }
      detail.setAttribute('aria-labelledby', 'subject');
      detail.showModal = showWithMode;
      detail.addEventListener('close', syncReader);
      rows.addEventListener('click', rowClicked, true);
      observer = new MutationObserver(detailUpdated);
      observer.observe(detail, { subtree: true, childList: true, attributes: true, attributeFilter: ['class', 'open'] });
      rowsObserver = new MutationObserver(markCurrent);
      rowsObserver.observe(rows, { childList: true });
      if (desktop.addEventListener) desktop.addEventListener('change', switchMode);
      else if (desktop.addListener) desktop.addListener(switchMode);
      switchMode();

      // The original timer pauses while a modal is open. A desktop reading pane
      // is not modal, so keep its existing load() routine refreshing the list.
      refreshTimer = setInterval(function () {
        var auto = document.getElementById('auto');
        if (!desktop.matches || !detail.open || document.hidden || !auto || !auto.checked || rows.querySelector('[data-check]:checked')) return;
        if (typeof window.load === 'function') Promise.resolve(window.load()).catch(function () {});
      }, 15000);
    } catch (error) { rollback(error); }
  }

  // The server places this script immediately after main, before data-loading
  // scripts. Build the reading pane while parsing, before the first painted page.
  if (document.querySelector('body > main')) init();
  else if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
