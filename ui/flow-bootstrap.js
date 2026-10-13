/* Runs in head. Only marks theme surfaces and prioritises existing table columns. */
(function () {
  'use strict';
  var path = location.pathname;
  var embedded = window.self !== window.top || new URLSearchParams(location.search).get('embedded') === '1';
  var native = path.indexOf('/admin/') === 0 && path.indexOf('/admin/mail-control/') !== 0 && path.indexOf('/admin/antispam/') !== 0;
  var rspamd = path.indexOf('/admin/antispam/') === 0;
  if (embedded) document.documentElement.classList.add('flow-embedded-surface');
  function apply() {
    var body = document.body;
    if (!body) return;
    if (native) body.classList.add('mailu-flow-admin');
    if (native) document.querySelectorAll('.main-sidebar').forEach(function (sidebar) { sidebar.classList.add('flow-sidebar-surface'); });
    if (rspamd) {
      body.dataset.flowSurface = 'rspamd';
      if (!embedded) body.classList.add('mail-control-shell');
    }
    // Mailu's DataTables app initialises at the end of body. Set priorities as
    // the table is parsed so its first Responsive pass retains the domain name.
    if (native && (path === '/admin/domain' || path === '/admin/domain/')) {
      document.querySelectorAll('table.dataTable thead tr').forEach(function (row) {
        if (row.cells.length < 3) return;
        row.cells[2].dataset.priority = '1';
        row.cells[0].dataset.priority = '2';
        row.cells[1].dataset.priority = '3';
      });
    }
  }
  var observer = new MutationObserver(apply);
  observer.observe(document.documentElement, {childList:true, subtree:true});
  apply();
  document.addEventListener('DOMContentLoaded', function () { apply(); observer.disconnect(); }, {once:true});
})();
