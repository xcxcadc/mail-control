(function () {
  'use strict';
  var sidebarStyle = '/admin/mail-control/ui/flow-sidebar.css';
  var toolsRoot = '/admin/mail-control/';
  var mounted = new WeakSet();

  // Move only existing navigation nodes. A restricted user never receives additional links.
  function arrange(sidebar) {
    var list = sidebar.querySelector('.nav-sidebar');
    if (!list) return;
    var tools = Array.from(list.children).filter(function (node) { return node.dataset.mailControlNav && node.dataset.mailControlNav !== 'header'; });
    var toolHeading = list.querySelector('[data-mail-control-nav="header"]');
    if (toolHeading && tools.length && list.firstElementChild !== toolHeading) {
      toolHeading.textContent = '邮件工作台';
      var globalTool = tools.find(function (node) { return node.dataset.mailControlNav === 'global/'; });
      if (globalTool) tools = [globalTool].concat(tools.filter(function (node) { return node !== globalTool; }));
      var fragment = document.createDocumentFragment();
      fragment.appendChild(toolHeading);
      tools.forEach(function (node) { fragment.appendChild(node); });
      list.prepend(fragment);
    }
    var current = location.pathname.replace(/\/+$/, '') || '/';
    var match = null;
    var longest = 0;
    list.querySelectorAll('a[href]').forEach(function (link) {
      var target;
      try { target = new URL(link.getAttribute('href'), location.origin); } catch (error) { return; }
      if (target.origin !== location.origin || target.pathname.indexOf('/admin/') !== 0 || target.pathname.indexOf(toolsRoot) === 0) return;
      var targetPath = target.pathname.replace(/\/+$/, '');
      if ((current === targetPath || current.indexOf(targetPath + '/') === 0) && targetPath.length > longest) { match = link; longest = targetPath.length; }
    });
    if (match && current.indexOf(toolsRoot) !== 0) {
      list.querySelectorAll('a.active').forEach(function (link) { if (link !== match) { link.classList.remove('active'); link.removeAttribute('aria-current'); } });
      match.classList.add('active');
      match.setAttribute('aria-current', 'page');
    }
  }

  function enhanceTables(root) {
    root.querySelectorAll('.content-wrapper table.table').forEach(function (table) {
      if (table.closest('.flow-table-scroll,.table-responsive')) return;
      var scroll = document.createElement('div');
      scroll.className = 'flow-table-scroll';
      scroll.tabIndex = 0;
      scroll.setAttribute('role', 'region');
      var heading = table.closest('.card,.box');
      heading = heading && heading.querySelector('.card-title,.box-title');
      scroll.setAttribute('aria-label', (heading && heading.textContent.trim() || '数据表') + '，可横向滚动');
      table.parentNode.insertBefore(scroll, table);
      scroll.appendChild(table);
    });
  }

  function nativeDrawer(sidebar) {
    if (document.getElementById('flow-admin-nav-toggle')) return;
    var header = document.querySelector('.main-header');
    if (!header) return;
    var toggle = document.createElement('button');
    toggle.id = 'flow-admin-nav-toggle';
    toggle.type = 'button';
    toggle.setAttribute('aria-label', '打开导航');
    toggle.setAttribute('aria-expanded', 'false');
    if (!sidebar.id) sidebar.id = 'flow-admin-sidebar';
    toggle.setAttribute('aria-controls', sidebar.id);
    var icon = document.createElement('i');
    icon.className = 'fa fa-bars';
    icon.setAttribute('aria-hidden', 'true');
    toggle.appendChild(icon);
    var close = document.createElement('button');
    close.id = 'flow-admin-nav-close';
    close.type = 'button';
    close.textContent = '\u00d7';
    close.setAttribute('aria-label', '关闭导航');
    var backdrop = document.createElement('button');
    backdrop.id = 'flow-admin-nav-backdrop';
    backdrop.type = 'button';
    backdrop.setAttribute('aria-label', '关闭导航');
    backdrop.tabIndex = -1;
    var inertNodes = [];
    var media = matchMedia('(max-width:900px)');
    function setOpen(open, restoreFocus) {
      document.body.classList.toggle('flow-admin-nav-open', open);
      toggle.setAttribute('aria-expanded', String(open));
      if (open) {
        inertNodes = Array.from(document.querySelectorAll('.main-header,.content-wrapper,.main-footer')).filter(function (node) { return !node.inert; });
        inertNodes.forEach(function (node) { node.inert = true; });
        close.focus();
      } else {
        inertNodes.forEach(function (node) { node.inert = false; });
        inertNodes = [];
        if (restoreFocus !== false) toggle.focus();
      }
    }
    toggle.addEventListener('click', function () { setOpen(true); });
    close.addEventListener('click', function () { setOpen(false); });
    backdrop.addEventListener('click', function () { setOpen(false); });
    document.addEventListener('keydown', function (event) {
      if (!document.body.classList.contains('flow-admin-nav-open')) return;
      if (event.key === 'Escape') { event.preventDefault(); setOpen(false); return; }
      if (event.key !== 'Tab') return;
      var focusable = Array.from(sidebar.querySelectorAll('a[href],button:not([disabled]),[tabindex="0"]')).filter(function (node) { return node.getClientRects().length; });
      if (!focusable.length) return;
      var first = focusable[0], last = focusable[focusable.length - 1];
      if (event.shiftKey && (document.activeElement === first || !sidebar.contains(document.activeElement))) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || !sidebar.contains(document.activeElement))) { event.preventDefault(); first.focus(); }
    });
    media.addEventListener('change', function () { if (!media.matches) setOpen(false, false); });
    header.prepend(toggle);
    sidebar.prepend(close);
    document.body.appendChild(backdrop);
  }

  function enhance() {
    var native = document.querySelector('.main-sidebar');
    if (native && document.querySelector('.content-wrapper')) {
      document.body.classList.add('mailu-flow-admin');
      native.classList.add('flow-sidebar-surface');
      arrange(native);
      nativeDrawer(native);
      enhanceTables(document);
    }
    var host = document.getElementById('mail-control-side-nav');
    if (host && host.shadowRoot) {
      var shadow = host.shadowRoot;
      if (!mounted.has(shadow)) {
        if (!shadow.querySelector('[data-flow-sidebar]')) {
          var style = document.createElement('link');
          style.rel = 'stylesheet';
          style.href = sidebarStyle;
          style.dataset.flowSidebar = 'true';
          shadow.appendChild(style);
        }
        mounted.add(shadow);
      }
      arrange(shadow);
    }
  }

  function init() {
    if (window.self !== window.top || location.pathname.indexOf('/admin/') !== 0 || new URLSearchParams(location.search).get('embedded') === '1') return;
    // The native stylesheet is a render-blocking head resource. This fallback is
    // only needed by older pages that have not received the new response filter.
    if (document.querySelector('.main-sidebar') && !document.querySelector('link[data-flow-native-sidebar]')) {
      var link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = sidebarStyle;
      link.dataset.flowNativeSidebar = 'true';
      document.head.appendChild(link);
    }
    enhance();
    var scheduled = false;
    var observer = new MutationObserver(function () {
      if (scheduled) return;
      scheduled = true;
      requestAnimationFrame(function () { scheduled = false; enhance(); });
    });
    observer.observe(document.body, {childList:true, subtree:true});
  }
  if (document.body && (document.querySelector('.main-sidebar') || document.getElementById('mail-control-side-nav'))) init();
  else if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
