/* Shared upload policy and genuine network progress. No global request hooks. */
(function () {
  'use strict';
  if (window.MailUpload) return;
  var policy = null, panel = null, line = null, progress = null, busy = false;
  var policyUrl = '/admin/mail-control/api/uploads/policy';
  function bytes(value) {
    value = Math.max(0, Number(value) || 0);
    if (value < 1024) return value + ' B';
    if (value < 1048576) return (value / 1024).toFixed(1) + ' KB';
    return (value / 1048576).toFixed(1) + ' MB';
  }
  function hint() {
    return policy ? '最多 ' + policy.max_count + ' 个附件；单个 ≤ ' + policy.single_mb + ' MB；附件合计 ≤ ' + policy.total_mb + ' MB；整封邮件 ≤ ' + policy.message_mb + ' MB。' : '正在读取全站附件限制…';
  }
  function mount() {
    if (panel) return;
    var input = document.querySelector('input[type=file]#files,input[type=file]#attachments');
    if (!input) return;
    var style = document.createElement('style');
    style.textContent = '.mail-upload-state{margin:10px 0 14px;padding:12px 14px;border:1px solid #e4eaf4;border-radius:6px;background:#f7f9fd;font-size:12px;line-height:1.65;color:#67758a}.mail-upload-state p{margin:0}.mail-upload-state progress{display:block;width:100%;height:8px;margin-top:9px;accent-color:#3c68cb}.mail-upload-state[data-error=true]{border-color:#e6b6bd;color:#aa3e4a;background:#fff7f8}.mail-upload-state [hidden]{display:none!important}';
    document.head.appendChild(style);
    panel = document.createElement('div');
    panel.className = 'mail-upload-state';
    panel.setAttribute('role', 'status');
    panel.setAttribute('aria-live', 'polite');
    var note = document.createElement('p'); note.dataset.uploadHint = ''; note.textContent = hint();
    line = document.createElement('p'); line.hidden = true;
    progress = document.createElement('progress'); progress.max = 100; progress.hidden = true;
    panel.append(note, line, progress); input.insertAdjacentElement('afterend', panel);
  }
  function show(message, value, error) {
    mount(); if (!panel) return;
    panel.dataset.error = error ? 'true' : 'false';
    line.hidden = !message; line.textContent = message || '';
    progress.hidden = value === false;
    if (typeof value === 'number') progress.value = Math.max(0, Math.min(100, value));
    else progress.removeAttribute('value');
  }
  function validate(files) {
    if (!policy) throw Error('附件限制尚未加载，请稍后重试');
    files = Array.from(files || []);
    if (files.length > Number(policy.max_count)) throw Error('附件数量不能超过 ' + policy.max_count + ' 个');
    var total = 0;
    files.forEach(function (file) {
      var size = Number(file.size);
      if (!Number.isFinite(size) || size < 0) throw Error('无法确认附件大小，请重新选择文件');
      if (size > Number(policy.single_mb) * 1048576) throw Error((file.name || file.filename || '附件') + ' 超过单个 ' + policy.single_mb + ' MB 限制');
      total += size;
    });
    if (total > Number(policy.total_mb) * 1048576) throw Error('附件合计 ' + bytes(total) + '，超过 ' + policy.total_mb + ' MB 限制');
    return {count: files.length, bytes: total};
  }
  function reading(loaded, total) {
    show('正在读取本地附件：' + bytes(loaded) + ' / ' + bytes(total) + '；尚未上传', total > 0 ? loaded / total * 100 : 0, false);
  }
  function reset() { if (!busy) show('', false, false); }
  function selectedFilesChanged(input, error) {
    // Only custom-send replaces its whole file selection. The API editor keeps
    // an accumulated attachment list managed by its own valid change handler.
    if (input.id !== 'files' || !document.getElementById('compose')) return;
    var result = document.getElementById('result');
    if (result) { result.classList.remove('visible'); result.textContent = ''; }
    var files = Array.from(input.files || []), summary = document.getElementById('file-summary');
    if (summary) summary.textContent = files.length ? files.map(function (file) { return file.name + ' (' + bytes(file.size) + ')'; }).join('、') : '未选择附件';
    var status = document.getElementById('status');
    if (status) {
      status.className = error ? 'error' : 'muted';
      status.textContent = error ? error.message : files.length ? '附件选择已更新，请重新检查发送内容。' : '当前未选择附件，请重新检查发送内容。';
    }
  }
  var ready = fetch(policyUrl, {credentials: 'same-origin', cache: 'no-store'}).then(async function (response) {
    var data; try { data = await response.json(); } catch (_) { throw Error('读取附件限制失败，请重新登录后重试'); }
    if (!response.ok || data.error) throw Error(data.error || '读取附件限制失败（HTTP ' + response.status + '）');
    var value = data.policy;
    if (!value || ['single_mb', 'total_mb', 'max_count', 'message_mb'].some(function (key) { return !Number.isFinite(Number(value[key])) || Number(value[key]) <= 0; })) throw Error('服务器返回的附件限制无效');
    policy = value; mount();
    if (panel) panel.querySelector('[data-upload-hint]').textContent = hint();
    return policy;
  });
  ready.catch(function (error) { show(error.message, false, true); });
  function send(url, options) {
    options = options || {};
    return ready.then(function () {
      if (busy) throw Error('已有上传请求正在处理，请等待完成');
      if (options.signal && options.signal.aborted) throw Error('上传已取消');
      busy = true;
      show('准备上传请求…', 0, false);
      return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest(), done = false, abort;
        function finish(error, value) {
          if (done) return; done = true; busy = false;
          if (options.signal && abort) options.signal.removeEventListener('abort', abort);
          if (error) { show(error.message, false, true); reject(error); }
          else { show('服务器已完成处理。', 100, false); resolve(value); }
        }
        try {
          xhr.open(options.method || 'POST', new URL(url, location.href).href, true);
          xhr.timeout = Number(options.timeout) || 300000;
          xhr.withCredentials = options.credentials === 'include';
          var headers = new Headers(options.headers || {});
          headers.forEach(function (value, key) { xhr.setRequestHeader(key, value); });
          xhr.upload.onprogress = function (event) {
            if (event.lengthComputable && event.total > 0) {
              var percent = Math.min(100, event.loaded / event.total * 100);
              show('正在上传请求：' + bytes(event.loaded) + ' / ' + bytes(event.total) + '（' + percent.toFixed(1) + '%，含编码数据）', percent, false);
            } else show('正在上传请求：已上传 ' + bytes(event.loaded), null, false);
            if (typeof options.onprogress === 'function') options.onprogress(event);
          };
          xhr.upload.onload = function () { show('请求上传完成，服务器正在验证并处理邮件，请勿重复提交…', null, false); };
          xhr.onload = function () {
            var value;
            try { value = JSON.parse(xhr.responseText); } catch (_) {
              finish(Error(xhr.status === 413 ? '请求超过服务器允许的大小，请调整附件限制或缩小附件' : '服务器返回异常响应（HTTP ' + xhr.status + '）')); return;
            }
            if (xhr.status < 200 || xhr.status >= 300 || value.error) finish(Error(value.error || '请求失败（HTTP ' + xhr.status + '）'));
            else finish(null, value);
          };
          xhr.onerror = function () { finish(Error('网络连接失败，未确认邮件是否提交，请先查看结果再重试')); };
          xhr.ontimeout = function () { finish(Error('服务器响应超时，未确认邮件是否提交，请先查看结果再重试')); };
          xhr.onabort = function () { finish(Error('上传已取消；如已上传完成，请先确认服务器处理结果')); };
          if (options.signal) { abort = function () { xhr.abort(); }; options.signal.addEventListener('abort', abort, {once: true}); }
          xhr.send(options.body === undefined ? null : options.body);
        } catch (error) { finish(error); }
      });
    });
  }
  document.addEventListener('change', function (event) {
    var input = event.target;
    if (!input.matches || !input.matches('input[type=file]#files,input[type=file]#attachments')) return;
    try { var result = validate(input.files); selectedFilesChanged(input); show(result.count ? '已选择 ' + result.count + ' 个文件，合计 ' + bytes(result.bytes) + '；待提交后开始上传' : '', false, false); }
    catch (error) { input.value = ''; selectedFilesChanged(input, error); event.stopImmediatePropagation(); show(error.message, false, true); }
  }, true);
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, {once: true}); else mount();
  window.MailUpload = {ready: ready, validate: validate, hint: hint, send: send, reading: reading, reset: reset};
})();
