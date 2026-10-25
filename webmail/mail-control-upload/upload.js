/* SnappyMail public compose hooks; native upload XHR stays untouched. */
((rl) => {
    'use strict';
    if (!rl || !window.ko) return;
    const defaults = { single_mb: 12, total_mb: 24, max_count: 12, message_mb: 200 };
    let policy = Object.assign({}, defaults, rl.pluginSettingsGet('mail-control-upload', 'policy') || {});
    const mib = 1048576;
    const bytes = n => n < 1024 ? Math.round(n) + ' B' : n < mib ? (n / 1024).toFixed(1) + ' KB' : (n / mib).toFixed(2) + ' MB';
    const value = v => typeof v === 'function' ? v() : v;
    function active(view) { return view.attachments().filter(a => value(a.enabled) && !value(a.error)); }
    function invalid(view, candidate) {
        const all = active(view).filter(a => a !== candidate);
        if (candidate) all.push(candidate);
        if (all.length > policy.max_count) return '附件数量不能超过 ' + policy.max_count + ' 个';
        if (all.some(a => Number(value(a.size)) > policy.single_mb * mib)) return '单个附件不能超过 ' + policy.single_mb + ' MB';
        if (all.reduce((n, a) => n + (Number(value(a.size)) || 0), 0) > policy.total_mb * mib) return '附件总大小不能超过 ' + policy.total_mb + ' MB';
        return '';
    }
    function modelProgress(a) {
        if (a.mcUploadLabel) return;
        a.mcLoaded = ko.observable(0); a.mcTotal = ko.observable(Number(value(a.size)) || 0);
        a.mcPhase = ko.observable(value(a.complete) ? 'ready' : 'waiting');
        a.mcUploadLabel = ko.computed(() => {
            const loaded = a.mcLoaded(), total = a.mcTotal(), phase = a.mcPhase();
            if (value(a.error)) return String(value(a.error));
            if (value(a.complete)) return '附件已就绪 · ' + bytes(Number(value(a.size)) || total);
            if (phase === 'ready') return '已上传 · ' + bytes(Number(value(a.size)) || total);
            if (phase === 'processing') return '100% · ' + bytes(loaded) + ' / ' + bytes(total) + ' · 服务器处理中';
            if (phase === 'uploading') return Math.min(100, Math.floor(total ? loaded / total * 100 : 0)) + '% · ' + bytes(loaded) + ' / ' + bytes(total);
            if (phase === 'failed') return '上传失败，请移除后重试';
            return '等待上传';
        }, {pure: true});
    }
    function installTemplate(template) {
        if (!template || template.querySelector('.mc-upload-policy')) return;
        const note = document.createElement('div');
        note.className = 'mc-upload-policy'; note.setAttribute('data-bind', 'text: mcPolicyText');
        // The attachment panel is hidden while editing the body. Keep limits
        // visible beneath the compose header before users choose any files.
        template.querySelector('.modal-body .b-header')?.append(note);
        const row = document.createElement('div'); row.className = 'mc-upload-row';
        row.innerHTML = '<progress max="100" data-bind="value: progress, visible: uploading() && !error()" aria-label="附件上传进度"></progress><span role="status" data-bind="text: mcUploadLabel, css: {\'mc-upload-error\': !!error()}"></span>';
        template.querySelector('.attachmentNameParent')?.append(row);
    }
    addEventListener('rl-view-model.create', event => {
        const view = event.detail;
        if (view.viewModelTemplateID !== 'PopupsCompose' || view.mcUploadInstalled) return;
        view.mcUploadInstalled = true;
        // Plugin scripts can load before the HTML templates. This event fires
        // immediately before SnappyMail binds/clones the compose template.
        installTemplate(document.getElementById(view.viewModelTemplateID)?.content);
        view.mcPolicyText = ko.observable('');
        const setNote = () => view.mcPolicyText('统一附件限制：最多 ' + policy.max_count + ' 个，单个 ' + policy.single_mb + ' MB，总计 ' + policy.total_mb + ' MB；上传完成后仍需等待服务器确认。');
        setNote();
        const build = view.onBuild;
        view.onBuild = function(dom, ...args) {
            const result = build?.call(this, dom, ...args);
            if (dom && !dom.querySelector('.mc-upload-policy')) {
                const note = document.createElement('div');
                note.className = 'mc-upload-policy';
                note.setAttribute('role', 'status');
                note.textContent = view.mcPolicyText();
                (dom.querySelector('.modal-body .b-header') || dom.querySelector('.modal-body'))?.append(note);
                view.mcPolicyText.subscribe(text => { note.textContent = text; });
            }
            return result;
        };
        let reportPending = false, reportLast = 0, reportTimer = 0;
        const reportQueue = new Map();
        function flushReports() {
            if (reportPending || !reportQueue.size) return;
            const delay = 1000 - (Date.now() - reportLast);
            if (delay > 0) {
                if (!reportTimer) reportTimer = setTimeout(() => { reportTimer = 0; flushReports(); }, delay);
                return;
            }
            const [id, data] = reportQueue.entries().next().value;
            reportQueue.delete(id); reportPending = true; reportLast = Date.now();
            rl.pluginRemoteRequest(() => { reportPending = false; flushReports(); }, 'MailControlUploadProgress', data, 15000);
        }
        function report(a, status, force) {
            if (!a || !a.mcLoaded || (!force && Date.now() - (a.mcReportAt || 0) < 1000)) return;
            a.mcReportAt = Date.now();
            reportQueue.set(a.id, {id:a.id, filename:String(value(a.fileName) || ''), size:Number(value(a.size)) || 0,
                received:a.mcLoaded(), total:a.mcTotal(), status});
            flushReports();
        }
        function installUploader(jua) {
            if (jua.mcUploadInstalled) return;
            jua.mcUploadInstalled = true;
            const select = jua.getEvent('onSelect');
            jua.on('onSelect', (id, file) => {
                const reason = invalid(view, { size: file.size, enabled: true, error: '' });
                if (reason) { view.mcPolicyText(reason); return false; }
                return select ? select(id, file) : true;
            });
            const uploadTask = jua.uploadTask;
            jua.uploadTask = function(id, info) {
                const a = view.getAttachmentById(id);
                if (a?.mcRejected) return false;
                return uploadTask.call(this, id, info);
            };
            const progress = jua.getEvent('onProgress');
            jua.on('onProgress', (id, loaded, total) => {
                progress?.(id, loaded, total);
                const a = view.getAttachmentById(id);
                if (a?.mcLoaded) { a.mcLoaded(loaded); a.mcTotal(total); a.mcPhase(loaded >= total ? 'processing' : 'uploading'); report(a, a.mcPhase(), false); }
            });
            const start = jua.getEvent('onStart');
            jua.on('onStart', id => { start?.(id); const a = view.getAttachmentById(id); a?.mcPhase?.('uploading'); report(a, 'uploading', true); });
            const complete = jua.getEvent('onComplete');
            jua.on('onComplete', (id, ok, data) => {
                complete?.(id, ok, data);
                const a = view.getAttachmentById(id);
                if (a?.mcPhase) { const success = ok && data?.Result?.Attachment && !value(a.error); a.mcPhase(success ? 'ready' : 'failed'); report(a, success ? 'completed' : 'failed', true); }
            });
        }
        const add = view.addAttachment;
        view.addAttachment = function(a, area, jua) {
            modelProgress(a);
            if (jua) {
                installUploader(jua);
                const reason = invalid(view, a);
                if (reason) {
                    a.mcRejected = true; a.waiting(false); a.uploading(false); a.complete(true); a.error(reason);
                    view.mcPolicyText(reason);
                }
            }
            const result = add.call(this, a, area, jua);
            if (jua && typeof a.cancel === 'function') {
                const cancel = a.cancel;
                a.cancel = function(...args) { report(a, 'cancelled', true); return cancel.apply(this, args); };
            }
            return result;
        };
        const send = view.sendCommand;
        const guardedSend = function(...args) {
            const reason = invalid(view);
            if (reason) { view.sendError(true); view.sendErrorDesc(reason); view.attachmentsArea(); return false; }
            return send.apply(this, args);
        };
        Object.assign(guardedSend, send); view.sendCommand = guardedSend;
        let lastRefresh = 0, refreshing = false;
        function refresh() {
            if (refreshing || !value(view.modalVisible) || Date.now() - lastRefresh < 9000) return;
            refreshing = true; lastRefresh = Date.now();
            rl.pluginRemoteRequest((error, data) => {
                refreshing = false;
                if (!error && data?.Result?.single_mb) { policy = Object.assign({}, defaults, data.Result); setNote(); }
            }, 'MailControlUploadPolicy', {});
        }
        view.modalVisible.subscribe(show => { if (show) refresh(); });
        setInterval(refresh, 10000);
    });
})(window.rl);
