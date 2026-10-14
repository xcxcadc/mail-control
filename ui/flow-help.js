/* Static, route-aware usage notes for Mailu pages. No network requests or form hooks. */
(function () {
  'use strict';

  var notes = {
    domain: ['域名管理', '先新增并验证域名，再为域名配置邮箱、别名和投递策略。', '例：example.com；确认 DNS 的 MX、SPF、DKIM 与 DMARC 指向当前 Mailu。'],
    alias: ['别名管理', '别名把一个收件地址映射到一个或多个目标地址；目标可以是站内邮箱，也可以是外部邮箱。', '例：sales@example.com → support@example.com。整域转发：别名前缀填写 % 并勾选 SQL LIKE 通配，将 %@example.com 指向目标；该域已有邮箱也会转发并保留本地副本，之后新增的邮箱自动继承。普通别名和前缀通配仅按原规则处理未建邮箱；目标相同只投递一份，循环目标会跳过。'],
    'alias-create': ['新增别名', '填写来源前缀和目标邮箱；多个目标按页面提示分隔，可以填写外部邮箱。', '例：info → help@example.com。整域转发填写 % 并勾选 SQL LIKE 通配：已有及今后新建的邮箱会自动保留副本并转发，无需逐个开启用户转发。'],
    'alias-edit': ['编辑别名', '修改来源或目标后保存，已有邮件不会被搬移；保存后再次检查来源地址和全部目标。', '例：把 old@example.com 的目标从 support@example.com 改为 help@example.com。'],
    relay: ['中继域', '中继域把指定域的邮件交给外部 SMTP；确认对端允许当前服务器后再保存并测试投递。', '例：smtp.example.com:25；也可按对端要求使用 mx:example.com 或 lmtp:example.com，普通本地域仍按本地投递。'],
    alternative: ['替代域名', '替代域名把一个备用域映射到主域的邮箱地址；先确认主域邮箱已经存在，再测试收件和发件。', '例：备用域 alias.example.com 映射主域 example.com，发送给 alice@alias.example.com 时对应主域邮箱接收。'],
    user: ['邮箱用户', '创建用户时选择已配置域名并设置初始密码；修改配额或状态后，建议用客户端和网页邮箱分别验证。停用主要控制登录状态，请按业务需要另行处理投递。', '例：alice@example.com；密码请使用随机长密码，不要复用网站后台密码。'],
    'user-create': ['新增邮箱', '填写本地部分、域名和初始密码后保存；首次登录后建议立即更新密码并检查自动回复。', '例：alice + example.com → alice@example.com。'],
    'user-edit': ['编辑邮箱', '可调整状态、配额及用户属性；停用控制账号登录，请先确认业务影响和后续收件安排。', '例：将离职账号设为停用前，先导出或转交仍需保留的邮件。'],
    settings: ['账户设置', '可设置显示名称、垃圾邮件处理和个人邮件转发；转发时填写目标并决定是否保留本地副本。域名 % 通配副本规则自动生效，无需在这里逐个设置。', '例：alice@example.com 转发到 external@example.net，勾选保留副本后两个邮箱均可收件；若域名副本规则生效，本地副本仍会保留。'],
    reply: ['自动回复', '启用后设置回复主题、正文和生效时间；先用外部邮箱发送普通邮件验证回复内容。', '例：主题“已收到您的来信”，正文写明预计回复时间；避免在正文放置密码或敏感信息。'],
    password: ['更新密码', '按页面要求填写并确认新密码后保存；保存完成后重新登录并更新客户端保存的凭据。', '例：使用至少 14 位随机密码，包含大小写、数字和符号。'],
    token: ['认证令牌', '令牌用于邮箱客户端等登录场景；只在创建时保存密钥，泄露后立即撤销并重新创建。', '例：为手机邮箱客户端单独创建一个令牌，不要把它当作本扩展的营销 API 密钥。'],
    fetch: ['外部邮箱收取', '填写外部邮箱服务器、端口、加密方式及登录凭据，保存后按收取周期导入邮件；这是主动拉取，不是 SMTP 自动转发。', '例：从 pop.example.net:995 使用 TLS 收取 alice@example.net 的来信，导入当前邮箱；服务器是否支持 POP3/IMAP 以页面选项为准。'],
    client: ['客户端设置', '按页面显示的 IMAP、SMTP、加密方式和端口配置客户端；优先使用 TLS。', '例：SMTP 通常使用 587 + STARTTLS；具体端口以此页和客户端提示为准。'],
    admin: ['管理员', '仅向可信人员授予管理员权限；变更后用目标账号重新登录检查权限范围。', '例：日常收发邮件使用普通邮箱账号，管理操作使用独立管理员账号。'],
    announcement: ['公告', '公告会显示在 Mailu 管理页面；内容保持简短并注明生效时间，保存后检查普通用户看到的范围。', '例：维护窗口：2026-10-20 02:00–03:00（北京时间）。'],
    control: ['邮件控制', '选择邮箱与文件夹查询邮件，点击查看正文；发送前可以先验证内容，删除操作请核对选择范围。', '例：先定位来信，再打开正文确认；验证发件内容不会提交实际邮件。'],
    global: ['全局邮件查询', '域名、邮箱前缀和完整邮箱支持精确筛选，关键词用于搜索邮件；打开邮件后可查看正文、附件并删除选中的邮件。', '例：域名 example.com + 前缀 support，只匹配 support@example.com；不会把 support1@example.com 一并纳入。'],
    custom: ['自定义发件', '选择本站域名并填写任意合法前缀即可发件；发送前检查收件人、回复地址和附件。', '例：1@example.com；地址无需预先创建，但回复地址应填写一个实际可收件邮箱。'],
    accounts: ['批量邮箱', '先选择域名，再逐行填写邮箱前缀或完整地址；批量删除前确认勾选范围和数据保留要求。', '例：alice、bob、team@example.com；初始密码不要直接在聊天或工单中传播。'],
    marketing: ['邮件营销', '先建立联系人、模板和发件设置，再创建任务；正式发送前使用测试邮箱检查排版和退订链接。', '例：先发送给 test@example.com，确认主题、正文、链接和统计后再安排任务。'],
    api: ['发件 API', '为每个调用方单独创建 API 密钥并限制用途；请求失败时先查看状态、时间范围和响应信息。', '例：服务端使用 Authorization: Bearer <API_KEY>；密钥只放在服务端环境变量中。'],
    task: ['营销任务', '选择发件人、联系人组和模板后检查预览，再选择立即发送或定时发送；发送中的任务不要重复提交。', '例：先选择 test@example.com 所在测试组，确认预览后再设置发送时间。'],
    antispam: ['反垃圾邮件', '先查看状态、吞吐量和历史记录定位问题；修改配置前记录原值，保存后用测试邮件验证判断结果。', '例：查看 test@example.com 的测试邮件评分；不要为解决一封邮件被拦截而整体关闭过滤。'],
  };

  function keyFor(pathname, search) {
    var path = (pathname || '').replace(/\/+$/, '') || '/';
    var query = new URLSearchParams(search || '');
    if (path === '/admin/domain' || /^\/admin\/domain\/(create|edit|details)(\/|$)/.test(path)) return 'domain';
    if (path === '/admin/alias' || /^\/admin\/alias\/list(\/|$)/.test(path)) return 'alias';
    if (/^\/admin\/alias\/(create|new)(\/|$)/.test(path)) return 'alias-create';
    if (/^\/admin\/alias\/edit(\/|$)/.test(path) || /^\/admin\/alias\/\d+$/.test(path)) return 'alias-edit';
    if (path === '/admin/user' || /^\/admin\/user\/list(\/|$)/.test(path)) return 'user';
    if (/^\/admin\/user\/(create|new)(\/|$)/.test(path)) return 'user-create';
    if (/^\/admin\/user\/edit(\/|$)/.test(path) || /^\/admin\/user\/\d+$/.test(path)) return 'user-edit';
    if (path === '/admin/user/settings' || /^\/admin\/user\/usersettings(\/|$)/.test(path)) return 'settings';
    if (/^\/admin\/user\/reply(\/|$)/.test(path)) return 'reply';
    if (/^\/admin\/user\/password(\/|$)/.test(path)) return 'password';
    if (/^\/admin\/token\/(list|create|delete)(\/|$)/.test(path)) return 'token';
    if (/^\/admin\/fetch\/(list|create|edit|delete)(\/|$)/.test(path)) return 'fetch';
    if (path === '/admin/client') return 'client';
    if (path === '/admin/admin/list' || /^\/admin\/admin\/create(\/|$)/.test(path) || /^\/admin\/manager\/list(\/|$)/.test(path)) return 'admin';
    if (path === '/admin/relay/alternative' || /^\/admin\/alternative(\/|$)/.test(path)) return 'alternative';
    if (path === '/admin/relay' || /^\/admin\/relay\/(create|edit|delete)(\/|$)/.test(path)) return 'relay';
    if (path === '/admin/announcement') return 'announcement';
    if (path === '/admin/antispam') return 'antispam';
    if (path === '/admin/mail-control' || path === '/admin/mail-control/') return 'control';
    if (path === '/admin/mail-control/global') return 'global';
    if (path === '/admin/mail-control/custom-send') return 'custom';
    if (path === '/admin/mail-control/accounts') return 'accounts';
    if (path === '/admin/mail-control/marketing/task') return 'task';
    if (path === '/admin/mail-control/marketing' || path === '/admin/mail-control/marketing/manage') return query.get('tab') === 'api' ? 'api' : 'marketing';
    return null;
  }

  function makeCard(note) {
    var card = document.createElement('section');
    card.className = 'flow-help-card';
    card.dataset.flowHelpCard = 'true';
    card.setAttribute('aria-label', '使用方法');
    var title = document.createElement('h2');
    title.className = 'flow-help-title';
    title.textContent = '使用方法：' + note[0];
    var text = document.createElement('p');
    text.className = 'flow-help-text';
    text.textContent = note[1];
    var example = document.createElement('p');
    example.className = 'flow-help-example';
    var label = document.createElement('strong');
    label.textContent = '示例与边界：';
    example.append(label, document.createTextNode(note[2]));
    card.append(title, text, example);
    return card;
  }

  function mount() {
    if (document.documentElement.dataset.flowHelpReady === '1') return;
    var key = keyFor(location.pathname, location.search);
    var note = key && notes[key];
    if (!note) return;
    var host;
    if (location.pathname.indexOf('/admin/mail-control') === 0) {
      host = document.querySelector('body.flow-tools > main') || document.querySelector('body.flow-tools main');
    } else {
      host = document.querySelector('.content-wrapper > .content') || document.querySelector('.content-wrapper .content') || (key === 'antispam' && document.querySelector('#mainUI > .container-fluid'));
    }
    if (!host || host.querySelector(':scope > [data-flow-help-card]')) return;
    host.insertBefore(makeCard(note), host.firstElementChild || null);
    document.documentElement.dataset.flowHelpReady = '1';
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount, { once: true });
  else mount();
})();
