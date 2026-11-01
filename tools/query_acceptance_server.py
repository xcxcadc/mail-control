#!/usr/bin/env python3
"""Loopback-only acceptance site using the real built Handler and synthetic Maildir.

Start after tools/build_ui.py. No production mailbox, credentials, database,
SMTP server, Docker service, or NekoPass instance is used. Ctrl+C cleans up the
temporary fixtures. The local proxy shim supplies an ephemeral test identity to
the unchanged authorization code, just as the production authenticated front
proxy does. Only GET endpoints are available in this acceptance fixture.
"""

import argparse
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile
import time
import urllib.parse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=4191)
    parser.add_argument("--delay-ms", type=int, default=600)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or not 0 <= args.delay_ms <= 3000:
        parser.error("port must be 1024..65535; delay must be 0..3000ms")
    with tempfile.TemporaryDirectory(prefix="mail-query-acceptance-") as directory:
        root = Path(directory)
        for env, value in {
            "MAIL_CONTROL_MAIL_ROOT": root / "mail", "MAIL_CONTROL_DB": root / "main.db",
            "MAIL_CONTROL_MARKETING_DB": root / "marketing.db",
            "MAIL_CONTROL_RSPAMD_DIR": root / "rspamd",
        }.items():
            os.environ[env] = str(value)
        os.environ["MAIL_CONTROL_PROXY_SECRET"] = secrets.token_urlsafe(32)
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        import mail_control as app

        with sqlite3.connect(app.CONFIG.db_path) as db:
            db.execute("CREATE TABLE domain(name TEXT PRIMARY KEY,max_users INTEGER,max_quota_bytes INTEGER)")
            db.execute("CREATE TABLE user(email TEXT PRIMARY KEY,domain_name TEXT,enabled INTEGER,global_admin INTEGER,password TEXT,displayed_name TEXT)")
            db.execute("INSERT INTO domain VALUES('example.com',100,1000000000)")
            db.execute("INSERT INTO domain VALUES('example.net',100,1000000000)")
            db.executemany("INSERT INTO user VALUES(?,?,?,?,?,?)", [
                ("admin@example.com", "example.com", 1, 1, "fixture-proxy-auth-only", "本地验收管理员"),
                ("support@example.com", "example.com", 1, 0, "fixture-unusable", "测试支持"),
                ("sales@example.com", "example.com", 1, 0, "fixture-unusable", "测试销售"),
                ("support@example.net", "example.net", 1, 0, "fixture-unusable", "测试分域"),
            ])

        def write(mailbox, filename, subject, text, html=None, charset="utf-8", cte="base64", attachment=None):
            message = EmailMessage()
            message["Subject"] = subject
            message["From"] = "验收发件人 <sender@example.org>"
            message["To"] = mailbox
            message["Date"] = format_datetime(datetime.now(timezone.utc))
            message["Message-ID"] = "<" + filename + "@fixture.invalid>"
            message.set_content(text, charset=charset, cte=cte)
            if html is not None:
                message.add_alternative(html, subtype="html", charset="utf-8", cte="quoted-printable")
            if attachment:
                message.add_attachment(attachment.encode("utf-8"), maintype="text", subtype="plain", filename="fixture-attachment.txt")
            folder = app.CONFIG.mail_root / mailbox / "new"
            folder.mkdir(parents=True, exist_ok=True)
            (folder / filename).write_bytes(message.as_bytes())

        write("support@example.com", "fixture-order", "订单确认 A1001", "欢迎，正文暗号：蓝鲸七号。This is a base64 UTF-8 test body.")
        write("sales@example.com", "fixture-html", "产品更新通知", "更新说明备用正文", '<html><head><style>.hidden{content:"禁止样式词"}</style></head><body><p>春日计划</p><p>这是正文关键词：樱花隧道</p><script>禁止脚本词</script></body></html>', attachment="只在附件出现的隐藏关键词")
        write("support@example.net", "fixture-gb", "Quarterly Invoice INV-2026", "GB18030 编码正文回归：财务审核通过。", charset="gb18030")
        write("support@example.com", "fixture-subject", "主题关键词：樱花隧道", "这封邮件的正文与上一封不同，用于区分主题与正文搜索。", cte="quoted-printable")

        prefix = "/admin/mail-control"

        class LocalHandler(app.Handler):
            def do_GET(self):
                parsed = urllib.parse.urlsplit(self.path)
                if parsed.path == "/":
                    self.send_response(302)
                    self.send_header("Location", prefix + "/global/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                original = self.path
                if parsed.path.startswith(prefix + "/"):
                    self.path = self.path[len(prefix):]
                if urllib.parse.urlsplit(self.path).path == "/api/global/messages":
                    time.sleep(args.delay_ms / 1000)
                    if urllib.parse.parse_qs(parsed.query).get("q", [""])[0] == "__fixture_error__":
                        self.send_json({"error": "本地验收：模拟查询失败，可直接重新查询"}, 503)
                        return
                self.headers["X-Remote-User"] = "admin@example.com"
                self.headers["X-Mail-Control-Proxy-Secret"] = app.CONFIG.proxy_secret
                try:
                    super().do_GET()
                finally:
                    self.path = original

            def do_POST(self):
                self.send_json({"error": "本地验收只允许读取，不发送邮件或修改设置"}, 405)

            def do_DELETE(self):
                self.send_json({"error": "本地验收只允许读取，不删除邮件"}, 405)

        server = app.ThreadingHTTPServer(("127.0.0.1", args.port), LocalHandler)
        print(json.dumps({
            "url": f"http://127.0.0.1:{args.port}/admin/mail-control/global/",
            "fixture_messages": 4, "configured_mailboxes": 4, "mailboxes_with_mail": 3, "real_backend": True,
            "queries": {"subject 樱花隧道": "主题关键词：樱花隧道", "body 樱花隧道": "产品更新通知",
                        "body 蓝鲸七号": "订单确认 A1001", "body 编码正文回归": "Quarterly Invoice INV-2026",
                        "all 只在附件出现的隐藏关键词": "no result", "all 禁止脚本词": "no result"},
            "shutdown": "Ctrl+C", "production_connections": 0,
        }, ensure_ascii=False), flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
