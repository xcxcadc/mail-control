import os
import base64
import hashlib
import gzip
import hmac
import sqlite3
import tempfile
import threading
import time
import urllib.request
import unittest
from unittest.mock import patch
from pathlib import Path


with tempfile.TemporaryDirectory() as bootstrap:
    base = Path(bootstrap)
    os.environ["MAIL_CONTROL_MAIL_ROOT"] = str(base / "mail")
    os.environ["MAIL_CONTROL_DB"] = str(base / "main.db")
    os.environ["MAIL_CONTROL_RSPAMD_DIR"] = str(base / "rspamd")
    import mail_control

    class MailControlTests(unittest.TestCase):
        def setUp(self):
            self.root = mail_control.CONFIG.mail_root
            self.previous_marketing_db = mail_control.CONFIG.marketing_db_path
            mail_control.CONFIG.marketing_db_path = self.root.parent / f"marketing-{self._testMethodName}.db"
            self.mailbox = "support@example.com"
            (self.root / self.mailbox / "new").mkdir(parents=True, exist_ok=True)
            (self.root / self.mailbox / ".Sent" / "cur").mkdir(parents=True, exist_ok=True)
            (self.root / self.mailbox / ".Junk" / "cur").mkdir(parents=True, exist_ok=True)
            mail_control.mailboxes = lambda: [self.mailbox]
            self._write(self.root / self.mailbox / "new" / "inbox-1", "New subject", "new body")
            self._write(self.root / self.mailbox / ".Sent" / "cur" / "sent-1", "Old subject", "old body")
            self._write(self.root / self.mailbox / ".Junk" / "cur" / "junk-1", "Junk subject", "junk body")

        def tearDown(self):
            mail_control.CONFIG.marketing_db_path = self.previous_marketing_db

        def _write(self, path, subject, body):
            path.write_text(
                f"From: sender@example.net\nTo: {self.mailbox}\nSubject: {subject}\n"
                "Content-Type: text/plain; charset=utf-8\n\n" + body + "\n",
                encoding="utf-8",
            )

        def test_history_folders_and_search(self):
            listing = mail_control.list_messages(self.mailbox, "all", "", "Old", 0, 50)
            self.assertEqual(listing["total"], 1)
            self.assertEqual(listing["messages"][0]["folder"], ".Sent")
            self.assertIn("INBOX", listing["folders"])
            self.assertIn(".Sent", listing["folders"])

        def test_new_scope_only(self):
            listing = mail_control.list_messages(self.mailbox, "new", "", "", 0, 50)
            self.assertEqual(listing["total"], 1)
            self.assertEqual(listing["messages"][0]["folder"], "INBOX")

        def test_listing_reads_only_page_headers_and_never_parses_bodies(self):
            with patch.object(mail_control, "parse_message", side_effect=AssertionError("body parsed")):
                with patch.object(mail_control, "_message_headers", wraps=mail_control._message_headers) as headers:
                    listing = mail_control.list_messages(self.mailbox, "all", limit=1)
                    self.assertGreaterEqual(listing["total"], 3)
                    self.assertEqual(len(listing["messages"]), 1)
                    self.assertEqual(headers.call_count, 1)
                filtered = mail_control.list_messages(self.mailbox, "all", ".Sent")
                self.assertIn("INBOX", filtered["folders"])
                self.assertTrue(all(m["folder"] == ".Sent" for m in filtered["messages"]))

        def test_header_cache_reflects_edits_new_mail_and_removed_mail(self):
            path = self.root / self.mailbox / "new" / "inbox-1"
            mail_control._message_headers.cache_clear()
            mail_control.list_messages(self.mailbox, "all", query="New subject")
            mail_control.list_messages(self.mailbox, "all", query="New subject")
            self.assertGreater(mail_control._message_headers.cache_info().hits, 0)
            self._write(path, "Updated subject", "body only needle")
            self.assertEqual(mail_control.list_messages(self.mailbox, "all", query="New subject")["total"], 0)
            self.assertEqual(mail_control.list_messages(self.mailbox, "all", query="Updated subject")["total"], 1)
            self.assertEqual(mail_control.list_messages(self.mailbox, "all", query="body only needle")["total"], 0)
            extra = path.with_name("arrival-test")
            try:
                self._write(extra, "New arrival", "body")
                self.assertEqual(mail_control.list_messages(self.mailbox, "all", query="New arrival")["total"], 1)
            finally:
                extra.unlink(missing_ok=True)
            self.assertEqual(mail_control.list_messages(self.mailbox, "all", query="New arrival")["total"], 0)

        def test_marketing_schema_initialized_once_and_recreated_when_missing(self):
            mail_control.init_marketing_db()
            with patch.object(mail_control, "marketing_db", side_effect=AssertionError("schema repeated")):
                mail_control.init_marketing_db()
            mail_control.CONFIG.marketing_db_path.unlink()
            mail_control.init_marketing_db()
            with mail_control.marketing_db() as db:
                self.assertEqual(db.execute("SELECT count(*) FROM mc_campaigns").fetchone()[0], 0)

        def test_all_pages_compress_without_bypassing_authorization(self):
            server = mail_control.ThreadingHTTPServer(("127.0.0.1", 0), mail_control.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base_url = f"http://127.0.0.1:{server.server_port}"
                with patch.object(mail_control.Handler, "authorized", return_value=True):
                    for route in ("/", "/accounts/", "/marketing/", "/marketing/?tab=api"):
                        request = urllib.request.Request(base_url + route, headers={"Accept-Encoding": "gzip"})
                        with urllib.request.urlopen(request, timeout=2) as response:
                            self.assertEqual(response.headers["Content-Encoding"], "gzip")
                            self.assertEqual(response.headers["Cache-Control"], "no-store")
                            self.assertIn(b"<!doctype html>", gzip.decompress(response.read()))
                    request = urllib.request.Request(base_url, headers={"Accept-Encoding": "gzip;q=0"})
                    with urllib.request.urlopen(request, timeout=2) as response:
                        self.assertIsNone(response.headers["Content-Encoding"])
                with patch.object(mail_control.Handler, "authorized", return_value=False):
                    with self.assertRaises(urllib.error.HTTPError) as error:
                        urllib.request.urlopen(base_url + "/api/messages?mailbox=" + self.mailbox, timeout=2)
                    self.assertEqual(error.exception.code, 401)
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

        def test_path_is_read_only_and_safe(self):
            with self.assertRaises(ValueError):
                mail_control.safe_message(self.mailbox, "../main.db")

        def test_release_junk_message_to_inbox(self):
            result = mail_control.release_message(self.mailbox, ".Junk/cur/junk-1")
            self.assertTrue(result["released"])
            self.assertFalse((self.root / self.mailbox / ".Junk" / "cur" / "junk-1").exists())
            self.assertTrue((self.root / self.mailbox / "cur" / "junk-1").exists())
            with self.assertRaises(ValueError):
                mail_control.release_message(self.mailbox, "new/inbox-1")

        def test_release_endpoint_is_present_in_mail_control_page(self):
            self.assertIn("api/message/release", mail_control.HTML)
            self.assertIn("放行到收件箱", mail_control.HTML)

        def test_health_endpoint_does_not_require_authentication(self):
            server = mail_control.ThreadingHTTPServer(("127.0.0.1", 0), mail_control.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}/healthz"
                with urllib.request.urlopen(url, timeout=2) as response:
                    self.assertEqual(response.status, 200)
                    self.assertIn('"ok": true', response.read().decode("utf-8"))
            finally:
                server.shutdown()
                thread.join(timeout=2)
                server.server_close()

        def test_current_mailu_admin_session_can_authorize_proxy_request(self):
            handler = mail_control.Handler.__new__(mail_control.Handler)
            handler.headers = {
                "X-Remote-User": "admin@example.com",
                "X-Mail-Control-Proxy-Secret": "proxy-secret",
            }
            old_secret = mail_control.CONFIG.proxy_secret
            old_admin_check = mail_control.is_global_admin
            try:
                mail_control.CONFIG.proxy_secret = "proxy-secret"
                mail_control.is_global_admin = lambda username: username == "admin@example.com"
                self.assertTrue(handler.authorized())
                handler.headers["X-Remote-User"] = "user@example.com"
                self.assertFalse(handler.authorized())
            finally:
                mail_control.CONFIG.proxy_secret = old_secret
                mail_control.is_global_admin = old_admin_check

        def test_embedded_pages_hide_their_standalone_shell(self):
            page = mail_control.html_bytes(mail_control.HTML, embedded=True).decode("utf-8")
            self.assertIn('<body class="embedded">', page)
            self.assertIn("body.embedded header{display:none}", page)

        def test_mailu_admin_routes_and_sidebar_are_not_overridden(self):
            installer = Path(__file__).with_name("install.sh").read_text(encoding="utf-8")
            self.assertNotIn("location = /admin {", installer)
            self.assertNotIn("location ^~ /admin/ {", installer)
            self.assertNotIn("mail-control-menu-group", installer)
            self.assertNotIn("mail-control-embed", installer)

        def test_client_settings_and_profiles_require_a_mailu_user_session(self):
            installer = Path(__file__).with_name("install.sh").read_text(encoding="utf-8")
            for route in ("/admin/client", "/apple.mobileconfig", "/mobileconfig"):
                marker = f"location = {route} {{"
                start = installer.index(marker)
                block = installer[start:installer.index("\n}", start)]
                self.assertIn("auth_request /internal/auth/user;", block)
                self.assertIn("error_page 401 403 = @sso_login;", block)
            self.assertEqual(installer.count("rewrite ^ /internal/autoconfig/apple break;"), 2)

        def test_admin_and_rspamd_overrides_require_auth_and_embed_control(self):
            installer = Path(__file__).with_name("install.sh").read_text(encoding="utf-8")
            self.assertIn("location = /admin/antispam {", installer)
            self.assertIn("location ^~ /admin/antispam/ {", installer)
            self.assertEqual(installer.count("auth_request /internal/auth/admin;"), 1)
            self.assertIn("mail-control-rspamd-nav", installer)
            self.assertIn("mail-control-rspamd-panel", installer)
            self.assertIn("/admin/mail-control/marketing/?tab=api", installer)

        def test_installer_disables_automatic_rspamd_rejects_but_keeps_manual_maps(self):
            installer = Path(__file__).with_name("install.sh").read_text(encoding="utf-8")
            self.assertIn("reject = 9999.0;", installer)
            self.assertIn("add_header = 9998.0;", installer)
            self.assertIn("greylist = 9997.0;", installer)
            self.assertIn('action = "no action";', installer)
            self.assertIn("RSPAMD_MULTIMAP_FILE", installer)

        def test_installer_configures_read_only_all_mail_virtual_folder(self):
            installer = Path(__file__).with_name("install.sh").read_text(encoding="utf-8")
            self.assertIn("--dovecot-dir", installer)
            self.assertIn("DOVECOT_VIRTUAL_DIR=\"&UWiQ6JCuTvY-\"", installer)
            self.assertIn("DOVECOT_VIRTUAL_RULE=\"$DOVECOT_DIR/virtual/$DOVECOT_VIRTUAL_DIR/dovecot-virtual\"", installer)
            self.assertIn("protocol imap {", installer)
            self.assertIn("mail_plugins = $mail_plugins virtual", installer)
            self.assertIn("location = virtual:/overrides/virtual:INDEX=~/virtual:LAYOUT=fs", installer)
            self.assertIn("prefix = virtual.", installer)
            self.assertIn("separator = .", installer)
            self.assertIn('mailbox "全部邮件" {', installer)
            self.assertIn("auto = subscribe", installer)
            self.assertIn(r"special_use = \All", installer)
            self.assertIn("*\n    all", installer)
            self.assertIn("doveconf -n", installer)
            self.assertIn("protocol=lmtp -h namespace", installer)
            self.assertIn("virtual namespace leaked into LMTP delivery", installer)
            self.assertIn("doveadm reload", installer)

        def test_html_preview_removes_active_content(self):
            preview = mail_control.sanitize_html(
                '<div onclick="alert(1)"><img src="https://example.com/a.png">'
                '<script>alert(2)</script>正文</div>'
            )
            self.assertIn("https://example.com/a.png", preview)
            self.assertIn("正文", preview)
            self.assertNotIn("onclick", preview)
            self.assertNotIn("script", preview.lower())

        def test_dry_run_supports_html_inline_image_and_attachment(self):
            image = base64.b64encode(b"fake-image").decode("ascii")
            result = mail_control.send_message({
                "from": self.mailbox,
                "to": "recipient@example.net",
                "subject": "图文测试",
                "text": "纯文本备用内容",
                "html": f'<p>正文<img src="data:image/png;base64,{image}"></p>',
                "attachments": [{
                    "filename": "image.png",
                    "content_type": "image/png",
                    "data_url": f"data:image/png;base64,{image}",
                    "data_base64": image,
                    "inline": True,
                    "content_id": "test-image",
                }],
                "dry_run": True,
            })
            self.assertTrue(result["dry_run"])
            self.assertTrue(result["html"])
            self.assertEqual(result["attachments"][0]["filename"], "image.png")

        def test_batch_create_and_delete_accounts(self):
            with sqlite3.connect(mail_control.CONFIG.db_path) as db:
                db.executescript("""
                    CREATE TABLE domain (name TEXT PRIMARY KEY, max_users INTEGER NOT NULL, max_quota_bytes INTEGER NOT NULL);
                    CREATE TABLE user (
                        created_at TEXT NOT NULL, updated_at TEXT, comment TEXT, localpart TEXT NOT NULL,
                        password TEXT NOT NULL, quota_bytes INTEGER NOT NULL, global_admin INTEGER NOT NULL,
                        enable_imap INTEGER NOT NULL, enable_pop INTEGER NOT NULL, forward_enabled INTEGER NOT NULL,
                        forward_destination TEXT, reply_enabled INTEGER NOT NULL, reply_subject TEXT,
                        reply_body TEXT, displayed_name TEXT NOT NULL, spam_enabled INTEGER NOT NULL,
                        domain_name TEXT NOT NULL, email TEXT PRIMARY KEY, spam_threshold INTEGER,
                        forward_keep INTEGER NOT NULL, reply_enddate TEXT NOT NULL, enabled INTEGER NOT NULL,
                        quota_bytes_used INTEGER NOT NULL, reply_startdate TEXT NOT NULL,
                        spam_mark_as_read INTEGER NOT NULL, allow_spoofing INTEGER NOT NULL,
                        change_pw_next_login INTEGER NOT NULL
                    );
                """)
                db.execute("INSERT INTO domain VALUES ('batch.example', 10, 0)")
            created = mail_control.create_batch_accounts({
                "domain": "batch.example",
                "localparts": "one\ntwo",
                "password": "initial-password",
            })
            self.assertEqual(created["created"], ["one@batch.example", "two@batch.example"])
            with sqlite3.connect(mail_control.CONFIG.db_path) as db:
                rows = db.execute("SELECT email, password FROM user ORDER BY email").fetchall()
            self.assertEqual([row[0] for row in rows], ["one@batch.example", "two@batch.example"])
            self.assertTrue(rows[0][1].startswith("$bcrypt-sha256$v=2,"))
            (mail_control.CONFIG.mail_root / "one@batch.example" / "cur").mkdir(parents=True)
            deleted = mail_control.delete_batch_accounts({
                "domain": "batch.example",
                "emails": ["one@batch.example"],
                "purge_data": True,
            })
            self.assertEqual(deleted["deleted"], ["one@batch.example"])
            self.assertFalse((mail_control.CONFIG.mail_root / "one@batch.example").exists())

        def test_generated_password_matches_mailu_bcrypt_sha256(self):
            import bcrypt
            encoded = mail_control.hash_mailu_password("password-for-test")
            _, scheme, params, salt, digest = encoded.split("$", 4)
            self.assertEqual(scheme, "bcrypt-sha256")
            values = dict(item.split("=", 1) for item in params.split(","))
            candidate = base64.b64encode(
                hmac.new(salt.encode("ascii"), b"password-for-test", hashlib.sha256).digest()
            )
            bcrypt_hash = bcrypt.hashpw(
                candidate,
                f"$2b${int(values['r']):02d}${salt}".encode("ascii"),
            ).decode("ascii")
            self.assertEqual(bcrypt_hash, f"$2b${int(values['r']):02d}${salt}{digest}")

        def test_system_crypt_backend_uses_bcrypt_cost_value(self):
            try:
                import crypt
            except ImportError:
                return
            if not hasattr(crypt, "METHOD_BLOWFISH"):
                return
            encoded = mail_control.hash_mailu_password("crypt-backend-test")
            self.assertIn("r=12", encoded)
            self.assertTrue(mail_control.verify_bcrypt_sha256("crypt-backend-test", encoded))

        def test_bcrypt_sha256_verification(self):
            encoded = mail_control.hash_mailu_password("verify-me")
            self.assertTrue(mail_control.verify_bcrypt_sha256("verify-me", encoded))
            self.assertFalse(mail_control.verify_bcrypt_sha256("wrong", encoded))

        def test_marketing_data_and_api_key_lifecycle(self):
            old_mailboxes = mail_control.mailboxes
            mail_control.mailboxes = lambda: [self.mailbox]
            try:
                group = mail_control.create_marketing_group({"name": "订阅用户"})
                imported = mail_control.import_marketing_contacts({
                    "group_id": group["id"],
                    "contacts": "alice@example.net,Alice\nbob@example.net,Bob",
                })
                self.assertEqual(imported["imported"], 2)
                saved = mail_control.save_marketing_template({
                    "name": "欢迎模板",
                    "subject": "你好 {{name}}",
                    "html": "<p>欢迎 {{email}}</p>",
                })
                campaign = mail_control.create_marketing_campaign({
                    "name": "欢迎任务",
                    "from": self.mailbox,
                    "template_id": saved["id"],
                    "group_id": group["id"],
                    "public_url": "https://mail.example.test/admin/mail-control",
                    "note": "备注验证",
                })
                self.assertEqual(campaign["total"], 2)
                self.assertEqual(campaign["status"], "draft")
                key = mail_control.create_marketing_api_key({
                    "name": "网站通知",
                    "sender": self.mailbox,
                })
                self.assertTrue(key["key"].startswith("mc_live_"))
                found = mail_control.find_marketing_api_key(key["key"])
                self.assertIsNotNone(found)
                summary = mail_control.marketing_summary()
                self.assertEqual(summary["campaigns"], 1)
                self.assertEqual(summary["contacts"], 2)
                self.assertEqual(summary["templates"], 1)
                self.assertEqual(mail_control.marketing_campaigns()[0]["note"], "备注验证")
            finally:
                mail_control.mailboxes = old_mailboxes

        def test_marketing_campaign_worker_sends_contacts(self):
            old_mailboxes = mail_control.mailboxes
            old_send = mail_control.send_message
            sent = []
            mail_control.mailboxes = lambda: [self.mailbox]
            mail_control.send_message = lambda payload: sent.append(payload) or {"message_id": "<test-message>"}
            try:
                group = mail_control.create_marketing_group({"name": "发送测试"})
                mail_control.import_marketing_contacts({
                    "group_id": group["id"],
                    "contacts": "alice@example.net,Alice\nbob@example.net,Bob",
                })
                campaign = mail_control.create_marketing_campaign({
                    "name": "工作线程测试",
                    "from": self.mailbox,
                    "group_id": group["id"],
                    "subject": "你好 {{name}}",
                    "html": "<p>收件人 {{email}}</p>",
                    "track_open": False,
                    "track_click": False,
                })
                mail_control.start_marketing_campaign(campaign["id"])
                deadline = time.time() + 3
                while time.time() < deadline:
                    row = mail_control._campaign_row(campaign["id"])
                    if row["status"] == "completed":
                        break
                    time.sleep(0.02)
                row = mail_control._campaign_row(campaign["id"])
                self.assertEqual(row["status"], "completed")
                self.assertEqual(row["sent"], 2)
                self.assertEqual([item["to"] for item in sent], ["alice@example.net", "bob@example.net"])
                self.assertEqual(sent[0]["subject"], "你好 Alice")
            finally:
                mail_control.mailboxes = old_mailboxes
                mail_control.send_message = old_send

        def test_api_configuration_send_and_statistics(self):
            old_mailboxes = mail_control.mailboxes
            old_send = mail_control.send_message
            sent = []
            mail_control.mailboxes = lambda: [self.mailbox]
            mail_control.send_message = lambda payload: sent.append(payload) or {"message_id": "<api-test>"}
            try:
                template = mail_control.save_marketing_template({
                    "name": "API 模板",
                    "subject": "你好 {{name}}",
                    "html": '<p>你好 {{name}}</p><a href="https://example.net">查看</a>',
                })
                created = mail_control.create_marketing_api_key({
                    "name": "Welcome",
                    "sender": self.mailbox,
                    "sender_name": "品牌通知",
                    "template_id": template["id"],
                    "track_open": True,
                    "track_click": True,
                    "ip_whitelist": "203.0.113.0/24",
                })
                found = mail_control.find_marketing_api_key(created["key"])
                self.assertTrue(mail_control.api_key_ip_allowed(found, "203.0.113.25"))
                self.assertFalse(mail_control.api_key_ip_allowed(found, "198.51.100.25"))
                result = mail_control.send_api_message({
                    "recipient": {"email": "recipient@example.net", "name": "Alice"},
                }, found, "https://mail.example.test/mail-control")
                self.assertTrue(result["sent"])
                self.assertEqual(sent[0]["from"], self.mailbox)
                self.assertEqual(sent[0]["from_name"], "品牌通知")
                self.assertEqual(sent[0]["subject"], "你好 Alice")
                self.assertIn("track/open", sent[0]["html"])
                self.assertIn("track/click", sent[0]["html"])
                log_id = result["log_id"]
                mail_control.track_api_open(log_id)
                mail_control.track_api_click(log_id)
                listing = mail_control.marketing_api_keys({"page": 1, "page_size": 10, "active": -1})
                row = listing["list"][0]
                self.assertEqual(row["send_count"], 1)
                self.assertEqual(row["success_count"], 1)
                self.assertEqual(row["open_rate"], 100.0)
                self.assertEqual(row["click_rate"], 100.0)
            finally:
                mail_control.mailboxes = old_mailboxes
                mail_control.send_message = old_send

        def test_api_test_fills_default_content_for_legacy_key(self):
            old_mailboxes = mail_control.mailboxes
            old_send = mail_control.send_message
            sent = []
            mail_control.mailboxes = lambda: [self.mailbox]
            mail_control.send_message = lambda payload: sent.append(payload) or {"message_id": "<api-test>"}
            try:
                created = mail_control.create_marketing_api_key({
                    "name": "Legacy API",
                    "sender": self.mailbox,
                })
                result = mail_control.test_marketing_api_key(
                    created["id"],
                    {"recipient": "recipient@example.net"},
                    "https://mail.example.test/mail-control",
                )
                self.assertTrue(result["sent"])
                self.assertEqual(sent[0]["subject"], "API 测试邮件")
                self.assertIn("API 测试邮件", sent[0]["text"])
            finally:
                mail_control.mailboxes = old_mailboxes
                mail_control.send_message = old_send

        def test_api_page_uses_dom_id_for_modal_close(self):
            page = mail_control.API_HTML
            self.assertIn("document.getElementById(b.dataset.close)", page)
            self.assertNotIn("$(b.dataset.close).classList", page)


    if __name__ == "__main__":
        unittest.main()
