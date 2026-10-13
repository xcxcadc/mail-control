#!/usr/bin/env python3
import base64
import csv
import datetime
import email
import email.header
import email.policy
import email.parser
import hashlib
import gzip
import hmac
import html
import io
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import smtplib
import subprocess
import logging
import shutil
import sqlite3
import tempfile
import threading
import time
import urllib.parse
from contextlib import contextmanager
from functools import lru_cache
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formataddr, formatdate, make_msgid
from html.parser import HTMLParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")
MAX_BODY = 1024 * 1024
MAX_PREVIEW = 1024 * 1024
MAX_REQUEST = 32 * 1024 * 1024
MAX_ATTACHMENT = 12 * 1024 * 1024
MAX_ATTACHMENTS = 12
MAX_TOTAL_ATTACHMENTS = 24 * 1024 * 1024
DEFAULT_USER_QUOTA = 1_000_000_000
MAX_BATCH_ACCOUNTS = 500
MAILU_BCRYPT_COST = 12

try:
    import bcrypt as _bcrypt
except ImportError:
    _bcrypt = None


class Config:
    def __init__(self):
        self.mail_root = Path(os.environ.get("MAIL_CONTROL_MAIL_ROOT", "/opt/mailu/mail"))
        self.db_path = Path(os.environ.get("MAIL_CONTROL_DB", "/opt/mailu/data/main.db"))
        self.marketing_db_path = Path(os.environ.get("MAIL_CONTROL_MARKETING_DB", "/opt/mail-control/marketing.db"))
        self.rspamd_dir = Path(os.environ.get("MAIL_CONTROL_RSPAMD_DIR", "/opt/mailu/overrides/rspamd"))
        self.bind = os.environ.get("MAIL_CONTROL_BIND", "172.20.0.1")
        self.port = int(os.environ.get("MAIL_CONTROL_PORT", "18080"))
        self.proxy_secret = os.environ.get("MAIL_CONTROL_PROXY_SECRET", "")
        self.public_url = os.environ.get("MAIL_CONTROL_PUBLIC_URL", "").rstrip("/")
        self.list_files = {
            "blacklist": self.rspamd_dir / "blacklist.inc",
            "whitelist": self.rspamd_dir / "whitelist.inc",
        }


CONFIG = Config()
WRITE_LOCK = threading.Lock()
MARKETING_WRITE_LOCK = threading.Lock()
CAMPAIGN_THREADS = {}
CAMPAIGN_THREADS_LOCK = threading.Lock()
CAMPAIGN_STOP = threading.Event()
MARKETING_SCHEMA_ID = None


def verify_bcrypt_sha256(password, encoded):
    if not encoded or not encoded.startswith("$bcrypt-sha256$"):
        return False
    try:
        _, scheme, params, salt, digest = encoded.split("$", 4)
        if scheme != "bcrypt-sha256" or not params.startswith("v=2"):
            return False
        values = dict(item.split("=", 1) for item in params.split(","))
        variant = values.get("t", "2b")
        rounds = int(values.get("r", "12"))
        if variant not in {"2a", "2b", "2y"} or len(salt) != 22:
            return False
        digest_input = hmac.new(
            salt.encode("ascii"), password.encode("utf-8"), hashlib.sha256
        ).digest()
        bcrypt_input = base64.b64encode(digest_input)
        bcrypt_salt = "\x24" + variant + "\x24" + f"{rounds:02d}" + "\x24" + salt
        expected = bcrypt_salt + digest
        if _bcrypt is not None:
            actual = _bcrypt.hashpw(bcrypt_input, bcrypt_salt.encode("ascii")).decode("ascii")
        else:
            import crypt
            actual = crypt.crypt(bcrypt_input.decode("ascii"), bcrypt_salt)
        return hmac.compare_digest(actual, expected)
    except (ImportError, ValueError, TypeError, UnicodeError, OSError):
        return False


def is_global_admin(username):
    username = str(username or "").strip().lower()
    if not EMAIL_RE.fullmatch(username) or not CONFIG.db_path.exists():
        return False
    try:
        with sqlite3.connect(CONFIG.db_path) as db:
            row = db.execute(
                "SELECT password FROM user WHERE email = ? AND enabled = 1 AND global_admin = 1",
                (username,),
            ).fetchone()
        return bool(row)
    except sqlite3.Error:
        return False


def verify_mailu_admin(username, password):
    username = str(username or "").strip().lower()
    if not is_global_admin(username):
        return False
    try:
        with sqlite3.connect(CONFIG.db_path) as db:
            row = db.execute(
                "SELECT password FROM user WHERE email = ? AND enabled = 1 AND global_admin = 1",
                (username,),
            ).fetchone()
        return bool(row and verify_bcrypt_sha256(password, row[0]))
    except sqlite3.Error:
        return False


def hash_mailu_password(password):
    password = str(password or "")
    if not password:
        raise ValueError("密码不能为空")
    if _bcrypt is not None:
        salt_record = _bcrypt.gensalt(rounds=MAILU_BCRYPT_COST, prefix=b"2b")
        salt_record = salt_record.decode("ascii")
        hashed = _bcrypt.hashpw(
            base64.b64encode(
                hmac.new(
                    salt_record.rsplit("$", 1)[-1][:22].encode("ascii"),
                    password.encode("utf-8"),
                    hashlib.sha256,
                ).digest()
            ),
            salt_record.encode("ascii"),
        ).decode("ascii")
    else:
        import crypt
        # crypt.mksalt expects the actual Blowfish rounds (2**cost), while
        # bcrypt.gensalt expects the cost value itself.
        salt_record = crypt.mksalt(crypt.METHOD_BLOWFISH, rounds=1 << MAILU_BCRYPT_COST)
        salt = salt_record.rsplit("$", 1)[-1][:22]
        digest_input = base64.b64encode(
            hmac.new(salt.encode("ascii"), password.encode("utf-8"), hashlib.sha256).digest()
        )
        hashed = crypt.crypt(digest_input.decode("ascii"), salt_record)
    if not hashed or not hashed.startswith("$2"):
        raise RuntimeError("无法生成 Mailu 密码哈希")
    parts = hashed.split("$")
    if len(parts) != 4:
        raise RuntimeError("Mailu 密码哈希格式异常")
    variant, rounds, salt_and_digest = parts[1], parts[2], parts[3]
    salt = salt_and_digest[:22]
    digest = salt_and_digest[22:]
    return f"$bcrypt-sha256$v=2,t={variant},r={int(rounds)}${salt}${digest}"


def marketing_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


@contextmanager
def marketing_db():
    CONFIG.marketing_db_path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(CONFIG.marketing_db_path, timeout=30, check_same_thread=False)
    db.row_factory = sqlite3.Row
    try:
        yield db
    finally:
        db.close()


def init_marketing_db():
    global MARKETING_SCHEMA_ID
    with MARKETING_WRITE_LOCK:
        path = CONFIG.marketing_db_path.resolve()
        if path.exists():
            stat = path.stat()
            if MARKETING_SCHEMA_ID == (path, stat.st_dev, stat.st_ino):
                return
        with marketing_db() as db:
            db.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS mc_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mc_contacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    group_id INTEGER,
                    active INTEGER NOT NULL DEFAULT 1,
                    attributes_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(email, group_id),
                    FOREIGN KEY(group_id) REFERENCES mc_groups(id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS mc_contacts_group_idx ON mc_contacts(group_id, active);
                CREATE TABLE IF NOT EXISTS mc_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    subject TEXT NOT NULL DEFAULT '',
                    text_body TEXT NOT NULL DEFAULT '',
                    html_body TEXT NOT NULL DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mc_campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    sender_name TEXT NOT NULL DEFAULT '',
                    subject TEXT NOT NULL,
                    text_body TEXT NOT NULL DEFAULT '',
                    html_body TEXT NOT NULL DEFAULT '',
                    group_id INTEGER,
                    unsubscribe INTEGER NOT NULL DEFAULT 1,
                    track_open INTEGER NOT NULL DEFAULT 1,
                    track_click INTEGER NOT NULL DEFAULT 1,
                    rate_per_minute INTEGER NOT NULL DEFAULT 0,
                    threads INTEGER NOT NULL DEFAULT 0,
                    warmup INTEGER NOT NULL DEFAULT 0,
                    send_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'draft',
                    public_url TEXT NOT NULL DEFAULT '',
                    note TEXT NOT NULL DEFAULT '',
                    total INTEGER NOT NULL DEFAULT 0,
                    sent INTEGER NOT NULL DEFAULT 0,
                    failed INTEGER NOT NULL DEFAULT 0,
                    opened INTEGER NOT NULL DEFAULT 0,
                    clicked INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(group_id) REFERENCES mc_groups(id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS mc_campaigns_status_idx ON mc_campaigns(status, send_at);
                CREATE TABLE IF NOT EXISTS mc_campaign_recipients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id INTEGER NOT NULL,
                    email TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    attributes_json TEXT NOT NULL DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'pending',
                    error TEXT NOT NULL DEFAULT '',
                    message_id TEXT NOT NULL DEFAULT '',
                    sent_at TEXT,
                    opened_at TEXT,
                    clicked_at TEXT,
                    UNIQUE(campaign_id, email),
                    FOREIGN KEY(campaign_id) REFERENCES mc_campaigns(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS mc_campaign_recipients_idx ON mc_campaign_recipients(campaign_id, status, id);
                CREATE TABLE IF NOT EXISTS mc_api_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    key_prefix TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    sender TEXT NOT NULL DEFAULT '',
                    sender_name TEXT NOT NULL DEFAULT '',
                    subject TEXT NOT NULL DEFAULT '',
                    template_id INTEGER NOT NULL DEFAULT 0,
                    group_id INTEGER,
                    unsubscribe INTEGER NOT NULL DEFAULT 1,
                    track_open INTEGER NOT NULL DEFAULT 1,
                    track_click INTEGER NOT NULL DEFAULT 1,
                    ip_whitelist TEXT NOT NULL DEFAULT '[]',
                    active INTEGER NOT NULL DEFAULT 1,
                    expires_at TEXT,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS mc_send_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    api_key_id INTEGER,
                    campaign_id INTEGER,
                    recipient TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    subject TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    error TEXT NOT NULL DEFAULT '',
                    message_id TEXT NOT NULL DEFAULT '',
                    opened_at TEXT,
                    clicked_at TEXT,
                    bounced_at TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(api_key_id) REFERENCES mc_api_keys(id) ON DELETE SET NULL,
                    FOREIGN KEY(campaign_id) REFERENCES mc_campaigns(id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS mc_send_logs_created_idx ON mc_send_logs(created_at, status);
                """
            )
            campaign_columns = {row[1] for row in db.execute("PRAGMA table_info(mc_campaigns)").fetchall()}
            for column, definition in {
                "unsubscribe": "INTEGER NOT NULL DEFAULT 1",
                "threads": "INTEGER NOT NULL DEFAULT 0",
                "warmup": "INTEGER NOT NULL DEFAULT 0",
            }.items():
                if column not in campaign_columns:
                    db.execute(f"ALTER TABLE mc_campaigns ADD COLUMN {column} {definition}")
            api_columns = {row[1] for row in db.execute("PRAGMA table_info(mc_api_keys)").fetchall()}
            for column, definition in {
                "sender_name": "TEXT NOT NULL DEFAULT ''",
                "subject": "TEXT NOT NULL DEFAULT ''",
                "template_id": "INTEGER NOT NULL DEFAULT 0",
                "group_id": "INTEGER",
                "unsubscribe": "INTEGER NOT NULL DEFAULT 1",
                "track_open": "INTEGER NOT NULL DEFAULT 1",
                "track_click": "INTEGER NOT NULL DEFAULT 1",
                "ip_whitelist": "TEXT NOT NULL DEFAULT '[]'",
            }.items():
                if column not in api_columns:
                    db.execute(f"ALTER TABLE mc_api_keys ADD COLUMN {column} {definition}")
            log_columns = {row[1] for row in db.execute("PRAGMA table_info(mc_send_logs)").fetchall()}
            for column in ("opened_at", "clicked_at", "bounced_at"):
                if column not in log_columns:
                    db.execute(f"ALTER TABLE mc_send_logs ADD COLUMN {column} TEXT")
            db.commit()
            stat = path.stat()
            MARKETING_SCHEMA_ID = (path, stat.st_dev, stat.st_ino)


def _json_object(value):
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def _iso_datetime(value, default_now=True):
    value = str(value or "").strip()
    if not value:
        return marketing_now() if default_now else ""
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("发送时间格式无效") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _contact_entries(value):
    if value in (None, ""):
        return []
    entries = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                entries.append(item)
            else:
                entries.append(str(item))
    else:
        for row in csv.reader(io.StringIO(str(value))):
            if not row or not any(str(cell).strip() for cell in row):
                continue
            entries.append({
                "email": row[0].strip(),
                "name": row[1].strip() if len(row) > 1 else "",
            })
    result = []
    seen = set()
    for item in entries:
        if isinstance(item, dict):
            address = str(item.get("email") or item.get("address") or "").strip().lower()
            name = str(item.get("name") or item.get("display_name") or "").strip()[:160]
            attributes = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        else:
            address = str(item).strip().lower()
            name = ""
            attributes = {}
        if not EMAIL_RE.fullmatch(address):
            raise ValueError(f"联系人邮箱无效: {address}")
        if address not in seen:
            seen.add(address)
            result.append({"email": address, "name": name, "attributes": attributes})
    return result


def marketing_groups():
    init_marketing_db()
    with marketing_db() as db:
        rows = db.execute(
            """
            SELECT g.id, g.name, g.description, g.created_at, COUNT(c.id) AS total,
                   SUM(CASE WHEN c.active = 1 THEN 1 ELSE 0 END) AS active
            FROM mc_groups g LEFT JOIN mc_contacts c ON c.group_id = g.id
            GROUP BY g.id ORDER BY g.name
            """
        ).fetchall()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "created_at": row["created_at"],
            "total": row["total"],
            "active": row["active"] or 0,
        }
        for row in rows
    ]


def create_marketing_group(payload):
    init_marketing_db()
    name = str(payload.get("name") or "").strip()[:160]
    if not name:
        raise ValueError("联系人分组名称不能为空")
    now = marketing_now()
    try:
        with marketing_db() as db:
            cursor = db.execute(
                "INSERT INTO mc_groups(name, description, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (name, str(payload.get("description") or "")[:500], now, now),
            )
            db.commit()
            return {"id": cursor.lastrowid, "name": name}
    except sqlite3.IntegrityError as exc:
        raise ValueError("联系人分组已存在") from exc


def import_marketing_contacts(payload):
    init_marketing_db()
    group_id = payload.get("group_id")
    group_name = str(payload.get("group_name") or "").strip()[:160]
    if group_id in (None, "") and group_name:
        existing = next((item for item in marketing_groups() if item["name"] == group_name), None)
        group_id = existing["id"] if existing else create_marketing_group({"name": group_name})["id"]
    if group_id not in (None, ""):
        try:
            group_id = int(group_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("联系人分组无效") from exc
        with marketing_db() as db:
            if not db.execute("SELECT 1 FROM mc_groups WHERE id = ?", (group_id,)).fetchone():
                raise ValueError("联系人分组不存在")
    contacts = _contact_entries(payload.get("contacts") or payload.get("file_data"))
    if not contacts:
        raise ValueError("没有可导入的联系人")
    now = marketing_now()
    imported = 0
    with marketing_db() as db:
        for contact in contacts:
            db.execute(
                """
                INSERT INTO mc_contacts(email, name, group_id, active, attributes_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(email, group_id) DO UPDATE SET
                    name = excluded.name,
                    active = excluded.active,
                    attributes_json = excluded.attributes_json,
                    updated_at = excluded.updated_at
                """,
                (
                    contact["email"], contact["name"], group_id,
                    1 if payload.get("active", True) else 0,
                    json.dumps(contact["attributes"], ensure_ascii=False), now, now,
                ),
            )
            imported += 1
        db.commit()
    return {"imported": imported, "group_id": group_id}


def marketing_contacts(group_id=None, query="", limit=500):
    init_marketing_db()
    clauses = []
    params = []
    if group_id not in (None, "", "all"):
        clauses.append("c.group_id = ?")
        params.append(int(group_id))
    if query:
        clauses.append("(c.email LIKE ? OR c.name LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%"])
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with marketing_db() as db:
        rows = db.execute(
            f"""
            SELECT c.id, c.email, c.name, c.group_id, c.active, c.attributes_json,
                   c.created_at, g.name AS group_name
            FROM mc_contacts c LEFT JOIN mc_groups g ON g.id = c.group_id
            {where} ORDER BY c.id DESC LIMIT ?
            """,
            params + [min(1000, max(1, int(limit)))],
        ).fetchall()
    return [
        {
            "id": row["id"], "email": row["email"], "name": row["name"],
            "group_id": row["group_id"], "group_name": row["group_name"] or "未分组",
            "active": bool(row["active"]), "attributes": _json_object(row["attributes_json"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def delete_marketing_contacts(payload):
    init_marketing_db()
    emails = _contact_entries(payload.get("emails") or payload.get("contacts"))
    if not emails:
        raise ValueError("请选择要删除的联系人")
    addresses = [item["email"] for item in emails]
    with marketing_db() as db:
        placeholders = ",".join("?" for _ in addresses)
        cursor = db.execute(f"DELETE FROM mc_contacts WHERE email IN ({placeholders})", addresses)
        db.commit()
    return {"deleted": cursor.rowcount}


def marketing_templates():
    init_marketing_db()
    with marketing_db() as db:
        rows = db.execute(
            "SELECT id, name, subject, text_body, html_body, active, created_at, updated_at FROM mc_templates ORDER BY updated_at DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def save_marketing_template(payload):
    init_marketing_db()
    name = str(payload.get("name") or "").strip()[:160]
    subject = str(payload.get("subject") or "").strip()[:500]
    html_body = str(payload.get("html") or payload.get("html_body") or "")[:MAX_BODY]
    text_body = str(payload.get("text") or payload.get("text_body") or "")[:MAX_BODY]
    if not name or not subject or not html_body and not text_body:
        raise ValueError("模板名称、主题和正文不能为空")
    now = marketing_now()
    try:
        with marketing_db() as db:
            template_id = payload.get("id")
            if template_id:
                db.execute(
                    "UPDATE mc_templates SET name = ?, subject = ?, text_body = ?, html_body = ?, updated_at = ? WHERE id = ?",
                    (name, subject, text_body, sanitize_html(html_body), now, int(template_id)),
                )
            else:
                cursor = db.execute(
                    "INSERT INTO mc_templates(name, subject, text_body, html_body, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (name, subject, text_body, sanitize_html(html_body), now, now),
                )
                template_id = cursor.lastrowid
            db.commit()
    except sqlite3.IntegrityError as exc:
        raise ValueError("模板名称已存在") from exc
    return {"id": int(template_id), "name": name}


def delete_marketing_template(template_id):
    init_marketing_db()
    with marketing_db() as db:
        db.execute("DELETE FROM mc_templates WHERE id = ?", (int(template_id),))
        db.commit()
    return {"deleted": int(template_id)}


def _template_values(value, contact):
    values = {"email": contact.get("email", ""), "name": contact.get("name", "")}
    values.update(_json_object(contact.get("attributes")))
    return re.sub(
        r"{{\s*([A-Za-z0-9_.-]+)\s*}}",
        lambda match: str(values.get(match.group(1), "")),
        str(value or ""),
    )


def _tracked_campaign_html(body, campaign_id, recipient_id, public_url, track_open, track_click):
    body = sanitize_html(body)
    base = str(public_url or CONFIG.public_url or "").rstrip("/")
    if not base:
        return body
    if track_click:
        def replace_link(match):
            target = match.group(2)
            if target.lower().startswith(("mailto:", "javascript:", "cid:")):
                return match.group(0)
            tracking = f"{base}/track/click?c={campaign_id}&r={recipient_id}&u={urllib.parse.quote(target, safe='')}"
            return f"{match.group(1)}{tracking}{match.group(3)}"

        body = re.sub(
            r"(?i)(href\s*=\s*[\"'])(https?://[^\"']+)([\"'])",
            replace_link,
            body,
        )
    if track_open:
        pixel = f'<img src="{html.escape(base)}/track/open?c={campaign_id}&r={recipient_id}" width="1" height="1" alt="" style="display:none">'
        body = f"{body}{pixel}"
    return body


def create_marketing_campaign(payload):
    init_marketing_db()
    sender = str(payload.get("from") or payload.get("sender") or "").strip().lower()
    if sender not in mailboxes():
        raise ValueError("发件人必须是当前 Mailu 中已启用的邮箱")
    template = None
    if payload.get("template_id"):
        with marketing_db() as db:
            template = db.execute("SELECT * FROM mc_templates WHERE id = ? AND active = 1", (int(payload["template_id"]),)).fetchone()
        if not template:
            raise ValueError("邮件模板不存在")
    subject = str(payload.get("subject") or (template["subject"] if template else "")).strip()[:500]
    html_body = str(payload.get("html") or payload.get("html_body") or (template["html_body"] if template else ""))[:MAX_BODY]
    text_body = str(payload.get("text") or payload.get("text_body") or (template["text_body"] if template else ""))[:MAX_BODY]
    if html_body and not text_body:
        text_body = html_to_text(html_body)[:MAX_BODY]
    if not subject or not html_body and not text_body:
        raise ValueError("营销任务主题和正文不能为空")
    group_id = payload.get("group_id")
    if group_id in (None, "", "all"):
        group_id = None
    else:
        group_id = int(group_id)
    contacts = _contact_entries(payload.get("recipients"))
    if group_id is not None:
        with marketing_db() as db:
            group = db.execute("SELECT id FROM mc_groups WHERE id = ?", (group_id,)).fetchone()
            if not group:
                raise ValueError("联系人分组不存在")
            rows = db.execute(
                "SELECT email, name, attributes_json FROM mc_contacts WHERE group_id = ? AND active = 1 ORDER BY id",
                (group_id,),
            ).fetchall()
        existing = {item["email"] for item in contacts}
        contacts.extend(
            {"email": row["email"], "name": row["name"], "attributes": _json_object(row["attributes_json"])}
            for row in rows if row["email"] not in existing
        )
    if not contacts:
        raise ValueError("请指定联系人分组或收件人")
    now = marketing_now()
    send_at = _iso_datetime(payload.get("send_at"))
    status = "scheduled" if send_at > now else "draft"
    try:
        rate = max(0, int(payload.get("rate_per_minute") or 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("每分钟发送量无效") from exc
    if rate > 6000:
        raise ValueError("每分钟发送量不能超过 6000")
    with marketing_db() as db:
        cursor = db.execute(
            """
            INSERT INTO mc_campaigns(
                name, sender, sender_name, subject, text_body, html_body, group_id,
                unsubscribe, track_open, track_click, rate_per_minute, threads, warmup,
                send_at, status, public_url,
                note, total, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(payload.get("name") or f"营销任务 {now[:10]}")[:160], sender,
                str(payload.get("sender_name") or payload.get("full_name") or "")[:160],
                subject, text_body, sanitize_html(html_body), group_id,
                1 if payload.get("unsubscribe", True) else 0,
                1 if payload.get("track_open", True) else 0,
                1 if payload.get("track_click", True) else 0,
                rate, max(0, int(payload.get("threads") or 0)),
                1 if payload.get("warmup", False) else 0,
                send_at, status, str(payload.get("public_url") or CONFIG.public_url).rstrip("/"),
                str(payload.get("note") or "")[:1000], len(contacts), now, now,
            ),
        )
        campaign_id = cursor.lastrowid
        db.executemany(
            "INSERT INTO mc_campaign_recipients(campaign_id, email, name, attributes_json) VALUES (?, ?, ?, ?)",
            [(campaign_id, item["email"], item["name"], json.dumps(item["attributes"], ensure_ascii=False)) for item in contacts],
        )
        db.commit()
    return {"id": campaign_id, "status": status, "total": len(contacts)}


def marketing_campaigns():
    init_marketing_db()
    with marketing_db() as db:
        rows = db.execute(
            "SELECT id, name, sender, sender_name, subject, text_body, html_body, group_id, unsubscribe, track_open, track_click, rate_per_minute, threads, warmup, send_at, status, public_url, note, total, sent, failed, opened, clicked, last_error, created_at, started_at, finished_at, updated_at FROM mc_campaigns ORDER BY id DESC"
        ).fetchall()
    return [dict(row) for row in rows]


def marketing_campaign_logs(campaign_id):
    init_marketing_db()
    with marketing_db() as db:
        rows = db.execute(
            "SELECT email, name, status, error, message_id, sent_at, opened_at, clicked_at FROM mc_campaign_recipients WHERE campaign_id = ? ORDER BY id DESC LIMIT 1000",
            (int(campaign_id),),
        ).fetchall()
    return [dict(row) for row in rows]


def _campaign_row(campaign_id):
    with marketing_db() as db:
        return db.execute("SELECT * FROM mc_campaigns WHERE id = ?", (int(campaign_id),)).fetchone()


def _campaign_send(campaign, recipient):
    contact = {
        "email": recipient["email"], "name": recipient["name"],
        "attributes": _json_object(recipient["attributes_json"]),
    }
    subject = _template_values(campaign["subject"], contact)
    text_body = _template_values(campaign["text_body"], contact)
    html_body = _template_values(campaign["html_body"], contact)
    html_body = _tracked_campaign_html(
        html_body, campaign["id"], recipient["id"], campaign["public_url"],
        campaign["track_open"], campaign["track_click"],
    )
    return send_message({
        "from": campaign["sender"], "from_name": campaign["sender_name"],
        "to": recipient["email"], "subject": subject, "text": text_body, "html": html_body,
    })


def _run_campaign(campaign_id):
    try:
        while not CAMPAIGN_STOP.is_set():
            with marketing_db() as db:
                campaign = db.execute("SELECT * FROM mc_campaigns WHERE id = ?", (campaign_id,)).fetchone()
                if not campaign or campaign["status"] != "sending":
                    return
                recipient = db.execute(
                    "SELECT * FROM mc_campaign_recipients WHERE campaign_id = ? AND status = 'pending' ORDER BY id LIMIT 1",
                    (campaign_id,),
                ).fetchone()
            if not recipient:
                now = marketing_now()
                with marketing_db() as db:
                    db.execute("UPDATE mc_campaigns SET status = 'completed', finished_at = ?, updated_at = ? WHERE id = ?", (now, now, campaign_id))
                    db.commit()
                return
            try:
                result = _campaign_send(campaign, recipient)
                with marketing_db() as db:
                    db.execute(
                        "UPDATE mc_campaign_recipients SET status = 'sent', message_id = ?, sent_at = ? WHERE id = ?",
                        (result.get("message_id", ""), marketing_now(), recipient["id"]),
                    )
                    db.execute("UPDATE mc_campaigns SET sent = sent + 1, updated_at = ? WHERE id = ?", (marketing_now(), campaign_id))
                    db.commit()
            except Exception as exc:
                with marketing_db() as db:
                    db.execute(
                        "UPDATE mc_campaign_recipients SET status = 'failed', error = ?, sent_at = ? WHERE id = ?",
                        (str(exc)[:1000], marketing_now(), recipient["id"]),
                    )
                    db.execute("UPDATE mc_campaigns SET failed = failed + 1, last_error = ?, updated_at = ? WHERE id = ?", (str(exc)[:1000], marketing_now(), campaign_id))
                    db.commit()
            delay = 60.0 / max(1, int(campaign["rate_per_minute"])) if campaign["rate_per_minute"] else 0
            if delay:
                CAMPAIGN_STOP.wait(delay)
    finally:
        with CAMPAIGN_THREADS_LOCK:
            CAMPAIGN_THREADS.pop(int(campaign_id), None)


def start_marketing_campaign(campaign_id):
    init_marketing_db()
    campaign_id = int(campaign_id)
    with marketing_db() as db:
        campaign = db.execute("SELECT * FROM mc_campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if not campaign:
            raise ValueError("营销任务不存在")
        if campaign["status"] in {"completed", "canceled"}:
            raise ValueError("营销任务已结束")
        if campaign["total"] <= 0:
            raise ValueError("营销任务没有收件人")
        db.execute("UPDATE mc_campaigns SET status = 'sending', started_at = COALESCE(started_at, ?), updated_at = ? WHERE id = ?", (marketing_now(), marketing_now(), campaign_id))
        db.commit()
    with CAMPAIGN_THREADS_LOCK:
        thread = CAMPAIGN_THREADS.get(campaign_id)
        if thread and thread.is_alive():
            return {"started": True, "id": campaign_id}
        thread = threading.Thread(target=_run_campaign, args=(campaign_id,), daemon=True, name=f"mail-campaign-{campaign_id}")
        CAMPAIGN_THREADS[campaign_id] = thread
        thread.start()
    return {"started": True, "id": campaign_id}


def marketing_campaign_action(campaign_id, action):
    init_marketing_db()
    campaign_id = int(campaign_id)
    action = str(action or "").lower()
    if action in {"start", "resume"}:
        return start_marketing_campaign(campaign_id)
    if action not in {"pause", "cancel"}:
        raise ValueError("营销任务操作无效")
    status = "paused" if action == "pause" else "canceled"
    with marketing_db() as db:
        cursor = db.execute("UPDATE mc_campaigns SET status = ?, updated_at = ? WHERE id = ? AND status NOT IN ('completed', 'canceled')", (status, marketing_now(), campaign_id))
        db.commit()
    if not cursor.rowcount:
        raise ValueError("营销任务不存在或已结束")
    return {"id": campaign_id, "status": status}


def delete_marketing_campaign(campaign_id):
    init_marketing_db()
    campaign_id = int(campaign_id)
    with marketing_db() as db:
        row = db.execute("SELECT status FROM mc_campaigns WHERE id = ?", (campaign_id,)).fetchone()
        if not row:
            raise ValueError("营销任务不存在")
        if row["status"] == "sending":
            raise ValueError("发送中的任务请先暂停")
        db.execute("DELETE FROM mc_campaigns WHERE id = ?", (campaign_id,))
        db.commit()
    return {"deleted": campaign_id}


def marketing_summary():
    init_marketing_db()
    with marketing_db() as db:
        campaigns = db.execute("SELECT COUNT(*) FROM mc_campaigns").fetchone()[0]
        contacts = db.execute("SELECT COUNT(*) FROM mc_contacts WHERE active = 1").fetchone()[0]
        templates = db.execute("SELECT COUNT(*) FROM mc_templates WHERE active = 1").fetchone()[0]
        api_keys = db.execute("SELECT COUNT(*) FROM mc_api_keys WHERE active = 1").fetchone()[0]
        total = db.execute("SELECT COUNT(*) FROM mc_send_logs").fetchone()[0]
        sent = db.execute("SELECT COUNT(*) FROM mc_send_logs WHERE status = 'sent'").fetchone()[0]
        failed = db.execute("SELECT COUNT(*) FROM mc_send_logs WHERE status = 'failed'").fetchone()[0]
        opened = db.execute("SELECT COUNT(*) FROM mc_campaign_recipients WHERE opened_at IS NOT NULL").fetchone()[0]
        clicked = db.execute("SELECT COUNT(*) FROM mc_campaign_recipients WHERE clicked_at IS NOT NULL").fetchone()[0]
    return {
        "campaigns": campaigns, "contacts": contacts, "templates": templates, "api_keys": api_keys,
        "total": total, "sent": sent, "failed": failed,
        "delivery_rate": round(sent / total * 100, 2) if total else 0,
        "open_rate": round(opened / sent * 100, 2) if sent else 0,
        "click_rate": round(clicked / sent * 100, 2) if sent else 0,
    }


def _api_ip_values(value):
    if isinstance(value, list):
        raw_values = value
    elif isinstance(value, str) and value.strip().startswith("["):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, list):
            raw_values = parsed
        else:
            raw_values = re.split(r"[,;\n]+", value)
    else:
        raw_values = re.split(r"[,;\n]+", str(value or ""))
    values = []
    for raw in raw_values:
        item = str(raw or "").strip()
        if not item:
            continue
        try:
            values.append(str(ipaddress.ip_network(item, strict=False)) if "/" in item else str(ipaddress.ip_address(item)))
        except ValueError as exc:
            raise ValueError(f"IP 白名单格式无效：{item}") from exc
    return list(dict.fromkeys(values))


def _api_time_bound(value, end=False):
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("时间范围格式无效") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    if end and len(value) <= 10:
        parsed += datetime.timedelta(days=1)
    return parsed.astimezone(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _api_template(template_id):
    if not template_id:
        return None
    with marketing_db() as db:
        row = db.execute(
            "SELECT id, subject, text_body, html_body FROM mc_templates WHERE id = ? AND active = 1",
            (int(template_id),),
        ).fetchone()
    if not row:
        raise ValueError("API 邮件模板不存在")
    return row


def _api_settings(payload, existing=None):
    existing = dict(existing) if existing else {}
    name = str(payload.get("name", existing.get("name", "默认发件 API")) or "默认发件 API").strip()[:160]
    sender = str(payload.get("sender", existing.get("sender", "")) or "").strip().lower()
    if not sender:
        raise ValueError("API 默认发件人不能为空")
    if sender not in mailboxes():
        raise ValueError("API 默认发件人必须是当前 Mailu 中已启用的邮箱")
    template_id = int(payload.get("template_id", existing.get("template_id", 0)) or 0)
    _api_template(template_id)
    return {
        "name": name,
        "sender": sender,
        "sender_name": str(payload.get("sender_name", existing.get("sender_name", "")) or "").strip()[:160],
        "subject": str(payload.get("subject", existing.get("subject", "")) or "").strip()[:500],
        "template_id": template_id,
        "group_id": int(payload.get("group_id", existing.get("group_id", 0)) or 0) or None,
        "unsubscribe": 1 if payload.get("unsubscribe", existing.get("unsubscribe", 1)) else 0,
        "track_open": 1 if payload.get("track_open", existing.get("track_open", 1)) else 0,
        "track_click": 1 if payload.get("track_click", existing.get("track_click", 1)) else 0,
        "ip_whitelist": _api_ip_values(payload.get("ip_whitelist", existing.get("ip_whitelist", []))),
        "active": 1 if payload.get("active", existing.get("active", 1)) else 0,
        "expires_at": _iso_datetime(payload.get("expires_at", existing.get("expires_at")), default_now=False) or None,
    }


def create_marketing_api_key(payload):
    init_marketing_db()
    settings = _api_settings(payload)
    raw_key = "mc_live_" + secrets.token_urlsafe(27)
    now = marketing_now()
    with marketing_db() as db:
        cursor = db.execute(
            """
            INSERT INTO mc_api_keys(
                name, key_prefix, key_hash, sender, sender_name, subject, template_id, group_id,
                unsubscribe, track_open, track_click, ip_whitelist, active, expires_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                settings["name"], raw_key[:16], hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
                settings["sender"], settings["sender_name"], settings["subject"], settings["template_id"],
                settings["group_id"], settings["unsubscribe"], settings["track_open"], settings["track_click"],
                json.dumps(settings["ip_whitelist"], ensure_ascii=False), settings["active"], settings["expires_at"], now,
            ),
        )
        db.commit()
    return {"id": cursor.lastrowid, "name": settings["name"], "key": raw_key, **settings}


def _api_row_dict(row):
    values = dict(row)
    values["api_key"] = f"{values.pop('key_prefix', '')}..."
    values.pop("key_hash", None)
    values["api_name"] = values.get("name", "")
    values["addresser"] = values.get("sender", "")
    values["full_name"] = values.get("sender_name", "")
    values["active"] = bool(values.get("active", 0)) and not (values.get("expires_at") and values["expires_at"] <= marketing_now())
    values["ip_whitelist"] = _api_ip_values(values.get("ip_whitelist", []))
    values["server_addresser"] = f"{CONFIG.public_url}/api/v1/send" if CONFIG.public_url else "/mail-control/api/v1/send"
    values["create_time"] = values.get("created_at", "")
    return values


def marketing_api_keys(filters=None):
    init_marketing_db()
    filters = filters or {}
    page = max(1, int(filters.get("page", 1) or 1))
    page_size = min(100, max(1, int(filters.get("page_size", 10) or 10)))
    keyword = str(filters.get("keyword", "") or "").strip()
    active = filters.get("active", -1)
    start = _api_time_bound(filters.get("start_time"))
    end = _api_time_bound(filters.get("end_time"), end=True)
    where = []
    where_params = []
    join_params = []
    if keyword:
        where.append("(k.name LIKE ? OR k.sender LIKE ? OR k.subject LIKE ?)")
        where_params.extend([f"%{keyword}%"] * 3)
    if str(active) in {"0", "1"}:
        where.append("k.active = ?")
        where_params.append(int(active))
    if start:
        where.append("k.created_at >= ?")
        where_params.append(start)
    if end:
        where.append("k.created_at < ?")
        where_params.append(end)
    where_sql = " WHERE " + " AND ".join(where) if where else ""
    log_filter = ""
    if start:
        log_filter += " AND l.created_at >= ?"
        join_params.append(start)
    if end:
        log_filter += " AND l.created_at < ?"
        join_params.append(end)
    select = f"""
        SELECT k.*, COUNT(l.id) AS send_count,
               COALESCE(SUM(CASE WHEN l.status = 'sent' THEN 1 ELSE 0 END), 0) AS success_count,
               COALESCE(SUM(CASE WHEN l.status = 'failed' THEN 1 ELSE 0 END), 0) AS fail_count,
               COALESCE(SUM(CASE WHEN l.status = 'bounced' OR l.bounced_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS bounce_count,
               COALESCE(SUM(CASE WHEN l.opened_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS opened_count,
               COALESCE(SUM(CASE WHEN l.clicked_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS clicked_count
        FROM mc_api_keys k
        LEFT JOIN mc_send_logs l ON l.api_key_id = k.id{log_filter}
        {where_sql}
        GROUP BY k.id
        ORDER BY k.id DESC
        LIMIT ? OFFSET ?
    """
    count_sql = f"SELECT COUNT(*) FROM mc_api_keys k{where_sql}"
    with marketing_db() as db:
        total = db.execute(count_sql, where_params).fetchone()[0]
        rows = db.execute(select, join_params + where_params + [page_size, (page - 1) * page_size]).fetchall()
    result = []
    for row in rows:
        item = _api_row_dict(row)
        sent = int(item.get("success_count") or 0)
        total_sent = int(item.get("send_count") or 0)
        item["open_rate"] = round(int(item.get("opened_count") or 0) / sent * 100, 2) if sent else 0
        item["click_rate"] = round(int(item.get("clicked_count") or 0) / sent * 100, 2) if sent else 0
        item["bounce_rate"] = round(int(item.get("bounce_count") or 0) / total_sent * 100, 2) if total_sent else 0
        item["delivery_rate"] = round(sent / total_sent * 100, 2) if total_sent else 0
        result.append(item)
    return {"list": result, "total": total, "page": page, "page_size": page_size}


def marketing_api_overview(start_time="", end_time=""):
    init_marketing_db()
    start = _api_time_bound(start_time)
    end = _api_time_bound(end_time, end=True)
    where = ["api_key_id IS NOT NULL"]
    params = []
    if start:
        where.append("created_at >= ?")
        params.append(start)
    if end:
        where.append("created_at < ?")
        params.append(end)
    with marketing_db() as db:
        row = db.execute(
            f"""
            SELECT COUNT(*) AS total_send,
                   COALESCE(SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END), 0) AS delivered,
                   COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) AS failed,
                   COALESCE(SUM(CASE WHEN status = 'bounced' OR bounced_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS bounced,
                   COALESCE(SUM(CASE WHEN opened_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS opened,
                   COALESCE(SUM(CASE WHEN clicked_at IS NOT NULL THEN 1 ELSE 0 END), 0) AS clicked
            FROM mc_send_logs WHERE {' AND '.join(where)}
            """,
            params,
        ).fetchone()
    total = int(row["total_send"] or 0)
    delivered = int(row["delivered"] or 0)
    return {
        "total_send": total,
        "avg_delivery_rate": round(delivered / total * 100, 2) if total else 0,
        "avg_open_rate": round(int(row["opened"] or 0) / delivered * 100, 2) if delivered else 0,
        "avg_click_rate": round(int(row["clicked"] or 0) / delivered * 100, 2) if delivered else 0,
        "avg_bounce_rate": round(int(row["bounced"] or 0) / total * 100, 2) if total else 0,
        "failed": int(row["failed"] or 0),
    }


def update_marketing_api_key(payload):
    init_marketing_db()
    key_id = int(payload.get("id") or 0)
    with marketing_db() as db:
        existing = db.execute("SELECT * FROM mc_api_keys WHERE id = ?", (key_id,)).fetchone()
        if not existing:
            raise ValueError("发件 API 不存在")
        settings = _api_settings(payload, existing)
        raw_key = "mc_live_" + secrets.token_urlsafe(27) if payload.get("reset_key") else ""
        columns = [
            "name = ?", "sender = ?", "sender_name = ?", "subject = ?", "template_id = ?", "group_id = ?",
            "unsubscribe = ?", "track_open = ?", "track_click = ?", "ip_whitelist = ?", "active = ?", "expires_at = ?",
        ]
        params = [
            settings["name"], settings["sender"], settings["sender_name"], settings["subject"], settings["template_id"],
            settings["group_id"], settings["unsubscribe"], settings["track_open"], settings["track_click"],
            json.dumps(settings["ip_whitelist"], ensure_ascii=False), settings["active"], settings["expires_at"],
        ]
        if raw_key:
            columns.extend(["key_prefix = ?", "key_hash = ?"])
            params.extend([raw_key[:16], hashlib.sha256(raw_key.encode("utf-8")).hexdigest()])
        params.append(key_id)
        db.execute(f"UPDATE mc_api_keys SET {', '.join(columns)} WHERE id = ?", params)
        db.commit()
    return {"id": key_id, "key": raw_key, **settings}


def delete_marketing_api_key(key_id):
    init_marketing_db()
    with marketing_db() as db:
        cursor = db.execute("UPDATE mc_api_keys SET active = 0 WHERE id = ?", (int(key_id),))
        db.commit()
    if not cursor.rowcount:
        raise ValueError("发件 API 不存在")
    return {"deleted": int(key_id)}


def find_marketing_api_key(value):
    value = str(value or "").strip()
    if not value:
        return None
    if value.lower().startswith("bearer "):
        value = value[7:].strip()
    if len(value) > 200:
        return None
    init_marketing_db()
    with marketing_db() as db:
        row = db.execute(
            "SELECT * FROM mc_api_keys WHERE key_hash = ? AND active = 1",
            (hashlib.sha256(value.encode("utf-8")).hexdigest(),),
        ).fetchone()
        if not row:
            return None
        if row["expires_at"] and row["expires_at"] <= marketing_now():
            return None
        db.execute("UPDATE mc_api_keys SET last_used_at = ? WHERE id = ?", (marketing_now(), row["id"]))
        db.commit()
        return row


def api_key_ip_allowed(api_key, remote_ip):
    whitelist = _api_ip_values(api_key["ip_whitelist"] if "ip_whitelist" in api_key.keys() else [])
    if not whitelist:
        return True
    try:
        address = ipaddress.ip_address(str(remote_ip or "").strip())
    except ValueError:
        return False
    for item in whitelist:
        try:
            if address in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def log_marketing_send(api_key_id, campaign_id, recipient, sender, subject, status, error="", message_id=""):
    try:
        init_marketing_db()
        with marketing_db() as db:
            cursor = db.execute(
                "INSERT INTO mc_send_logs(api_key_id, campaign_id, recipient, sender, subject, status, error, message_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (api_key_id, campaign_id, recipient, sender, subject, status, error[:1000], message_id, marketing_now()),
            )
            db.commit()
            return cursor.lastrowid
    except sqlite3.Error:
        return None


def update_marketing_send(log_id, status, error="", message_id=""):
    if not log_id:
        return
    try:
        init_marketing_db()
        with marketing_db() as db:
            db.execute(
                "UPDATE mc_send_logs SET status = ?, error = ?, message_id = ? WHERE id = ?",
                (status, error[:1000], message_id, int(log_id)),
            )
            db.commit()
    except sqlite3.Error:
        pass


def _tracked_api_html(body, log_id, public_url, track_open, track_click):
    body = sanitize_html(body)
    base = str(public_url or CONFIG.public_url or "").rstrip("/")
    if not base:
        return body
    if track_click:
        def replace_link(match):
            target = match.group(2)
            if target.lower().startswith(("mailto:", "javascript:", "cid:")):
                return match.group(0)
            tracking = f"{base}/track/click?a=1&l={log_id}&u={urllib.parse.quote(target, safe='')}"
            return f"{match.group(1)}{tracking}{match.group(3)}"

        body = re.sub(r"(?i)(href\s*=\s*[\"'])(https?://[^\"']+)([\"'])", replace_link, body)
    if track_open:
        body += f'<img src="{html.escape(base)}/track/open?a=1&l={log_id}" width="1" height="1" alt="" style="display:none">'
    return body


def _api_payload_for_recipient(payload, api_key, recipient, log_id, public_url):
    if isinstance(recipient, dict):
        address = str(recipient.get("email") or recipient.get("recipient") or "").strip().lower()
        name = str(recipient.get("name") or "").strip()
        attributes = recipient.get("attributes") or recipient.get("attribs") or {}
    else:
        address, name, attributes = str(recipient).strip().lower(), "", {}
    if not isinstance(attributes, dict):
        attributes = {}
    template = _api_template(api_key["template_id"]) if api_key["template_id"] else None
    contact = {"email": address, "name": name, "attributes": attributes}
    item = dict(payload)
    item["from"] = str(payload.get("from") or api_key["sender"] or "").strip().lower()
    item["from_name"] = str(payload.get("from_name") or payload.get("sender_name") or api_key["sender_name"] or "").strip()
    item["subject"] = _template_values(str(payload.get("subject") or api_key["subject"] or (template["subject"] if template else "")), contact)
    item["text"] = _template_values(str(payload.get("text") or (template["text_body"] if template else "")), contact)
    item["html"] = _template_values(str(payload.get("html") or (template["html_body"] if template else "")), contact)
    if item["html"] and log_id:
        item["html"] = _tracked_api_html(item["html"], log_id, public_url, api_key["track_open"], api_key["track_click"])
    item["to"] = address
    item.pop("recipients", None)
    item.pop("recipient", None)
    item.pop("attribs", None)
    item.pop("attributes", None)
    return item


def send_api_message(payload, api_key, public_url=""):
    recipients = payload.get("recipients")
    if recipients is None:
        recipients = payload.get("recipient") or payload.get("to")
    if isinstance(recipients, dict):
        recipients = [recipients]
    if isinstance(recipients, str):
        recipients = [item.strip() for item in recipients.replace(";", ",").split(",") if item.strip()]
    if not isinstance(recipients, list) or not recipients:
        raise ValueError("请提供 recipient、to 或 recipients")
    if len(recipients) > MAX_BATCH_ACCOUNTS:
        raise ValueError(f"一次最多发送 {MAX_BATCH_ACCOUNTS} 个收件人")
    sender = str(payload.get("from") or api_key["sender"] or "").strip().lower()
    if sender not in mailboxes():
        raise ValueError("发件人必须是当前 Mailu 中已启用的邮箱")
    results = []
    for recipient in recipients:
        address = str(recipient.get("email") if isinstance(recipient, dict) else recipient).strip().lower()
        log_id = log_marketing_send(api_key["id"], None, address, sender, str(payload.get("subject") or api_key["subject"] or ""), "pending")
        item = _api_payload_for_recipient(payload, api_key, recipient, log_id, public_url)
        try:
            result = send_message(item)
            message_id = result.get("message_id", "")
            update_marketing_send(log_id, "sent", message_id=message_id)
            results.append({"recipient": address, "sent": True, "message_id": message_id, "log_id": log_id})
        except Exception as exc:
            update_marketing_send(log_id, "failed", str(exc))
            if len(recipients) == 1:
                raise
            results.append({"recipient": address, "sent": False, "error": str(exc), "log_id": log_id})
    if len(results) == 1:
        return results[0]
    return {
        "sent": sum(1 for item in results if item.get("sent")),
        "failed": sum(1 for item in results if not item.get("sent")),
        "results": results,
    }


def test_marketing_api_key(key_id, payload, public_url=""):
    init_marketing_db()
    with marketing_db() as db:
        api_key = db.execute("SELECT * FROM mc_api_keys WHERE id = ? AND active = 1", (int(key_id),)).fetchone()
    if not api_key:
        raise ValueError("发件 API 不存在、已停用或已过期")
    if api_key["expires_at"] and api_key["expires_at"] <= marketing_now():
        raise ValueError("发件 API 已过期")
    recipient = str(payload.get("recipient") or "").strip().lower()
    if not recipient:
        raise ValueError("测试邮箱不能为空")
    template = _api_template(api_key["template_id"]) if api_key["template_id"] else None
    test_payload = {"recipient": recipient}
    if not api_key["subject"] and not (template and template["subject"]):
        test_payload["subject"] = "API 测试邮件"
    if not (template and (template["text_body"] or template["html_body"])):
        test_payload["text"] = "这是一封 API 测试邮件，用于验证发件 API 配置。"
    return send_api_message(test_payload, api_key, public_url)


def track_open(campaign_id, recipient_id):
    init_marketing_db()
    with marketing_db() as db:
        row = db.execute("SELECT opened_at FROM mc_campaign_recipients WHERE id = ? AND campaign_id = ?", (int(recipient_id), int(campaign_id))).fetchone()
        if row and not row["opened_at"]:
            now = marketing_now()
            db.execute("UPDATE mc_campaign_recipients SET opened_at = ? WHERE id = ?", (now, int(recipient_id)))
            db.execute("UPDATE mc_campaigns SET opened = opened + 1, updated_at = ? WHERE id = ?", (now, int(campaign_id)))
            db.commit()


def track_click(campaign_id, recipient_id):
    init_marketing_db()
    with marketing_db() as db:
        row = db.execute("SELECT clicked_at FROM mc_campaign_recipients WHERE id = ? AND campaign_id = ?", (int(recipient_id), int(campaign_id))).fetchone()
        if row and not row["clicked_at"]:
            now = marketing_now()
            db.execute("UPDATE mc_campaign_recipients SET clicked_at = ? WHERE id = ?", (now, int(recipient_id)))
            db.execute("UPDATE mc_campaigns SET clicked = clicked + 1, updated_at = ? WHERE id = ?", (now, int(campaign_id)))
            db.commit()


def track_api_open(log_id):
    init_marketing_db()
    with marketing_db() as db:
        db.execute(
            "UPDATE mc_send_logs SET opened_at = COALESCE(opened_at, ?) WHERE id = ? AND api_key_id IS NOT NULL",
            (marketing_now(), int(log_id)),
        )
        db.commit()


def track_api_click(log_id):
    init_marketing_db()
    with marketing_db() as db:
        db.execute(
            "UPDATE mc_send_logs SET clicked_at = COALESCE(clicked_at, ?) WHERE id = ? AND api_key_id IS NOT NULL",
            (marketing_now(), int(log_id)),
        )
        db.commit()


def marketing_scheduler():
    while not CAMPAIGN_STOP.wait(10):
        try:
            init_marketing_db()
            now = marketing_now()
            with marketing_db() as db:
                rows = db.execute(
                    "SELECT id FROM mc_campaigns WHERE status = 'scheduled' AND send_at <= ? OR status = 'sending'",
                    (now,),
                ).fetchall()
            for row in rows:
                try:
                    start_marketing_campaign(row["id"])
                except (ValueError, OSError, sqlite3.Error):
                    continue
        except (OSError, sqlite3.Error):
            continue


def decode_value(value):
    if not value:
        return ""
    try:
        return str(email.header.make_header(email.header.decode_header(value)))
    except (ValueError, UnicodeError):
        return value


class EmailHTMLSanitizer(HTMLParser):
    """Keep normal email markup while removing active content and unsafe URLs."""

    DROP_TAGS = {"form", "iframe", "object", "script"}
    DROP_VOID = {"base", "embed", "input", "link", "meta"}
    VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.parts = []
        self.drop_depth = 0

    @staticmethod
    def safe_url(value, tag, attribute):
        value = str(value or "").strip()
        scheme = urllib.parse.urlsplit(value).scheme.lower()
        if scheme in {"javascript", "vbscript"}:
            return ""
        if scheme == "data" and not (tag == "img" and attribute == "src"):
            return ""
        if scheme == "cid" and tag != "img":
            return ""
        return value

    def _attrs(self, tag, attrs):
        output = []
        for name, value in attrs:
            name = name.lower()
            if name.startswith("on") or name in {"srcdoc", "formaction"}:
                continue
            if value is not None and name in {"href", "src", "action"}:
                value = self.safe_url(value, tag, name)
                if not value:
                    continue
            if value is None:
                output.append(f" {name}")
            else:
                output.append(f' {name}="{html.escape(value, quote=True)}"')
        return "".join(output)

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if self.drop_depth:
            if tag in self.DROP_TAGS and tag not in self.VOID_TAGS:
                self.drop_depth += 1
            return
        if tag in self.DROP_VOID:
            return
        if tag in self.DROP_TAGS:
            self.drop_depth = 1
            return
        self.parts.append(f"<{tag}{self._attrs(tag, attrs)}>")

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if self.drop_depth or tag in self.DROP_TAGS or tag in self.DROP_VOID:
            return
        self.parts.append(f"<{tag}{self._attrs(tag, attrs)} />")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.drop_depth:
            if tag in self.DROP_TAGS:
                self.drop_depth -= 1
            return
        if tag not in self.VOID_TAGS:
            self.parts.append(f"</{tag}>")

    def handle_data(self, data):
        if not self.drop_depth:
            self.parts.append(data)

    def handle_entityref(self, name):
        if not self.drop_depth:
            self.parts.append(f"&{name};")

    def handle_charref(self, name):
        if not self.drop_depth:
            self.parts.append(f"&#{name};")

    def handle_comment(self, data):
        if not self.drop_depth:
            self.parts.append(f"<!--{data}-->")


def sanitize_html(value):
    parser = EmailHTMLSanitizer()
    try:
        parser.feed(str(value or ""))
        parser.close()
        return "".join(parser.parts)
    except (TypeError, ValueError):
        return html.escape(str(value or ""))


class PlainTextExtractor(HTMLParser):
    BREAK_TAGS = {"br", "div", "li", "p", "section", "table", "tr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.BREAK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag.lower() in self.BREAK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        self.parts.append(data)


def html_to_text(value):
    parser = PlainTextExtractor()
    try:
        parser.feed(str(value or ""))
        parser.close()
        return re.sub(r"\n{3,}", "\n\n", "".join(parser.parts)).strip()
    except (TypeError, ValueError):
        return re.sub(r"<[^>]+>", " ", str(value or "")).strip()


def content_id(value):
    value = re.sub(r"[^A-Za-z0-9_.-]", "", str(value or ""))
    return value[:120]


def decode_attachment(item, index):
    if not isinstance(item, dict):
        raise ValueError("附件格式无效")
    filename = str(item.get("filename") or f"attachment-{index}").strip()
    filename = Path(filename).name[:255]
    if not filename or filename in {".", ".."}:
        filename = f"attachment-{index}"
    data_value = item.get("data_url") or item.get("data_base64") or item.get("data") or ""
    if not isinstance(data_value, str):
        raise ValueError("附件数据无效")
    data_url = ""
    content_type = str(item.get("content_type") or "").strip().lower()
    if data_value.startswith("data:"):
        header, separator, encoded = data_value.partition(",")
        if not separator or ";base64" not in header.lower():
            raise ValueError("附件必须使用 base64 数据")
        data_url = data_value
        metadata = header[5:].split(";", 1)[0].strip().lower()
        if metadata:
            content_type = content_type or metadata
        data_value = encoded
    try:
        raw = base64.b64decode(data_value, validate=True)
    except (ValueError, TypeError, base64.binascii.Error) as exc:
        raise ValueError("附件 base64 数据无效") from exc
    if not raw or len(raw) > MAX_ATTACHMENT:
        raise ValueError(f"单个附件不能超过 {MAX_ATTACHMENT // 1024 // 1024} MB")
    content_type = content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    if "/" not in content_type:
        content_type = "application/octet-stream"
    cid = content_id(item.get("content_id"))
    inline = bool(item.get("inline")) or bool(cid)
    if inline and not cid:
        cid = f"mail-control-image-{secrets.token_hex(8)}"
    return {
        "filename": filename,
        "content_type": content_type,
        "data": raw,
        "data_url": data_url,
        "cid": cid,
        "inline": inline,
    }


def parse_attachments(items):
    if items in (None, ""):
        return []
    if not isinstance(items, list) or len(items) > MAX_ATTACHMENTS:
        raise ValueError(f"附件数量不能超过 {MAX_ATTACHMENTS} 个")
    attachments = []
    total = 0
    for index, item in enumerate(items, 1):
        attachment = decode_attachment(item, index)
        total += len(attachment["data"])
        if total > MAX_TOTAL_ATTACHMENTS:
            raise ValueError(f"附件总大小不能超过 {MAX_TOTAL_ATTACHMENTS // 1024 // 1024} MB")
        attachments.append(attachment)
    return attachments


def normalize_entry(value):
    value = str(value or "").strip().lower()
    if value.startswith("@"):
        domain = value[1:]
        if not DOMAIN_RE.fullmatch(domain):
            raise ValueError("无效的域名")
        return "@" + domain
    if not EMAIL_RE.fullmatch(value):
        raise ValueError("请输入完整邮箱地址，或以 @ 开头的域名")
    return value


def read_map(kind):
    path = CONFIG.list_files[kind]
    if not path.exists():
        return []
    entries = []
    seen = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            item = normalize_entry(line)
        except ValueError:
            continue
        if item not in seen:
            seen.add(item)
            entries.append(item)
    return sorted(entries)


def write_map(kind, entries):
    path = CONFIG.list_files[kind]
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "# Managed by Mail Control\n" + "\n".join(entries) + "\n"
    with WRITE_LOCK:
        fd, temp_path = tempfile.mkstemp(prefix=f".{kind}.", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_path, 0o640)
            os.replace(temp_path, path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


def reload_rspamd():
    # Rspamd watches maps, but a HUP makes the change visible immediately.
    os.system("docker kill -s HUP mailu-antispam-1 >/dev/null 2>&1 || true")


def mailboxes():
    values = []
    if CONFIG.db_path.exists():
        try:
            with sqlite3.connect(CONFIG.db_path) as db:
                rows = db.execute(
                    "SELECT email FROM user WHERE enabled = 1 ORDER BY email"
                ).fetchall()
                values = [row[0] for row in rows if row[0]]
        except sqlite3.Error:
            values = []
    if not values and CONFIG.mail_root.exists():
        values = sorted(p.name for p in CONFIG.mail_root.iterdir() if p.is_dir() and "@" in p.name)
    return values


def normalize_domain(value):
    value = str(value or "").strip().lower().rstrip(".")
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError("域名无效")
    return value


def normalize_localpart(value, domain):
    value = str(value or "").strip().lower()
    if "@" in value:
        localpart, supplied_domain = value.rsplit("@", 1)
        if supplied_domain != domain:
            raise ValueError(f"邮箱 {value} 不属于域名 {domain}")
    else:
        localpart = value
    if not localpart or len(localpart) > 80 or not EMAIL_RE.fullmatch(f"{localpart}@{domain}"):
        raise ValueError(f"邮箱前缀无效: {value}")
    return localpart


def list_domains():
    if not CONFIG.db_path.exists():
        return []
    with sqlite3.connect(CONFIG.db_path) as db:
        rows = db.execute(
            """
            SELECT d.name, d.max_users, d.max_quota_bytes, COUNT(u.email)
            FROM domain d LEFT JOIN user u ON u.domain_name = d.name
            GROUP BY d.name, d.max_users, d.max_quota_bytes
            ORDER BY d.name
            """
        ).fetchall()
    result = []
    for name, max_users, max_quota_bytes, used in rows:
        result.append({
            "name": name,
            "max_users": max_users,
            "max_quota_bytes": max_quota_bytes,
            "used": used,
            "remaining": None if max_users == -1 else max(0, max_users - used),
        })
    return result


def list_accounts(domain):
    domain = normalize_domain(domain)
    if not CONFIG.db_path.exists():
        return []
    with sqlite3.connect(CONFIG.db_path) as db:
        rows = db.execute(
            "SELECT email, global_admin, enabled, quota_bytes, created_at, comment "
            "FROM user WHERE domain_name = ? ORDER BY email",
            (domain,),
        ).fetchall()
    return [
        {
            "email": email,
            "global_admin": bool(global_admin),
            "enabled": bool(enabled),
            "quota_bytes": quota_bytes,
            "created_at": created_at,
            "comment": comment or "",
        }
        for email, global_admin, enabled, quota_bytes, created_at, comment in rows
    ]


def parse_batch_localparts(value, domain):
    if isinstance(value, str):
        values = re.split(r"[\r\n,;]+", value)
    elif isinstance(value, list):
        values = value
    else:
        values = []
    result = []
    seen = set()
    for item in values:
        localpart = normalize_localpart(item, domain)
        if localpart not in seen:
            seen.add(localpart)
            result.append(localpart)
    if not result:
        raise ValueError("请至少填写一个邮箱前缀")
    if len(result) > MAX_BATCH_ACCOUNTS:
        raise ValueError(f"一次最多处理 {MAX_BATCH_ACCOUNTS} 个邮箱")
    return result


def create_batch_accounts(payload):
    domain = normalize_domain(payload.get("domain"))
    localparts = parse_batch_localparts(payload.get("localparts"), domain)
    generate_password = bool(payload.get("generate_password"))
    common_password = str(payload.get("password") or "")
    if not generate_password and len(common_password) < 8:
        raise ValueError("统一密码至少需要 8 个字符，或选择自动生成密码")
    change_pw_next_login = bool(payload.get("change_pw_next_login"))
    created = []
    skipped = []
    credentials = []
    today = datetime.date.today().isoformat()
    with WRITE_LOCK:
        with sqlite3.connect(CONFIG.db_path) as db:
            db.row_factory = sqlite3.Row
            domain_row = db.execute(
                "SELECT name, max_users, max_quota_bytes FROM domain WHERE name = ?",
                (domain,),
            ).fetchone()
            if not domain_row:
                raise ValueError(f"域名不存在: {domain}")
            existing = {
                row[0] for row in db.execute(
                    "SELECT localpart FROM user WHERE domain_name = ?", (domain,)
                ).fetchall()
            }
            new_localparts = [item for item in localparts if item not in existing]
            skipped = [f"{item}@{domain}" for item in localparts if item in existing]
            max_users = domain_row["max_users"]
            if max_users != -1 and len(existing) + len(new_localparts) > max_users:
                raise ValueError(
                    f"域名 {domain} 配额不足：当前 {len(existing)}/{max_users}，本次还需要 {len(new_localparts)} 个名额"
                )
            quota_bytes = int(payload.get("quota_bytes") or domain_row["max_quota_bytes"] or DEFAULT_USER_QUOTA)
            if quota_bytes <= 0:
                raise ValueError("邮箱配额必须大于 0")
            if domain_row["max_quota_bytes"] and quota_bytes > domain_row["max_quota_bytes"]:
                raise ValueError("邮箱配额不能超过域名配额上限")
            try:
                for localpart in new_localparts:
                    email_address = f"{localpart}@{domain}"
                    password = secrets.token_urlsafe(12) if generate_password else common_password
                    db.execute(
                        """
                        INSERT INTO user (
                            created_at, updated_at, comment, localpart, password,
                            quota_bytes, global_admin, enable_imap, enable_pop,
                            forward_enabled, forward_destination, reply_enabled,
                            reply_subject, reply_body, displayed_name, spam_enabled,
                            domain_name, email, spam_threshold, forward_keep,
                            reply_enddate, enabled, quota_bytes_used, reply_startdate,
                            spam_mark_as_read, allow_spoofing, change_pw_next_login
                        ) VALUES (?, NULL, '', ?, ?, ?, 0, 1, 1, 0, NULL, 0,
                                  NULL, NULL, '', 1, ?, ?, 80, 1, '2999-12-31',
                                  1, 0, '1900-01-01', 1, 0, ?)
                        """,
                        (
                            today,
                            localpart,
                            hash_mailu_password(password),
                            quota_bytes,
                            domain,
                            email_address,
                            int(change_pw_next_login),
                        ),
                    )
                    created.append(email_address)
                    if generate_password:
                        credentials.append({"email": email_address, "password": password})
                db.commit()
            except Exception:
                db.rollback()
                raise
    return {"created": created, "skipped": skipped, "credentials": credentials}


def delete_batch_accounts(payload):
    domain = normalize_domain(payload.get("domain"))
    raw_emails = payload.get("emails")
    if not isinstance(raw_emails, list) or not raw_emails:
        raise ValueError("请选择至少一个邮箱")
    emails = []
    seen = set()
    for item in raw_emails:
        localpart = normalize_localpart(item, domain)
        email_address = f"{localpart}@{domain}"
        if email_address not in seen:
            seen.add(email_address)
            emails.append(email_address)
    if len(emails) > MAX_BATCH_ACCOUNTS:
        raise ValueError(f"一次最多处理 {MAX_BATCH_ACCOUNTS} 个邮箱")
    purge_data = bool(payload.get("purge_data", True))
    deleted = []
    protected = []
    missing = []
    data_errors = []
    with WRITE_LOCK:
        with sqlite3.connect(CONFIG.db_path) as db:
            try:
                for email_address in emails:
                    row = db.execute(
                        "SELECT global_admin FROM user WHERE email = ? AND domain_name = ?",
                        (email_address, domain),
                    ).fetchone()
                    if row is None:
                        missing.append(email_address)
                        continue
                    if row[0]:
                        protected.append(email_address)
                        continue
                    for table in ("fetch", "manager", "token"):
                        try:
                            db.execute(f"DELETE FROM {table} WHERE user_email = ?", (email_address,))
                        except sqlite3.OperationalError:
                            pass
                    db.execute("DELETE FROM user WHERE email = ?", (email_address,))
                    deleted.append(email_address)
                db.commit()
            except Exception:
                db.rollback()
                raise
        if purge_data:
            root = CONFIG.mail_root.resolve()
            for email_address in deleted:
                mailbox_path = (CONFIG.mail_root / email_address).resolve()
                if root not in mailbox_path.parents:
                    data_errors.append(f"{email_address}: 邮箱路径无效")
                    continue
                try:
                    if mailbox_path.is_symlink():
                        mailbox_path.unlink()
                    elif mailbox_path.is_dir():
                        shutil.rmtree(mailbox_path)
                except OSError as exc:
                    data_errors.append(f"{email_address}: {exc}")
    return {
        "deleted": deleted,
        "protected": protected,
        "missing": missing,
        "data_errors": data_errors,
    }


def safe_mailbox(value):
    if value not in mailboxes():
        raise ValueError("邮箱不存在或已停用")
    path = (CONFIG.mail_root / value).resolve()
    root = CONFIG.mail_root.resolve()
    if root not in path.parents or not path.is_dir():
        raise ValueError("邮箱路径无效")
    return path


def message_files(mailbox, new_only=False, folder=""):
    root = safe_mailbox(mailbox)
    return _message_files(root, new_only, folder)


def _message_files(root, new_only=False, folder=""):
    folders = []
    # Walk mailbox directories, never message files, tmp or virtual indexes.
    for directory, children, _ in os.walk(root, followlinks=False):
        parent = Path(directory)
        for name in ("new", "cur"):
            candidate = parent / name
            if name not in children or candidate.is_symlink() or (new_only and name != "new"):
                continue
            relative = parent.relative_to(root).as_posix()
            folder_name = "INBOX" if relative == "." else relative
            if not folder or folder == "ALL" or folder_name == folder:
                folders.append((candidate, folder_name))
        children[:] = [name for name in children if name not in {"new", "cur", "tmp", "virtual"}]
    result = []
    for folder_path, folder_name in folders:
        with os.scandir(folder_path) as entries:
            for item in entries:
                try:
                    if item.is_file(follow_symlinks=False) and not item.name.startswith("."):
                        relative = Path(item.path).relative_to(root).as_posix()
                        result.append((item.stat().st_mtime, relative, folder_name))
                except FileNotFoundError:
                    continue  # IMAP can rename a message while it is being listed.
    return sorted(result, reverse=True)


def safe_message(mailbox, relative):
    root = safe_mailbox(mailbox)
    relative = urllib.parse.unquote(relative or "")
    path = (root / relative).resolve()
    if root not in path.parents or path.parent.name not in {"new", "cur"} or not path.is_file():
        raise ValueError("邮件路径无效")
    return path


def release_message(mailbox, relative):
    root = safe_mailbox(mailbox)
    relative = urllib.parse.unquote(relative or "")
    path = (root / relative).resolve()
    if root not in path.parents or path.parent.name not in {"new", "cur"}:
        raise ValueError("邮件路径无效")
    junk_folders = {".Junk", ".Spam", ".Quarantine", "Junk", "Spam", "Quarantine"}
    if path.parent.parent.name not in junk_folders or not path.is_file():
        raise ValueError("只有垃圾邮件或隔离区中的邮件可以放行")
    target_dir = root / path.parent.name
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / path.name
    if target.exists():
        target = target_dir / f"{path.name}.released-{secrets.token_hex(6)}"
    with WRITE_LOCK:
        os.replace(path, target)
    return {
        "released": True,
        "mailbox": mailbox,
        "from": relative,
        "path": target.relative_to(root).as_posix(),
    }


def parse_message(path):
    raw = path.read_bytes()
    message = BytesParser(policy=email.policy.default).parsebytes(raw)
    text_parts = []
    html_parts = []
    attachments = []
    inline_images = {}
    for part_index, part in enumerate(message.walk()):
        if part.is_multipart():
            continue
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        content_type = part.get_content_type()
        payload = part.get_payload(decode=True) or b""
        cid = str(part.get("Content-ID") or "").strip().strip("<>")
        if cid and content_type.startswith("image/") and payload:
            inline_images[cid] = f"data:{content_type};base64,{base64.b64encode(payload).decode('ascii')}"
        if disposition == "attachment" or (filename and not cid):
            attachments.append({
                "part": part_index,
                "filename": decode_value(filename or "attachment"),
                "content_type": content_type,
                "size": len(payload),
            })
            continue
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            content = payload.decode("utf-8", "replace")
        if not isinstance(content, str):
            content = payload.decode("utf-8", "replace")
        if content_type == "text/html":
            html_parts.append(content)
        elif content_type == "text/plain":
            text_parts.append(content)
    html_body = "\n\n".join(html_parts)
    for cid, data_url in inline_images.items():
        html_body = html_body.replace(f"cid:{cid}", data_url).replace(f"cid:<{cid}>", data_url)
    return {
        "subject": decode_value(message.get("subject")),
        "from": decode_value(message.get("from")),
        "to": decode_value(message.get("to")),
        "cc": decode_value(message.get("cc")),
        "date": decode_value(message.get("date")),
        "message_id": decode_value(message.get("message-id")),
        "text": "\n\n".join(text_parts),
        "html": sanitize_html(html_body),
        "attachments": attachments,
        "size": len(raw),
    }


@lru_cache(maxsize=4096)
def _message_headers(path, file_id):
    # Stop at the MIME header boundary instead of reading attachments for a list.
    headers = bytearray()
    with path.open("rb") as stream:
        for line in stream:
            headers.extend(line)
            if line in {b"\n", b"\r\n"} or len(headers) >= MAX_BODY:
                break
    message = email.parser.BytesHeaderParser(policy=email.policy.default).parsebytes(headers)
    return {key: decode_value(message.get(key)) for key in ("subject", "from", "to", "cc", "date")}


def list_messages(mailbox, scope="new", folder="", query="", offset=0, limit=50):
    new_only = scope != "all"
    query = str(query or "").strip().lower()
    root = safe_mailbox(mailbox)
    all_files = _message_files(root, new_only)
    folders = sorted({item[2] for item in all_files})
    candidates = [item for item in all_files if not folder or folder == "ALL" or item[2] == folder]
    result = []
    total = 0 if query else len(candidates)
    for _, relative, folder_name in (candidates if query else candidates[offset:offset + limit]):
        try:
            path = (root / relative).resolve()
            if root not in path.parents:
                continue
            stat = path.stat()
            parsed = _message_headers(path, (stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size))
            haystack = " ".join(
                parsed.get(key, "") for key in ("subject", "from", "to", "cc")
            ).lower()
            if query and query not in haystack:
                continue
            if query:
                total += 1
                if total <= offset or len(result) >= limit:
                    continue
            result.append({
                "path": relative,
                "folder": folder_name,
                "subject": parsed["subject"],
                "from": parsed["from"],
                "to": parsed["to"],
                "date": parsed["date"],
                "size": stat.st_size,
            })
        except (OSError, ValueError, email.errors.MessageParseError):
            continue
    return {"messages": result, "total": total, "folders": folders}


def global_mailboxes():
    """Include retained mail for disabled accounts as well as active accounts."""
    values = set()
    if CONFIG.db_path.exists():
        with sqlite3.connect(CONFIG.db_path) as db:
            values.update(row[0] for row in db.execute('SELECT email FROM user') if row[0])
    if CONFIG.mail_root.exists():
        values.update(p.name for p in CONFIG.mail_root.iterdir()
                      if p.is_dir() and not p.is_symlink() and EMAIL_RE.fullmatch(p.name))
    return sorted(values)


def global_mailbox_root(mailbox, allowed=None):
    allowed = global_mailboxes() if allowed is None else allowed
    if mailbox not in allowed or '/' in mailbox or '\\' in mailbox:
        raise ValueError('邮箱不存在')
    base = CONFIG.mail_root.resolve()
    root = CONFIG.mail_root / mailbox
    if root.is_symlink() or base not in root.resolve().parents:
        raise ValueError('邮箱路径无效')
    return root.resolve()


def global_filters(mailbox='', domain='', prefix=''):
    mailbox = str(mailbox or '').strip().lower()
    domain = normalize_domain(domain) if domain else ''
    prefix = str(prefix or '').strip().lower()
    if prefix and not domain:
        raise ValueError('指定邮箱前缀时，请同时选择域名')
    if prefix:
        if any(c in prefix for c in '@/\\') or any(ord(c) < 33 for c in prefix):
            raise ValueError('邮箱前缀无效')
        exact = prefix + '@' + domain
        if mailbox and mailbox != exact:
            raise ValueError('完整邮箱与前缀、域名不一致')
        mailbox = exact
    if mailbox and (not EMAIL_RE.fullmatch(mailbox) or '/' in mailbox or '\\' in mailbox):
        raise ValueError('邮箱地址无效')
    if mailbox and domain and mailbox.rsplit('@', 1)[1] != domain:
        raise ValueError('邮箱不属于指定域名')
    allowed = global_mailboxes()
    selected = [box for box in allowed if (not mailbox or box.lower() == mailbox)
                and (not domain or box.rsplit('@', 1)[-1].lower() == domain)]
    return allowed, selected


def list_global_messages(mailbox='', domain='', prefix='', scope='all', folder='', query='', offset=0, limit=50):
    if scope not in {'all', 'unread'}:
        raise ValueError('邮件范围无效')
    allowed, selected = global_filters(mailbox, domain, prefix)
    query = str(query or '').strip().lower()
    candidates = []
    folders = set()
    for box in selected:
        root = global_mailbox_root(box, allowed)
        if not root.is_dir():
            continue
        try:
            files = _message_files(root)
        except FileNotFoundError:
            continue
        for modified, relative, folder_name in files:
            folders.add(folder_name)
            unread = 'S' not in Path(relative).name.partition(':2,')[2]
            if (folder and folder != 'ALL' and folder_name != folder) or (scope == 'unread' and not unread):
                continue
            candidates.append((modified, box, relative, folder_name, unread, root))
    candidates.sort(key=lambda item: item[:3], reverse=True)
    results = []
    total = 0 if query else len(candidates)
    for modified, box, relative, folder_name, unread, root in (candidates if query else candidates[offset:offset + limit]):
        try:
            path = (root / relative).resolve()
            if root not in path.parents or path.is_symlink():
                continue
            stat = path.stat()
            headers = _message_headers(path, (stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size))
            if query:
                if query not in ' '.join([box] + [headers[k] for k in ('subject', 'from', 'to', 'cc')]).lower():
                    continue
                total += 1
                if total <= offset or len(results) >= limit:
                    continue
            results.append({'mailbox': box, 'id': path.name.split(':2,', 1)[0],
                            'folder': folder_name, 'unread': unread, 'received_at': modified,
                            'size': stat.st_size, **headers})
        except (OSError, ValueError, email.errors.MessageParseError):
            continue
    return {'messages': results, 'total': total, 'folders': sorted(folders),
            'mailboxes': len(selected), 'offset': offset, 'limit': limit}


def global_message_path(mailbox, message_id, folder):
    root = global_mailbox_root(mailbox)
    message_id = str(message_id or '')
    folder = str(folder or '')
    if not message_id or message_id in {'.', '..'} or any(c in message_id for c in '/\\:') or any(ord(c) < 32 for c in message_id):
        raise ValueError('邮件标识无效')
    if not folder or folder == 'ALL' or '\\' in folder or any(ord(c) < 32 for c in folder):
        raise ValueError('邮件文件夹无效')
    parent = root if folder == 'INBOX' else (root / folder)
    resolved = parent.resolve()
    if (resolved != root and root not in resolved.parents) or parent.is_symlink():
        raise ValueError('邮件文件夹无效')
    for name in ('new', 'cur'):
        directory = parent / name
        if directory.is_symlink() or not directory.is_dir():
            continue
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.name.split(':2,', 1)[0] == message_id and entry.is_file(follow_symlinks=False):
                    return Path(entry.path)
    raise ValueError('邮件已删除或已移到其他文件夹，请刷新列表')


def _doveadm(*arguments):
    try:
        result = subprocess.run(['docker', 'exec', 'mailu-imap-1', 'doveadm', *arguments],
                                capture_output=True, text=True, timeout=45)
    except subprocess.TimeoutExpired:
        raise ValueError('邮件服务操作超时，请刷新确认结果后重试')
    if result.returncode:
        logging.error('Dovecot operation failed: %s', result.stderr[:1000])
        raise ValueError('邮件服务操作失败，请稍后重试')
    return result.stdout


def delete_global_messages(payload):
    items = payload.get('messages')
    if not isinstance(items, list) or not 1 <= len(items) <= 100:
        raise ValueError('每次请选择 1 到 100 封邮件')
    groups = {}
    seen = set()
    # Validate the entire selection before mutating any mailbox.
    for item in items:
        if not isinstance(item, dict):
            raise ValueError('邮件参数无效')
        key = (str(item.get('mailbox', '')), str(item.get('id', '')), str(item.get('folder', '')))
        if key in seen:
            continue
        global_message_path(*key)
        seen.add(key)
        groups.setdefault((key[0], key[2]), []).append(key)
    plans = []
    for (mailbox, folder), keys in groups.items():
        dove_folder = folder[1:] if folder.startswith('.') else folder
        output = _doveadm('fetch', '-u', mailbox, 'uid mailbox-guid storageid mailbox', 'mailbox', dove_folder)
        records = []
        for block in output.split('\f'):
            record = dict(line.split(': ', 1) for line in block.strip().splitlines() if ': ' in line)
            if record:
                records.append(record)
        for key in keys:
            matches = [r for r in records if r.get('storageid') == key[1] and r.get('mailbox') == dove_folder]
            if len(matches) != 1:
                raise ValueError('邮件位置已变化，请刷新列表后重新选择')
            match = matches[0]
            uid, guid = match.get('uid', ''), match.get('mailbox-guid', '')
            if not uid.isdigit() or not re.fullmatch('[a-fA-F0-9]{32}', guid):
                raise ValueError('邮件索引无效')
            plans.append((key, guid, uid))
    deleted, errors = [], []
    with WRITE_LOCK:
        for key, guid, uid in plans:
            try:
                _doveadm('expunge', '-u', key[0], 'mailbox-guid', guid, 'uid', uid)
                deleted.append({'mailbox': key[0], 'id': key[1], 'folder': key[2]})
                logging.warning('Global admin expunged message: mailbox=%r folder=%r uid=%s', key[0], key[2], uid)
            except (ValueError, OSError) as exc:
                errors.append({'mailbox': key[0], 'id': key[1], 'error': str(exc)})
    _message_headers.cache_clear()
    return {'deleted': deleted, 'errors': errors}



def address_list(value, label):
    if isinstance(value, str):
        values = [item.strip().lower() for item in value.replace(";", ",").split(",") if item.strip()]
    elif isinstance(value, list):
        values = [str(item).strip().lower() for item in value if str(item).strip()]
    else:
        values = []
    if any(not EMAIL_RE.fullmatch(item) for item in values):
        raise ValueError(f"{label}必须是有效邮箱地址")
    return values


CUSTOM_LOCAL_RE = re.compile(r"^[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*$", re.I)


def custom_send_message(payload):
    domain = normalize_domain(payload.get("domain"))
    prefix = str(payload.get("prefix") or "").strip().lower()
    if len(prefix) > 64 or not CUSTOM_LOCAL_RE.fullmatch(prefix):
        raise ValueError("发件前缀无效；只能使用合法邮箱字符")
    if not any(item["name"] == domain for item in list_domains()):
        raise ValueError("发件域名必须是本站已存在的域名")
    forwarded = dict(payload)
    forwarded["from"] = prefix + "@" + domain
    return send_message(forwarded, allow_unlisted_sender=True)


def send_message(payload, allow_unlisted_sender=False):
    sender = str(payload.get("from") or "").strip().lower()
    recipients = address_list(payload.get("to"), "收件人")
    cc = address_list(payload.get("cc"), "抄送人")
    bcc = address_list(payload.get("bcc"), "密送人")
    if not sender:
        raise ValueError("发件人无效")
    if not allow_unlisted_sender and sender not in mailboxes():
        raise ValueError("发件人必须是当前 Mailu 中已启用的邮箱")
    if not recipients and not cc and not bcc:
        raise ValueError("至少填写一个收件人、抄送人或密送人")
    subject = str(payload.get("subject") or "")[:500]
    text = str(payload.get("text") or "")[:MAX_BODY]
    html_body = str(payload.get("html") or "")[:MAX_BODY]
    attachments = parse_attachments(payload.get("attachments"))
    if not subject and not text and not html_body and not attachments:
        raise ValueError("主题、正文和附件不能同时为空")

    for attachment in attachments:
        if attachment["inline"] and attachment["data_url"] and attachment["cid"]:
            html_body = html_body.replace(attachment["data_url"], f"cid:{attachment['cid']}")

    if html_body and not text:
        text = html_to_text(html_body)[:MAX_BODY]
    message = EmailMessage()
    sender_name = str(payload.get("from_name") or payload.get("sender_name") or "").strip()[:160]
    message["From"] = formataddr((sender_name, sender)) if sender_name else sender
    if recipients:
        message["To"] = ", ".join(recipients)
    if cc:
        message["Cc"] = ", ".join(cc)
    if bcc:
        message["Bcc"] = ", ".join(bcc)
    reply_to = str(payload.get("reply_to") or "").strip()
    if reply_to:
        if not EMAIL_RE.fullmatch(reply_to):
            raise ValueError("回复地址必须是有效邮箱地址")
        message["Reply-To"] = reply_to
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid()
    message["X-Mail-Control"] = "admin-api"
    message.set_content(text or " ")
    if html_body:
        message.add_alternative(html_body, subtype="html")
        alternative = message.get_payload()[-1]
        for attachment in attachments:
            if attachment["inline"]:
                maintype, subtype = attachment["content_type"].split("/", 1)
                alternative.add_related(
                    attachment["data"],
                    maintype=maintype,
                    subtype=subtype,
                    cid=f"<{attachment['cid']}>",
                    filename=attachment["filename"],
                )
    for attachment in attachments:
        if html_body and attachment["inline"]:
            continue
        maintype, subtype = attachment["content_type"].split("/", 1)
        message.add_attachment(
            attachment["data"],
            maintype=maintype,
            subtype=subtype,
            filename=attachment["filename"],
        )
    all_recipients = recipients + cc + bcc
    if payload.get("dry_run", False):
        return {
            "dry_run": True,
            "from": sender,
            "to": recipients,
            "cc": cc,
            "bcc": bcc,
            "subject": subject,
            "html": bool(html_body),
            "attachments": [{"filename": item["filename"], "size": len(item["data"]), "inline": item["inline"]} for item in attachments],
            "size": len(message.as_bytes()),
        }
    with smtplib.SMTP("127.0.0.1", 25, timeout=20) as smtp:
        smtp.send_message(message, from_addr=sender, to_addrs=all_recipients)
    return {"sent": True, "from": sender, "to": recipients, "cc": cc, "bcc": bcc, "subject": subject, "attachments": len(attachments), "message_id": message["Message-ID"]}


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False).encode("utf-8")



MESSAGE_VIEWER_JS = 'window.MailViewer=(()=>{\n const esc=s=>String(s??\'\').replace(/[&<>"\']/g,c=>({\'&\':\'&amp;\',\'<\':\'&lt;\',\'>\':\'&gt;\',\'"\':\'&quot;\',"\'":\'&#39;\'}[c]));\n const states=new WeakMap();\n function clear(frame){const state=states.get(frame);if(state){state.observer?.disconnect();clearInterval(state.timer);if(state.blob)URL.revokeObjectURL(state.blob)}frame.onload=null;frame.removeAttribute(\'srcdoc\');frame.src=\'about:blank\';states.delete(frame)}\n function resize(frame){try{const doc=frame.contentDocument;if(!doc?.body)return;const body=doc.body;const max=Math.max(120,Math.floor(innerHeight*.60));frame.style.height=Math.min(max,Math.max(100,Math.ceil(body.getBoundingClientRect().height)+4))+\'px\';frame.style.minHeight=\'0\';}catch(e){}}\n function setup(frame,blob){frame.removeAttribute(\'srcdoc\');frame.setAttribute(\'sandbox\',\'allow-same-origin allow-popups allow-popups-to-escape-sandbox\');const state={blob,attempts:0};states.set(frame,state);function watch(){try{const doc=frame.contentDocument;if(!doc?.body||doc.URL!==frame.src)return false;resize(frame);if(state.document!==doc){state.document=doc;state.observer?.disconnect();state.observer=new ResizeObserver(()=>resize(frame));state.observer.observe(doc.body);doc.querySelectorAll(\'img\').forEach(img=>img.addEventListener(\'load\',()=>resize(frame),{once:true}));}return true;}catch(e){return false}}frame.onload=()=>{if(watch())clearInterval(state.timer)};state.timer=setInterval(()=>{if(watch()||++state.attempts>=300)clearInterval(state.timer)},100);frame.style.height=\'120px\';}\n function show(frame,value,url){clear(frame);setup(frame);frame.src=url;}\n function preview(frame,value){clear(frame);const doc=new DOMParser().parseFromString(value||\'<p>暂无正文</p>\',\'text/html\');doc.querySelectorAll(\'script,iframe,object,embed,base,meta,link,form,input\').forEach(n=>n.remove());doc.querySelectorAll(\'*\').forEach(n=>[...n.attributes].forEach(a=>{if(/^on/i.test(a.name)||a.name===\'srcdoc\'||(/^(href|src)$/i.test(a.name)&&/^\\s*(javascript|vbscript):/i.test(a.value)))n.removeAttribute(a.name)}));const markup=\'<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \\\'none\\\'; style-src \\\'unsafe-inline\\\'; img-src data: https:; script-src \\\'none\\\'; base-uri \\\'none\\\'; form-action \\\'none\\\'"><style>body{font:14px/1.65 system-ui;margin:0;padding:16px;overflow-wrap:anywhere}img{max-width:100%;height:auto}pre{white-space:pre-wrap}</style>\'+doc.body.innerHTML;const blob=URL.createObjectURL(new Blob([markup],{type:\'text/html;charset=utf-8\'}));setup(frame,blob);frame.src=blob;}\n function attachments(element,value,base,identity){element.innerHTML=value.attachments?.length?\'<b>附件：</b>\'+value.attachments.map(a=>\'<a download href="\'+esc(base+new URLSearchParams({...identity,part:a.part}))+\'">\'+esc(a.filename)+\' (\'+Math.ceil(a.size/1024)+\' KB)</a>\').join(\' · \'):\'无附件\';}\n addEventListener(\'resize\',()=>document.querySelectorAll(\'.message-frame,iframe[src^="blob:"]\').forEach(resize));\n return {show,clear,preview,attachments};\n})();\n'
MESSAGE_VIEWER_CSS = 'dialog{position:fixed;inset:auto;top:50%;left:50%;transform:translate(-50%,-50%);margin:0;width:min(880px,calc(100vw - 32px));max-height:calc(100dvh - 32px);height:auto;overflow:auto;padding:20px;border-radius:8px}dialog .message-frame{display:block;height:120px;min-height:0;max-height:60vh;background:#fff}dialog pre{min-height:0;max-height:60vh}dialog .modal-head{align-items:flex-start}dialog .modal-head button{flex-shrink:0}.modal{position:fixed;inset:0;align-items:center;justify-content:center;padding:16px;z-index:1100}.modal-dialog,.modal-box,.modal-card{height:auto!important;width:min(880px,100%)!important;max-height:calc(100dvh - 32px)!important;overflow:auto!important;margin:auto}.modal-content{flex:0 1 auto;overflow:auto}.message-frame{display:block;min-height:0!important;max-height:60vh!important;height:120px;width:100%;background:#fff}.message-text{min-height:0;max-height:60vh!important}.message-attachments a,#attachments a{color:var(--accent,#1677a8);overflow-wrap:anywhere}.modal-head{flex-shrink:0}.modal-head h2,.modal-head h3{overflow-wrap:anywhere}.modal-head button{flex-shrink:0}.modal.hidden,.message-frame.hidden{display:none}@media(max-width:760px){.modal{padding:10px}.modal-dialog,.modal-box,.modal-card{width:100%!important;max-height:calc(100dvh - 20px)!important;height:auto!important;border-radius:8px}.modal-content{padding:0 14px 14px}dialog{width:calc(100vw - 20px);max-height:calc(100dvh - 20px);padding:14px}}\n'

NAVIGATION_JS = '(function () {\n  \'use strict\';\n  var rootPath = \'/admin/mail-control/\';\n  var entries = [\n    {label: \'邮件控制\', path: \'\', icon: \'fa-envelope\'},\n    {label: \'全局邮件查询\', path: \'global/\', icon: \'fa-search\'},\n    {label: \'自定义发件\', path: \'custom-send/\', icon: \'fa-paper-plane\'},\n    {label: \'批量邮箱\', path: \'accounts/\', icon: \'fa-users\'},\n    {label: \'邮件营销\', path: \'marketing/\', icon: \'fa-bullhorn\'},\n    {label: \'发件 API\', path: \'marketing/?tab=api\', icon: \'fa-code\'}\n  ];\n\n  function selected(item) {\n    var current = location.pathname.replace(/\\/+$/, \'\') || \'/\';\n    var target = new URL(rootPath + item.path, location.origin);\n    if (item.path === \'marketing/?tab=api\') {\n      return current === target.pathname.replace(/\\/+$/, \'\') && new URLSearchParams(location.search).get(\'tab\') === \'api\';\n    }\n    if (item.path === \'marketing/\') {\n      return current.indexOf(rootPath + \'marketing\') === 0 && new URLSearchParams(location.search).get(\'tab\') !== \'api\';\n    }\n    return current === target.pathname.replace(/\\/+$/, \'\');\n  }\n\n  function installLinks(sidebar) {\n    var list = sidebar.querySelector(\'.nav-sidebar\');\n    // The original admin template exposes this link only to global administrators.\n    if (!list || !list.querySelector(\'a[href="/admin/admin/list"]\') || list.querySelector(\'[data-mail-control-nav]\')) return false;\n    var domain = list.querySelector(\'a[href="/admin/domain"]\');\n    var before = domain ? domain.closest(\'li\').nextElementSibling : null;\n    var heading = document.createElement(\'li\');\n    heading.className = \'nav-header text-uppercase text-primary\';\n    heading.dataset.mailControlNav = \'header\';\n    heading.setAttribute(\'role\', \'none\');\n    heading.textContent = \'邮件工具\';\n    list.insertBefore(heading, before);\n    entries.forEach(function (item) {\n      var li = document.createElement(\'li\');\n      li.className = \'nav-item\';\n      li.dataset.mailControlNav = item.path || \'control\';\n      li.setAttribute(\'role\', \'none\');\n      var link = document.createElement(\'a\');\n      link.href = rootPath + item.path;\n      link.className = \'nav-link\' + (selected(item) ? \' active\' : \'\');\n      link.setAttribute(\'role\', \'menuitem\');\n      if (selected(item)) link.setAttribute(\'aria-current\', \'page\');\n      var icon = document.createElement(\'i\');\n      icon.className = \'nav-icon fa \' + item.icon;\n      icon.setAttribute(\'aria-hidden\', \'true\');\n      var label = document.createElement(\'p\');\n      label.textContent = item.label;\n      link.append(icon, label);\n      li.appendChild(link);\n      list.insertBefore(li, before);\n    });\n    return true;\n  }\n\n  function safeSidebar(source) {\n    var sidebar = source.cloneNode(true);\n    sidebar.querySelectorAll(\'a[href]\').forEach(function(link){\n      var url=new URL(link.getAttribute(\'href\'),location.origin);\n      if(url.origin===location.origin && url.pathname.indexOf(\'/admin/antispam\')===0){link.href=\'/admin/antispam/\';link.removeAttribute(\'target\');link.removeAttribute(\'data-clicked\');}\n    });\n    sidebar.querySelectorAll(\'script, style, iframe, form\').forEach(function (node) { node.remove(); });\n    sidebar.querySelectorAll(\'*\').forEach(function (node) {\n      Array.from(node.attributes).forEach(function (attribute) {\n        if (/^on/i.test(attribute.name)) node.removeAttribute(attribute.name);\n      });\n    });\n    sidebar.querySelectorAll(\'a.active\').forEach(function (link) { link.classList.remove(\'active\'); link.removeAttribute(\'aria-current\'); });\n    return sidebar;\n  }\n\n  async function toolShell() {\n    if (document.getElementById(\'mail-control-side-nav\')) return;\n    var response = await (window.flowNavigationResponse || fetch(\'/admin/domain\', {cache: \'no-store\', credentials: \'same-origin\'}));\n    if (!response) response = await fetch(\'/admin/domain\', {cache: \'no-store\', credentials: \'same-origin\'});\n    if (!response.ok || new URL(response.url).pathname.indexOf(\'/admin/\') !== 0) throw Error(\'管理导航加载失败\');\n    var original = new DOMParser().parseFromString(await response.text(), \'text/html\');\n    var source = original.querySelector(\'.sidebar\');\n    if (!source) throw Error(\'管理导航加载失败\');\n    var sidebar = safeSidebar(source);\n    if (!installLinks(sidebar)) return;\n\n    var host = document.createElement(\'aside\');\n    host.id = \'mail-control-side-nav\';\n    host.setAttribute(\'aria-label\', \'Mailu 导航\');\n    var shadow = host.attachShadow({mode: \'open\'});\n    // Shadow styles keep the Mailu framework from changing the tool forms and dialogs.\n    original.querySelectorAll(\'head link[rel="stylesheet"]\').forEach(function (link) {\n      var url = new URL(link.getAttribute(\'href\'), location.origin);\n      if (url.pathname.indexOf(\'/admin/mail-control/ui/\') === 0) return;\n      if (url.origin !== location.origin) return;\n      var copy = document.createElement(\'link\');\n      copy.rel = \'stylesheet\';\n      copy.href = url.href;\n      copy.onload = function () {\n        // Chrome does not register @font-face rules contained only in a shadow tree.\n        var rules;\n        try { rules = Array.from(copy.sheet.cssRules); } catch (error) { return; }\n        rules.filter(function (rule) {\n          return rule.type === CSSRule.FONT_FACE_RULE;\n        }).forEach(function (rule) {\n          try {\n          var family = rule.style.getPropertyValue(\'font-family\').replace(/^"|"$/g, \'\');\n          var source = rule.style.getPropertyValue(\'src\').replace(/url\\(([\'"]?)(.*?)\\1\\)/g, function (match, quote, value) {\n            var fontUrl = new URL(value, url.href);\n            if (fontUrl.origin !== location.origin) throw Error(\'Font origin is not allowed\');\n            return \'url(\' + JSON.stringify(fontUrl.href) + \')\';\n          });\n          var font = new FontFace(family, source, {\n            style: rule.style.getPropertyValue(\'font-style\') || \'normal\',\n            weight: rule.style.getPropertyValue(\'font-weight\') || \'normal\',\n            display: \'swap\'\n          });\n          document.fonts.add(font);\n          font.load().catch(function () {});\n          } catch (error) {}\n        });\n      };\n      shadow.appendChild(copy);\n    });\n    var style = document.createElement(\'style\');\n    style.textContent = \':host{display:block;font:14px system-ui,sans-serif;color:#c2c7d0;background:#343a40;letter-spacing:0}.sidebar{height:calc(100% - 58px);padding:0 8px;overflow-y:auto!important}.brand{height:58px;display:flex;align-items:center;padding:0 20px;border-bottom:1px solid #4b545c;font-size:20px;color:#fff;text-decoration:none}.nav-sidebar{list-style:none;padding:0;margin:0}.nav-sidebar .nav-header{font-size:12px;padding:10px 12px 6px;color:#8db3d8!important}.nav-sidebar .nav-link{display:flex;align-items:center;gap:8px;margin-bottom:3px;padding:8px 12px;border-radius:4px;color:#c2c7d0;text-decoration:none;white-space:normal}.nav-sidebar .nav-link:hover,.nav-sidebar .nav-link:focus-visible{background:#ffffff1a;color:#fff}.nav-sidebar .nav-link.active{background:#007bff;color:#fff}.nav-sidebar .nav-icon{flex:none;width:22px;text-align:center}.nav-sidebar p{margin:0;line-height:20px;overflow-wrap:anywhere}.user-panel .info{min-width:0}.user-panel .info a{color:#c2c7d0;overflow-wrap:anywhere}.user-panel{border-bottom:1px solid #4b545c}.close-nav{display:none;position:absolute;right:8px;top:11px;width:36px;height:36px;border:0;background:transparent;color:white;cursor:pointer;font:26px system-ui}.close-nav:focus-visible{outline:2px solid #fff}@media(max-width:900px){.close-nav{display:block}}\';\n    shadow.appendChild(style);\n    var flowStyle = document.createElement("style");\n    flowStyle.dataset.flowSidebar = "true";\n    flowStyle.textContent = \'/* Shared native/Shadow DOM sidebar. Existing menu nodes and permissions stay intact. */\\n:host {\\n  --flow-text:#2d3544; --flow-muted:#68788e; --flow-line:#e6eaf0;\\n  --flow-blue:#3c68cb; --flow-blue-soft:#edf2fc; --flow-sidebar:#f9fafc;\\n  display:block; width:194px!important; color:var(--flow-text); background:var(--flow-sidebar)!important;\\n  font:14px/1.5 Inter,"Noto Sans SC","Microsoft YaHei",system-ui,sans-serif;\\n  letter-spacing:0; color-scheme:light;\\n}\\n.flow-sidebar-surface { --flow-text:#2d3544; --flow-muted:#68788e; --flow-line:#e6eaf0; --flow-blue:#3c68cb; --flow-blue-soft:#edf2fc; --flow-sidebar:#f9fafc; }\\n.flow-sidebar-surface, :host { box-shadow:none!important; border-right:1px solid var(--flow-line)!important; }\\n:host *, .flow-sidebar-surface * { box-sizing:border-box; letter-spacing:0; }\\n:host .brand, .flow-sidebar-surface .brand-link {\\n  display:flex!important; align-items:center; gap:10px; height:74px; min-height:74px;\\n  padding:0 20px!important; margin:0; color:var(--flow-text)!important; background:var(--flow-sidebar)!important;\\n  border-bottom:1px solid var(--flow-line)!important; font-size:22px!important; font-weight:650;\\n  line-height:1.2; text-decoration:none; white-space:normal;\\n}\\n.flow-sidebar-surface .brand-link .brand-image { float:none; max-height:25px; width:25px; height:25px; margin:0!important; opacity:1; border-radius:4px; box-shadow:none!important; }\\n.flow-sidebar-surface .brand-link .brand-text { margin:0!important; font-weight:650!important; font-size:22px; }\\n:host .brand i, .flow-sidebar-surface .brand-link>i { color:var(--flow-blue); font-size:22px; }\\n:host .sidebar, .flow-sidebar-surface .sidebar {\\n  display:flex!important; flex-direction:column; height:calc(100dvh - 74px)!important;\\n  min-height:0; padding:0 9px!important; overflow-x:hidden!important; overflow-y:auto!important;\\n  scrollbar-width:thin; scrollbar-color:#cad4e6 transparent;\\n}\\n:host .sidebar>nav, .flow-sidebar-surface .sidebar>nav { flex:1 0 auto; min-width:0; margin:0!important; padding:0; }\\n:host .nav-sidebar, .flow-sidebar-surface .nav-sidebar { width:100%!important; margin:0; padding:0; list-style:none; display:flex; flex-direction:column; }\\n:host .nav-sidebar>.nav-item, .flow-sidebar-surface .nav-sidebar>.nav-item { width:100%; margin:0; }\\n:host .nav-sidebar .nav-header, .flow-sidebar-surface .nav-sidebar .nav-header {\\n  padding:17px 10px 7px!important; margin:0; color:var(--flow-muted)!important; background:none!important;\\n  font-size:12px!important; font-weight:500; line-height:18px; text-transform:none!important;\\n}\\n:host .nav-sidebar .nav-link, .flow-sidebar-surface .nav-sidebar .nav-link {\\n  position:relative; display:flex!important; align-items:center; gap:10px; min-height:36px;\\n  width:100%!important; padding:7px 10px!important; margin:0 0 2px!important; border:0!important;\\n  border-radius:4px!important; background:transparent; color:var(--flow-muted)!important;\\n  font-size:14px!important; font-weight:400; line-height:22px; text-decoration:none;\\n  white-space:normal; box-shadow:none!important;\\n}\\n:host .nav-sidebar .nav-link:hover, :host .nav-sidebar .nav-link:focus-visible,\\n.flow-sidebar-surface .nav-sidebar .nav-link:hover, .flow-sidebar-surface .nav-sidebar .nav-link:focus-visible { background:#eef1f7!important; color:var(--flow-text)!important; }\\n:host .nav-sidebar .nav-link.active, .flow-sidebar-surface .nav-sidebar .nav-link.active {\\n  background:var(--flow-blue-soft)!important; color:var(--flow-blue)!important; font-weight:600;\\n}\\n:host .nav-sidebar .nav-link.active:before, .flow-sidebar-surface .nav-sidebar .nav-link.active:before {\\n  content:""; position:absolute; left:0; top:8px; bottom:8px; width:2px; border-radius:2px; background:var(--flow-blue);\\n}\\n:host .nav-sidebar .nav-icon, .flow-sidebar-surface .nav-sidebar .nav-icon {\\n  flex:none; width:18px!important; min-width:18px; margin:0!important; text-align:center; font-size:16px!important;\\n}\\n:host .nav-sidebar p, .flow-sidebar-surface .nav-sidebar p { display:block!important; width:auto!important; min-width:0; margin:0!important; line-height:22px; overflow-wrap:anywhere; }\\n:host .nav-sidebar p .text-xs, .flow-sidebar-surface .nav-sidebar p .text-xs { font-size:10px!important; margin-left:3px; }\\n:host .user-panel, .flow-sidebar-surface .user-panel {\\n  display:flex!important; align-items:center; gap:9px; flex:none; min-height:58px;\\n  padding:12px 3px!important; margin:0 3px 2px!important; border-bottom:1px solid var(--flow-line)!important;\\n  white-space:normal; overflow:visible;\\n}\\n:host .user-panel .image, .flow-sidebar-surface .user-panel .image { padding:0; flex:none; }\\n:host .user-panel .image>div, .flow-sidebar-surface .user-panel .image>div {\\n  display:grid; place-items:center; width:28px; height:28px; border-radius:6px; background:#eaf0fb!important; box-shadow:none!important;\\n}\\n:host .user-panel .image i, .flow-sidebar-surface .user-panel .image i { font-size:14px!important; color:var(--flow-blue)!important; }\\n:host .user-panel .info, .flow-sidebar-surface .user-panel .info { min-width:0; padding:0; flex:1; }\\n:host .user-panel .info a, .flow-sidebar-surface .user-panel .info a {\\n  color:var(--flow-text)!important; font-size:12px; line-height:18px; text-decoration:none; overflow-wrap:anywhere;\\n}\\n:host .close-nav { display:none; position:absolute; top:20px; right:8px; width:32px; height:32px; padding:0; border:0; border-radius:4px; background:transparent; color:var(--flow-muted)!important; font:25px/1 system-ui; cursor:pointer; }\\n:host .close-nav:hover { background:#eef1f7; color:var(--flow-text)!important; }\\n:host a:focus-visible, :host button:focus-visible,\\n.flow-sidebar-surface a:focus-visible, .flow-sidebar-surface button:focus-visible { outline:2px solid var(--flow-blue)!important; outline-offset:2px; }\\n@media(max-width:900px) {\\n  :host { width:236px!important; }\\n  :host .close-nav { display:block; }\\n  :host .brand { padding-right:45px!important; }\\n}\\n\';\n    shadow.appendChild(flowStyle);\n    var brand = document.createElement(\'a\');\n    brand.className = \'brand\';\n    brand.href = \'/admin/domain\';\n    brand.textContent = \'Mailu\';\n    var close = document.createElement(\'button\');\n    close.type = \'button\';\n    close.className = \'close-nav\';\n    close.textContent = \'\\u00d7\';\n    close.title = \'关闭导航\';\n    close.setAttribute(\'aria-label\', \'关闭导航\');\n    shadow.append(brand, close, sidebar);\n\n    var layout = document.createElement(\'style\');\n    layout.id = \'mail-control-shell-style\';\n    layout.textContent = \'body.mail-control-shell{margin-left:194px;min-width:0}#mail-control-side-nav{position:fixed;inset:0 auto 0 0;width:194px;height:100dvh;z-index:1000}body.mail-control-shell>header{background:#fff;color:#17212b;border-bottom:1px solid #d9e1e8}body.mail-control-shell>header a{color:#1677a8}body.mail-control-shell>main{min-width:0}#mail-control-nav-toggle{display:none}#mail-control-nav-backdrop{display:none}@media(max-width:900px){body.mail-control-shell{margin-left:0;padding-top:44px}#mail-control-side-nav{transform:translateX(-100%);transition:transform .15s ease}body.mail-control-nav-open #mail-control-side-nav{transform:translateX(0)}#mail-control-nav-toggle{display:flex;align-items:center;gap:10px;position:fixed;top:0;left:0;right:0;height:44px;z-index:900;width:100%;border:0;border-bottom:1px solid #d9e1e8;border-radius:0;background:#fff;color:#17212b;padding:0 14px;font:14px system-ui;cursor:pointer}#mail-control-nav-toggle .menu-symbol{font-size:22px;line-height:1}body.mail-control-nav-open #mail-control-nav-backdrop{display:block;position:fixed;inset:0;z-index:999;background:#0006;border:0;width:100%;height:100%;border-radius:0}}@media(prefers-reduced-motion:reduce){#mail-control-side-nav{transition:none}}\';\n    var toggle = document.createElement(\'button\');\n    toggle.id = \'mail-control-nav-toggle\';\n    toggle.type = \'button\';\n    toggle.title = \'打开导航\';\n    toggle.setAttribute(\'aria-label\', \'打开导航\');\n    toggle.setAttribute(\'aria-controls\', host.id);\n    toggle.setAttribute(\'aria-expanded\', \'false\');\n    toggle.innerHTML = \'<span class="menu-symbol" aria-hidden="true">&#9776;</span><span>Mailu</span>\';\n    var backdrop = document.createElement(\'button\');\n    backdrop.id = \'mail-control-nav-backdrop\';\n    backdrop.type = \'button\';\n    backdrop.setAttribute(\'aria-label\', \'关闭导航\');\n    var inertContent = [];\n    function opened(value) {\n      document.body.classList.toggle(\'mail-control-nav-open\', value);\n      toggle.setAttribute(\'aria-expanded\', String(value));\n      if (value) inertContent = Array.from(document.body.children).filter(function (node) {\n        if (node === host || node === backdrop || node === toggle || node.tagName === \'SCRIPT\') return;\n        return !node.inert;\n      });\n      inertContent.forEach(function (node) { node.inert = value; });\n      if (!value) inertContent = [];\n      if (value) close.focus();\n      else toggle.focus();\n    }\n    toggle.onclick = function () { opened(true); };\n    close.onclick = backdrop.onclick = function () { opened(false); };\n    document.addEventListener(\'keydown\', function (event) { if (event.key === \'Escape\' && document.body.classList.contains(\'mail-control-nav-open\')) opened(false); });\n    document.head.appendChild(layout);\n    document.body.classList.add(\'mail-control-shell\');\n    document.body.prepend(host, toggle, backdrop);\n  }\n\n  function init() {\n    if (window.self !== window.top || new URLSearchParams(location.search).get(\'embedded\') === \'1\') return;\n    var sidebar = document.querySelector(\'.main-sidebar .sidebar\');\n    if (sidebar) { installLinks(sidebar); return; }\n    if (location.pathname.indexOf(rootPath) !== 0 && location.pathname.indexOf(\'/admin/antispam/\') !== 0) return;\n    toolShell().catch(function (error) { console.warn(error.message); });\n  }\n  if (document.querySelector(\'.main-sidebar .sidebar\') || document.querySelector(\'body > main\') || document.getElementById(\'mainUI\')) init();\n  else if (document.readyState === \'loading\') document.addEventListener(\'DOMContentLoaded\', init);\n  else init();\n})();\n'



FLOW_UI_ASSETS = {'flow-tools.css': '/* Selected Mailu theme: 秩序蓝白. Loaded only by the mail-control tools. */\nbody.flow-tools {\n  --ink: #2d3544;\n  --muted: #8390a6;\n  --line: #e6eaf0;\n  --accent: #3c68cb;\n  --accent-dark: #315bb7;\n  --accent-soft: #edf2fc;\n  --green: #3c68cb;\n  --green-dark: #315bb7;\n  --green-soft: #edf2fc;\n  --danger: #b84b53;\n  --bg: #fff;\n  --card: #fff;\n  --ok: #2e7d60;\n  color-scheme: light;\n  color: var(--ink);\n  background: var(--bg);\n  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif;\n  min-width: 0;\n}\nbody.flow-tools *, body.flow-tools *::before, body.flow-tools *::after { box-sizing: border-box; }\nbody.flow-tools.mail-control-shell { margin-left:194px!important; }\nbody.flow-tools #mail-control-nav-toggle { background:#fff; color:#68788e; }\n@media(max-width:900px) { body.flow-tools.mail-control-shell { margin-left:0!important; padding-top:44px; } }\nhtml.flow-embedded-surface body.flow-tools.mail-control-shell { margin-left:0!important; padding-top:0; }\nbody.flow-tools > header {\n  padding: 20px 24px 17px;\n  color: var(--ink);\n  background: #fff;\n  border-bottom: 1px solid var(--line);\n}\nbody.flow-tools > header h1 { margin: 5px 0 0; font-size: 23px; font-weight: 650; letter-spacing: -.35px; line-height: 1.35; }\nbody.flow-tools > header p { color: var(--muted); margin: 6px 0 0; font-size: 12px; }\nbody.flow-tools > header .crumb { margin: 0 0 6px; font-size: 12px; }\nbody.flow-tools > header a { color: var(--accent); font-size: 12px; text-decoration: none; margin-bottom: 0; }\nbody.flow-tools main {\n  width: 100%; max-width: 1600px; min-width: 0;\n  margin: 0 auto; padding: 22px 24px 32px;\n}\nbody.flow-tools.embedded main { padding: 18px 22px; }\nbody.flow-tools h2 { font-size: 16px; font-weight: 650; line-height: 1.4; }\nbody.flow-tools h3 { font-size: 14px; font-weight: 600; line-height: 1.5; }\nbody.flow-tools .panel {\n  min-width: 0; padding: 18px; margin-bottom: 16px;\n  background: #fff; border: 1px solid var(--line); border-radius: 5px; box-shadow: none;\n}\nbody.flow-tools .panel h2 { margin: 0 0 14px; font-size: 16px; }\nbody.flow-tools .grid { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 18px; align-items: start; }\nbody.flow-tools .grid > *, body.flow-tools .row > *, body.flow-tools .fields > *, body.flow-tools .form-grid > * { min-width: 0; }\nbody.flow-tools .fields { grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px 16px; }\nbody.flow-tools .fields .wide { grid-column: 1 / -1; }\nbody.flow-tools label, body.flow-tools label.field { font-size: 12px; color: #627087; margin: 10px 0 6px; }\nbody.flow-tools .fields label { margin-top: 0; }\nbody.flow-tools input:not([type=checkbox]):not([type=radio]):not([type=hidden]):not([type=range]),\nbody.flow-tools select, body.flow-tools textarea {\n  max-width: 100%; min-width: 0; min-height: 39px; height: auto;\n  padding: 8px 10px; border: 1px solid #dce2eb; border-radius: 4px;\n  font: inherit; color: var(--ink); background: #fff; box-shadow: none;\n}\nbody.flow-tools textarea { line-height: 1.65; resize: vertical; }\nbody.flow-tools input::placeholder, body.flow-tools textarea::placeholder { color: #99a3b3; }\nbody.flow-tools input[type=checkbox], body.flow-tools input[type=radio] {\n  width: 16px; height: 16px; min-width: 16px; padding: 0; margin: 0;\n  vertical-align: middle; accent-color: var(--accent); cursor: pointer;\n}\nbody.flow-tools input:focus-visible, body.flow-tools select:focus-visible,\nbody.flow-tools textarea:focus-visible, body.flow-tools .editor:focus-visible {\n  outline: 2px solid #3c68cb33; outline-offset: 1px; border-color: #6f90d9;\n}\nbody.flow-tools button {\n  min-height: 37px; max-width: 100%; padding: 8px 13px; margin-top: 0;\n  border: 1px solid var(--accent); border-radius: 4px;\n  background: var(--accent); color: #fff; font-family: inherit; font-size: 13px; line-height: 1.4;\n  cursor: pointer; white-space: normal;\n}\nbody.flow-tools button:hover { background: var(--accent-dark); border-color: var(--accent-dark); color: #fff; }\nbody.flow-tools button.secondary,\nbody.flow-tools .pager button,\nbody.flow-tools button.close,\nbody.flow-tools button.modal-close,\nbody.flow-tools .modal-head > button {\n  color: #5c687c !important; background: #fff !important; border: 1px solid #dce2eb;\n}\nbody.flow-tools button.secondary:hover,\nbody.flow-tools .pager button:hover,\nbody.flow-tools .modal-head > button:hover { color: var(--accent) !important; background: #f6f8fc !important; border-color: #b9cbed; }\nbody.flow-tools button.danger { border-color: #edcbd0; background: #fff; color: var(--danger); }\nbody.flow-tools button.danger:hover { color: #9e3941; border-color: #dca6ad; background: #fff5f6; }\nbody.flow-tools button:disabled { opacity: .45; cursor: not-allowed; }\nbody.flow-tools button:focus-visible, body.flow-tools a:focus-visible, body.flow-tools summary:focus-visible { outline: 2px solid #7998df; outline-offset: 2px; }\nbody.flow-tools button.small { min-height: 30px; padding: 5px 9px; font-size: 12px; }\nbody.flow-tools a { color: var(--accent); }\nbody.flow-tools .toolbar, body.flow-tools .actions, body.flow-tools .send-actions,\nbody.flow-tools .modal-actions, body.flow-tools .check-row, body.flow-tools .switch-row {\n  gap: 8px; flex-wrap: wrap;\n}\nbody.flow-tools .toolbar { margin: 14px 0; }\nbody.flow-tools .toolbar input, body.flow-tools .toolbar select { min-width: 0; }\nbody.flow-tools .toolbar label, body.flow-tools .check-row label,\nbody.flow-tools .switch-row label, body.flow-tools .check, body.flow-tools .radio-row label { font-size: 12px; }\nbody.flow-tools .check, body.flow-tools .check-row label, body.flow-tools .switch-row label,\nbody.flow-tools .radio-row label { gap: 7px; }\nbody.flow-tools .check-row { gap: 12px 18px; }\nbody.flow-tools .muted, body.flow-tools .meta, body.flow-tools .hint,\nbody.flow-tools .status:not(.error):not(.ok), body.flow-tools .file-list { color: var(--muted); font-size: 12px; }\nbody.flow-tools .hint { margin: 6px 0; line-height: 1.6; }\nbody.flow-tools .error, body.flow-tools .failure { color: var(--danger); }\nbody.flow-tools .ok, body.flow-tools .success { color: #2e7d60; }\nbody.flow-tools .summary, body.flow-tools .sender, body.flow-tools .result { font-size: 13px; overflow-wrap: anywhere; }\nbody.flow-tools .summary { background: #f7f8fb; border-color: var(--line); }\nbody.flow-tools .scroll, body.flow-tools .table-wrap { min-width: 0; max-width: 100%; overflow: auto; border-color: var(--line); border-radius: 4px; }\nbody.flow-tools table { width: 100%; border-collapse: collapse; font-size: 13px; }\nbody.flow-tools th, body.flow-tools td { padding: 11px 10px; border-bottom: 1px solid var(--line); }\nbody.flow-tools th { color: #718097; background: #f8f9fc; font-size: 12px; font-weight: 600; }\nbody.flow-tools td { color: var(--ink); }\nbody.flow-tools td small { color: var(--muted); font-size: 11px; }\nbody.flow-tools tbody tr:hover > td { background-color: #f8faff; }\nbody.flow-tools td .actions { flex-wrap: nowrap; gap: 10px; }\nbody.flow-tools td .actions button, body.flow-tools button.link, body.flow-tools button.copy {\n  min-height: 28px; padding: 3px 0; margin: 0; color: var(--accent); background: transparent; border: 0; text-align: left;\n}\nbody.flow-tools td .actions button:hover, body.flow-tools button.link:hover, body.flow-tools button.copy:hover { color: var(--accent-dark); background: transparent; text-decoration: underline; }\nbody.flow-tools td .actions button.danger { color: var(--danger); }\nbody.flow-tools .tag, body.flow-tools .pill { color: var(--accent); background: var(--accent-soft); border-radius: 4px; font-size: 11px; }\nbody.flow-tools .tag.gray, body.flow-tools .pill.gray, body.flow-tools td .status.gray { background: #f0f2f6; color: #7c8799; }\nbody.flow-tools .pill.red { color: var(--danger); background: #fff0f2; }\nbody.flow-tools .stats { gap: 12px; }\nbody.flow-tools .stat { padding: 15px 18px; border: 1px solid var(--line); border-radius: 5px; background: #fff; box-shadow: none; }\nbody.flow-tools .stat-title, body.flow-tools .stat small { color: var(--muted); font-size: 12px; }\nbody.flow-tools .stat-value, body.flow-tools .stat strong { font-size: 25px; font-weight: 650; letter-spacing: -.5px; }\nbody.flow-tools .filters { padding: 14px 16px; gap: 8px; border-color: var(--line); border-radius: 5px; }\nbody.flow-tools .filters label { margin: 0; }\nbody.flow-tools .filters button { border-color: #dce2eb; background: #fff; color: #5c687c; }\nbody.flow-tools .filters button:hover { color: var(--accent); background: #f6f8fc; border-color: #b9cbed; }\nbody.flow-tools .filters button.primary { color: #fff; background: var(--accent); border-color: var(--accent); }\nbody.flow-tools .pager { gap: 8px; flex-wrap: wrap; font-size: 12px; }\nbody.flow-tools .pager select { width: auto; min-height: 34px; }\nbody.flow-tools .nav { gap: 0; padding: 0; margin: 0 0 18px; border-bottom: 1px solid var(--line); }\nbody.flow-tools .nav button { min-height: 43px; padding: 10px 18px; border: 0; border-bottom: 2px solid transparent; border-radius: 0; background: transparent; color: #718097; }\nbody.flow-tools .nav button.active { color: var(--accent); border-bottom-color: var(--accent); background: transparent; }\nbody.flow-tools > .tabs { padding: 0 24px; border-bottom-color: var(--line); }\nbody.flow-tools > .tabs a { color: var(--accent); border-bottom-color: var(--accent); font-size: 13px; }\nbody.flow-tools .editor-toolbar { background: #f8f9fc; border-color: #dce2eb; gap: 4px; }\nbody.flow-tools .editor-toolbar button, body.flow-tools.flow-marketing-task .panel > .toolbar button { min-height: 29px; padding: 4px 9px; background: #fff; color: var(--ink); border: 1px solid var(--line); }\nbody.flow-tools.flow-marketing-task .panel > .toolbar { margin: 0; border-color: #dce2eb; background: #f8f9fc; }\nbody.flow-tools .editor-toolbar button:hover { background: var(--accent-soft); color: var(--accent); }\nbody.flow-tools .editor { min-height: 200px; max-width: 100%; border-color: #dce2eb; font-size: 14px; line-height: 1.65; overflow: auto; }\nbody.flow-tools .editor img { max-width: 100%; height: auto; }\nbody.flow-tools pre { white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; font: 12px/1.7 ui-monospace, "Cascadia Code", Consolas, monospace; border-radius: 4px; }\nbody.flow-tools .code, body.flow-tools .command { background: #f7f8fb; color: #56637b; border: 1px solid var(--line); }\nbody.flow-tools .preview { width: 100%; height: 240px; min-height: 0; max-height: 60vh; background: #fff; border: 1px solid var(--line); border-radius: 4px; }\nbody.flow-tools .preview-box { min-height: 0; background: #fff; }\nbody.flow-tools .preview-meta { text-align: left; min-height: 0; padding-bottom: 12px; font-size: 12px; overflow-wrap: anywhere; }\nbody.flow-tools .empty { padding: 28px 16px; color: var(--muted); font-size: 13px; }\nbody.flow-tools .hidden { display: none !important; }\n\n/* Dialogs shrink to their content and remain centered within the viewport. */\nbody.flow-tools dialog {\n  position: fixed; inset: auto; top: 50%; left: 50%; transform: translate(-50%, -50%);\n  margin: 0; width: min(880px, calc(100vw - 32px)); height: auto;\n  max-height: calc(100dvh - 32px); padding: 20px; overflow: auto;\n  border: 1px solid var(--line); border-radius: 6px; background: #fff; color: var(--ink);\n  box-shadow: 0 12px 45px #25395a26;\n}\nbody.flow-tools dialog::backdrop { background: #263b5966; }\nbody.flow-tools .modal { position: fixed; inset: 0; z-index: 1100; align-items: center; justify-content: center; padding: 16px; background: #263b5966; }\nbody.flow-tools .modal-dialog, body.flow-tools .modal-box, body.flow-tools .modal-card {\n  height: auto !important; width: min(880px, 100%) !important;\n  max-height: calc(100dvh - 32px) !important; margin: auto; overflow: auto !important;\n  border: 1px solid var(--line); border-radius: 6px; background: #fff;\n  box-shadow: 0 12px 45px #25395a26;\n}\nbody.flow-tools .modal-head { align-items: flex-start; gap: 12px; }\nbody.flow-tools .modal-head h2, body.flow-tools .modal-head h3 { font-size: 18px; line-height: 1.45; margin: 0; }\nbody.flow-tools .modal-head > button { flex: none; min-height: 32px; padding: 5px 10px; font-size: 12px; }\nbody.flow-tools .modal-content { flex: none; min-height: 0; overflow: visible; }\nbody.flow-tools .modal-tabs { gap: 6px; }\nbody.flow-tools .modal-tabs button, body.flow-tools .tabs button { min-height: 33px; padding: 6px 11px; font-size: 12px; }\nbody.flow-tools .modal-tabs button:not(.active), body.flow-tools .tabs button:not(.active) { background: #fff; border: 1px solid var(--line); color: #718097; }\nbody.flow-tools .message-frame { display: block; width: 100%; height: 120px; min-height: 0 !important; max-height: 60vh !important; margin-top: 14px; border: 1px solid var(--line); border-radius: 4px; background: #fff; }\nbody.flow-tools .message-text, body.flow-tools #text-view { min-height: 0; height: auto; max-height: 60vh; overflow: auto; background: #f8f9fc; border: 1px solid var(--line); padding: 14px; font-size: 13px; }\nbody.flow-tools .meta { line-height: 1.8; }\nbody.flow-tools .attachments, body.flow-tools .message-attachments, body.flow-tools #attachments { overflow-wrap: anywhere; font-size: 12px; }\nbody.flow-tools .attachments a, body.flow-tools .message-attachments a, body.flow-tools #attachments a { display: inline-block; margin: 5px 12px 0 0; }\n\n/* Global search keeps the original table controls and dialog event handlers. */\nbody.flow-tools .flow-filter-toggle { display: none; }\nbody.flow-tools.flow-global .flow-global-filters { margin-bottom: 18px; padding: 15px 18px 12px; }\nbody.flow-tools.flow-global .flow-global-filters > .muted { margin: 8px 0 0; font-size: 11px; }\nbody.flow-tools.flow-global .flow-global-filters > .toolbar { margin: 12px 0 0; }\nbody.flow-tools.flow-global .flow-global-filters #auto { margin-right: 5px; }\nbody.flow-tools .flow-inbox-layout { display: block; min-width: 0; }\nbody.flow-tools.flow-global .flow-global-list { padding: 0; overflow: hidden; margin: 0; }\nbody.flow-tools.flow-global .flow-global-list > .toolbar { padding: 12px 14px; margin: 0; gap: 8px; }\nbody.flow-tools.flow-global .flow-global-list > .toolbar:first-child { border-bottom: 1px solid var(--line); }\nbody.flow-tools.flow-global .flow-global-list #status { flex-basis: 100%; font-size: 11px; }\nbody.flow-tools.flow-global .flow-global-list > .toolbar:last-child { border-top: 1px solid var(--line); }\nbody.flow-tools.flow-global .flow-global-list #page { font-size: 12px; color: #718097; }\nbody.flow-tools.flow-global .flow-global-list #limit { min-height: 32px; padding: 4px 7px; }\nbody.flow-tools.flow-global .flow-global-list .scroll { max-height: 68vh; overflow: auto; }\nbody.flow-tools.flow-global .flow-global-list table { display: block; min-width: 0; width: 100%; }\nbody.flow-tools.flow-global .flow-global-list thead, body.flow-tools.flow-global .flow-global-list tbody { display: block; }\nbody.flow-tools.flow-global .flow-global-list thead tr { display: block; padding: 8px 14px; background: #f8f9fc; border-bottom: 1px solid var(--line); }\nbody.flow-tools.flow-global .flow-global-list th { display: none; border: 0; }\nbody.flow-tools.flow-global .flow-global-list th:first-child { display: flex; align-items: center; gap: 8px; padding: 0; font-weight: 400; }\nbody.flow-tools .flow-select-label { font-size: 11px; color: #8390a6; }\nbody.flow-tools.flow-global .flow-global-list tbody tr {\n  display: grid; grid-template-columns: 20px minmax(0, 1fr) auto; gap: 3px 9px;\n  padding: 12px 14px; border-bottom: 1px solid var(--line); background: #fff;\n}\nbody.flow-tools.flow-global .flow-global-list tbody tr:last-child { border-bottom: 0; }\nbody.flow-tools.flow-global .flow-global-list td { display: block; padding: 0; border: 0; background: transparent; min-width: 0; overflow-wrap: anywhere; }\nbody.flow-tools.flow-global .flow-global-list tr.unread { background: #fbfcff; }\nbody.flow-tools.flow-global .flow-global-list tr.flow-current-message { background: #edf2fc; box-shadow: inset 3px 0 #3c68cb; }\nbody.flow-tools.flow-global .flow-global-list tbody tr:hover { background: #f5f8fe; }\nbody.flow-tools.flow-global .flow-global-list td:nth-child(1) { grid-column: 1; grid-row: 1 / 4; padding-top: 5px; }\nbody.flow-tools.flow-global .flow-global-list td:nth-child(2) { grid-column: 2; grid-row: 3; font-size: 11px; color: #8390a6; }\nbody.flow-tools.flow-global .flow-global-list td:nth-child(2) small { display: inline; margin: 0 0 0 8px; font-size: 10px; }\nbody.flow-tools.flow-global .flow-global-list td:nth-child(3) { grid-column: 2 / 4; grid-row: 1; }\nbody.flow-tools.flow-global .flow-global-list td:nth-child(3) button { width: 100%; min-height: 24px; padding: 0; font-size: 14px; font-weight: 500; line-height: 1.5; color: var(--ink); }\nbody.flow-tools.flow-global .flow-global-list tr.unread td:nth-child(3) button { font-weight: 650; }\nbody.flow-tools.flow-global .flow-global-list td:nth-child(4) { grid-column: 2; grid-row: 2; font-size: 12px; color: #718097; }\nbody.flow-tools.flow-global .flow-global-list td:nth-child(5) { display: none; }\nbody.flow-tools.flow-global .flow-global-list td:nth-child(6) { grid-column: 3; grid-row: 2; font-size: 10px; color: #8390a6; white-space: nowrap; }\nbody.flow-tools.flow-global .flow-global-list td:nth-child(7) { grid-column: 3; grid-row: 3; font-size: 10px; color: #8390a6; text-align: right; }\nbody.flow-tools.flow-global .flow-global-list td.empty { grid-column: 1 / -1; grid-row: auto; padding: 28px 12px; text-align: center; }\nbody.flow-tools .flow-reader { display: none; min-width: 0; }\nbody.flow-tools .flow-reader-placeholder { padding: 54px 24px; text-align: center; border: 1px solid var(--line); border-radius: 5px; background: #fff; color: var(--muted); font-size: 12px; }\nbody.flow-tools .flow-reader-placeholder strong { display: block; margin-bottom: 8px; font-size: 15px; font-weight: 550; color: #627087; }\nbody.flow-tools.flow-reader-layout .flow-inbox-layout { display: grid; grid-template-columns: minmax(330px, .82fr) minmax(0, 1.18fr); gap: 20px; align-items: start; }\nbody.flow-tools.flow-reader-layout .flow-reader { display: block; position: sticky; top: 20px; }\nbody.flow-tools.flow-reader-layout dialog.flow-reader-detail {\n  position: static; inset: auto; transform: none; width: 100%; height: auto;\n  max-height: none; margin: 0; padding: 20px; overflow: visible;\n  border: 1px solid var(--line); border-radius: 5px; box-shadow: none;\n}\nbody.flow-tools.flow-reader-layout dialog.flow-reader-detail[open] { display: block; }\nbody.flow-tools.flow-reader-layout .flow-reader .modal-head h2 { font-size: 20px; font-weight: 600; }\nbody.flow-tools.flow-reader-layout .flow-reader .meta { margin: 12px 0; padding: 0 0 12px; border-bottom: 1px solid var(--line); font-size: 12px; }\nbody.flow-tools.flow-reader-layout .flow-reader .toolbar { margin: 0; }\nbody.flow-tools.flow-reader-layout .flow-reader .toolbar button { min-height: 32px; font-size: 12px; padding: 6px 10px; }\nbody.flow-tools.flow-reader-layout .flow-reader .message-frame { margin-top: 14px; }\nbody.flow-tools.flow-reader-layout .flow-reader #attachments:empty { margin: 0; }\nbody.flow-tools.flow-reader-layout .flow-reader #attachments:not(:empty) { padding-top: 10px; border-top: 1px solid var(--line); }\nbody.flow-tools.flow-global #html-tab.flow-active-tab,\nbody.flow-tools.flow-global #text-tab.flow-active-tab { color: var(--accent) !important; border-color: #b9cbed; background: var(--accent-soft) !important; }\nbody.flow-tools.flow-api table { min-width: 1050px; }\nbody.flow-tools.flow-marketing-list table { min-width: 1080px; }\nbody.flow-tools.flow-marketing-task .grid { grid-template-columns: minmax(0, 1.05fr) minmax(0, .95fr); }\nbody.flow-tools.flow-marketing-task .grid > .preview-box { position: sticky; top: 20px; }\nbody.flow-tools.flow-accounts #account-list { max-width: 100%; overflow: auto; }\nbody.flow-tools.flow-accounts #account-list td { overflow-wrap: anywhere; }\nbody.flow-tools.flow-control #messages, body.flow-tools.flow-accounts #create-result { min-width: 0; max-width: 100%; overflow: auto; }\nbody.flow-tools.flow-control #messages table { min-width: 560px; }\nbody.flow-tools.flow-compose .fields { grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); }\nbody.flow-tools.flow-compose #sender { margin: 14px 0; padding: 10px 12px; border: 1px solid #dbe5fa; border-radius: 4px; background: #f7f9ff; }\nbody.flow-tools.flow-view > header #meta { margin: 12px 0 0; font-size: 12px; }\nbody.flow-tools.flow-view main { max-width: 1200px; }\n\n@media (max-width: 1319px) {\n  body.flow-tools.flow-marketing-task .grid { grid-template-columns: minmax(0, 1fr); }\n  body.flow-tools.flow-marketing-task .grid > .preview-box { position: static; }\n}\n@media (max-width: 1099px) {\n  body.flow-tools .grid { grid-template-columns: minmax(0, 1fr); }\n  body.flow-tools .wide { grid-column: auto; }\n  body.flow-tools .fields .wide { grid-column: 1 / -1; }\n  body.flow-tools .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }\n  body.flow-tools .fields { grid-template-columns: repeat(2, minmax(0, 1fr)); }\n}\n@media (max-width: 760px) {\n  body.flow-tools > header { padding: 17px 14px 14px; }\n  body.flow-tools > header h1 { font-size: 21px; }\n  body.flow-tools main, body.flow-tools.embedded main { margin: 0; padding: 14px 12px 24px; }\n  body.flow-tools .panel { padding: 14px; margin-bottom: 14px; }\n  body.flow-tools .fields, body.flow-tools.flow-compose .fields, body.flow-tools .row,\n  body.flow-tools .row.three, body.flow-tools .form-grid { grid-template-columns: minmax(0, 1fr); }\n  body.flow-tools .fields .wide, body.flow-tools .form-grid .full { grid-column: auto; }\n  body.flow-tools .toolbar select, body.flow-tools .toolbar input { width: auto; }\n  body.flow-tools .toolbar input:not([type=checkbox]):not([type=radio]) { flex: 1 1 180px; }\n  body.flow-tools .toolbar-right { min-width: 0; flex-wrap: wrap; }\n  body.flow-tools .toolbar-right input { min-width: 0; }\n  body.flow-tools .filters > * { width: auto !important; }\n  body.flow-tools .filters input, body.flow-tools .filters select { flex: 1 1 130px; }\n  body.flow-tools .filters input.search { flex-basis: 100%; }\n  body.flow-tools.flow-api .filters { display: grid; grid-template-columns: minmax(0, 1fr) 12px minmax(0, 1fr); align-items: center; }\n  body.flow-tools.flow-api .filters > * { min-width: 0; width: 100% !important; }\n  body.flow-tools.flow-api .filters label,\n  body.flow-tools.flow-api .filters #time-range,\n  body.flow-tools.flow-api .filters #active-filter,\n  body.flow-tools.flow-api .filters #keyword { grid-column: 1 / -1; }\n  body.flow-tools.flow-api .filters #start-date, body.flow-tools.flow-api .filters #search { grid-column: 1; }\n  body.flow-tools.flow-api .filters span { grid-column: 2; text-align: center; font-size: 12px; }\n  body.flow-tools.flow-api .filters #end-date, body.flow-tools.flow-api .filters #refresh-data { grid-column: 3; }\n  body.flow-tools .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }\n  body.flow-tools .stat { padding: 12px; }\n  body.flow-tools .stat-value, body.flow-tools .stat strong { font-size: 22px; }\n  body.flow-tools .inline-field { display: flex; align-items: center; }\n  body.flow-tools .inline-field button { flex: none; }\n  body.flow-tools > .tabs { padding-left: 14px; padding-right: 14px; }\n  body.flow-tools .back { float: none; display: inline-block; margin: 8px 0 0; }\n  body.flow-tools dialog { width: calc(100vw - 20px); max-height: calc(100dvh - 20px); padding: 15px; }\n  body.flow-tools .modal { padding: 10px; }\n  body.flow-tools .modal-dialog, body.flow-tools .modal-box, body.flow-tools .modal-card { width: 100% !important; max-height: calc(100dvh - 20px) !important; height: auto !important; border-radius: 6px; }\n  body.flow-tools .modal-box, body.flow-tools .modal-card { padding: 15px; }\n  body.flow-tools .modal-head { padding-left: 14px; padding-right: 14px; }\n  body.flow-tools dialog .modal-head, body.flow-tools .modal-box .modal-head { padding-left: 0; padding-right: 0; }\n  body.flow-tools .modal-head h2, body.flow-tools .modal-head h3 { font-size: 17px; }\n  body.flow-tools .modal-actions, body.flow-tools .modal-tabs, body.flow-tools .modal-content { padding-left: 14px; padding-right: 14px; }\n  body.flow-tools .modal-box .modal-actions { padding-left: 0; padding-right: 0; }\n  body.flow-tools .flow-filter-toggle { display: inline-flex; align-items: center; width: 100%; justify-content: space-between; margin: 0 0 12px; background: #f7f9fc; color: #5c687c; border-color: var(--line); }\n  body.flow-tools .flow-filter-toggle:hover { background: #edf2fc; color: var(--accent); border-color: #b9cbed; }\n  body.flow-tools .flow-global-filters.flow-filters-collapsed > .fields,\n  body.flow-tools .flow-global-filters.flow-filters-collapsed > .muted,\n  body.flow-tools .flow-global-filters.flow-filters-collapsed #search,\n  body.flow-tools .flow-global-filters.flow-filters-collapsed #reset { display: none; }\n  body.flow-tools.flow-global .flow-global-filters { padding: 12px; margin-bottom: 14px; }\n  body.flow-tools.flow-global .flow-global-filters > .toolbar { margin-top: 0; }\n  body.flow-tools.flow-global .flow-global-filters > .toolbar label { margin-left: auto !important; font-size: 11px; }\n  body.flow-tools.flow-global .flow-global-list tbody tr { padding: 12px; column-gap: 8px; }\n  body.flow-tools.flow-global .flow-global-list td:nth-child(3) button { font-size: 13px; }\n  body.flow-tools.flow-global .flow-global-list td:nth-child(6) { font-size: 9px; }\n  body.flow-tools.flow-global .flow-global-list td:nth-child(2) { font-size: 10px; }\n  body.flow-tools.flow-global .flow-global-list .scroll { max-height: none; }\n  body.flow-tools.flow-global .flow-global-list > .toolbar { padding: 10px 12px; }\n  body.flow-tools.flow-global .flow-global-list > .toolbar:last-child { gap: 6px; }\n  body.flow-tools.flow-global .flow-global-list > .toolbar:last-child button { min-height: 32px; padding: 5px 8px; font-size: 11px; }\n  body.flow-tools.flow-global .flow-global-list > .toolbar:last-child label { flex-basis: 100%; font-size: 11px; }\n}\n@media (prefers-reduced-motion: reduce) {\n  body.flow-tools * { scroll-behavior: auto !important; }\n}\n', 'flow-tools.js': "/* Progressive visual enhancement. Existing mail-control APIs own all data/actions. */\n(function () {\n  'use strict';\n  function init() {\n    if (!document.body || document.body.dataset.flowToolsReady) return;\n    var body = document.body;\n    var main = document.querySelector('body > main');\n    if (!main) return;\n    body.dataset.flowToolsReady = '1';\n    body.classList.add('flow-tools');\n\n    var pages = [\n      ['flow-global', '#rows', '#detail'],\n      ['flow-compose', '#compose'],\n      ['flow-accounts', '#localparts'],\n      ['flow-api', '#api-form'],\n      ['flow-marketing-task', '#sender-domain'],\n      ['flow-marketing-list', '#task-list'],\n      ['flow-marketing-manage', '#tab-campaigns'],\n      ['flow-control', '#message-modal'],\n      ['flow-view', 'body > header #subject']\n    ];\n    pages.some(function (page) {\n      if (page.slice(1).every(function (selector) { return document.querySelector(selector); })) {\n        body.classList.add(page[0]);\n        return true;\n      }\n      return false;\n    });\n    if (body.classList.contains('flow-global')) {\n      try { enhanceGlobal(main); }\n      catch (error) { console.warn('Mailu theme enhancement: ' + error.message); }\n    }\n  }\n\n  function enhanceGlobal(main) {\n    var detail = document.getElementById('detail');\n    var rows = document.getElementById('rows');\n    var list = rows && rows.closest('section.panel');\n    var filters = main.querySelector('section.panel');\n    if (!detail || !list || !filters || detail === list || typeof detail.showModal !== 'function' || typeof detail.show !== 'function') return;\n\n    var body = document.body;\n    var desktop = window.matchMedia('(min-width: 1100px)');\n    var originalShowModal = detail.showModal;\n    var originalShow = detail.show;\n    var originalClose = detail.close;\n    var anchor = document.createComment('flow-detail-original-position');\n    var layout = document.createElement('div');\n    var reader = document.createElement('section');\n    var placeholder = document.createElement('div');\n    var mobileFilters = document.createElement('button');\n    var selectLabel = document.createElement('span');\n    var switching = false;\n    var observer;\n    var rowsObserver;\n    var refreshTimer;\n    var pendingRow = null;\n    var activeKey = '';\n\n    function rowKey(row) {\n      if (!row || row.cells.length < 7) return '';\n      return [row.cells[1].firstChild ? row.cells[1].firstChild.textContent : '', row.cells[2].textContent, row.cells[3].textContent, row.cells[5].textContent, row.cells[6].textContent].join('\\u001f');\n    }\n    function markCurrent() {\n      Array.from(rows.querySelectorAll('tr')).forEach(function (row) {\n        var current = detail.open && activeKey && rowKey(row) === activeKey;\n        row.classList.toggle('flow-current-message', !!current);\n        var link = row.querySelector('[data-view]');\n        if (link) {\n          if (current) link.setAttribute('aria-current', 'true');\n          else link.removeAttribute('aria-current');\n        }\n      });\n    }\n    function syncReader() {\n      placeholder.hidden = !!detail.open;\n      var frame = document.getElementById('html-view');\n      var text = document.getElementById('text-view');\n      var htmlTab = document.getElementById('html-tab');\n      var textTab = document.getElementById('text-tab');\n      var htmlActive = frame && !frame.classList.contains('hidden');\n      if (htmlTab) {\n        htmlTab.classList.toggle('flow-active-tab', !!htmlActive);\n        htmlTab.setAttribute('aria-pressed', String(!!htmlActive));\n      }\n      if (textTab) {\n        textTab.classList.toggle('flow-active-tab', !htmlActive && !!text);\n        textTab.setAttribute('aria-pressed', String(!htmlActive && !!text));\n      }\n      markCurrent();\n    }\n    function notifyResize() {\n      var frame = document.getElementById('html-view');\n      if (frame && window.MailViewer) {\n        // The existing viewer owns measurement through its window resize listener.\n        requestAnimationFrame(function () { window.dispatchEvent(new Event('resize')); });\n      }\n    }\n    function showWithMode() {\n      if (desktop.matches && body.classList.contains('flow-reader-layout')) {\n        originalShow.call(detail);\n      } else originalShowModal.call(detail);\n      syncReader();\n      notifyResize();\n    }\n    function switchMode() {\n      if (switching) return;\n      switching = true;\n      try {\n        var isOpen = detail.open;\n        if (isOpen) originalClose.call(detail);\n        if (desktop.matches) {\n          reader.appendChild(detail);\n          detail.classList.add('flow-reader-detail');\n          body.classList.add('flow-reader-layout');\n        } else {\n          anchor.parentNode.insertBefore(detail, anchor.nextSibling);\n          detail.classList.remove('flow-reader-detail');\n          body.classList.remove('flow-reader-layout');\n        }\n        if (isOpen) showWithMode();\n        syncReader();\n        notifyResize();\n      } finally { switching = false; }\n    }\n    function rowClicked(event) {\n      var link = event.target.closest('[data-view]');\n      if (link && rows.contains(link)) pendingRow = link.closest('tr');\n    }\n    function detailUpdated(records) {\n      if (pendingRow && records.some(function (record) {\n        return record.type === 'childList' && (record.target.id === 'subject' || record.target.id === 'meta');\n      })) {\n        activeKey = rowKey(pendingRow);\n        pendingRow = null;\n      }\n      syncReader();\n    }\n    function filterToggle() {\n      var collapsed = filters.classList.toggle('flow-filters-collapsed');\n      mobileFilters.textContent = collapsed ? '展开筛选' : '收起筛选';\n      mobileFilters.setAttribute('aria-expanded', String(!collapsed));\n    }\n    function rollback(error) {\n      if (observer) observer.disconnect();\n      if (rowsObserver) rowsObserver.disconnect();\n      if (refreshTimer) clearInterval(refreshTimer);\n      rows.removeEventListener('click', rowClicked, true);\n      detail.removeEventListener('close', syncReader);\n      if (desktop.removeEventListener) desktop.removeEventListener('change', switchMode);\n      else if (desktop.removeListener) desktop.removeListener(switchMode);\n      detail.showModal = originalShowModal;\n      var isOpen = detail.open;\n      if (isOpen) originalClose.call(detail);\n      if (anchor.parentNode) anchor.parentNode.insertBefore(detail, anchor.nextSibling);\n      detail.classList.remove('flow-reader-detail');\n      if (layout.parentNode) layout.parentNode.insertBefore(list, layout);\n      layout.remove();\n      anchor.remove(); mobileFilters.remove(); selectLabel.remove();\n      list.classList.remove('flow-global-list');\n      filters.classList.remove('flow-global-filters', 'flow-filters-collapsed');\n      body.classList.remove('flow-reader-layout');\n      if (isOpen) originalShowModal.call(detail);\n      console.warn('Mailu theme fallback: ' + error.message);\n    }\n\n    try {\n      detail.parentNode.insertBefore(anchor, detail);\n      layout.className = 'flow-inbox-layout';\n      reader.className = 'flow-reader';\n      reader.setAttribute('aria-label', '邮件阅读区');\n      placeholder.className = 'flow-reader-placeholder';\n      var title = document.createElement('strong');\n      title.textContent = '选择一封邮件';\n      placeholder.append(title, document.createTextNode('点击左侧邮件主题，在此查看完整正文和附件。'));\n      reader.appendChild(placeholder);\n      list.parentNode.insertBefore(layout, list);\n      layout.append(list, reader);\n      list.classList.add('flow-global-list');\n      filters.classList.add('flow-global-filters', 'flow-filters-collapsed');\n      var fields = filters.querySelector('.fields');\n      if (fields) {\n        if (!fields.id) fields.id = 'flow-global-filter-fields';\n        mobileFilters.type = 'button';\n        mobileFilters.className = 'flow-filter-toggle';\n        mobileFilters.textContent = '展开筛选';\n        mobileFilters.setAttribute('aria-expanded', 'false');\n        mobileFilters.setAttribute('aria-controls', fields.id);\n        mobileFilters.addEventListener('click', filterToggle);\n        filters.insertBefore(mobileFilters, fields);\n      }\n      var selectAll = document.getElementById('select-all');\n      if (selectAll && selectAll.parentNode) {\n        selectLabel.className = 'flow-select-label';\n        selectLabel.textContent = '选择当前页全部邮件';\n        selectAll.parentNode.appendChild(selectLabel);\n      }\n      detail.setAttribute('aria-labelledby', 'subject');\n      detail.showModal = showWithMode;\n      detail.addEventListener('close', syncReader);\n      rows.addEventListener('click', rowClicked, true);\n      observer = new MutationObserver(detailUpdated);\n      observer.observe(detail, { subtree: true, childList: true, attributes: true, attributeFilter: ['class', 'open'] });\n      rowsObserver = new MutationObserver(markCurrent);\n      rowsObserver.observe(rows, { childList: true });\n      if (desktop.addEventListener) desktop.addEventListener('change', switchMode);\n      else if (desktop.addListener) desktop.addListener(switchMode);\n      switchMode();\n\n      // The original timer pauses while a modal is open. A desktop reading pane\n      // is not modal, so keep its existing load() routine refreshing the list.\n      refreshTimer = setInterval(function () {\n        var auto = document.getElementById('auto');\n        if (!desktop.matches || !detail.open || document.hidden || !auto || !auto.checked || rows.querySelector('[data-check]:checked')) return;\n        if (typeof window.load === 'function') Promise.resolve(window.load()).catch(function () {});\n      }, 15000);\n    } catch (error) { rollback(error); }\n  }\n\n  // The server places this script immediately after main, before data-loading\n  // scripts. Build the reading pane while parsing, before the first painted page.\n  if (document.querySelector('body > main')) init();\n  else if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });\n  else init();\n})();\n", 'flow-admin.css': '/* Scoped to the native Mailu AdminLTE shell; no webmail/Rspamd/tool content selectors. */\nbody.mailu-flow-admin {\n  --flow-text:#2d3544; --flow-muted:#68788e; --flow-line:#e6eaf0;\n  --flow-blue:#3c68cb; --flow-blue-soft:#edf2fc; --flow-sidebar:#f9fafc;\n  --flow-danger:#bd5148; --flow-soft:#f7f8fb;\n  font:14px/1.6 Inter,"Noto Sans SC","Microsoft YaHei",system-ui,sans-serif;\n  color:var(--flow-text); background:#fff; min-width:320px; letter-spacing:0; -webkit-font-smoothing:antialiased;\n}\n.mailu-flow-admin *, .mailu-flow-admin *:before, .mailu-flow-admin *:after { box-sizing:border-box; }\n.mailu-flow-admin .wrapper { background:#fff; min-width:0; overflow:visible; }\n.mailu-flow-admin a { color:var(--flow-blue); }\n.mailu-flow-admin a:hover { color:#315bb7; }\n.mailu-flow-admin .main-sidebar { position:fixed!important; top:0; left:0; bottom:0; width:194px!important; height:100dvh; margin:0!important; transform:none; background:var(--flow-sidebar)!important; overflow:hidden; z-index:1038; transition:transform .16s ease; }\n.mailu-flow-admin .main-header, .mailu-flow-admin .content-wrapper, .mailu-flow-admin .main-footer { margin-left:194px!important; transition:none!important; }\n.mailu-flow-admin .main-header {\n  height:58px; min-height:58px; background:#fff!important; border:0; border-bottom:1px solid var(--flow-line);\n  padding:0 25px; color:var(--flow-muted); box-shadow:none!important; flex-wrap:nowrap;\n}\n.mailu-flow-admin .main-header .navbar-nav { align-items:center; min-width:0; }\n.mailu-flow-admin .main-header .nav-link { padding:8px 10px; height:auto; color:var(--flow-muted)!important; font-size:13px; overflow-wrap:anywhere; }\n.mailu-flow-admin .main-header .nav-link:hover { color:var(--flow-blue)!important; }\n.mailu-flow-admin .main-header [data-widget="pushmenu"] { display:none!important; }\n.mailu-flow-admin .main-header .navbar-brand { font-size:14px; color:var(--flow-text); }\n.mailu-flow-admin .content-wrapper { background:#fff!important; min-width:0; min-height:calc(100dvh - 114px)!important; padding:0 30px 25px; }\n.mailu-flow-admin .content-header { padding:26px 0 20px; }\n.mailu-flow-admin .content-header h1 { font-size:23px!important; line-height:1.5; font-weight:600; margin:0; overflow-wrap:anywhere; }\n.mailu-flow-admin .content-header h1 small { display:block; margin-top:5px; font-size:13px; font-weight:400; color:var(--flow-muted); }\n.mailu-flow-admin .content-header .breadcrumb { padding:0; margin:0; font-size:12px; color:var(--flow-muted); background:none; flex-wrap:wrap; }\n.mailu-flow-admin .content-header .row { align-items:center; gap:10px 0; }\n.mailu-flow-admin .content, .mailu-flow-admin .content>.container-fluid { padding:0; min-width:0; }\n.mailu-flow-admin .content>.container-fluid { max-width:1600px; }\n.mailu-flow-admin .container, .mailu-flow-admin .container-fluid, .mailu-flow-admin .row>[class*="col"] { min-width:0; }\n.mailu-flow-admin .main-footer { padding:17px 30px; border-top:1px solid var(--flow-line); background:#fff; font-size:12px; color:var(--flow-muted); }\n.mailu-flow-admin h2, .mailu-flow-admin h3, .mailu-flow-admin .card-title { font-size:17px; font-weight:600; line-height:1.6; }\n.mailu-flow-admin h4, .mailu-flow-admin h5, .mailu-flow-admin h6 { font-size:14px; font-weight:600; }\n.mailu-flow-admin p { overflow-wrap:anywhere; }\n.mailu-flow-admin .card, .mailu-flow-admin .box { border:1px solid var(--flow-line); border-radius:5px; box-shadow:none!important; background:#fff; margin-bottom:22px; }\n.mailu-flow-admin .card[class*="card-outline"], .mailu-flow-admin .box { border-top:1px solid var(--flow-line); }\n.mailu-flow-admin .card-header, .mailu-flow-admin .box-header { padding:16px 20px; background:#fff; border-bottom:1px solid var(--flow-line); display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }\n.mailu-flow-admin .card-header:after, .mailu-flow-admin .box-header:after { display:none; }\n.mailu-flow-admin .card-header .card-title, .mailu-flow-admin .box-header .box-title { float:none; margin:0; }\n.mailu-flow-admin .card-tools { position:static; margin:0 0 0 auto; display:flex; gap:7px; align-items:center; flex-wrap:wrap; }\n.mailu-flow-admin .card-body, .mailu-flow-admin .box-body { padding:20px; min-width:0; }\n.mailu-flow-admin .card-footer, .mailu-flow-admin .box-footer { padding:14px 20px; background:var(--flow-soft); border-top:1px solid var(--flow-line); }\n.mailu-flow-admin label { color:var(--flow-text); font-size:14px; font-weight:500!important; margin-bottom:7px; }\n.mailu-flow-admin .form-group { margin-bottom:20px; min-width:0; }\n.mailu-flow-admin .form-control, .mailu-flow-admin .custom-select, .mailu-flow-admin .select2-container--default .select2-selection--single,\n.mailu-flow-admin .select2-container--default .select2-selection--multiple {\n  min-height:39px; height:auto; max-width:100%; border:1px solid #dfe5ee; border-radius:5px;\n  background:#fff; color:var(--flow-text); font-family:inherit; font-size:14px; line-height:1.5; padding:8px 11px; box-shadow:none;\n}\n.mailu-flow-admin input:not([type="checkbox"]):not([type="radio"]):not([type="hidden"]):not([type="submit"]):not([type="button"]), .mailu-flow-admin select, .mailu-flow-admin textarea { max-width:100%; }\n.mailu-flow-admin textarea.form-control { height:auto; min-height:110px; resize:vertical; }\n.mailu-flow-admin .form-control:focus, .mailu-flow-admin .custom-select:focus { border-color:#8da8e9; box-shadow:0 0 0 2px #3c68cb16; }\n.mailu-flow-admin .form-control::placeholder { color:#8a96a8; opacity:1; }\n.mailu-flow-admin .form-control:disabled, .mailu-flow-admin .form-control[readonly] { color:#607087; background:var(--flow-soft); }\n.mailu-flow-admin .input-group { min-width:0; flex-wrap:nowrap; }\n.mailu-flow-admin .input-group>.form-control { min-width:0; width:1%; }\n.mailu-flow-admin .input-group-text { border-color:#dfe5ee; background:var(--flow-soft); font-size:13px; overflow-wrap:anywhere; }\n.mailu-flow-admin input[type="checkbox"], .mailu-flow-admin input[type="radio"] { accent-color:var(--flow-blue); }\n.mailu-flow-admin .help-block, .mailu-flow-admin .form-text, .mailu-flow-admin .text-muted { color:var(--flow-muted)!important; font-size:12px; line-height:1.7; overflow-wrap:anywhere; }\n.mailu-flow-admin .invalid-feedback, .mailu-flow-admin .has-error .help-block, .mailu-flow-admin .text-danger { color:var(--flow-danger)!important; font-size:13px; line-height:1.6; }\n.mailu-flow-admin .has-error .form-control, .mailu-flow-admin .form-control.is-invalid { border-color:var(--flow-danger)!important; }\n.mailu-flow-admin .btn { min-height:37px; max-width:100%; border-radius:4px; padding:7px 12px; font-size:14px; line-height:1.5; box-shadow:none!important; white-space:normal; }\n.mailu-flow-admin .btn-sm, .mailu-flow-admin .btn-xs { min-height:31px; padding:4px 9px; font-size:12px; }\n.mailu-flow-admin .btn-primary, .mailu-flow-admin .btn-info { color:#fff; background:var(--flow-blue); border-color:var(--flow-blue); }\n.mailu-flow-admin .btn-primary:hover, .mailu-flow-admin .btn-info:hover { color:#fff; background:#315bb7; border-color:#315bb7; }\n.mailu-flow-admin .btn-default, .mailu-flow-admin .btn-secondary { color:var(--flow-text); background:#fff; border-color:#dfe5ee; }\n.mailu-flow-admin .btn-default:hover, .mailu-flow-admin .btn-secondary:hover { background:var(--flow-soft); color:var(--flow-text); }\n.mailu-flow-admin .btn-danger { background:var(--flow-danger); border-color:var(--flow-danger); color:#fff; }\n.mailu-flow-admin .btn-outline-danger { border-color:#efc8c3; background:#fff5f3; color:#af4b42; }\n.mailu-flow-admin .btn-link { color:var(--flow-blue); }\n.mailu-flow-admin .btn:disabled, .mailu-flow-admin .btn.disabled { opacity:.45; }\n.mailu-flow-admin .btn-group { flex-wrap:wrap; }\n.mailu-flow-admin .flow-table-scroll, .mailu-flow-admin .table-responsive { max-width:100%; overflow-x:auto; scrollbar-width:thin; }\n.mailu-flow-admin .table { margin-bottom:0; color:var(--flow-text); font-size:14px; border-color:var(--flow-line); }\n.mailu-flow-admin .table thead th { color:var(--flow-muted); font-size:12px; font-weight:500; background:var(--flow-soft); border-bottom:1px solid var(--flow-line); padding:11px 13px; vertical-align:middle; }\n.mailu-flow-admin .table tbody td, .mailu-flow-admin .table tbody th { padding:13px; border-color:var(--flow-line); vertical-align:middle; line-height:1.6; }\n.mailu-flow-admin .table tbody tr:nth-of-type(odd) { background:transparent; }\n.mailu-flow-admin .table tbody tr:hover { background:#f7f9fd; }\n.mailu-flow-admin .table .btn { white-space:nowrap; }\n.mailu-flow-admin .table td code { overflow-wrap:anywhere; }\n.mailu-flow-admin .flow-table-scroll:focus-visible { outline:2px solid var(--flow-blue); outline-offset:2px; }\n.mailu-flow-admin .badge { font-size:12px; padding:4px 7px; font-weight:500; border-radius:4px; }\n.mailu-flow-admin .badge-info, .mailu-flow-admin .badge-primary { color:var(--flow-blue); background:var(--flow-blue-soft); }\n.mailu-flow-admin .alert { border-radius:5px; padding:13px 16px; font-size:14px; line-height:1.7; overflow-wrap:anywhere; box-shadow:none; }\n.mailu-flow-admin .alert-info { background:#edf3fd; border:1px solid #dbe6fc; color:#315591; }\n.mailu-flow-admin .alert-danger { background:#fff2ef; border:1px solid #efcfca; color:#a6453d; }\n.mailu-flow-admin .alert-warning { background:#fff8e9; border:1px solid #eddfbb; color:#876825; }\n.mailu-flow-admin .alert-success { background:#edf7f2; border:1px solid #d6e9df; color:#337158; }\n.mailu-flow-admin .nav-tabs { border-color:var(--flow-line); gap:12px; overflow-x:auto; flex-wrap:nowrap; }\n.mailu-flow-admin .nav-tabs .nav-link { border:0; border-bottom:2px solid transparent; border-radius:0; padding:14px 8px; white-space:nowrap; color:var(--flow-muted); }\n.mailu-flow-admin .nav-tabs .nav-link.active { color:var(--flow-blue); border-bottom-color:var(--flow-blue); background:#fff; }\n.mailu-flow-admin .page-link { color:var(--flow-blue); border-color:var(--flow-line); }\n.mailu-flow-admin .page-item.active .page-link { background:var(--flow-blue); border-color:var(--flow-blue); }\n.mailu-flow-admin pre { padding:16px; border:1px solid var(--flow-line); border-radius:5px; background:var(--flow-soft); white-space:pre-wrap; overflow-wrap:anywhere; font-size:12px; line-height:1.7; }\n.mailu-flow-admin code { color:#4266a0; font-size:12px; }\n.mailu-flow-admin .modal-dialog { min-height:calc(100% - 48px); display:flex; align-items:center; width:calc(100% - 48px); max-width:600px; margin:24px auto; }\n.mailu-flow-admin .modal-content { border:1px solid var(--flow-line); border-radius:7px; box-shadow:0 20px 70px #23385638; max-height:calc(100dvh - 48px); overflow:hidden; }\n.mailu-flow-admin .modal-body { overflow-y:auto; min-height:0; padding:20px 24px; }\n.mailu-flow-admin .modal-header, .mailu-flow-admin .modal-footer { flex-shrink:0; padding:16px 24px; border-color:var(--flow-line); }\n.mailu-flow-admin .modal-footer { background:var(--flow-soft); flex-wrap:wrap; }\n.mailu-flow-admin .modal-title { font-size:17px; font-weight:600; }\n.mailu-flow-admin :is(a,button,input,select,textarea):focus-visible { outline:2px solid var(--flow-blue); outline-offset:2px; }\n#flow-admin-nav-toggle, #flow-admin-nav-close, #flow-admin-nav-backdrop { display:none; }\n@media(max-width:1100px) {\n  .mailu-flow-admin .content-wrapper { padding-right:22px; padding-left:22px; }\n  .mailu-flow-admin .main-header { padding:0 17px; }\n}\n@media(max-width:900px) {\n  .mailu-flow-admin .main-sidebar { width:236px!important; transform:translateX(-100%)!important; z-index:1051; }\n  .mailu-flow-admin.flow-admin-nav-open .main-sidebar { transform:translateX(0)!important; }\n  .mailu-flow-admin .main-header, .mailu-flow-admin .content-wrapper, .mailu-flow-admin .main-footer { margin-left:0!important; }\n  .mailu-flow-admin .main-header { padding:0 12px; height:58px; }\n  #flow-admin-nav-toggle, #flow-admin-nav-close { display:inline-flex; align-items:center; justify-content:center; width:33px; height:33px; flex:none; padding:0; margin-right:6px; border:0; border-radius:4px; background:transparent; color:#68788e; cursor:pointer; }\n  #flow-admin-nav-close { position:absolute; right:8px; top:20px; z-index:2; margin:0; font-size:25px; line-height:1; }\n  .mailu-flow-admin .brand-link { padding-right:45px!important; }\n  #flow-admin-nav-toggle:hover, #flow-admin-nav-close:hover { background:#eef1f7; color:#3c68cb; }\n  .mailu-flow-admin.flow-admin-nav-open { overflow:hidden; }\n  .mailu-flow-admin.flow-admin-nav-open #flow-admin-nav-backdrop { display:block; position:fixed; inset:0; width:100%; height:100%; border:0; border-radius:0; padding:0; margin:0; background:#1b294955; z-index:1050; cursor:pointer; }\n  .mailu-flow-admin .content-wrapper { padding:0 15px 20px; }\n  .mailu-flow-admin .content-header { padding:21px 0 17px; }\n  .mailu-flow-admin .content-header h1 { font-size:22px!important; }\n  .mailu-flow-admin .content-header .breadcrumb.float-sm-right { float:none!important; margin-top:5px; }\n  .mailu-flow-admin .main-footer { padding:15px; overflow-wrap:anywhere; }\n  .mailu-flow-admin .card-header, .mailu-flow-admin .box-header { padding:14px 15px; }\n  .mailu-flow-admin .card-body, .mailu-flow-admin .box-body { padding:16px 15px; }\n  .mailu-flow-admin .card-footer, .mailu-flow-admin .box-footer { padding:12px 15px; }\n  .mailu-flow-admin .table th, .mailu-flow-admin .table td { white-space:nowrap; }\n  .mailu-flow-admin .table td code { white-space:normal; }\n  .mailu-flow-admin .form-inline { gap:10px; align-items:stretch; }\n  .mailu-flow-admin .form-inline>.form-group, .mailu-flow-admin .form-inline>.form-control { width:100%; }\n  .mailu-flow-admin .form-inline label { justify-content:flex-start; }\n  .mailu-flow-admin .form-inline .btn { width:auto; }\n  .mailu-flow-admin .form-group .input-group-text { max-width:45vw; }\n  .mailu-flow-admin .modal-dialog { min-height:calc(100% - 24px); width:calc(100% - 24px); margin:12px auto; }\n  .mailu-flow-admin .modal-content { max-height:calc(100dvh - 24px); }\n  .mailu-flow-admin .modal-header, .mailu-flow-admin .modal-footer { padding:15px 16px; }\n  .mailu-flow-admin .modal-body { padding:17px 16px; }\n}\n@media(prefers-reduced-motion:reduce) { .mailu-flow-admin .main-sidebar { transition:none; } }\n/* The outer Mailu shell owns navigation when a native page is embedded. */\nhtml.flow-embedded-surface .mailu-flow-admin .main-sidebar { display:none!important; }\nhtml.flow-embedded-surface .mailu-flow-admin :is(.main-header,.content-wrapper,.main-footer) { margin-left:0!important; }\n', 'flow-admin.js': '(function () {\n  \'use strict\';\n  var sidebarStyle = \'/admin/mail-control/ui/flow-sidebar.css\';\n  var toolsRoot = \'/admin/mail-control/\';\n  var mounted = new WeakSet();\n\n  // Move only existing navigation nodes. A restricted user never receives additional links.\n  function arrange(sidebar) {\n    var list = sidebar.querySelector(\'.nav-sidebar\');\n    if (!list) return;\n    var tools = Array.from(list.children).filter(function (node) { return node.dataset.mailControlNav && node.dataset.mailControlNav !== \'header\'; });\n    var toolHeading = list.querySelector(\'[data-mail-control-nav="header"]\');\n    if (toolHeading && tools.length && list.firstElementChild !== toolHeading) {\n      toolHeading.textContent = \'邮件工作台\';\n      var globalTool = tools.find(function (node) { return node.dataset.mailControlNav === \'global/\'; });\n      if (globalTool) tools = [globalTool].concat(tools.filter(function (node) { return node !== globalTool; }));\n      var fragment = document.createDocumentFragment();\n      fragment.appendChild(toolHeading);\n      tools.forEach(function (node) { fragment.appendChild(node); });\n      list.prepend(fragment);\n    }\n    var current = location.pathname.replace(/\\/+$/, \'\') || \'/\';\n    var match = null;\n    var longest = 0;\n    list.querySelectorAll(\'a[href]\').forEach(function (link) {\n      var target;\n      try { target = new URL(link.getAttribute(\'href\'), location.origin); } catch (error) { return; }\n      if (target.origin !== location.origin || target.pathname.indexOf(\'/admin/\') !== 0 || target.pathname.indexOf(toolsRoot) === 0) return;\n      var targetPath = target.pathname.replace(/\\/+$/, \'\');\n      if ((current === targetPath || current.indexOf(targetPath + \'/\') === 0) && targetPath.length > longest) { match = link; longest = targetPath.length; }\n    });\n    if (match && current.indexOf(toolsRoot) !== 0) {\n      list.querySelectorAll(\'a.active\').forEach(function (link) { if (link !== match) { link.classList.remove(\'active\'); link.removeAttribute(\'aria-current\'); } });\n      match.classList.add(\'active\');\n      match.setAttribute(\'aria-current\', \'page\');\n    }\n  }\n\n  function enhanceTables(root) {\n    root.querySelectorAll(\'.content-wrapper table.table\').forEach(function (table) {\n      if (table.closest(\'.flow-table-scroll,.table-responsive\')) return;\n      var scroll = document.createElement(\'div\');\n      scroll.className = \'flow-table-scroll\';\n      scroll.tabIndex = 0;\n      scroll.setAttribute(\'role\', \'region\');\n      var heading = table.closest(\'.card,.box\');\n      heading = heading && heading.querySelector(\'.card-title,.box-title\');\n      scroll.setAttribute(\'aria-label\', (heading && heading.textContent.trim() || \'数据表\') + \'，可横向滚动\');\n      table.parentNode.insertBefore(scroll, table);\n      scroll.appendChild(table);\n    });\n  }\n\n  function nativeDrawer(sidebar) {\n    if (document.getElementById(\'flow-admin-nav-toggle\')) return;\n    var header = document.querySelector(\'.main-header\');\n    if (!header) return;\n    var toggle = document.createElement(\'button\');\n    toggle.id = \'flow-admin-nav-toggle\';\n    toggle.type = \'button\';\n    toggle.setAttribute(\'aria-label\', \'打开导航\');\n    toggle.setAttribute(\'aria-expanded\', \'false\');\n    if (!sidebar.id) sidebar.id = \'flow-admin-sidebar\';\n    toggle.setAttribute(\'aria-controls\', sidebar.id);\n    var icon = document.createElement(\'i\');\n    icon.className = \'fa fa-bars\';\n    icon.setAttribute(\'aria-hidden\', \'true\');\n    toggle.appendChild(icon);\n    var close = document.createElement(\'button\');\n    close.id = \'flow-admin-nav-close\';\n    close.type = \'button\';\n    close.textContent = \'\\u00d7\';\n    close.setAttribute(\'aria-label\', \'关闭导航\');\n    var backdrop = document.createElement(\'button\');\n    backdrop.id = \'flow-admin-nav-backdrop\';\n    backdrop.type = \'button\';\n    backdrop.setAttribute(\'aria-label\', \'关闭导航\');\n    backdrop.tabIndex = -1;\n    var inertNodes = [];\n    var media = matchMedia(\'(max-width:900px)\');\n    function setOpen(open, restoreFocus) {\n      document.body.classList.toggle(\'flow-admin-nav-open\', open);\n      toggle.setAttribute(\'aria-expanded\', String(open));\n      if (open) {\n        inertNodes = Array.from(document.querySelectorAll(\'.main-header,.content-wrapper,.main-footer\')).filter(function (node) { return !node.inert; });\n        inertNodes.forEach(function (node) { node.inert = true; });\n        close.focus();\n      } else {\n        inertNodes.forEach(function (node) { node.inert = false; });\n        inertNodes = [];\n        if (restoreFocus !== false) toggle.focus();\n      }\n    }\n    toggle.addEventListener(\'click\', function () { setOpen(true); });\n    close.addEventListener(\'click\', function () { setOpen(false); });\n    backdrop.addEventListener(\'click\', function () { setOpen(false); });\n    document.addEventListener(\'keydown\', function (event) {\n      if (!document.body.classList.contains(\'flow-admin-nav-open\')) return;\n      if (event.key === \'Escape\') { event.preventDefault(); setOpen(false); return; }\n      if (event.key !== \'Tab\') return;\n      var focusable = Array.from(sidebar.querySelectorAll(\'a[href],button:not([disabled]),[tabindex="0"]\')).filter(function (node) { return node.getClientRects().length; });\n      if (!focusable.length) return;\n      var first = focusable[0], last = focusable[focusable.length - 1];\n      if (event.shiftKey && (document.activeElement === first || !sidebar.contains(document.activeElement))) { event.preventDefault(); last.focus(); }\n      else if (!event.shiftKey && (document.activeElement === last || !sidebar.contains(document.activeElement))) { event.preventDefault(); first.focus(); }\n    });\n    media.addEventListener(\'change\', function () { if (!media.matches) setOpen(false, false); });\n    header.prepend(toggle);\n    sidebar.prepend(close);\n    document.body.appendChild(backdrop);\n  }\n\n  function enhance() {\n    var native = document.querySelector(\'.main-sidebar\');\n    if (native && document.querySelector(\'.content-wrapper\')) {\n      document.body.classList.add(\'mailu-flow-admin\');\n      native.classList.add(\'flow-sidebar-surface\');\n      arrange(native);\n      nativeDrawer(native);\n      enhanceTables(document);\n    }\n    var host = document.getElementById(\'mail-control-side-nav\');\n    if (host && host.shadowRoot) {\n      var shadow = host.shadowRoot;\n      if (!mounted.has(shadow)) {\n        if (!shadow.querySelector(\'[data-flow-sidebar]\')) {\n          var style = document.createElement(\'link\');\n          style.rel = \'stylesheet\';\n          style.href = sidebarStyle;\n          style.dataset.flowSidebar = \'true\';\n          shadow.appendChild(style);\n        }\n        mounted.add(shadow);\n      }\n      arrange(shadow);\n    }\n  }\n\n  function init() {\n    if (window.self !== window.top || location.pathname.indexOf(\'/admin/\') !== 0 || new URLSearchParams(location.search).get(\'embedded\') === \'1\') return;\n    // The native stylesheet is a render-blocking head resource. This fallback is\n    // only needed by older pages that have not received the new response filter.\n    if (document.querySelector(\'.main-sidebar\') && !document.querySelector(\'link[data-flow-native-sidebar]\')) {\n      var link = document.createElement(\'link\');\n      link.rel = \'stylesheet\';\n      link.href = sidebarStyle;\n      link.dataset.flowNativeSidebar = \'true\';\n      document.head.appendChild(link);\n    }\n    enhance();\n    var scheduled = false;\n    var observer = new MutationObserver(function () {\n      if (scheduled) return;\n      scheduled = true;\n      requestAnimationFrame(function () { scheduled = false; enhance(); });\n    });\n    observer.observe(document.body, {childList:true, subtree:true});\n  }\n  if (document.body && (document.querySelector(\'.main-sidebar\') || document.getElementById(\'mail-control-side-nav\'))) init();\n  else if (document.readyState === \'loading\') document.addEventListener(\'DOMContentLoaded\', init);\n  else init();\n})();\n', 'flow-sidebar.css': '/* Shared native/Shadow DOM sidebar. Existing menu nodes and permissions stay intact. */\n:host {\n  --flow-text:#2d3544; --flow-muted:#68788e; --flow-line:#e6eaf0;\n  --flow-blue:#3c68cb; --flow-blue-soft:#edf2fc; --flow-sidebar:#f9fafc;\n  display:block; width:194px!important; color:var(--flow-text); background:var(--flow-sidebar)!important;\n  font:14px/1.5 Inter,"Noto Sans SC","Microsoft YaHei",system-ui,sans-serif;\n  letter-spacing:0; color-scheme:light;\n}\n.flow-sidebar-surface { --flow-text:#2d3544; --flow-muted:#68788e; --flow-line:#e6eaf0; --flow-blue:#3c68cb; --flow-blue-soft:#edf2fc; --flow-sidebar:#f9fafc; }\n.flow-sidebar-surface, :host { box-shadow:none!important; border-right:1px solid var(--flow-line)!important; }\n:host *, .flow-sidebar-surface * { box-sizing:border-box; letter-spacing:0; }\n:host .brand, .flow-sidebar-surface .brand-link {\n  display:flex!important; align-items:center; gap:10px; height:74px; min-height:74px;\n  padding:0 20px!important; margin:0; color:var(--flow-text)!important; background:var(--flow-sidebar)!important;\n  border-bottom:1px solid var(--flow-line)!important; font-size:22px!important; font-weight:650;\n  line-height:1.2; text-decoration:none; white-space:normal;\n}\n.flow-sidebar-surface .brand-link .brand-image { float:none; max-height:25px; width:25px; height:25px; margin:0!important; opacity:1; border-radius:4px; box-shadow:none!important; }\n.flow-sidebar-surface .brand-link .brand-text { margin:0!important; font-weight:650!important; font-size:22px; }\n:host .brand i, .flow-sidebar-surface .brand-link>i { color:var(--flow-blue); font-size:22px; }\n:host .sidebar, .flow-sidebar-surface .sidebar {\n  display:flex!important; flex-direction:column; height:calc(100dvh - 74px)!important;\n  min-height:0; padding:0 9px!important; overflow-x:hidden!important; overflow-y:auto!important;\n  scrollbar-width:thin; scrollbar-color:#cad4e6 transparent;\n}\n:host .sidebar>nav, .flow-sidebar-surface .sidebar>nav { flex:1 0 auto; min-width:0; margin:0!important; padding:0; }\n:host .nav-sidebar, .flow-sidebar-surface .nav-sidebar { width:100%!important; margin:0; padding:0; list-style:none; display:flex; flex-direction:column; }\n:host .nav-sidebar>.nav-item, .flow-sidebar-surface .nav-sidebar>.nav-item { width:100%; margin:0; }\n:host .nav-sidebar .nav-header, .flow-sidebar-surface .nav-sidebar .nav-header {\n  padding:17px 10px 7px!important; margin:0; color:var(--flow-muted)!important; background:none!important;\n  font-size:12px!important; font-weight:500; line-height:18px; text-transform:none!important;\n}\n:host .nav-sidebar .nav-link, .flow-sidebar-surface .nav-sidebar .nav-link {\n  position:relative; display:flex!important; align-items:center; gap:10px; min-height:36px;\n  width:100%!important; padding:7px 10px!important; margin:0 0 2px!important; border:0!important;\n  border-radius:4px!important; background:transparent; color:var(--flow-muted)!important;\n  font-size:14px!important; font-weight:400; line-height:22px; text-decoration:none;\n  white-space:normal; box-shadow:none!important;\n}\n:host .nav-sidebar .nav-link:hover, :host .nav-sidebar .nav-link:focus-visible,\n.flow-sidebar-surface .nav-sidebar .nav-link:hover, .flow-sidebar-surface .nav-sidebar .nav-link:focus-visible { background:#eef1f7!important; color:var(--flow-text)!important; }\n:host .nav-sidebar .nav-link.active, .flow-sidebar-surface .nav-sidebar .nav-link.active {\n  background:var(--flow-blue-soft)!important; color:var(--flow-blue)!important; font-weight:600;\n}\n:host .nav-sidebar .nav-link.active:before, .flow-sidebar-surface .nav-sidebar .nav-link.active:before {\n  content:""; position:absolute; left:0; top:8px; bottom:8px; width:2px; border-radius:2px; background:var(--flow-blue);\n}\n:host .nav-sidebar .nav-icon, .flow-sidebar-surface .nav-sidebar .nav-icon {\n  flex:none; width:18px!important; min-width:18px; margin:0!important; text-align:center; font-size:16px!important;\n}\n:host .nav-sidebar p, .flow-sidebar-surface .nav-sidebar p { display:block!important; width:auto!important; min-width:0; margin:0!important; line-height:22px; overflow-wrap:anywhere; }\n:host .nav-sidebar p .text-xs, .flow-sidebar-surface .nav-sidebar p .text-xs { font-size:10px!important; margin-left:3px; }\n:host .user-panel, .flow-sidebar-surface .user-panel {\n  display:flex!important; align-items:center; gap:9px; flex:none; min-height:58px;\n  padding:12px 3px!important; margin:0 3px 2px!important; border-bottom:1px solid var(--flow-line)!important;\n  white-space:normal; overflow:visible;\n}\n:host .user-panel .image, .flow-sidebar-surface .user-panel .image { padding:0; flex:none; }\n:host .user-panel .image>div, .flow-sidebar-surface .user-panel .image>div {\n  display:grid; place-items:center; width:28px; height:28px; border-radius:6px; background:#eaf0fb!important; box-shadow:none!important;\n}\n:host .user-panel .image i, .flow-sidebar-surface .user-panel .image i { font-size:14px!important; color:var(--flow-blue)!important; }\n:host .user-panel .info, .flow-sidebar-surface .user-panel .info { min-width:0; padding:0; flex:1; }\n:host .user-panel .info a, .flow-sidebar-surface .user-panel .info a {\n  color:var(--flow-text)!important; font-size:12px; line-height:18px; text-decoration:none; overflow-wrap:anywhere;\n}\n:host .close-nav { display:none; position:absolute; top:20px; right:8px; width:32px; height:32px; padding:0; border:0; border-radius:4px; background:transparent; color:var(--flow-muted)!important; font:25px/1 system-ui; cursor:pointer; }\n:host .close-nav:hover { background:#eef1f7; color:var(--flow-text)!important; }\n:host a:focus-visible, :host button:focus-visible,\n.flow-sidebar-surface a:focus-visible, .flow-sidebar-surface button:focus-visible { outline:2px solid var(--flow-blue)!important; outline-offset:2px; }\n@media(max-width:900px) {\n  :host { width:236px!important; }\n  :host .close-nav { display:block; }\n  :host .brand { padding-right:45px!important; }\n}\n', 'flow-surfaces.css': '/* Existing Rspamd controls and SnappyMail theme tokens; message bodies stay untouched. */\nbody[data-flow-surface="rspamd"] { font:14px/1.6 system-ui,"Microsoft YaHei",sans-serif; color:#2d3544; background:#fff; --bs-primary:#3c68cb; --bs-link-color:#3c68cb; }\nbody[data-flow-surface="rspamd"].mail-control-shell { margin-left:194px!important; }\nbody[data-flow-surface="rspamd"] #navBar { background:#fff!important; border-bottom:1px solid #e6eaf0; padding:12px 20px; }\nbody[data-flow-surface="rspamd"] #mainUI>.container-fluid { padding:20px 24px; }\nbody[data-flow-surface="rspamd"] .card { border:1px solid #e6eaf0; border-radius:5px; box-shadow:none!important; }\nbody[data-flow-surface="rspamd"] #mainUI .row>* { min-width:0; }\nbody[data-flow-surface="rspamd"] .card { min-width:0; max-width:100%; }\nbody[data-flow-surface="rspamd"] .card-body { min-width:0; overflow-x:auto; }\nbody[data-flow-surface="rspamd"] .card-body svg { max-width:100%; }\nbody[data-flow-surface="rspamd"] .card-header { padding:13px 16px; background:#f7f8fb; background-image:none; border-color:#e6eaf0; color:#627087; }\nbody[data-flow-surface="rspamd"] .nav-link { color:#627087; border-radius:4px; }\nbody[data-flow-surface="rspamd"] .nav-link.active { background:#edf2fc!important; color:#3c68cb!important; }\nbody[data-flow-surface="rspamd"] .btn { border-radius:4px; box-shadow:none; }\nbody[data-flow-surface="rspamd"] .btn-primary { --bs-btn-bg:#3c68cb; --bs-btn-border-color:#3c68cb; --bs-btn-hover-bg:#315bb7; --bs-btn-hover-border-color:#315bb7; }\nbody[data-flow-surface="rspamd"] :is(.form-control,.form-select) { border-color:#dce2eb; border-radius:4px; }\nbody[data-flow-surface="rspamd"] .table thead th { background:#f7f8fb; font-size:12px; font-weight:500; color:#627087; }\nbody[data-flow-surface="rspamd"] .table :is(td,th) { padding:10px 12px; border-color:#e6eaf0; }\nbody[data-flow-surface="rspamd"] .modal-dialog { max-width:min(800px,calc(100vw - 32px)); min-height:calc(100dvh - 32px); margin:16px auto; display:flex; align-items:center; }\nbody[data-flow-surface="rspamd"] .modal-content { max-height:calc(100dvh - 32px); border:1px solid #e6eaf0; border-radius:6px; }\nbody[data-flow-surface="rspamd"] .modal-body { overflow:auto; }\nbody[data-flow-surface="rspamd"] #mail-control-nav-toggle { background:#fff; color:#627087; border-bottom:1px solid #e6eaf0; }\nbody#rl-app {\n color-scheme:light; --main-color:#2d3544; --main-bg-color:#f9fafc; --main-bg-image:none;\n --fontSans:system-ui,"Microsoft YaHei",sans-serif; --loading-color:#68788e; --loading-text-shadow:none;\n --login-color:#2d3544; --login-bg-color:#fff; --login-box-shadow:0 12px 45px #23385612; --login-border:1px solid #e6eaf0; --login-border-radius:6px;\n --dropdown-menu-color:#2d3544; --dropdown-menu-bg-color:#fff; --dropdown-menu-hover-bg-color:#edf2fc; --dropdown-menu-hover-color:#3c68cb; --dropdown-menu-disable-color:#99a3b3;\n --folders-color:#68788e; --folders-disabled-color:#99a3b3; --folders-selected-color:#3c68cb; --folders-selected-bg-color:#edf2fc; --folders-focused-color:#3c68cb; --folders-focused-bg-color:#edf2fc; --folders-hover-color:#2d3544; --folders-hover-bg-color:#eef1f7; --folders-drop-color:#3c68cb; --folders-drop-bg-color:#edf2fc;\n --settings-menu-color:#68788e; --settings-menu-selected-color:#3c68cb; --settings-menu-selected-bg-color:#edf2fc; --settings-menu-hover-color:#2d3544; --settings-menu-hover-bg-color:#eef1f7; --message-list-toolbar-bg-color:#fff;\n background-image:none!important;\n}\nbody#rl-app :is(.thm-message-list-top-toolbar,.thm-message-list-bottom-toolbar) { background:#fff!important; border-color:#e6eaf0; box-shadow:none; }\nbody#rl-app #rl-left { border-right:1px solid #e6eaf0; }\nbody#rl-app .btn { border-radius:4px; text-shadow:none; box-shadow:none; }\nbody#rl-app .btn-primary { color:#fff; background:#3c68cb; background-image:none; border-color:#3c68cb; }\nbody#rl-app .btn-primary:hover { background:#315bb7; border-color:#315bb7; }\nbody#rl-app .buttonCompose { background:#3c68cb!important; background-image:none!important; border-color:#3c68cb!important; color:#fff!important; }\nbody#rl-app .messageListItem { border-color:#e6eaf0; }\nbody#rl-app .messageListItem.unseen { background:#f4f7fd; border-left-color:#3c68cb; }\nbody#rl-app .messageListItem.selected { background:#edf2fc; }\nbody#rl-app :is(input[type=text],input[type=password],input[type=email],textarea,select) { border-color:#dce2eb; border-radius:4px; }\nbody#rl-app .dropdown-menu { border:1px solid #e6eaf0; border-radius:5px; box-shadow:0 10px 30px #23385618; }\n@media(max-width:900px) {\n body[data-flow-surface="rspamd"].mail-control-shell { margin-left:0!important; padding-top:44px; }\n body[data-flow-surface="rspamd"] #mainUI>.container-fluid { padding:16px 12px; }\n body[data-flow-surface="rspamd"] #navBar { padding:10px 12px; }\n body[data-flow-surface="rspamd"] .table-responsive { max-width:100%; overflow:auto; }\n}\n', 'flow-surfaces.js': "(function(){\n 'use strict';\n function init(){\n  if(document.getElementById('navBar')&&document.getElementById('mainUI'))document.body.dataset.flowSurface='rspamd';\n }\n if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();\n})();\n", 'flow-bootstrap.js': "/* Runs in head. Only marks theme surfaces and prioritises existing table columns. */\n(function () {\n  'use strict';\n  var path = location.pathname;\n  var embedded = window.self !== window.top || new URLSearchParams(location.search).get('embedded') === '1';\n  var native = path.indexOf('/admin/') === 0 && path.indexOf('/admin/mail-control/') !== 0 && path.indexOf('/admin/antispam/') !== 0;\n  var rspamd = path.indexOf('/admin/antispam/') === 0;\n  if (embedded) document.documentElement.classList.add('flow-embedded-surface');\n  function apply() {\n    var body = document.body;\n    if (!body) return;\n    if (native) body.classList.add('mailu-flow-admin');\n    if (native) document.querySelectorAll('.main-sidebar').forEach(function (sidebar) { sidebar.classList.add('flow-sidebar-surface'); });\n    if (rspamd) {\n      body.dataset.flowSurface = 'rspamd';\n      if (!embedded) body.classList.add('mail-control-shell');\n    }\n    // Mailu's DataTables app initialises at the end of body. Set priorities as\n    // the table is parsed so its first Responsive pass retains the domain name.\n    if (native && (path === '/admin/domain' || path === '/admin/domain/')) {\n      document.querySelectorAll('table.dataTable thead tr').forEach(function (row) {\n        if (row.cells.length < 3) return;\n        row.cells[2].dataset.priority = '1';\n        row.cells[0].dataset.priority = '2';\n        row.cells[1].dataset.priority = '3';\n      });\n    }\n  }\n  var observer = new MutationObserver(apply);\n  observer.observe(document.documentElement, {childList:true, subtree:true});\n  apply();\n  document.addEventListener('DOMContentLoaded', function () { apply(); observer.disconnect(); }, {once:true});\n})();\n", 'flow-shell.css': '/* Font Awesome 5 Free, the same icon set shipped by Mailu\'s vendor.css.\n * Icons: CC BY 4.0; fonts: SIL OFL 1.1. https://fontawesome.com/license/free */\n@font-face{font-family:"Font Awesome 5 Free";font-style:normal;font-weight:900;font-display:swap;src:url("/static/fa-solid-900.woff2") format("woff2")}\n.flow-server-sidebar .fas,#mail-control-nav-toggle .fas{font-family:"Font Awesome 5 Free";font-weight:900;font-style:normal;font-variant:normal;text-rendering:auto;line-height:1;-webkit-font-smoothing:antialiased}\n.flow-server-sidebar .fa-search:before{content:"\\f002"}.flow-server-sidebar .fa-envelope:before{content:"\\f0e0"}.flow-server-sidebar .fa-paper-plane:before{content:"\\f1d8"}.flow-server-sidebar .fa-users:before{content:"\\f0c0"}.flow-server-sidebar .fa-bullhorn:before{content:"\\f0a1"}.flow-server-sidebar .fa-code:before{content:"\\f121"}.flow-server-sidebar .fa-wrench:before{content:"\\f0ad"}.flow-server-sidebar .fa-lock:before{content:"\\f023"}.flow-server-sidebar .fa-plane:before{content:"\\f072"}.flow-server-sidebar .fa-ticket-alt:before{content:"\\f3ff"}.flow-server-sidebar .fa-laptop:before{content:"\\f109"}.flow-server-sidebar .fa-user:before{content:"\\f007"}.flow-server-sidebar .fa-reply-all:before{content:"\\f122"}.flow-server-sidebar .fa-trash-alt:before{content:"\\f2ed"}.flow-server-sidebar .fa-globe:before{content:"\\f0ac"}.flow-server-sidebar .fa-life-ring:before{content:"\\f1cd"}.flow-server-sidebar .fa-sign-out-alt:before{content:"\\f2f5"}.flow-server-sidebar .fa-external-link-alt:before{content:"\\f35d"}#mail-control-nav-toggle .fa-bars:before{content:"\\f0c9"}\n:is(body.flow-tools,body[data-flow-surface="rspamd"]) #mail-control-side-nav.flow-server-sidebar{position:fixed;inset:0 auto 0 0;width:194px;height:100dvh;z-index:1000;background:#f9fafc;color:#2d3544;border-right:1px solid #e6eaf0;font:14px/1.5 system-ui,"Microsoft YaHei",sans-serif}\n:is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar .brand-link{display:flex;align-items:center;gap:10px;height:74px;padding:0 20px;color:#2d3544;text-decoration:none;border-bottom:1px solid #e6eaf0;font-size:22px;font-weight:650;line-height:1.2}\n:is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar .brand-image{width:25px;height:25px;object-fit:contain;border-radius:4px}\n:is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar .sidebar{display:flex;flex-direction:column;height:calc(100dvh - 74px);min-height:0;padding:0 9px;overflow-x:hidden;overflow-y:auto;scrollbar-width:thin;background:transparent}\n:is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar .user-panel{display:flex;align-items:center;gap:9px;flex:none;min-height:58px;padding:12px 3px;margin:0 3px 2px;border-bottom:1px solid #e6eaf0;white-space:normal;overflow:visible}\n:is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar .user-panel .image{flex:none}.flow-server-sidebar .user-panel .image>div{display:grid;place-items:center;width:28px;height:28px;border-radius:6px;background:#eaf0fb}.flow-server-sidebar .user-panel .image i{font-size:14px;color:#3c68cb}.flow-server-sidebar .user-panel .info{min-width:0;flex:1}.flow-server-sidebar .user-panel .info a{color:#2d3544;font-size:12px;line-height:18px;text-decoration:none;overflow-wrap:anywhere}\n:is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar nav{flex:1 0 auto;min-width:0}.flow-server-sidebar .nav-sidebar{width:100%;margin:0;padding:0;list-style:none}.flow-server-sidebar .nav-sidebar .nav-header{padding:17px 10px 7px;color:#68788e;font-size:12px;font-weight:500;line-height:18px}.flow-server-sidebar .nav-sidebar .nav-item{width:100%;margin:0}.flow-server-sidebar .nav-sidebar .nav-link{position:relative;display:flex;align-items:center;gap:10px;min-height:36px;width:100%;padding:7px 10px;margin:0 0 2px;border-radius:4px;color:#68788e;font-size:14px;line-height:22px;text-decoration:none;white-space:normal}.flow-server-sidebar .nav-sidebar .nav-link:hover,.flow-server-sidebar .nav-sidebar .nav-link:focus-visible{background:#eef1f7;color:#2d3544}.flow-server-sidebar .nav-sidebar .nav-link.active{background:#edf2fc;color:#3c68cb;font-weight:600}.flow-server-sidebar .nav-sidebar .nav-link.active:before{content:"";position:absolute;left:0;top:8px;bottom:8px;width:2px;border-radius:2px;background:#3c68cb}.flow-server-sidebar .nav-sidebar .nav-icon{flex:none;width:18px;min-width:18px;margin:0;text-align:center;font-size:16px}.flow-server-sidebar .nav-sidebar p{display:block;width:auto;min-width:0;margin:0;line-height:22px;overflow-wrap:anywhere}.flow-server-sidebar .nav-sidebar .text-xs{font-size:10px;margin-left:3px}\n:is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar a:focus-visible,:is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar button:focus-visible,:is(body.flow-tools,body[data-flow-surface="rspamd"]) #mail-control-nav-toggle:focus-visible{outline:2px solid #3c68cb;outline-offset:2px}\n:is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar .flow-shell-close{display:none}\n:is(body.flow-tools,body[data-flow-surface="rspamd"]) #mail-control-nav-toggle,:is(body.flow-tools,body[data-flow-surface="rspamd"]) #mail-control-nav-backdrop{display:none}\nhtml.flow-embedded-surface :is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar,html.flow-embedded-surface :is(body.flow-tools,body[data-flow-surface="rspamd"]) #mail-control-nav-toggle{display:none!important}\n@media(max-width:900px){\n :is(body.flow-tools,body[data-flow-surface="rspamd"]) #mail-control-side-nav.flow-server-sidebar{width:236px;transform:translateX(-100%);transition:transform .15s ease;z-index:1000}\n :is(body.flow-tools,body[data-flow-surface="rspamd"]).mail-control-nav-open #mail-control-side-nav.flow-server-sidebar{transform:translateX(0)}\n :is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar .flow-shell-close{display:flex;position:absolute;right:8px;top:20px;width:32px;height:32px;align-items:center;justify-content:center;padding:0;min-height:0;border:0;border-radius:4px;background:transparent;color:#68788e;font:25px/1 system-ui;cursor:pointer;z-index:1}\n :is(body.flow-tools,body[data-flow-surface="rspamd"]) #mail-control-nav-toggle{display:flex;align-items:center;gap:10px;position:fixed;top:0;left:0;right:0;height:44px;z-index:900;width:100%;border:0;border-bottom:1px solid #e6eaf0;border-radius:0;background:#fff;color:#68788e;padding:0 14px;font:14px system-ui;cursor:pointer}\n :is(body.flow-tools,body[data-flow-surface="rspamd"]).mail-control-nav-open #mail-control-nav-backdrop{display:block;position:fixed;inset:0;z-index:999;background:#1b294955;border:0;width:100%;height:100%;border-radius:0;padding:0;margin:0}\n :is(body.flow-tools,body[data-flow-surface="rspamd"]).mail-control-nav-open{overflow:hidden}\n :is(body.flow-tools,body[data-flow-surface="rspamd"]) .flow-server-sidebar .brand-link{padding-right:45px!important}\n}\n@media(prefers-reduced-motion:reduce){:is(body.flow-tools,body[data-flow-surface="rspamd"]) #mail-control-side-nav.flow-server-sidebar{transition:none}}\n', 'flow-shell.js': "/* Hydrate the already-rendered navigation; never fetch account/menu data. */\n(function(){\n 'use strict';\n var host=document.getElementById('mail-control-side-nav');\n if(!host||!host.classList.contains('flow-server-sidebar')||self!==top)return;\n var toggle=document.getElementById('mail-control-nav-toggle'),close=document.getElementById('flow-shell-close'),backdrop=document.getElementById('mail-control-nav-backdrop');\n var inertNodes=[],previousFocus=null,media=matchMedia('(max-width:900px)');\n function setOpen(value,restore){\n  document.body.classList.toggle('mail-control-nav-open',value);toggle.setAttribute('aria-expanded',String(value));\n  if(value){previousFocus=document.activeElement;inertNodes=Array.from(document.body.children).filter(function(n){return n!==host&&n!==toggle&&n!==backdrop&&n.tagName!=='SCRIPT'&&n.tagName!=='STYLE'&&!n.inert});inertNodes.forEach(function(n){n.inert=true});close.focus()}\n  else{inertNodes.forEach(function(n){n.inert=false});inertNodes=[];if(restore!==false)(previousFocus&&previousFocus.isConnected?previousFocus:toggle).focus()}\n }\n toggle.addEventListener('click',function(){setOpen(true)});close.addEventListener('click',function(){setOpen(false)});backdrop.addEventListener('click',function(){setOpen(false)});\n document.addEventListener('keydown',function(e){\n  if(!document.body.classList.contains('mail-control-nav-open'))return;\n  if(e.key==='Escape'){e.preventDefault();setOpen(false);return}\n  if(e.key!=='Tab')return;\n  var nodes=Array.from(host.querySelectorAll('a[href],button:not([disabled])')).filter(function(n){return n.getClientRects().length});if(!nodes.length)return;\n  var first=nodes[0],last=nodes[nodes.length-1];\n  if(e.shiftKey&&(document.activeElement===first||!host.contains(document.activeElement))){e.preventDefault();last.focus()}\n  else if(!e.shiftKey&&(document.activeElement===last||!host.contains(document.activeElement))){e.preventDefault();first.focus()}\n });\n media.addEventListener('change',function(){if(!media.matches)setOpen(false,false)});\n})();\n", 'flow-navigation.js': '(function () {\n  \'use strict\';\n  var rootPath = \'/admin/mail-control/\';\n  var entries = [\n    {label: \'邮件控制\', path: \'\', icon: \'fa-envelope\'},\n    {label: \'全局邮件查询\', path: \'global/\', icon: \'fa-search\'},\n    {label: \'自定义发件\', path: \'custom-send/\', icon: \'fa-paper-plane\'},\n    {label: \'批量邮箱\', path: \'accounts/\', icon: \'fa-users\'},\n    {label: \'邮件营销\', path: \'marketing/\', icon: \'fa-bullhorn\'},\n    {label: \'发件 API\', path: \'marketing/?tab=api\', icon: \'fa-code\'}\n  ];\n\n  function selected(item) {\n    var current = location.pathname.replace(/\\/+$/, \'\') || \'/\';\n    var target = new URL(rootPath + item.path, location.origin);\n    if (item.path === \'marketing/?tab=api\') {\n      return current === target.pathname.replace(/\\/+$/, \'\') && new URLSearchParams(location.search).get(\'tab\') === \'api\';\n    }\n    if (item.path === \'marketing/\') {\n      return current.indexOf(rootPath + \'marketing\') === 0 && new URLSearchParams(location.search).get(\'tab\') !== \'api\';\n    }\n    return current === target.pathname.replace(/\\/+$/, \'\');\n  }\n\n  function installLinks(sidebar) {\n    var list = sidebar.querySelector(\'.nav-sidebar\');\n    // The original admin template exposes this link only to global administrators.\n    if (!list || !list.querySelector(\'a[href="/admin/admin/list"]\') || list.querySelector(\'[data-mail-control-nav]\')) return false;\n    var domain = list.querySelector(\'a[href="/admin/domain"]\');\n    var before = domain ? domain.closest(\'li\').nextElementSibling : null;\n    var heading = document.createElement(\'li\');\n    heading.className = \'nav-header text-uppercase text-primary\';\n    heading.dataset.mailControlNav = \'header\';\n    heading.setAttribute(\'role\', \'none\');\n    heading.textContent = \'邮件工具\';\n    list.insertBefore(heading, before);\n    entries.forEach(function (item) {\n      var li = document.createElement(\'li\');\n      li.className = \'nav-item\';\n      li.dataset.mailControlNav = item.path || \'control\';\n      li.setAttribute(\'role\', \'none\');\n      var link = document.createElement(\'a\');\n      link.href = rootPath + item.path;\n      link.className = \'nav-link\' + (selected(item) ? \' active\' : \'\');\n      link.setAttribute(\'role\', \'menuitem\');\n      if (selected(item)) link.setAttribute(\'aria-current\', \'page\');\n      var icon = document.createElement(\'i\');\n      icon.className = \'nav-icon fa \' + item.icon;\n      icon.setAttribute(\'aria-hidden\', \'true\');\n      var label = document.createElement(\'p\');\n      label.textContent = item.label;\n      link.append(icon, label);\n      li.appendChild(link);\n      list.insertBefore(li, before);\n    });\n    return true;\n  }\n\n  function safeSidebar(source) {\n    var sidebar = source.cloneNode(true);\n    sidebar.querySelectorAll(\'a[href]\').forEach(function(link){\n      var url=new URL(link.getAttribute(\'href\'),location.origin);\n      if(url.origin===location.origin && url.pathname.indexOf(\'/admin/antispam\')===0){link.href=\'/admin/antispam/\';link.removeAttribute(\'target\');link.removeAttribute(\'data-clicked\');}\n    });\n    sidebar.querySelectorAll(\'script, style, iframe, form\').forEach(function (node) { node.remove(); });\n    sidebar.querySelectorAll(\'*\').forEach(function (node) {\n      Array.from(node.attributes).forEach(function (attribute) {\n        if (/^on/i.test(attribute.name)) node.removeAttribute(attribute.name);\n      });\n    });\n    sidebar.querySelectorAll(\'a.active\').forEach(function (link) { link.classList.remove(\'active\'); link.removeAttribute(\'aria-current\'); });\n    return sidebar;\n  }\n\n  async function toolShell() {\n    if (document.getElementById(\'mail-control-side-nav\')) return;\n    var response = await (window.flowNavigationResponse || fetch(\'/admin/domain\', {cache: \'no-store\', credentials: \'same-origin\'}));\n    if (!response) response = await fetch(\'/admin/domain\', {cache: \'no-store\', credentials: \'same-origin\'});\n    if (!response.ok || new URL(response.url).pathname.indexOf(\'/admin/\') !== 0) throw Error(\'管理导航加载失败\');\n    var original = new DOMParser().parseFromString(await response.text(), \'text/html\');\n    var source = original.querySelector(\'.sidebar\');\n    if (!source) throw Error(\'管理导航加载失败\');\n    var sidebar = safeSidebar(source);\n    if (!installLinks(sidebar)) return;\n\n    var host = document.createElement(\'aside\');\n    host.id = \'mail-control-side-nav\';\n    host.setAttribute(\'aria-label\', \'Mailu 导航\');\n    var shadow = host.attachShadow({mode: \'open\'});\n    // Shadow styles keep the Mailu framework from changing the tool forms and dialogs.\n    original.querySelectorAll(\'head link[rel="stylesheet"]\').forEach(function (link) {\n      var url = new URL(link.getAttribute(\'href\'), location.origin);\n      if (url.pathname.indexOf(\'/admin/mail-control/ui/\') === 0) return;\n      if (url.origin !== location.origin) return;\n      var copy = document.createElement(\'link\');\n      copy.rel = \'stylesheet\';\n      copy.href = url.href;\n      copy.onload = function () {\n        // Chrome does not register @font-face rules contained only in a shadow tree.\n        var rules;\n        try { rules = Array.from(copy.sheet.cssRules); } catch (error) { return; }\n        rules.filter(function (rule) {\n          return rule.type === CSSRule.FONT_FACE_RULE;\n        }).forEach(function (rule) {\n          try {\n          var family = rule.style.getPropertyValue(\'font-family\').replace(/^"|"$/g, \'\');\n          var source = rule.style.getPropertyValue(\'src\').replace(/url\\(([\'"]?)(.*?)\\1\\)/g, function (match, quote, value) {\n            var fontUrl = new URL(value, url.href);\n            if (fontUrl.origin !== location.origin) throw Error(\'Font origin is not allowed\');\n            return \'url(\' + JSON.stringify(fontUrl.href) + \')\';\n          });\n          var font = new FontFace(family, source, {\n            style: rule.style.getPropertyValue(\'font-style\') || \'normal\',\n            weight: rule.style.getPropertyValue(\'font-weight\') || \'normal\',\n            display: \'swap\'\n          });\n          document.fonts.add(font);\n          font.load().catch(function () {});\n          } catch (error) {}\n        });\n      };\n      shadow.appendChild(copy);\n    });\n    var style = document.createElement(\'style\');\n    style.textContent = \':host{display:block;font:14px system-ui,sans-serif;color:#c2c7d0;background:#343a40;letter-spacing:0}.sidebar{height:calc(100% - 58px);padding:0 8px;overflow-y:auto!important}.brand{height:58px;display:flex;align-items:center;padding:0 20px;border-bottom:1px solid #4b545c;font-size:20px;color:#fff;text-decoration:none}.nav-sidebar{list-style:none;padding:0;margin:0}.nav-sidebar .nav-header{font-size:12px;padding:10px 12px 6px;color:#8db3d8!important}.nav-sidebar .nav-link{display:flex;align-items:center;gap:8px;margin-bottom:3px;padding:8px 12px;border-radius:4px;color:#c2c7d0;text-decoration:none;white-space:normal}.nav-sidebar .nav-link:hover,.nav-sidebar .nav-link:focus-visible{background:#ffffff1a;color:#fff}.nav-sidebar .nav-link.active{background:#007bff;color:#fff}.nav-sidebar .nav-icon{flex:none;width:22px;text-align:center}.nav-sidebar p{margin:0;line-height:20px;overflow-wrap:anywhere}.user-panel .info{min-width:0}.user-panel .info a{color:#c2c7d0;overflow-wrap:anywhere}.user-panel{border-bottom:1px solid #4b545c}.close-nav{display:none;position:absolute;right:8px;top:11px;width:36px;height:36px;border:0;background:transparent;color:white;cursor:pointer;font:26px system-ui}.close-nav:focus-visible{outline:2px solid #fff}@media(max-width:900px){.close-nav{display:block}}\';\n    shadow.appendChild(style);\n    var flowStyle = document.createElement("style");\n    flowStyle.dataset.flowSidebar = "true";\n    flowStyle.textContent = \'/* Shared native/Shadow DOM sidebar. Existing menu nodes and permissions stay intact. */\\n:host {\\n  --flow-text:#2d3544; --flow-muted:#68788e; --flow-line:#e6eaf0;\\n  --flow-blue:#3c68cb; --flow-blue-soft:#edf2fc; --flow-sidebar:#f9fafc;\\n  display:block; width:194px!important; color:var(--flow-text); background:var(--flow-sidebar)!important;\\n  font:14px/1.5 Inter,"Noto Sans SC","Microsoft YaHei",system-ui,sans-serif;\\n  letter-spacing:0; color-scheme:light;\\n}\\n.flow-sidebar-surface { --flow-text:#2d3544; --flow-muted:#68788e; --flow-line:#e6eaf0; --flow-blue:#3c68cb; --flow-blue-soft:#edf2fc; --flow-sidebar:#f9fafc; }\\n.flow-sidebar-surface, :host { box-shadow:none!important; border-right:1px solid var(--flow-line)!important; }\\n:host *, .flow-sidebar-surface * { box-sizing:border-box; letter-spacing:0; }\\n:host .brand, .flow-sidebar-surface .brand-link {\\n  display:flex!important; align-items:center; gap:10px; height:74px; min-height:74px;\\n  padding:0 20px!important; margin:0; color:var(--flow-text)!important; background:var(--flow-sidebar)!important;\\n  border-bottom:1px solid var(--flow-line)!important; font-size:22px!important; font-weight:650;\\n  line-height:1.2; text-decoration:none; white-space:normal;\\n}\\n.flow-sidebar-surface .brand-link .brand-image { float:none; max-height:25px; width:25px; height:25px; margin:0!important; opacity:1; border-radius:4px; box-shadow:none!important; }\\n.flow-sidebar-surface .brand-link .brand-text { margin:0!important; font-weight:650!important; font-size:22px; }\\n:host .brand i, .flow-sidebar-surface .brand-link>i { color:var(--flow-blue); font-size:22px; }\\n:host .sidebar, .flow-sidebar-surface .sidebar {\\n  display:flex!important; flex-direction:column; height:calc(100dvh - 74px)!important;\\n  min-height:0; padding:0 9px!important; overflow-x:hidden!important; overflow-y:auto!important;\\n  scrollbar-width:thin; scrollbar-color:#cad4e6 transparent;\\n}\\n:host .sidebar>nav, .flow-sidebar-surface .sidebar>nav { flex:1 0 auto; min-width:0; margin:0!important; padding:0; }\\n:host .nav-sidebar, .flow-sidebar-surface .nav-sidebar { width:100%!important; margin:0; padding:0; list-style:none; display:flex; flex-direction:column; }\\n:host .nav-sidebar>.nav-item, .flow-sidebar-surface .nav-sidebar>.nav-item { width:100%; margin:0; }\\n:host .nav-sidebar .nav-header, .flow-sidebar-surface .nav-sidebar .nav-header {\\n  padding:17px 10px 7px!important; margin:0; color:var(--flow-muted)!important; background:none!important;\\n  font-size:12px!important; font-weight:500; line-height:18px; text-transform:none!important;\\n}\\n:host .nav-sidebar .nav-link, .flow-sidebar-surface .nav-sidebar .nav-link {\\n  position:relative; display:flex!important; align-items:center; gap:10px; min-height:36px;\\n  width:100%!important; padding:7px 10px!important; margin:0 0 2px!important; border:0!important;\\n  border-radius:4px!important; background:transparent; color:var(--flow-muted)!important;\\n  font-size:14px!important; font-weight:400; line-height:22px; text-decoration:none;\\n  white-space:normal; box-shadow:none!important;\\n}\\n:host .nav-sidebar .nav-link:hover, :host .nav-sidebar .nav-link:focus-visible,\\n.flow-sidebar-surface .nav-sidebar .nav-link:hover, .flow-sidebar-surface .nav-sidebar .nav-link:focus-visible { background:#eef1f7!important; color:var(--flow-text)!important; }\\n:host .nav-sidebar .nav-link.active, .flow-sidebar-surface .nav-sidebar .nav-link.active {\\n  background:var(--flow-blue-soft)!important; color:var(--flow-blue)!important; font-weight:600;\\n}\\n:host .nav-sidebar .nav-link.active:before, .flow-sidebar-surface .nav-sidebar .nav-link.active:before {\\n  content:""; position:absolute; left:0; top:8px; bottom:8px; width:2px; border-radius:2px; background:var(--flow-blue);\\n}\\n:host .nav-sidebar .nav-icon, .flow-sidebar-surface .nav-sidebar .nav-icon {\\n  flex:none; width:18px!important; min-width:18px; margin:0!important; text-align:center; font-size:16px!important;\\n}\\n:host .nav-sidebar p, .flow-sidebar-surface .nav-sidebar p { display:block!important; width:auto!important; min-width:0; margin:0!important; line-height:22px; overflow-wrap:anywhere; }\\n:host .nav-sidebar p .text-xs, .flow-sidebar-surface .nav-sidebar p .text-xs { font-size:10px!important; margin-left:3px; }\\n:host .user-panel, .flow-sidebar-surface .user-panel {\\n  display:flex!important; align-items:center; gap:9px; flex:none; min-height:58px;\\n  padding:12px 3px!important; margin:0 3px 2px!important; border-bottom:1px solid var(--flow-line)!important;\\n  white-space:normal; overflow:visible;\\n}\\n:host .user-panel .image, .flow-sidebar-surface .user-panel .image { padding:0; flex:none; }\\n:host .user-panel .image>div, .flow-sidebar-surface .user-panel .image>div {\\n  display:grid; place-items:center; width:28px; height:28px; border-radius:6px; background:#eaf0fb!important; box-shadow:none!important;\\n}\\n:host .user-panel .image i, .flow-sidebar-surface .user-panel .image i { font-size:14px!important; color:var(--flow-blue)!important; }\\n:host .user-panel .info, .flow-sidebar-surface .user-panel .info { min-width:0; padding:0; flex:1; }\\n:host .user-panel .info a, .flow-sidebar-surface .user-panel .info a {\\n  color:var(--flow-text)!important; font-size:12px; line-height:18px; text-decoration:none; overflow-wrap:anywhere;\\n}\\n:host .close-nav { display:none; position:absolute; top:20px; right:8px; width:32px; height:32px; padding:0; border:0; border-radius:4px; background:transparent; color:var(--flow-muted)!important; font:25px/1 system-ui; cursor:pointer; }\\n:host .close-nav:hover { background:#eef1f7; color:var(--flow-text)!important; }\\n:host a:focus-visible, :host button:focus-visible,\\n.flow-sidebar-surface a:focus-visible, .flow-sidebar-surface button:focus-visible { outline:2px solid var(--flow-blue)!important; outline-offset:2px; }\\n@media(max-width:900px) {\\n  :host { width:236px!important; }\\n  :host .close-nav { display:block; }\\n  :host .brand { padding-right:45px!important; }\\n}\\n\';\n    shadow.appendChild(flowStyle);\n    var brand = document.createElement(\'a\');\n    brand.className = \'brand\';\n    brand.href = \'/admin/domain\';\n    brand.textContent = \'Mailu\';\n    var close = document.createElement(\'button\');\n    close.type = \'button\';\n    close.className = \'close-nav\';\n    close.textContent = \'\\u00d7\';\n    close.title = \'关闭导航\';\n    close.setAttribute(\'aria-label\', \'关闭导航\');\n    shadow.append(brand, close, sidebar);\n\n    var layout = document.createElement(\'style\');\n    layout.id = \'mail-control-shell-style\';\n    layout.textContent = \'body.mail-control-shell{margin-left:194px;min-width:0}#mail-control-side-nav{position:fixed;inset:0 auto 0 0;width:194px;height:100dvh;z-index:1000}body.mail-control-shell>header{background:#fff;color:#17212b;border-bottom:1px solid #d9e1e8}body.mail-control-shell>header a{color:#1677a8}body.mail-control-shell>main{min-width:0}#mail-control-nav-toggle{display:none}#mail-control-nav-backdrop{display:none}@media(max-width:900px){body.mail-control-shell{margin-left:0;padding-top:44px}#mail-control-side-nav{transform:translateX(-100%);transition:transform .15s ease}body.mail-control-nav-open #mail-control-side-nav{transform:translateX(0)}#mail-control-nav-toggle{display:flex;align-items:center;gap:10px;position:fixed;top:0;left:0;right:0;height:44px;z-index:900;width:100%;border:0;border-bottom:1px solid #d9e1e8;border-radius:0;background:#fff;color:#17212b;padding:0 14px;font:14px system-ui;cursor:pointer}#mail-control-nav-toggle .menu-symbol{font-size:22px;line-height:1}body.mail-control-nav-open #mail-control-nav-backdrop{display:block;position:fixed;inset:0;z-index:999;background:#0006;border:0;width:100%;height:100%;border-radius:0}}@media(prefers-reduced-motion:reduce){#mail-control-side-nav{transition:none}}\';\n    var toggle = document.createElement(\'button\');\n    toggle.id = \'mail-control-nav-toggle\';\n    toggle.type = \'button\';\n    toggle.title = \'打开导航\';\n    toggle.setAttribute(\'aria-label\', \'打开导航\');\n    toggle.setAttribute(\'aria-controls\', host.id);\n    toggle.setAttribute(\'aria-expanded\', \'false\');\n    toggle.innerHTML = \'<span class="menu-symbol" aria-hidden="true">&#9776;</span><span>Mailu</span>\';\n    var backdrop = document.createElement(\'button\');\n    backdrop.id = \'mail-control-nav-backdrop\';\n    backdrop.type = \'button\';\n    backdrop.setAttribute(\'aria-label\', \'关闭导航\');\n    var inertContent = [];\n    function opened(value) {\n      document.body.classList.toggle(\'mail-control-nav-open\', value);\n      toggle.setAttribute(\'aria-expanded\', String(value));\n      if (value) inertContent = Array.from(document.body.children).filter(function (node) {\n        if (node === host || node === backdrop || node === toggle || node.tagName === \'SCRIPT\') return;\n        return !node.inert;\n      });\n      inertContent.forEach(function (node) { node.inert = value; });\n      if (!value) inertContent = [];\n      if (value) close.focus();\n      else toggle.focus();\n    }\n    toggle.onclick = function () { opened(true); };\n    close.onclick = backdrop.onclick = function () { opened(false); };\n    document.addEventListener(\'keydown\', function (event) { if (event.key === \'Escape\' && document.body.classList.contains(\'mail-control-nav-open\')) opened(false); });\n    document.head.appendChild(layout);\n    document.body.classList.add(\'mail-control-shell\');\n    document.body.prepend(host, toggle, backdrop);\n  }\n\n  function init() {\n    if (window.self !== window.top || new URLSearchParams(location.search).get(\'embedded\') === \'1\') return;\n    var sidebar = document.querySelector(\'.main-sidebar .sidebar\');\n    if (sidebar) { installLinks(sidebar); return; }\n    if (location.pathname.indexOf(rootPath) !== 0 && location.pathname.indexOf(\'/admin/antispam/\') !== 0) return;\n    toolShell().catch(function (error) { console.warn(error.message); });\n  }\n  if (document.querySelector(\'.main-sidebar .sidebar\') || document.querySelector(\'body > main\') || document.getElementById(\'mainUI\')) init();\n  else if (document.readyState === \'loading\') document.addEventListener(\'DOMContentLoaded\', init);\n  else init();\n})();\n'}
FLOW_NAVIGATION_VERSION = '4a7755b4ffc7'

"""Server-rendered shell for already-authorized mail-control tool pages."""

def flow_shell_identity(headers):
    trusted = headers.get('X-Mail-Control-Proxy-Secret', '')
    if CONFIG.proxy_secret and trusted and hmac.compare_digest(trusted, CONFIG.proxy_secret):
        return headers.get('X-Remote-User', '').strip().lower()
    value = headers.get('Authorization', '')
    if value.startswith('Basic '):
        try:
            return base64.b64decode(value[6:], validate=True).decode('utf-8').split(':', 1)[0].strip().lower()
        except (ValueError, UnicodeError):
            pass
    return ''


def flow_shell_display_name(username):
    if not username:
        return '管理员'
    # Match Mailu's existing displayed_name where the field is available. A
    # schema/version without that field simply uses the authenticated address.
    try:
        db_uri = 'file:' + urllib.parse.quote(str(CONFIG.db_path), safe='/:') + '?mode=ro'
        db = sqlite3.connect(db_uri, uri=True)
        try:
            columns = {row[1] for row in db.execute('PRAGMA table_info(user)')}
            name_column = next((name for name in ('displayed_name', 'display_name') if name in columns), None)
            if name_column:
                row = db.execute('SELECT "' + name_column + '" FROM user WHERE email = ?', (username,)).fetchone()
                if row and row[0] and str(row[0]).strip():
                    return str(row[0]).strip()
        finally:
            db.close()
    except (OSError, sqlite3.Error, AttributeError):
        pass
    return username


def flow_shell_markup(username, request_path='', request_query=''):
    root = '/admin/mail-control/'
    pathname = request_path or root
    if not pathname.startswith('/admin/'):
        pathname = root + pathname.lstrip('/')
    current = pathname.rstrip('/') or '/'
    query = urllib.parse.parse_qs(request_query)
    groups = (
        ('邮件工作台', (
            ('全局邮件查询', root + 'global/', 'fa-search'),
            ('邮件控制', root, 'fa-envelope'),
            ('自定义发件', root + 'custom-send/', 'fa-paper-plane'),
            ('批量邮箱', root + 'accounts/', 'fa-users'),
            ('邮件营销', root + 'marketing/', 'fa-bullhorn'),
            ('发件 API', root + 'marketing/?tab=api', 'fa-code'),
        )),
        ('我的账户', (
            ('设置', '/admin/user/settings', 'fa-wrench'),
            ('更新密码', '/admin/user/password', 'fa-lock'),
            ('自动回复', '/admin/user/reply', 'fa-plane'),
            ('认证令牌', '/admin/token/list', 'fa-ticket-alt'),
            ('客户端设置', '/admin/client', 'fa-laptop'),
        )),
        ('管理', (
            ('公告', '/admin/announcement', 'fa-bullhorn'),
            ('管理员', '/admin/admin/list', 'fa-user'),
            ('中继域', '/admin/relay', 'fa-reply-all'),
            ('反垃圾邮件', '/admin/antispam/', 'fa-trash-alt'),
            ('邮件域', '/admin/domain', 'fa-envelope'),
        )),
        ('转到', (
            ('网页邮箱', '/webmail', 'fa-envelope'),
            ('网站', 'https://mailu.io', 'fa-globe'),
            ('帮助', 'https://mailu.io', 'fa-life-ring'),
            ('登出', '/sso/logout', 'fa-sign-out-alt'),
        )),
    )
    def selected(href):
        target = urllib.parse.urlsplit(href)
        if target.scheme or target.netloc:
            return False
        target_path = target.path.rstrip('/') or '/'
        if target_path == (root + 'marketing').rstrip('/'):
            api = query.get('tab', [''])[0] == 'api'
            return current.startswith(target_path) and (api if target.query else not api)
        return current == target_path
    items = []
    for heading, links in groups:
        items.append('<li class="nav-header" role="none">' + heading + '</li>')
        for label, href, icon in links:
            active = selected(href)
            external = href.startswith('https://')
            attrs = (' aria-current="page"' if active else '') + (' target="_blank" rel="noreferrer noopener"' if external else '')
            items.append('<li class="nav-item" role="none"><a class="nav-link' + (' active' if active else '') + '" href="' + html.escape(href, quote=True) + '" role="menuitem"' + attrs + '><i class="nav-icon fas ' + icon + '" aria-hidden="true"></i><p>' + label + (' <i class="fas fa-external-link-alt text-xs" aria-hidden="true"></i>' if external else '') + '</p></a></li>')
    name = html.escape(flow_shell_display_name(username), quote=True)
    address = html.escape(username, quote=True)
    return ('<aside id="mail-control-side-nav" class="flow-server-sidebar flow-sidebar-surface" aria-label="Mailu 导航">'
            '<a class="brand-link" href="/admin/domain"><img class="brand-image" src="/static/mailu.png" width="25" height="25" alt=""><span class="brand-text">Mailu</span></a>'
            '<button id="flow-shell-close" class="flow-shell-close" type="button" aria-label="关闭导航">×</button>'
            '<div class="sidebar"><div class="user-panel" title="' + address + '"><div class="image"><div><i class="fas fa-user" aria-hidden="true"></i></div></div>'
            '<div class="info"><a href="/admin/user/settings">' + name + '</a></div></div>'
            '<nav><ul class="nav-sidebar" role="menu">' + ''.join(items) + '</ul></nav></div></aside>'
            '<button id="mail-control-nav-toggle" type="button" aria-label="打开导航" aria-controls="mail-control-side-nav" aria-expanded="false"><i class="fas fa-bars" aria-hidden="true"></i><span>Mailu</span></button>'
            '<button id="mail-control-nav-backdrop" type="button" aria-label="关闭导航" tabindex="-1"></button>'
            '<script>' + FLOW_UI_ASSETS['flow-shell.js'] + '</script>')


def html_bytes(template, embedded=False, username="", request_path="", request_query=""):
    if embedded:
        refresh = {
            HTML: "loadMessages()",
            ACCOUNTS_HTML: "loadAccounts()",
            API_HTML: "load()",
            MARKETING_LIST_HTML: "load()",
        }.get(template)
        if refresh:
            template = template.replace(
                "</body>",
                "<script>window.addEventListener('mail-control-activate',()=>{Promise.resolve("
                + refresh + ").catch(()=>{})});</script></body>",
            )
        template = template.replace(
            "<body>",
            '<body class="embedded"><style>body.embedded header{display:none}body.embedded main{max-width:none;margin:0;padding:18px}</style>',
            1,
        )
    template = template.replace("</head>", "<style>" + MESSAGE_VIEWER_CSS + "</style></head>", 1)
    template = template.replace("</head>", "<script>" + MESSAGE_VIEWER_JS + "</script></head>", 1)
    if not embedded:
        template = template.replace(
            "</body>",
            '<script defer src="/admin/mail-control/navigation.js"></script></body>',
            1,
        )
    # Theme the server-rendered body before any content can paint. The page
    # class also applies list/compose/etc. rules before asynchronous data arrives.
    page_class = next((name for marker, name in (
        ('id="rows"', 'flow-global'), ('id="compose"', 'flow-compose'),
        ('id="localparts"', 'flow-accounts'), ('id="api-form"', 'flow-api'),
        ('id="sender-domain"', 'flow-marketing-task'), ('id="task-list"', 'flow-marketing-list'),
        ('id="tab-campaigns"', 'flow-marketing-manage'), ('id="message-modal"', 'flow-control'),
        ('id="subject"', 'flow-view')) if marker in template), '')
    classes = 'flow-tools ' + page_class + (' embedded' if embedded else ' mail-control-shell')
    template = template.replace('<body class="embedded">', '<body class="' + classes + '">', 1) if embedded else template.replace('<body>', '<body class="' + classes + '">', 1)
    preload = '<script>if(self!==top)document.documentElement.classList.add("flow-embedded-surface");</script>'
    theme_css = FLOW_UI_ASSETS["flow-tools.css"] + ('' if embedded else FLOW_UI_ASSETS['flow-shell.css'])
    template = template.replace("</head>", "<style>" + theme_css + "</style>" + preload + "</head>", 1)
    if not embedded:
        body_start = template.index('>', template.index('<body')) + 1
        template = template[:body_start] + flow_shell_markup(username, request_path, request_query) + template[body_start:]
    # Dialog markup follows main on some pages. Run after it has parsed but
    # before the existing page script starts requests and handlers.
    theme_pos = template.find('<script', template.index('</main>') + len('</main>'))
    theme_script = '<script>' + FLOW_UI_ASSETS['flow-tools.js'] + '</script>'
    template = template[:theme_pos] + theme_script + template[theme_pos:] if theme_pos >= 0 else template.replace('</body>', theme_script + '</body>', 1)
    template = template.replace('<script defer src="/admin/mail-control/navigation.js"></script>', '', 1)
    template = template.replace("</body>", "<script>" + FLOW_UI_ASSETS["flow-admin.js"] + "</script></body>", 1)
    return template.encode("utf-8")


CUSTOM_SEND_HTML = r"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>自定义发件</title><style>
:root{--ink:#17212b;--muted:#637381;--line:#d9e1e8;--accent:#1677a8;--danger:#b42318}*{box-sizing:border-box}body{margin:0;background:#f5f7f9;color:var(--ink);font:14px system-ui,sans-serif}header{padding:18px 24px;background:#27333e;color:white}header a{color:#d8edf7;text-decoration:none}h1{font-size:20px;margin:10px 0 0}main{max-width:1100px;margin:24px auto;padding:0 16px}.panel{padding:20px;background:white;border:1px solid var(--line);border-radius:6px}.fields{display:grid;grid-template-columns:1fr 1fr;gap:14px}.wide{grid-column:1/-1}label{display:block;color:var(--muted);margin-bottom:6px}input,select,textarea{width:100%;padding:9px;border:1px solid #b9c7d2;border-radius:4px;font:inherit}textarea{resize:vertical;min-height:220px}button{padding:10px 16px;border:0;border-radius:4px;background:var(--accent);color:white;cursor:pointer}button.secondary{background:#64748b}button:disabled{opacity:.5;cursor:default}.toolbar{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-top:18px}.muted{color:var(--muted)}.error{color:var(--danger)}.ok{color:#087443}.sender{padding:12px;background:#edf6fa;border-radius:4px;overflow-wrap:anywhere;margin:14px 0}.result{white-space:pre-wrap;overflow-wrap:anywhere;padding:12px;background:#f5f7f9;border-radius:4px;display:none}.result.visible{display:block}.hint{margin-top:6px;font-size:12px;color:var(--muted)}@media(max-width:600px){.fields{grid-template-columns:1fr}.wide{grid-column:auto}main{margin:12px auto;padding:0 10px}}
</style></head><body><header><a href="../">← 邮件控制</a><h1>自定义发件</h1></header><main><section class="panel"><p class="muted">填写任意合法邮箱前缀，并选择本站已有域名，无需先创建该发件邮箱。</p><form id="compose"><div class="fields"><div><label for="prefix">发件邮箱前缀</label><input id="prefix" required maxlength="64" placeholder="例如 1、support、notice"></div><div><label for="domain">发件域名</label><select id="domain" required></select></div></div><div id="sender" class="sender">正在加载域名…</div><div class="fields"><div><label for="from-name">发件人显示名称</label><input id="from-name" maxlength="160" placeholder="可选"></div><div><label for="reply-to">回复地址</label><input id="reply-to" type="email" placeholder="可选：填写能收件的邮箱"><div class="hint">未创建的发件地址可能无法接收回复，可指定现有邮箱作为回复地址。</div></div><div class="wide"><label for="to">收件人</label><input id="to" placeholder="多个地址用逗号或分号分隔"></div><div><label for="cc">抄送</label><input id="cc" placeholder="可选"></div><div><label for="bcc">密送</label><input id="bcc" placeholder="可选"></div><div class="wide"><label for="subject">主题</label><input id="subject" maxlength="500"></div><div class="wide"><label for="format">正文格式</label><select id="format" style="width:auto"><option value="text">纯文本</option><option value="html">HTML</option></select></div><div class="wide"><label for="body">正文</label><textarea id="body" placeholder="填写邮件正文"></textarea></div><div class="wide"><label for="files">附件</label><input id="files" type="file" multiple><div id="file-summary" class="hint">最多 12 个附件，单个不超过 12 MB，总计不超过 24 MB。</div></div></div><div class="toolbar"><button id="send" type="submit" disabled>发送邮件</button><button id="preview" type="button" class="secondary" disabled>检查发送内容</button><button id="clear" type="button" class="secondary">清空内容</button></div></form><p id="status" class="muted" role="status">正在加载…</p><div id="result" class="result"></div></section></main><script>
const $=s=>document.querySelector(s),base=location.pathname.endsWith('/')?'../':'./';let busy=false,ready=false;
async function api(path,options){const r=await fetch(base+'api/'+path,options);const j=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw Error(j.error||r.statusText);return j}
function status(s,type='muted'){$('#status').textContent=s;$('#status').className=type}
function updateSender(){$('#sender').textContent=($('#prefix').value.trim()||'前缀')+'@'+($('#domain').value||'域名')}
function busyState(value){busy=value;$('#send').disabled=value||!ready;$('#preview').disabled=value||!ready;$('#clear').disabled=value;document.querySelectorAll('#compose input,#compose select,#compose textarea').forEach(x=>x.disabled=value)}
function attachment(file){return new Promise((resolve,reject)=>{const reader=new FileReader();reader.onerror=()=>reject(Error('附件读取失败：'+file.name));reader.onload=()=>resolve({filename:file.name,content_type:file.type||'application/octet-stream',data_base64:String(reader.result).split(',')[1]});reader.readAsDataURL(file)})}
async function payload(dryRun){const prefix=$('#prefix').value.trim(),domain=$('#domain').value;if(!prefix||!domain)throw Error('请填写邮箱前缀并选择域名');if(![$('#to').value,$('#cc').value,$('#bcc').value].some(x=>x.trim()))throw Error('请至少填写一个收件人、抄送人或密送人');const files=[...$('#files').files];if(files.length>12||files.some(f=>f.size>12*1024*1024)||files.reduce((sum,f)=>sum+f.size,0)>24*1024*1024)throw Error('附件超过数量或大小限制');return {prefix,domain,from_name:$('#from-name').value,reply_to:$('#reply-to').value,to:$('#to').value,cc:$('#cc').value,bcc:$('#bcc').value,subject:$('#subject').value,[$('#format').value]:$('#body').value,dry_run:dryRun,attachments:await Promise.all(files.map(attachment))}}
async function submit(dryRun){if(busy)return;try{const data=await payload(dryRun);busyState(true);status(dryRun?'正在检查…':'正在提交邮件…');const j=await api('custom-send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});status(dryRun?'内容检查通过，尚未发送。':'邮件已提交到邮件服务器。','ok');$('#result').classList.add('visible');$('#result').textContent=[`发件人：${j.from}`,`收件人：${j.to.join('、')||'无'}`,`抄送：${j.cc.join('、')||'无'}`,`密送：${j.bcc.join('、')||'无'}`,`主题：${j.subject||'(无主题)'}`,dryRun?`附件：${j.attachments.length} 个`:`附件：${j.attachments} 个`,j.message_id?'邮件编号：'+j.message_id:''].filter(Boolean).join('\n')}catch(e){status(e.message,'error')}finally{busyState(false)}}
$('#compose').onsubmit=e=>{e.preventDefault();submit(false)};$('#preview').onclick=()=>submit(true);$('#prefix').oninput=updateSender;$('#domain').onchange=updateSender;$('#files').onchange=()=>{$('#file-summary').textContent=[...$('#files').files].map(f=>`${f.name} (${Math.ceil(f.size/1024)} KB)`).join('、')||'未选择附件'};$('#clear').onclick=()=>{const domain=$('#domain').value;$('#compose').reset();$('#domain').value=domain;$('#result').classList.remove('visible');$('#file-summary').textContent='最多 12 个附件，单个不超过 12 MB，总计不超过 24 MB。';updateSender();status('内容已清空')};
api('domains').then(j=>{$('#domain').replaceChildren(...j.domains.map(d=>new Option(d.name,d.name)));ready=j.domains.length>0;updateSender();busyState(false);status(ready?'可以发送':'本站尚未配置发件域名',ready?'muted':'error')}).catch(e=>status(e.message,'error'));
</script></body></html>
"""


GLOBAL_HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>全局邮件查询</title>
<style>
:root{--ink:#17212b;--muted:#637381;--line:#d9e1e8;--accent:#1677a8;--danger:#b42318}*{box-sizing:border-box}body{margin:0;background:#f5f7f9;color:var(--ink);font:14px system-ui,sans-serif}header{padding:18px 24px;background:#27333e;color:#fff}header a{color:#d8edf7;text-decoration:none}h1{font-size:20px;margin:10px 0 0}main{max-width:1500px;margin:24px auto;padding:0 16px}.panel{background:#fff;border:1px solid var(--line);border-radius:6px;padding:18px;margin-bottom:16px}.fields{display:grid;grid-template-columns:repeat(3,minmax(160px,1fr));gap:12px}label{display:block;color:var(--muted);margin-bottom:6px}input,select{width:100%;padding:9px;border:1px solid #b9c7d2;border-radius:4px;font:inherit}button{padding:9px 14px;border:0;border-radius:4px;background:var(--accent);color:#fff;cursor:pointer}button.secondary{background:#64748b}button.danger{background:var(--danger)}button:disabled{opacity:.5;cursor:default}.toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-top:16px}.toolbar input{width:auto}.muted{color:var(--muted)}.error{color:var(--danger)}.scroll{overflow:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;vertical-align:top;border-bottom:1px solid var(--line);padding:10px 8px;overflow-wrap:anywhere}th{white-space:nowrap;color:var(--muted)}td input,th input{width:auto}td button.link{background:none;color:var(--accent);padding:0;text-align:left;font:inherit}tr.unread td{background:#f1f8fc}td small{display:block;margin-top:5px;color:var(--muted)}.empty{padding:30px;text-align:center;color:var(--muted)}dialog{width:min(1100px,95vw);max-height:92vh;border:1px solid var(--line);border-radius:8px;padding:20px}dialog::backdrop{background:#0006}.modal-head{display:flex;justify-content:space-between;gap:12px}.modal-head h2{margin:0;font-size:18px;overflow-wrap:anywhere}.message-frame{width:100%;height:52vh;border:1px solid var(--line);margin-top:16px}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:52vh;overflow:auto;background:#f5f7f9;padding:14px}.hidden{display:none}.meta{overflow-wrap:anywhere;margin:12px 0;color:var(--muted)}@media(max-width:800px){.fields{grid-template-columns:1fr 1fr}main{margin:12px auto;padding:0 10px}}@media(max-width:480px){.fields{grid-template-columns:1fr}}
</style></head><body><header><a href="../">← 邮件控制</a><h1>全局邮件查询</h1></header><main>
<section class="panel"><div class="fields"><div><label for="domain">精确域名</label><select id="domain"><option value="">全站所有域名</option></select></div><div><label for="prefix">精确邮箱前缀（配合域名）</label><input id="prefix" placeholder="例如 support，不会匹配 support1"></div><div><label for="mailbox">完整邮箱地址（精确查询）</label><input id="mailbox" placeholder="例如 support@99765.my.id"></div><div><label for="scope">邮件范围</label><select id="scope"><option value="all">全部邮件</option><option value="unread">仅未读邮件</option></select></div><div><label for="folder">文件夹</label><select id="folder"><option value="">全部文件夹</option></select></div><div><label for="query">主题 / 发件人 / 收件人关键词</label><input id="query" placeholder="可选关键词"></div></div><div class="toolbar"><button id="search">查询</button><button id="reset" class="secondary">重置</button><button id="refresh" class="secondary">刷新</button><label style="margin:0"><input id="auto" type="checkbox" checked>每 15 秒自动刷新</label></div><p class="muted">统一查看全站已投递的邮件，包含收件箱和其他文件夹。选择域名可查询该域名下所有邮箱；前缀与域名组合可定位一个邮箱。</p></section>
<section class="panel"><div class="toolbar" style="margin-top:0"><button id="delete" class="danger" disabled>删除选中邮件</button><span id="selection" class="muted">已选 0 封</span><span id="status" role="status" class="muted">正在加载…</span></div><div class="scroll"><table><thead><tr><th><input id="select-all" type="checkbox" aria-label="选择当前页全部邮件"></th><th>所属邮箱</th><th>主题</th><th>发件人</th><th>收件人</th><th>入站时间</th><th>文件夹</th></tr></thead><tbody id="rows"></tbody></table></div><div class="toolbar"><button id="prev" class="secondary">上一页</button><span id="page"></span><button id="next" class="secondary">下一页</button><label style="margin:0">每页 <select id="limit" style="width:auto"><option>25</option><option selected>50</option><option>100</option></select> 封</label></div></section></main>
<dialog id="detail"><div class="modal-head"><h2 id="subject"></h2><button id="close" class="secondary">关闭</button></div><div id="meta" class="meta"></div><div class="toolbar"><button id="html-tab">HTML 正文</button><button id="text-tab" class="secondary">纯文本</button><button id="delete-one" class="danger">删除此邮件</button></div><iframe id="html-view" class="message-frame" sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer" title="邮件正文"></iframe><pre id="text-view" class="hidden"></pre><p id="attachments" class="muted"></p></dialog>
<script>
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const base=location.pathname.endsWith('/')?'../':'./';let rows=[],offset=0,total=0,loading=false,filters={},current=null,detailVersion=0;
async function api(path,options){const r=await fetch(base+'api/'+path,options);const j=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw Error(j.error||r.statusText);return j}
function status(text,error=false){$('#status').textContent=text;$('#status').className=error?'error':'muted'}
function selected(){return [...document.querySelectorAll('[data-check]:checked')].map(x=>rows[Number(x.dataset.check)])}
function updateSelection(){const n=selected().length;$('#selection').textContent=`已选 ${n} 封`;$('#delete').disabled=!n;$('#select-all').checked=rows.length>0&&n===rows.length;$('#select-all').indeterminate=n>0&&n<rows.length}
function capture(){filters={domain:$('#domain').value,prefix:$('#prefix').value.trim(),mailbox:$('#mailbox').value.trim(),scope:$('#scope').value,folder:$('#folder').value,q:$('#query').value.trim()};offset=0}
async function load(){if(loading)return;loading=true;try{const params=new URLSearchParams({...filters,offset,limit:$('#limit').value});const j=await api('global/messages?'+params);total=j.total;if(offset>=total&&offset>0){offset=Math.max(0,Math.floor(Math.max(0,total-1)/Number($('#limit').value))*Number($('#limit').value));loading=false;return load()}rows=j.messages;$('#rows').innerHTML=rows.length?rows.map((m,i)=>`<tr class="${m.unread?'unread':''}"><td><input type="checkbox" data-check="${i}" aria-label="选择 ${esc(m.subject||'无主题')}"></td><td>${esc(m.mailbox)}<small>${m.unread?'未读':'已读'}</small></td><td><button class="link" data-view="${i}">${esc(m.subject||'(无主题)')}</button></td><td>${esc(m.from)}</td><td>${esc(m.to)}</td><td>${esc(new Date(m.received_at*1000).toLocaleString())}</td><td>${esc(m.folder)}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">没有符合条件的邮件</td></tr>';const folder=$('#folder').value;$('#folder').innerHTML='<option value="">全部文件夹</option>'+j.folders.map(f=>`<option value="${esc(f)}">${esc(f)}</option>`).join('');if(folder&&!j.folders.includes(folder))$('#folder').add(new Option(folder,folder));$('#folder').value=folder;$('#prev').disabled=offset===0;$('#next').disabled=offset+rows.length>=total;$('#page').textContent=`${total?offset+1:0}–${offset+rows.length} / ${total} 封`;updateSelection();status(`已查 ${j.mailboxes} 个邮箱 · 更新于 ${new Date().toLocaleTimeString()}`)}catch(e){status(e.message,true)}finally{loading=false}}
function identity(m){return {mailbox:m.mailbox,id:m.id,folder:m.folder}}
async function remove(items){if(!items.length)return;if(!confirm(`确定永久删除所选 ${items.length} 封邮件？邮件将从对应邮箱中删除，此操作不可恢复。`))return;$('#delete').disabled=true;$('#delete-one').disabled=true;try{const j=await api('global/messages',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({messages:items.map(identity)})});if(current&&j.deleted.some(x=>x.mailbox===current.mailbox&&x.id===current.id&&x.folder===current.folder))$('#detail').close();await load();status(`已删除 ${j.deleted.length} 封${j.errors.length?'；'+j.errors.map(x=>x.error).join('；'):''}`,!!j.errors.length)}catch(e){status(e.message,true)}finally{updateSelection();$('#delete-one').disabled=false}}
async function view(m){const version=++detailVersion;try{const j=await api('global/message?'+new URLSearchParams(identity(m)));if(version!==detailVersion)return;current=m;const v=j.message;$('#subject').textContent=v.subject||'(无主题)';$('#meta').textContent=`所属邮箱：${m.mailbox} | 发件人：${v.from} | 收件人：${v.to}${v.cc?' | 抄送：'+v.cc:''} | ${v.date}`;MailViewer.show($('#html-view'),v,base+'api/body?'+new URLSearchParams(identity(m)));MailViewer.attachments($('#attachments'),v,base+'api/attachment?',identity(m));$('#text-view').textContent=v.text||'(无纯文本正文)';$('#html-view').classList.remove('hidden');$('#text-view').classList.add('hidden');if(!$('#detail').open)$('#detail').showModal()}catch(e){status(e.message,true)}}
$('#rows').onclick=e=>{const b=e.target.closest('[data-view]');if(b)view(rows[Number(b.dataset.view)])};$('#rows').onchange=updateSelection;$('#select-all').onchange=()=>{document.querySelectorAll('[data-check]').forEach(x=>x.checked=$('#select-all').checked);updateSelection()};$('#delete').onclick=()=>remove(selected());$('#delete-one').onclick=()=>remove(current?[current]:[]);$('#close').onclick=()=>{detailVersion++;current=null;$('#detail').close()};$('#detail').addEventListener('cancel',()=>{detailVersion++;current=null});$('#detail').addEventListener('close',()=>{if(!$('#detail').open){detailVersion++;current=null}});$('#html-tab').onclick=()=>{$('#html-view').classList.remove('hidden');$('#text-view').classList.add('hidden')};$('#text-tab').onclick=()=>{$('#text-view').classList.remove('hidden');$('#html-view').classList.add('hidden')};$('#search').onclick=()=>{capture();load()};$('#refresh').onclick=()=>{capture();load()};$('#reset').onclick=()=>{['domain','prefix','mailbox','query','folder'].forEach(id=>$('#'+id).value='');$('#scope').value='all';capture();load()};$('#prev').onclick=()=>{offset=Math.max(0,offset-Number($('#limit').value));load()};$('#next').onclick=()=>{offset+=Number($('#limit').value);load()};$('#limit').onchange=()=>{offset=0;load()};['prefix','mailbox','query'].forEach(id=>$('#'+id).onkeydown=e=>{if(e.key==='Enter'){capture();load()}});
setInterval(()=>{if($('#auto').checked&&!document.hidden&&!$('#detail').open&&!selected().length)load()},15000);window.addEventListener('mail-control-activate',()=>{if(!selected().length)load()});
api('domains').then(j=>{$('#domain').innerHTML='<option value="">全站所有域名</option>'+j.domains.map(d=>`<option value="${esc(d.name)}">${esc(d.name)}</option>`).join('');capture();load()}).catch(e=>status(e.message,true));
</script></body></html>
"""


HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Mail Control</title>
<style>
:root{color-scheme:light;--ink:#17212b;--muted:#637381;--line:#d9e1e8;--accent:#1677a8;--danger:#b42318;--bg:#f5f7f9}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:#27333e;color:#fff;padding:18px 24px}header h1{font-size:20px;margin:0 0 4px}header p{margin:0;color:#c8d2db}
main{max-width:1180px;margin:24px auto;padding:0 16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.panel{background:#fff;border:1px solid var(--line);border-radius:6px;padding:18px}.panel h2{font-size:16px;margin:0 0 14px}.wide{grid-column:1/-1}
label{display:block;color:var(--muted);margin:10px 0 6px}input,select,textarea{width:100%;border:1px solid #b9c7d2;border-radius:4px;padding:9px;font:inherit;background:#fff}textarea{min-height:130px;resize:vertical}
button{border:0;border-radius:4px;padding:9px 14px;background:var(--accent);color:#fff;cursor:pointer;margin-top:12px}button.danger{background:var(--danger)}button.secondary{background:#64748b}button.small{padding:5px 8px;margin:0;font-size:12px}
table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:8px;vertical-align:top}th{color:var(--muted);font-weight:600}.toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:12px 0}.toolbar select,.toolbar input{width:auto;min-width:150px}.list{max-height:180px;overflow:auto;border:1px solid var(--line);padding:6px;margin-top:8px}.entry{display:flex;justify-content:space-between;gap:8px;padding:5px 0}.entry span{overflow-wrap:anywhere}.status{margin:0 0 12px;color:var(--muted)}.ok{color:#087443}.error{color:var(--danger)}pre{white-space:pre-wrap;word-break:break-word;background:#f1f4f6;border:1px solid var(--line);padding:12px;border-radius:4px;max-height:500px;overflow:auto}.hidden{display:none}.editor-toolbar{display:flex;gap:4px;flex-wrap:wrap;padding:6px;background:#f1f4f6;border:1px solid #b9c7d2;border-bottom:0;border-radius:4px 4px 0 0}.editor-toolbar button{margin:0;min-width:34px;padding:6px 9px;background:#fff;color:var(--ink);border:1px solid var(--line)}.editor-toolbar button:hover{background:#e8f2f7}.editor{min-height:180px;border:1px solid #b9c7d2;border-radius:0 0 4px 4px;padding:10px;background:#fff;outline:none;overflow:auto}.editor:empty:before{content:attr(data-placeholder);color:#9aa6b2}.file-list{margin:8px 0 0;color:var(--muted);overflow-wrap:anywhere}.file-list div{padding:3px 0}.send-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.send-actions button{margin-top:12px}.inline-field{display:flex;gap:8px;align-items:end}.inline-field input{flex:1}.view-link{white-space:nowrap}.modal-open{overflow:hidden}.modal{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;padding:18px;background:rgba(23,33,43,.58)}.modal.hidden{display:none}.modal-dialog{display:flex;flex-direction:column;width:min(980px,100%);height:min(760px,calc(100vh - 36px));background:#fff;border-radius:7px;box-shadow:0 18px 60px rgba(0,0,0,.28);overflow:hidden}.modal-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:16px 18px;border-bottom:1px solid var(--line)}.modal-head h3{margin:0 0 6px;font-size:18px;overflow-wrap:anywhere}.modal-head p{margin:0;color:var(--muted);overflow-wrap:anywhere}.modal-close{margin:0;padding:4px 10px;background:#eef2f5;color:var(--ink);font-size:22px;line-height:1}.modal-actions{display:flex;gap:8px;flex-wrap:wrap;padding:12px 18px 0}.modal-actions button{margin:0}.modal-tabs{display:flex;gap:6px;padding:12px 18px 0}.modal-tabs button{margin:0;background:#64748b}.modal-tabs button.active{background:var(--accent)}.modal-content{flex:1;min-height:0;padding:0 18px 18px;overflow:auto}.message-frame{display:block;width:100%;height:100%;min-height:360px;border:1px solid var(--line);border-radius:4px;background:#fff}.message-text{white-space:pre-wrap;word-break:break-word;background:#f1f4f6;border:1px solid var(--line);padding:14px;border-radius:4px;min-height:360px;max-height:100%;overflow:auto}.message-attachments{padding:12px 0 0;color:var(--muted);overflow-wrap:anywhere}@media(max-width:760px){.grid{grid-template-columns:1fr}.wide{grid-column:auto}.toolbar select,.toolbar input{width:100%}.inline-field{display:block}.modal{padding:0}.modal-dialog{width:100%;height:100%;border-radius:0}.modal-head{padding:14px}.modal-actions,.modal-tabs,.modal-content{padding-left:14px;padding-right:14px}.message-frame,.message-text{min-height:300px}}
</style></head><body>
<header><h1>Mail Control</h1><p>Mailu 邮件查询、收发与 Rspamd 名单管理</p></header>
<main><p id="status" class="status">正在加载...</p><div class="grid">
<section class="panel"><h2>黑名单</h2><p class="status">拒绝指定邮箱或域名的来件。</p><form id="black-form"><input name="entry" placeholder="sender@example.com 或 @example.com" required><button class="danger">加入黑名单</button></form><div id="black-list" class="list"></div></section>
<section class="panel"><h2>白名单</h2><p class="status">允许指定邮箱或域名，跳过 Rspamd 垃圾判定。</p><form id="white-form"><input name="entry" placeholder="sender@example.com 或 @example.com" required><button>加入白名单</button></form><div id="white-list" class="list"></div></section>
<section class="panel wide"><h2>邮件查询</h2><label>邮箱</label><select id="mailbox"></select><div class="toolbar"><select id="scope"><option value="all">全部历史邮件</option><option value="new">只看新邮件</option></select><select id="folder"><option value="ALL">全部文件夹</option></select><input id="search" placeholder="搜索主题、发件人或收件人"><button id="refresh" class="secondary">查询</button><button id="prev" class="secondary small">上一页</button><button id="next" class="secondary small">下一页</button><span id="page-info" class="status"></span></div><div id="messages"></div><p class="status">点击“查看”会在当前页面弹出邮件详情窗口，HTML 邮件会按原样预览。</p><div id="message-modal" class="modal hidden" role="dialog" aria-modal="true" aria-labelledby="message-subject"><div class="modal-dialog"><div class="modal-head"><div><h3 id="message-subject">邮件详情</h3><p id="message-meta"></p></div><button id="close-message" class="modal-close" title="关闭">×</button></div><div class="modal-actions"><button id="modal-block" class="danger">拉黑发件人</button><button id="modal-allow">加入白名单</button></div><div class="modal-tabs"><button id="modal-html-tab" class="active">HTML 视图</button><button id="modal-text-tab">纯文本</button></div><div class="modal-content"><iframe id="modal-html" class="message-frame" sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer" title="HTML 邮件内容"></iframe><pre id="modal-text" class="message-text hidden"></pre><div id="modal-attachments" class="message-attachments"></div></div></div></div></section>
<section class="panel wide"><h2>发送 API 测试</h2><form id="send-form"><label>发件人</label><select id="from"></select><label>收件人</label><input id="to" placeholder="多个地址用逗号分隔" required><label>抄送</label><input id="cc" placeholder="可选，多个地址用逗号分隔"><label>密送</label><input id="bcc" placeholder="可选，多个地址用逗号分隔"><label>主题</label><input id="send-subject"><label>正文</label><div class="editor-toolbar"><button type="button" data-cmd="bold" title="加粗"><b>B</b></button><button type="button" data-cmd="italic" title="斜体"><i>I</i></button><button type="button" data-cmd="underline" title="下划线"><u>U</u></button><button type="button" id="insert-link" title="插入链接">链</button><button type="button" id="insert-image-url" title="插入图片链接">图</button><button type="button" data-cmd="removeFormat" title="清除格式">清</button></div><div id="send-editor" class="editor" contenteditable="true" data-placeholder="输入图文内容，可直接粘贴或插入图片链接"></div><label>插入图片链接</label><div class="inline-field"><input id="image-url" type="url" placeholder="https://example.com/image.png"><button type="button" id="add-image-url" class="secondary">插入</button></div><label>上传图片或附件</label><input id="attachments" type="file" multiple><div id="file-list" class="file-list">尚未选择附件</div><div class="send-actions"><button type="button" id="dry-run" class="secondary">验证</button><button type="submit" id="send-submit">发送</button></div><p id="send-status" class="status" aria-live="polite"></p></form></section>
<section class="panel"><h2>接口说明</h2><p class="status">使用 Mailu 后台的全局管理员邮箱和密码登录。API 路径：<code>/api/mailboxes</code>、<code>/api/messages</code>、<code>/api/message</code>、<code>/api/lists</code>、<code>/api/send</code>。</p><p class="status">查询只读，不会自动标记已读或删除邮件。发送 API 支持纯文本、HTML、抄送、密送、图片链接和 base64 附件。</p></section>
</div></main>
<script>
const $=s=>document.querySelector(s); const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path, options){const r=await fetch(path,options);const j=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw Error(j.error||r.statusText);return j}
function setStatus(s,good=true){$('#status').textContent=s;$('#status').className='status '+(good?'ok':'error')}
async function loadLists(){const j=await api('api/lists');for(const [id,key] of [['black-list','blacklist'],['white-list','whitelist']]){$('#'+id).innerHTML=j[key].map(x=>`<div class="entry"><span>${esc(x)}</span><button class="small danger" data-list="${key}" data-entry="${esc(x)}">删除</button></div>`).join('')||'<span class="status">暂无</span>'}}
let offset=0; const pageSize=50; let uploaded=[];
async function loadMailboxes(){const j=await api('api/mailboxes');for(const id of ['mailbox','from']){$('#'+id).innerHTML=j.mailboxes.map(x=>`<option>${esc(x)}</option>`).join('')};await loadMessages(true)}
function loadFolders(){ $('#folder').innerHTML='<option value="ALL">全部文件夹</option>';return Promise.resolve() }
let messageListRequest=0,messageDetailRequest=0;
async function loadMessages(reset=false){const box=$('#mailbox').value;if(!box)return;if(reset)offset=0;const scope=$('#scope').value;const folder=$('#folder').value;const q=$('#search').value.trim();const request=++messageListRequest;$('#page-info').textContent='正在加载...';const j=await api('api/messages?mailbox='+encodeURIComponent(box)+'&scope='+scope+'&folder='+encodeURIComponent(folder)+'&q='+encodeURIComponent(q)+'&offset='+offset+'&limit='+pageSize);if(request!==messageListRequest)return;const current=$('#folder').value;$('#folder').innerHTML='<option value="ALL">全部文件夹</option>'+j.folders.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');if(j.folders.includes(current))$('#folder').value=current;const label=scope==='all'?'历史邮件':'新邮件';$('#page-info').textContent=`${label} ${j.total} 封，第 ${j.total?Math.floor(offset/pageSize)+1:0} 页`;$('#prev').disabled=offset<=0;$('#next').disabled=offset+pageSize>=j.total;$('#messages').innerHTML=j.messages.length?'<table><thead><tr><th>文件夹</th><th>时间</th><th>发件人</th><th>主题</th><th>操作</th></tr></thead><tbody>'+j.messages.map(m=>`<tr><td>${esc(m.folder)}</td><td>${esc(m.date)}</td><td>${esc(m.from)}</td><td>${esc(m.subject)}</td><td><button class="small view-link" data-mailbox="${esc(box)}" data-path="${esc(m.path)}">查看</button></td></tr>`).join('')+'</tbody></table>':'<p class="status">没有匹配邮件</p>'}
let currentMessage=null;
function ensureReleaseButton(){let button=$('#modal-release');if(button)return button;button=document.createElement('button');button.id='modal-release';button.className='secondary hidden';button.textContent='放行到收件箱';button.onclick=()=>releaseCurrent().catch(x=>setStatus(x.message,false));$('#modal-block').parentElement.appendChild(button);return button}
async function releaseCurrent(){if(!currentMessage?.mailbox||!currentMessage?.path)return;await api('api/message/release',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({mailbox:currentMessage.mailbox,path:currentMessage.path})});closeMessage();await loadMessages(true);setStatus('邮件已放行到收件箱')}
async function showMessage(box,path){const request=++messageDetailRequest;currentMessage=null;$('#message-subject').textContent='正在加载邮件...';$('#message-meta').textContent='';MailViewer.clear($('#modal-html')); $('#modal-text').textContent='';$('#modal-attachments').textContent='';ensureReleaseButton().classList.add('hidden');$('#message-modal').classList.remove('hidden');document.body.classList.add('modal-open');const j=await api('api/message?mailbox='+encodeURIComponent(box)+'&path='+encodeURIComponent(path));if(request!==messageDetailRequest)return;currentMessage={...j.message,mailbox:box,path};ensureReleaseButton().classList.toggle('hidden',! /^(?:\.Junk|\.Spam|\.Quarantine|Junk|Spam|Quarantine)\/(?:new|cur)\//.test(path));$('#message-subject').textContent=currentMessage.subject||'(无主题)';$('#message-meta').textContent=[currentMessage.from,currentMessage.to,currentMessage.cc,currentMessage.date].filter(Boolean).join(' | ');MailViewer.show($('#modal-html'),currentMessage,'api/body?'+new URLSearchParams({mailbox:box,path}));MailViewer.attachments($('#modal-attachments'),currentMessage,'api/attachment?',{mailbox:box,path});$('#modal-text').textContent=currentMessage.text||'(无纯文本正文)';$('#modal-html-tab').classList.add('active');$('#modal-text-tab').classList.remove('active');$('#modal-html').classList.remove('hidden');$('#modal-text').classList.add('hidden');$('#message-modal').classList.remove('hidden');document.body.classList.add('modal-open')}

function closeMessage(){ ++messageDetailRequest;$('#message-modal').classList.add('hidden');document.body.classList.remove('modal-open');MailViewer.clear($('#modal-html')); currentMessage=null }
async function addCurrent(kind){const sender=(currentMessage?.from||'').match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);if(!sender)throw Error('当前邮件没有可识别的发件人地址');await api('api/lists',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({list:kind,entry:sender[0]})});await loadLists();setStatus(kind==='blacklist'?'发件人已加入黑名单':'发件人已加入白名单')}
$('#modal-block').onclick=()=>addCurrent('blacklist').catch(x=>setStatus(x.message,false));$('#modal-allow').onclick=()=>addCurrent('whitelist').catch(x=>setStatus(x.message,false));$('#close-message').onclick=closeMessage;$('#message-modal').onclick=e=>{if(e.target.id==='message-modal')closeMessage()};document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('#message-modal').classList.contains('hidden'))closeMessage()});$('#modal-html-tab').onclick=()=>{$('#modal-html-tab').classList.add('active');$('#modal-text-tab').classList.remove('active');$('#modal-html').classList.remove('hidden');$('#modal-text').classList.add('hidden')};$('#modal-text-tab').onclick=()=>{$('#modal-text-tab').classList.add('active');$('#modal-html-tab').classList.remove('active');$('#modal-text').classList.remove('hidden');$('#modal-html').classList.add('hidden')};
document.addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;try{if(b.dataset.list){await api('api/lists',{method:'DELETE',headers:{'content-type':'application/json'},body:JSON.stringify({list:b.dataset.list,entry:b.dataset.entry})});await loadLists();setStatus('名单已更新')}else if(b.dataset.path){await showMessage(b.dataset.mailbox,b.dataset.path)}}catch(x){setStatus(x.message,false)}});
for(const [id,key] of [['black-form','blacklist'],['white-form','whitelist']])$('#'+id).addEventListener('submit',async e=>{e.preventDefault();try{await api('api/lists',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({list:key,entry:e.target.entry.value})});e.target.reset();await loadLists();setStatus('名单已更新')}catch(x){setStatus(x.message,false)}});
$('#refresh').onclick=()=>loadMessages(true).catch(x=>setStatus(x.message,false));$('#mailbox').onchange=()=>loadFolders().then(()=>loadMessages(true)).catch(x=>setStatus(x.message,false));$('#scope').onchange=()=>loadFolders().then(()=>loadMessages(true)).catch(x=>setStatus(x.message,false));$('#folder').onchange=()=>loadMessages(true).catch(x=>setStatus(x.message,false));$('#search').onkeydown=e=>{if(e.key==='Enter')loadMessages(true).catch(x=>setStatus(x.message,false))};$('#prev').onclick=()=>{if(offset>0){offset=Math.max(0,offset-pageSize);loadMessages().catch(x=>setStatus(x.message,false))}};$('#next').onclick=()=>{offset+=pageSize;loadMessages().catch(x=>setStatus(x.message,false))};
function insertEditorHtml(value){const editor=$('#send-editor');editor.focus();document.execCommand('insertHTML',false,value)}
function insertImageUrl(){const input=$('#image-url');const url=input.value.trim();if(!/^https?:\/\//i.test(url)){setStatus('图片链接必须以 http:// 或 https:// 开头',false);return}insertEditorHtml(`<img src="${esc(url)}" alt="图片" style="max-width:100%">`);input.value=''}
document.querySelectorAll('[data-cmd]').forEach(b=>b.onclick=()=>{const editor=$('#send-editor');editor.focus();document.execCommand(b.dataset.cmd,false,null)});$('#add-image-url').onclick=insertImageUrl;$('#insert-image-url').onclick=()=>$('#image-url').focus();$('#insert-link').onclick=()=>{const url=prompt('请输入链接地址');if(url&&/^https?:\/\//i.test(url))document.execCommand('createLink',false,url)};
function renderFiles(){$('#file-list').innerHTML=uploaded.length?uploaded.map((x,i)=>`<div>${esc(x.filename)} (${Math.ceil(x.size/1024)} KB) <button type="button" class="small danger" data-file-index="${i}">移除</button></div>`).join(''):'尚未选择附件'}
document.addEventListener('click',e=>{const b=e.target.closest('[data-file-index]');if(b){uploaded.splice(Number(b.dataset.fileIndex),1);renderFiles()}});
function readFile(file){return new Promise((resolve,reject)=>{if(file.size>12*1024*1024){reject(Error(file.name+' 超过 12 MB'));return}const reader=new FileReader();reader.onerror=()=>reject(Error('读取 '+file.name+' 失败'));reader.onload=()=>{const dataUrl=String(reader.result);resolve({filename:file.name,content_type:file.type||'application/octet-stream',size:file.size,data_url:dataUrl,data_base64:dataUrl.split(',')[1]||'',inline:file.type.startsWith('image/')})};reader.readAsDataURL(file)})}
$('#attachments').onchange=async e=>{try{const items=await Promise.all([...e.target.files].map(readFile));uploaded.push(...items);for(const item of items)if(item.inline)insertEditorHtml(`<img src="${item.data_url}" alt="${esc(item.filename)}" style="max-width:100%">`);renderFiles();e.target.value=''}catch(x){setStatus(x.message,false)}};
function buildPayload(dry){let htmlBody=$('#send-editor').innerHTML.trim();const attachments=uploaded.map((x,i)=>({...x,content_id:x.inline?'mail-control-'+Date.now()+'-'+i:''}));for(const item of attachments)if(item.inline&&item.data_url)htmlBody=htmlBody.split(item.data_url).join('cid:'+item.content_id);return {from:$('#from').value,to:$('#to').value,cc:$('#cc').value,bcc:$('#bcc').value,subject:$('#send-subject').value,text:$('#send-editor').innerText.trim(),html:htmlBody,attachments:attachments.map(x=>({filename:x.filename,content_type:x.content_type,data_url:x.data_url,data_base64:x.data_base64,content_id:x.content_id,inline:x.inline})),dry_run:dry}}
function setSendStatus(message,good=true){$('#send-status').textContent=message;$('#send-status').className='status '+(good?'ok':'error')}
function setSendBusy(busy){$('#dry-run').disabled=busy;$('#send-submit').disabled=busy;$('#dry-run').textContent=busy?'处理中...':'验证';$('#send-submit').textContent=busy?'发送中...':'发送'}
async function send(dry){setSendBusy(true);setSendStatus(dry?'正在验证请求...':'正在提交邮件，请稍候...');try{const j=await api('api/send',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(buildPayload(dry))});const count=Number(j.attachments||0);const message=dry?'验证通过，未发信':`邮件已提交，邮件服务器已接收${count?`，含 ${count} 个附件`:''}`;setSendStatus(message);setStatus(message);return j}catch(x){setSendStatus(x.message,false);setStatus(x.message,false);throw x}finally{setSendBusy(false)}}
$('#dry-run').onclick=()=>send(true).catch(()=>{});$('#send-form').onsubmit=e=>{e.preventDefault();send(false).catch(()=>{})};
Promise.all([loadLists(),loadMailboxes()]).then(()=>setStatus('已连接')).catch(x=>setStatus(x.message,false));
</script></body></html>"""


VIEW_HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>邮件详情</title>
<style>
:root{color-scheme:light;--ink:#17212b;--muted:#637381;--line:#d9e1e8;--accent:#1677a8;--danger:#b42318;--bg:#f5f7f9}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px system-ui,-apple-system,"Segoe UI",sans-serif}header{background:#27333e;color:#fff;padding:16px 24px}header a{color:#d8edf7;text-decoration:none}header h1{margin:14px 0 4px;font-size:20px;overflow-wrap:anywhere}main{max-width:1180px;margin:24px auto;padding:0 16px}.panel{background:#fff;border:1px solid var(--line);border-radius:6px;padding:18px}.meta{color:var(--muted);overflow-wrap:anywhere}.actions{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}button{border:0;border-radius:4px;padding:8px 12px;background:var(--accent);color:#fff;cursor:pointer}.danger{background:var(--danger)}.secondary{background:#64748b}.tabs{display:flex;gap:8px;border-bottom:1px solid var(--line);margin:8px 0 16px}.tabs button{border-radius:4px 4px 0 0}.tabs button.active{background:#0f5c82}.message-frame{width:100%;min-height:560px;border:1px solid var(--line);border-radius:4px;background:#fff}.plain{white-space:pre-wrap;word-break:break-word;background:#f1f4f6;border:1px solid var(--line);padding:14px;border-radius:4px;min-height:240px;max-height:720px;overflow:auto}.attachments{margin:16px 0 0;padding-top:12px;border-top:1px solid var(--line);color:var(--muted)}.hidden{display:none}.error{color:var(--danger)}
</style></head><body><header><a href="./">← 返回邮件查询</a><h1 id="subject">正在加载邮件...</h1><div id="meta" class="meta"></div></header><main><section class="panel"><div class="actions"><button id="block" class="danger">拉黑发件人</button><button id="allow">加入白名单</button><button id="reload" class="secondary">重新加载</button></div><div class="tabs"><button id="html-tab" class="active">HTML 视图</button><button id="text-tab" class="secondary">纯文本</button></div><iframe id="html-view" class="message-frame" sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox" referrerpolicy="no-referrer" title="HTML 邮件内容"></iframe><pre id="text-view" class="plain hidden"></pre><div id="attachments" class="attachments"></div><p id="status" class="meta"></p></section></main>
<script>
const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const params=new URLSearchParams(location.search);let current=null;
async function api(path,options){const r=await fetch(path,options);const j=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw Error(j.error||r.statusText);return j}
function setStatus(s,error=false){$('#status').textContent=s;$('#status').className='meta '+(error?'error':'')}
function sender(){const m=(current?.from||'').match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);return m?m[0]:''}
async function load(){const mailbox=params.get('mailbox')||'';const path=params.get('path')||'';if(!mailbox||!path)throw Error('邮件参数不完整');const j=await api('api/message?mailbox='+encodeURIComponent(mailbox)+'&path='+encodeURIComponent(path));current=j.message;$('#subject').textContent=current.subject||'(无主题)';$('#meta').textContent=[current.from,current.to,current.cc,current.date].filter(Boolean).join(' | ');MailViewer.show($('#html-view'),current,'api/body?'+new URLSearchParams({mailbox,path}));MailViewer.attachments($('#attachments'),current,'api/attachment?',{mailbox,path});$('#text-view').textContent=current.text||'(无纯文本正文)';setStatus('邮件已加载')}
async function updateList(kind){const value=sender();if(!value)throw Error('当前邮件没有可识别的发件人地址');await api('api/lists',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({list:kind,entry:value})});setStatus(kind==='blacklist'?'发件人已加入黑名单':'发件人已加入白名单')}
$('#block').onclick=()=>updateList('blacklist').catch(x=>setStatus(x.message,true));$('#allow').onclick=()=>updateList('whitelist').catch(x=>setStatus(x.message,true));$('#reload').onclick=()=>load().catch(x=>setStatus(x.message,true));$('#html-tab').onclick=()=>{$('#html-tab').classList.add('active');$('#text-tab').classList.remove('active');$('#html-view').classList.remove('hidden');$('#text-view').classList.add('hidden')};$('#text-tab').onclick=()=>{$('#text-tab').classList.add('active');$('#html-tab').classList.remove('active');$('#text-view').classList.remove('hidden');$('#html-view').classList.add('hidden')};load().catch(x=>setStatus(x.message,true));
</script></body></html>"""


ACCOUNTS_HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>批量邮箱管理</title>
<style>
:root{color-scheme:light;--ink:#17212b;--muted:#637381;--line:#d9e1e8;--accent:#1677a8;--danger:#b42318;--bg:#f5f7f9;--ok:#087443}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px system-ui,-apple-system,"Segoe UI",sans-serif}header{background:#27333e;color:#fff;padding:18px 24px}header h1{font-size:20px;margin:0 0 4px}header p{margin:0;color:#c8d2db}header a{color:#d8edf7;text-decoration:none;display:inline-block;margin-bottom:10px}main{max-width:1180px;margin:24px auto;padding:0 16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.panel{background:#fff;border:1px solid var(--line);border-radius:6px;padding:18px}.wide{grid-column:1/-1}.panel h2{font-size:16px;margin:0 0 14px}label{display:block;color:var(--muted);margin:10px 0 6px}input,select,textarea{width:100%;border:1px solid #b9c7d2;border-radius:4px;padding:9px;font:inherit;background:#fff}textarea{resize:vertical;min-height:160px}.check{display:flex;align-items:center;gap:8px}.check input{width:auto}.toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:12px 0}button{border:0;border-radius:4px;padding:9px 14px;background:var(--accent);color:#fff;cursor:pointer;margin-top:12px}button.secondary{background:#64748b}button.danger{background:var(--danger)}button:disabled{opacity:.55;cursor:not-allowed}.status{color:var(--muted);margin:8px 0}.ok{color:var(--ok)}.error{color:var(--danger)}.summary{padding:10px;background:#f1f4f6;border:1px solid var(--line);border-radius:4px;margin-top:10px}.result{margin-top:12px;border-top:1px solid var(--line);padding-top:10px;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:8px;vertical-align:top}th{color:var(--muted);font-weight:600}.email{overflow-wrap:anywhere}.password{font-family:ui-monospace,monospace;word-break:break-all}.protected{color:var(--muted)}@media(max-width:760px){.grid{grid-template-columns:1fr}.wide{grid-column:auto}main{margin:12px auto;padding:0 10px}th,td{padding:6px 4px;font-size:12px}}
</style></head><body><header><a href="../">← 返回邮件控制</a><h1>批量邮箱管理</h1><p>按域名批量创建、查看和删除邮箱账户</p></header><main><p id="status" class="status">正在加载...</p><section class="panel"><h2>选择域名</h2><select id="domain"></select><div id="domain-summary" class="summary"></div></section><div class="grid"><section class="panel"><h2>批量新增</h2><label>邮箱前缀</label><textarea id="localparts" placeholder="每行一个，也支持完整邮箱地址&#10;例如：&#10;user01&#10;user02&#10;team@665321.xyz"></textarea><label>初始密码</label><input id="password" type="password" autocomplete="new-password" placeholder="统一密码至少 8 个字符"><label class="check"><input id="generate-password" type="checkbox">为每个邮箱自动生成随机密码</label><label class="check"><input id="change-password" type="checkbox">首次登录强制修改密码</label><label>单邮箱配额（GB，可留空使用默认值）</label><input id="quota" type="number" min="0.1" step="0.1" placeholder="默认 1 GB"><button id="create" type="button">批量创建</button><div id="create-result" class="result"></div></section><section class="panel"><h2>删除邮箱</h2><p class="status">全局管理员账号不可批量删除。勾选后删除会同时清理对应邮箱数据目录。</p><div class="toolbar"><button id="select-all" type="button" class="secondary small">全选可删除邮箱</button><button id="clear-all" type="button" class="secondary small">清空选择</button><button id="delete" type="button" class="danger">删除选中邮箱</button></div><div id="account-list"></div></section></div></main><script>
const $=s=>document.querySelector(s);const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const apiRoot='../';let domains=[];
async function api(path,options){const r=await fetch(apiRoot+path,options);const j=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw Error(j.error||r.statusText);return j}
function status(message,good=true){$('#status').textContent=message;$('#status').className='status '+(good?'ok':'error')}
function selectedDomain(){return $('#domain').value}
function updateSummary(){const d=domains.find(x=>x.name===selectedDomain());if(!d){$('#domain-summary').textContent='';return}$('#domain-summary').textContent=`当前邮箱 ${d.used} / ${d.max_users===-1?'∞':d.max_users}，剩余 ${d.remaining===null?'∞':d.remaining} 个名额`}
async function loadDomains(){const j=await api('api/domains');domains=j.domains;$('#domain').innerHTML=domains.map(x=>`<option value="${esc(x.name)}">${esc(x.name)}</option>`).join('');updateSummary();await loadAccounts()}
async function loadAccounts(){const domain=selectedDomain();if(!domain)return;const j=await api('api/accounts?domain='+encodeURIComponent(domain));$('#account-list').innerHTML=j.accounts.length?'<table><thead><tr><th></th><th>邮箱</th><th>状态</th><th>创建时间</th><th>配额</th></tr></thead><tbody>'+j.accounts.map(x=>`<tr><td>${x.global_admin?'<span class="protected">管理员</span>':`<input type="checkbox" data-email="${esc(x.email)}">`}</td><td class="email">${esc(x.email)}</td><td>${x.enabled?'启用':'停用'}</td><td>${esc(x.created_at||'-')}</td><td>${x.quota_bytes?Math.round(x.quota_bytes/1073741824*10)/10+' GB':'-'}</td></tr>`).join('')+'</tbody></table>':'<p class="status">该域名暂无邮箱</p>';updateSummary()}
function renderCreateResult(j){let html=`创建成功 ${j.created.length} 个`;if(j.skipped.length)html+=`，已存在 ${j.skipped.length} 个`;if(j.credentials.length)html+='<br><b>请立即保存以下自动生成的密码：</b><table><thead><tr><th>邮箱</th><th>密码</th></tr></thead><tbody>'+j.credentials.map(x=>`<tr><td>${esc(x.email)}</td><td class="password">${esc(x.password)}</td></tr>`).join('')+'</tbody></table>';$('#create-result').innerHTML=html}
$('#domain').onchange=()=>loadAccounts().catch(x=>status(x.message,false));$('#generate-password').onchange=()=>{$('#password').disabled=$('#generate-password').checked;$('#password').required=!$('#generate-password').checked};$('#select-all').onclick=()=>document.querySelectorAll('[data-email]').forEach(x=>x.checked=true);$('#clear-all').onclick=()=>document.querySelectorAll('[data-email]').forEach(x=>x.checked=false);
$('#create').onclick=async()=>{try{const names=$('#localparts').value.trim();if(!names)throw Error('请填写邮箱前缀');const quota=Number($('#quota').value);const payload={domain:selectedDomain(),localparts:names,password:$('#password').value,generate_password:$('#generate-password').checked,change_pw_next_login:$('#change-password').checked};if(quota)payload.quota_bytes=Math.round(quota*1073741824);$('#create').disabled=true;const j=await api('api/accounts/batch-create',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});renderCreateResult(j);$('#localparts').value='';await loadDomains();status(`批量创建完成：成功 ${j.created.length} 个`)}catch(x){status(x.message,false);$('#create-result').textContent=x.message}finally{$('#create').disabled=false}};
$('#delete').onclick=async()=>{const emails=[...document.querySelectorAll('[data-email]:checked')].map(x=>x.dataset.email);if(!emails.length){status('请先勾选要删除的邮箱',false);return}if(!confirm(`确定删除 ${emails.length} 个邮箱及其邮箱数据吗？此操作不可恢复。`))return;try{$('#delete').disabled=true;const j=await api('api/accounts/batch-delete',{method:'DELETE',headers:{'content-type':'application/json'},body:JSON.stringify({domain:selectedDomain(),emails,purge_data:true})});await loadDomains();status(`删除完成：已删除 ${j.deleted.length} 个${j.protected.length?'，管理员账号已保护':''}`);$('#create-result').textContent=j.data_errors.length?'数据清理异常：'+j.data_errors.join('；'):''}catch(x){status(x.message,false)}finally{$('#delete').disabled=false}};
loadDomains().then(()=>status('已连接')).catch(x=>status(x.message,false));
</script></body></html>"""


MARKETING_HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>邮件营销与发件 API</title>
<style>
:root{color-scheme:light;--ink:#17212b;--muted:#637381;--line:#d9e1e8;--accent:#159447;--accent-dark:#0c7135;--danger:#b42318;--bg:#f2f5f7;--card:#fff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px system-ui,-apple-system,"Segoe UI",sans-serif}header{background:#fff;border-bottom:1px solid var(--line);padding:18px 24px}header h1{margin:0 0 5px;font-size:22px}header p{margin:0;color:var(--muted)}main{max-width:1500px;margin:0 auto;padding:18px 22px 40px}.nav{display:flex;gap:8px;flex-wrap:wrap;padding:14px 0}.nav button{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:4px;padding:9px 15px;cursor:pointer}.nav button.active{background:var(--accent);border-color:var(--accent);color:#fff}.tab{display:none}.tab.active{display:block}.grid{display:grid;grid-template-columns:minmax(420px,1fr) minmax(360px,1fr);gap:16px}.panel{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:18px;margin-bottom:16px}.panel h2{font-size:16px;margin:0 0 14px}.panel h3{font-size:14px;margin:18px 0 8px}.wide{grid-column:1/-1}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}.stat{background:#fff;border:1px solid var(--line);border-radius:6px;padding:15px}.stat small{display:block;color:var(--muted);margin-bottom:6px}.stat strong{font-size:25px;font-weight:650}.status{min-height:20px;margin:8px 0;color:var(--muted)}.ok{color:#087443}.error{color:var(--danger)}label{display:block;color:var(--muted);margin:10px 0 6px}input,select,textarea{width:100%;border:1px solid #b9c7d2;border-radius:4px;padding:9px;font:inherit;background:#fff}textarea{min-height:125px;resize:vertical}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.row.three{grid-template-columns:1fr 1fr 1fr}.check-row{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0}.check-row label{display:flex;align-items:center;gap:6px;margin:0;color:var(--ink)}.check-row input{width:auto}.actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.actions button,button.primary,button.secondary,button.danger{border:0;border-radius:4px;padding:9px 14px;background:var(--accent);color:#fff;cursor:pointer}.actions button:hover,button.primary:hover{background:var(--accent-dark)}button.secondary{background:#64748b}button.danger{background:var(--danger)}button.small{padding:5px 9px;margin:0;font-size:12px}button:disabled{opacity:.55;cursor:not-allowed}.editor-toolbar{display:flex;gap:5px;flex-wrap:wrap;padding:6px;background:#f1f4f6;border:1px solid #b9c7d2;border-bottom:0;border-radius:4px 4px 0 0}.editor-toolbar button{margin:0;padding:6px 10px;border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:3px;cursor:pointer}.editor{min-height:220px;border:1px solid #b9c7d2;border-radius:0 0 4px 4px;padding:11px;background:#fff;outline:none;overflow:auto}.editor:empty:before{content:attr(data-placeholder);color:#9aa6b2}.preview{width:100%;height:520px;border:1px solid var(--line);border-radius:4px;background:#fff}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:700px}th,td{text-align:left;border-bottom:1px solid var(--line);padding:9px 8px;vertical-align:top}th{color:var(--muted);font-weight:600;white-space:nowrap}.pill{display:inline-block;border-radius:12px;padding:3px 8px;background:#e8f5ed;color:#087443;font-size:12px}.pill.gray{background:#edf0f2;color:#637381}.pill.red{background:#fdeceb;color:var(--danger)}.secret{word-break:break-all;background:#fff8df;border:1px solid #ead38a;border-radius:4px;padding:12px;margin:12px 0}.code{white-space:pre-wrap;word-break:break-word;background:#17212b;color:#e8f2f7;border-radius:4px;padding:13px;overflow:auto}.muted{color:var(--muted)}.empty{padding:18px;color:var(--muted);text-align:center}.modal{position:fixed;inset:0;background:rgba(23,33,43,.58);display:flex;align-items:center;justify-content:center;padding:18px;z-index:10}.modal.hidden{display:none}.modal-box{background:#fff;border-radius:7px;width:min(980px,100%);max-height:calc(100vh - 36px);overflow:auto;padding:18px}.modal-head{display:flex;justify-content:space-between;gap:12px;align-items:center}.modal-head button{border:0;background:#eef2f5;border-radius:4px;padding:5px 10px;font-size:20px;cursor:pointer}@media(max-width:900px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.wide{grid-column:auto}}@media(max-width:560px){main{padding:12px}.row,.row.three{grid-template-columns:1fr}.stats{grid-template-columns:1fr}.panel{padding:14px}}
</style></head><body><header><h1>邮件营销与发件 API</h1><p>基于当前 Mailu 邮箱发送，支持联系人分组、模板、定时任务、限速和发送统计。</p></header><main>
<nav class="nav"><button class="active" data-tab="campaigns">邮件营销</button><button data-tab="templates">模板</button><button data-tab="contacts">联系人</button><button data-tab="api">发件 API</button></nav>
<div id="status" class="status" aria-live="polite"></div>
<section id="tab-campaigns" class="tab active"><div class="stats"><div class="stat"><small>营销任务</small><strong id="stat-campaigns">0</strong></div><div class="stat"><small>有效联系人</small><strong id="stat-contacts">0</strong></div><div class="stat"><small>已提交邮件</small><strong id="stat-sent">0</strong></div><div class="stat"><small>打开率 / 点击率</small><strong id="stat-rates">0% / 0%</strong></div></div>
<div class="grid"><section class="panel"><h2>添加营销任务</h2><div class="row"><div><label>任务名称</label><input id="campaign-name" placeholder="例如：新品通知"></div><div><label>发件人</label><select id="campaign-from"></select></div></div><div class="row"><div><label>显示名称</label><input id="campaign-sender-name" placeholder="品牌名称"></div><div><label>邮件主题</label><input id="campaign-subject" placeholder="请输入邮件主题"></div></div><div class="row"><div><label>收件人分组</label><select id="campaign-group"><option value="">不使用分组</option></select></div><div><label>邮件模板</label><select id="campaign-template"><option value="">手动编辑正文</option></select></div></div><label>补充收件人</label><textarea id="campaign-recipients" placeholder="每行一个邮箱，也支持：邮箱,姓名"></textarea><label>邮件正文</label><div class="editor-toolbar"><button type="button" data-cmd="bold"><b>B</b></button><button type="button" data-cmd="italic"><i>I</i></button><button type="button" data-cmd="underline"><u>U</u></button><button type="button" id="campaign-link">插入链接</button><button type="button" id="campaign-image">插入图片</button></div><div id="campaign-editor" class="editor" contenteditable="true" data-placeholder="输入图文内容，可使用 {{name}} 和 {{email}} 变量"></div><div class="row three"><div><label>发送时间</label><input id="campaign-send-at" type="datetime-local"></div><div><label>每分钟最多发送</label><input id="campaign-rate" type="number" min="0" max="6000" value="0" placeholder="0 表示不限速"></div><div><label>跟踪地址</label><input id="campaign-public-url" placeholder="留空使用服务器设置"></div></div><div class="check-row"><label><input id="track-open" type="checkbox" checked>跟踪打开</label><label><input id="track-click" type="checkbox" checked>跟踪点击</label></div><label>备注</label><input id="campaign-note" placeholder="可选"><div class="actions"><button id="save-campaign" class="primary">保存任务</button><button id="send-campaign" class="primary">保存并立即发送</button><button id="reset-campaign" class="secondary">清空</button></div></section><section class="panel"><h2>邮件预览</h2><iframe id="campaign-preview" class="preview" sandbox="allow-popups"></iframe><p class="muted">发送前可先保存为任务；模板变量会在发送时按联系人资料替换。</p></section><section class="panel wide"><div class="actions"><h2 style="margin:0;flex:1">营销任务</h2><button id="refresh-campaigns" class="secondary small">刷新</button></div><div class="table-wrap"><table><thead><tr><th>任务</th><th>发件人</th><th>收件人</th><th>进度</th><th>发送时间</th><th>状态</th><th>操作</th></tr></thead><tbody id="campaign-list"></tbody></table></div></section></div></section>
<section id="tab-templates" class="tab"><div class="grid"><section class="panel"><h2>模板编辑</h2><input id="template-id" type="hidden"><label>模板名称</label><input id="template-name" placeholder="例如：产品月报"><label>主题</label><input id="template-subject"><label>纯文本正文</label><textarea id="template-text" placeholder="HTML 不支持时显示"></textarea><label>HTML 正文</label><div id="template-html" class="editor" contenteditable="true" data-placeholder="请输入 HTML 邮件内容"></div><div class="actions"><button id="save-template" class="primary">保存模板</button><button id="clear-template" class="secondary">清空</button></div></section><section class="panel"><h2>模板列表</h2><div class="table-wrap"><table><thead><tr><th>名称</th><th>主题</th><th>更新时间</th><th>操作</th></tr></thead><tbody id="template-list"></tbody></table></div></section></div></section>
<section id="tab-contacts" class="tab"><div class="grid"><section class="panel"><h2>联系人分组</h2><div class="row"><div><label>分组名称</label><input id="group-name" placeholder="例如：订阅用户"></div><div><label>说明</label><input id="group-description" placeholder="可选"></div></div><button id="create-group" class="primary">创建分组</button><h3>导入联系人</h3><label>目标分组</label><select id="contact-group"></select><label>联系人</label><textarea id="contact-input" placeholder="每行：email 或 email,姓名"></textarea><button id="import-contacts" class="primary">导入联系人</button></section><section class="panel"><h2>分组概览</h2><div class="table-wrap"><table><thead><tr><th>分组</th><th>有效</th><th>总数</th><th>创建时间</th></tr></thead><tbody id="group-list"></tbody></table></div></section><section class="panel wide"><div class="actions"><h2 style="margin:0;flex:1">联系人</h2><div><select id="contact-filter"><option value="all">全部分组</option></select> <button id="refresh-contacts" class="secondary small">刷新</button> <button id="delete-contacts" class="danger small">删除选中</button></div></div><div class="table-wrap"><table><thead><tr><th><input id="select-contacts" type="checkbox"></th><th>邮箱</th><th>姓名</th><th>分组</th><th>状态</th><th>创建时间</th></tr></thead><tbody id="contact-list"></tbody></table></div></section></div></section>
<section id="tab-api" class="tab"><div class="grid"><section class="panel"><h2>创建发件 API</h2><label>名称</label><input id="api-name" placeholder="例如：网站通知"><label>默认发件人</label><select id="api-sender"></select><p class="muted">密钥只在创建成功时显示一次，请妥善保存。</p><button id="create-api-key" class="primary">生成 API 密钥</button><div id="new-api-key"></div></section><section class="panel"><h2>调用示例</h2><p class="muted">支持 `X-API-Key` 或 `Authorization: Bearer`，可发送纯文本、HTML、CC/BCC 和 base64 附件。</p><pre class="code">POST /mail-control/api/v1/send
Content-Type: application/json
X-API-Key: mc_live_xxx

{
  "from": "sender@example.com",
  "to": "user@example.net",
  "subject": "通知",
  "text": "纯文本内容",
  "html": "&lt;p&gt;&lt;b&gt;图文内容&lt;/b&gt;&lt;/p&gt;"
}</pre><p class="muted">批量发送使用 `/api/v1/batch-send`，将 `to` 换成 `recipients` 数组即可。</p></section><section class="panel wide"><div class="actions"><h2 style="margin:0;flex:1">API 密钥</h2><button id="refresh-api-keys" class="secondary small">刷新</button></div><div class="table-wrap"><table><thead><tr><th>名称</th><th>密钥前缀</th><th>默认发件人</th><th>创建时间</th><th>最后使用</th><th>状态</th><th>操作</th></tr></thead><tbody id="api-key-list"></tbody></table></div></section></div></section>
<div id="logs-modal" class="modal hidden"><div class="modal-box"><div class="modal-head"><h2 id="logs-title">任务记录</h2><button id="close-logs">×</button></div><div class="table-wrap"><table><thead><tr><th>收件人</th><th>状态</th><th>发送时间</th><th>打开</th><th>点击</th><th>错误</th></tr></thead><tbody id="logs-list"></tbody></table></div></div></div>
</main><script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)], esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const apiRoot=location.pathname.replace(/\/marketing(?:\/manage)?\/?$/,'/');async function api(path,options){const r=await fetch(apiRoot+path,options);const j=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw Error(j.error||r.statusText);return j}
function status(message,good=true){$('#status').textContent=message;$('#status').className='status '+(good?'ok':'error')}
function publicBase(){return $('#campaign-public-url').value.trim()||location.origin+location.pathname.replace(/\/marketing(?:\/manage)?\/?$/,'')}
let groups=[],templates=[],campaigns=[];
function setOptions(id,items,empty){const el=$(id);el.innerHTML=empty||'';items.forEach(x=>{const o=document.createElement('option');o.value=x.id;o.textContent=x.name+(x.active!==undefined?` (${x.active})`:'');el.appendChild(o)})}
async function loadMailboxes(){const j=await api('api/mailboxes');['#campaign-from','#api-sender'].forEach(id=>{$(id).innerHTML=j.mailboxes.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('')});}
async function loadGroups(){const j=await api('api/marketing/groups');groups=j.groups;setOptions('#campaign-group',groups,'<option value="">不使用分组</option>');setOptions('#contact-group',groups,groups.length?'':'<option value="">请先创建分组</option>');$('#contact-filter').innerHTML='<option value="all">全部分组</option>'+groups.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join('');$('#group-list').innerHTML=groups.length?groups.map(x=>`<tr><td>${esc(x.name)}</td><td>${x.active}</td><td>${x.total}</td><td>${esc(x.created_at)}</td></tr>`).join(''):'<tr><td colspan="4" class="empty">暂无联系人分组</td></tr>'}
async function loadTemplates(){const j=await api('api/marketing/templates');templates=j.templates;$('#campaign-template').innerHTML='<option value="">手动编辑正文</option>'+templates.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join('');$('#template-list').innerHTML=templates.length?templates.map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x.subject)}</td><td>${esc(x.updated_at)}</td><td><button class="secondary small" data-template-edit="${x.id}">编辑</button> <button class="danger small" data-template-delete="${x.id}">删除</button></td></tr>`).join(''):'<tr><td colspan="4" class="empty">暂无模板</td></tr>'}
function campaignStatus(x){const labels={draft:'草稿',scheduled:'待发送',sending:'发送中',paused:'已暂停',completed:'已完成',canceled:'已取消'};return `<span class="pill ${x.status==='failed'?'red':x.status==='draft'?'gray':''}">${labels[x.status]||x.status}</span>`}
async function loadCampaigns(){const j=await api('api/marketing/campaigns');campaigns=j.campaigns;$('#campaign-list').innerHTML=campaigns.length?campaigns.map(x=>`<tr><td><b>${esc(x.name)}</b><br><span class="muted">${esc(x.subject)}</span></td><td>${esc(x.sender)}${x.sender_name?`<br>${esc(x.sender_name)}`:''}</td><td>${x.total}</td><td>${x.sent}/${x.total}<br><span class="muted">失败 ${x.failed}</span></td><td>${esc(x.send_at)}</td><td>${campaignStatus(x)}</td><td><button class="secondary small" data-campaign-logs="${x.id}">记录</button> ${['draft','scheduled','paused'].includes(x.status)?`<button class="primary small" data-campaign-action="start" data-campaign-id="${x.id}">发送</button>`:''}${x.status==='sending'?`<button class="secondary small" data-campaign-action="pause" data-campaign-id="${x.id}">暂停</button>`:''}${x.status==='paused'?`<button class="primary small" data-campaign-action="resume" data-campaign-id="${x.id}">继续</button>`:''}${!['sending','completed'].includes(x.status)?`<button class="danger small" data-campaign-delete="${x.id}">删除</button>`:''}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">暂无营销任务</td></tr>'}
async function loadContacts(){const group=$('#contact-filter').value;const j=await api('api/marketing/contacts?group_id='+encodeURIComponent(group));$('#contact-list').innerHTML=j.contacts.length?j.contacts.map(x=>`<tr><td><input type="checkbox" data-contact-email="${esc(x.email)}"></td><td>${esc(x.email)}</td><td>${esc(x.name||'-')}</td><td>${esc(x.group_name)}</td><td>${x.active?'有效':'已停用'}</td><td>${esc(x.created_at)}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">暂无联系人</td></tr>'}
async function loadApiKeys(){const j=await api('api/marketing/api-keys');$('#api-key-list').innerHTML=j.api_keys.length?j.api_keys.map(x=>`<tr><td>${esc(x.name)}</td><td><code>${esc(x.key_prefix)}...</code></td><td>${esc(x.sender||'-')}</td><td>${esc(x.created_at)}</td><td>${esc(x.last_used_at||'-')}</td><td>${x.active?'<span class="pill">可用</span>':'<span class="pill gray">已停用</span>'}</td><td>${x.active?`<button class="danger small" data-api-delete="${x.id}">停用</button>`:''}</td></tr>`).join(''):'<tr><td colspan="7" class="empty">暂无 API 密钥</td></tr>'}
async function loadSummary(){const x=await api('api/marketing/summary');$('#stat-campaigns').textContent=x.campaigns;$('#stat-contacts').textContent=x.contacts;$('#stat-sent').textContent=x.sent;$('#stat-rates').textContent=`${x.open_rate}% / ${x.click_rate}%`}
function updatePreview(){const value=$('#campaign-editor').innerHTML.trim();MailViewer.preview($('#campaign-preview'),value)}
function resetCampaign(){$('#campaign-name').value='';$('#campaign-sender-name').value='';$('#campaign-subject').value='';$('#campaign-recipients').value='';$('#campaign-editor').innerHTML='';$('#campaign-send-at').value='';$('#campaign-rate').value='0';$('#campaign-note').value='';$('#campaign-template').value='';updatePreview()}
async function saveCampaign(immediate){const recipients=$('#campaign-recipients').value.trim();const group=$('#campaign-group').value;const sendAt=$('#campaign-send-at').value;const payload={name:$('#campaign-name').value,from:$('#campaign-from').value,sender_name:$('#campaign-sender-name').value,subject:$('#campaign-subject').value,html:$('#campaign-editor').innerHTML,text:$('#campaign-editor').innerText,recipients,group_id:group||null,template_id:$('#campaign-template').value||null,send_at:sendAt?new Date(sendAt).toISOString():'',rate_per_minute:Number($('#campaign-rate').value||0),track_open:$('#track-open').checked,track_click:$('#track-click').checked,public_url:publicBase(),note:$('#campaign-note').value};const j=await api('api/marketing/campaigns',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});if(immediate)await api('api/marketing/campaigns/'+j.id+'/action',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'start'})});return j}
$$('[data-tab]').forEach(b=>b.onclick=()=>{$$('[data-tab]').forEach(x=>x.classList.toggle('active',x===b));$$('.tab').forEach(x=>x.classList.toggle('active',x.id==='tab-'+b.dataset.tab));history.replaceState({},'',location.pathname+'?tab='+b.dataset.tab)})
const tab=new URLSearchParams(location.search).get('tab');if(tab&&$(`[data-tab="${tab}"]`))$(`[data-tab="${tab}"]`).click();
$('#campaign-editor').oninput=updatePreview;['#campaign-subject','#campaign-sender-name'].forEach(id=>$(id).oninput=updatePreview);document.querySelectorAll('[data-cmd]').forEach(b=>b.onclick=()=>{document.execCommand(b.dataset.cmd,false,null);updatePreview()});$('#campaign-link').onclick=()=>{const u=prompt('请输入 https:// 链接');if(u&&/^https?:\/\//i.test(u))document.execCommand('createLink',false,u);updatePreview()};$('#campaign-image').onclick=()=>{const u=prompt('请输入图片链接');if(u&&/^https?:\/\//i.test(u))document.execCommand('insertHTML',false,`<img src="${esc(u)}" style="max-width:100%" alt="">`);updatePreview()};$('#campaign-template').onchange=()=>{const x=templates.find(t=>String(t.id)===$('#campaign-template').value);if(x){$('#campaign-subject').value=x.subject;$('#campaign-editor').innerHTML=x.html_body||`<pre>${esc(x.text_body)}</pre>`;updatePreview()}};
$('#save-campaign').onclick=async()=>{try{const j=await saveCampaign(false);status(`任务已保存，共 ${j.total} 位收件人`);resetCampaign();await Promise.all([loadCampaigns(),loadSummary()])}catch(x){status(x.message,false)}};$('#send-campaign').onclick=async()=>{try{const j=await saveCampaign(true);status(`任务已开始发送，共 ${j.total} 位收件人`);resetCampaign();await Promise.all([loadCampaigns(),loadSummary()])}catch(x){status(x.message,false)}};$('#reset-campaign').onclick=resetCampaign;$('#refresh-campaigns').onclick=()=>Promise.all([loadCampaigns(),loadSummary()]).catch(x=>status(x.message,false));
$('#create-group').onclick=async()=>{try{await api('api/marketing/groups',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:$('#group-name').value,description:$('#group-description').value})});$('#group-name').value='';$('#group-description').value='';await loadGroups();status('联系人分组已创建')}catch(x){status(x.message,false)}};$('#import-contacts').onclick=async()=>{try{await api('api/marketing/contacts/import',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({group_id:$('#contact-group').value||null,contacts:$('#contact-input').value})});$('#contact-input').value='';await Promise.all([loadGroups(),loadContacts(),loadSummary()]);status('联系人导入完成')}catch(x){status(x.message,false)}};$('#contact-filter').onchange=()=>loadContacts().catch(x=>status(x.message,false));$('#refresh-contacts').onclick=()=>loadContacts().catch(x=>status(x.message,false));$('#select-contacts').onchange=e=>$$('[data-contact-email]').forEach(x=>x.checked=e.target.checked);$('#delete-contacts').onclick=async()=>{const emails=$$('[data-contact-email]:checked').map(x=>x.dataset.contactEmail);if(!emails.length){status('请先选择联系人',false);return}if(!confirm(`确定删除 ${emails.length} 个联系人吗？`))return;try{await api('api/marketing/contacts',{method:'DELETE',headers:{'content-type':'application/json'},body:JSON.stringify({emails})});await Promise.all([loadGroups(),loadContacts(),loadSummary()]);status('联系人已删除')}catch(x){status(x.message,false)}};
$('#save-template').onclick=async()=>{try{await api('api/marketing/templates',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({id:$('#template-id').value||null,name:$('#template-name').value,subject:$('#template-subject').value,text:$('#template-text').value,html:$('#template-html').innerHTML})});clearTemplate();await loadTemplates();status('模板已保存')}catch(x){status(x.message,false)}};function clearTemplate(){$('#template-id').value='';$('#template-name').value='';$('#template-subject').value='';$('#template-text').value='';$('#template-html').innerHTML=''}$('#clear-template').onclick=clearTemplate;
$('#create-api-key').onclick=async()=>{try{const j=await api('api/marketing/api-keys',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:$('#api-name').value,sender:$('#api-sender').value})});$('#api-name').value='';$('#new-api-key').innerHTML=`<div class="secret"><b>请立即保存 API 密钥：</b><br><code>${esc(j.key)}</code></div>`;await loadApiKeys();status('API 密钥已创建')}catch(x){status(x.message,false)}};$('#refresh-api-keys').onclick=()=>loadApiKeys().catch(x=>status(x.message,false));
document.addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;try{if(b.dataset.templateEdit){const x=templates.find(t=>String(t.id)===b.dataset.templateEdit);if(x){$('#template-id').value=x.id;$('#template-name').value=x.name;$('#template-subject').value=x.subject;$('#template-text').value=x.text_body;$('#template-html').innerHTML=x.html_body;document.querySelector('[data-tab="templates"]').click()}}else if(b.dataset.templateDelete){if(!confirm('确定删除此模板吗？'))return;await api('api/marketing/templates/'+b.dataset.templateDelete,{method:'DELETE'});await loadTemplates();status('模板已删除')}else if(b.dataset.campaignAction){await api('api/marketing/campaigns/'+b.dataset.campaignId+'/action',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:b.dataset.campaignAction})});await loadCampaigns();status('任务状态已更新')}else if(b.dataset.campaignDelete){if(!confirm('确定删除此任务吗？'))return;await api('api/marketing/campaigns/'+b.dataset.campaignDelete,{method:'DELETE'});await loadCampaigns();status('任务已删除')}else if(b.dataset.campaignLogs){const j=await api('api/marketing/campaigns/'+b.dataset.campaignLogs+'/logs');const c=campaigns.find(x=>String(x.id)===b.dataset.campaignLogs);$('#logs-title').textContent=c?`任务记录：${c.name}`:'任务记录';$('#logs-list').innerHTML=j.logs.length?j.logs.map(x=>`<tr><td>${esc(x.email)}</td><td>${x.status==='sent'?'<span class="pill">成功</span>':'<span class="pill red">失败</span>'}</td><td>${esc(x.sent_at||'-')}</td><td>${esc(x.opened_at||'-')}</td><td>${esc(x.clicked_at||'-')}</td><td>${esc(x.error||'-')}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">暂无记录</td></tr>';$('#logs-modal').classList.remove('hidden')}else if(b.dataset.apiDelete){if(!confirm('停用此 API 密钥吗？'))return;await api('api/marketing/api-keys/'+b.dataset.apiDelete,{method:'DELETE'});await loadApiKeys();status('API 密钥已停用')}}catch(x){status(x.message,false)}});$('#close-logs').onclick=()=>$('#logs-modal').classList.add('hidden');$('#logs-modal').onclick=e=>{if(e.target.id==='logs-modal')$('#logs-modal').classList.add('hidden')};
Promise.all([loadMailboxes(),loadGroups(),loadTemplates(),loadCampaigns(),loadContacts(),loadApiKeys(),loadSummary()]).then(()=>{status('已连接');updatePreview()}).catch(x=>status(x.message,false));
</script></body></html>"""


API_HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>发件 API</title>
<style>
:root{color-scheme:light;--ink:#24303a;--muted:#768590;--line:#e1e7eb;--green:#18a34a;--green-dark:#0f873d;--green-soft:#e7f6ec;--danger:#d93636;--bg:#f3f6f8;--card:#fff}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px system-ui,-apple-system,"Segoe UI",sans-serif}header{padding:18px 24px 12px;background:#fff;border-bottom:1px solid var(--line)}header h1{margin:0;font-size:22px}.crumb{margin:0 0 12px;color:var(--muted)}main{max-width:1800px;margin:0 auto;padding:18px 20px 32px}.filters{display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:#fff;border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:18px}.filters label{color:var(--muted);white-space:nowrap}.filters select,.filters input{height:36px;border:1px solid #cbd6dc;border-radius:4px;background:#fff;padding:0 10px;font:inherit}.filters select{min-width:112px}.filters input{width:142px}.filters input.search{width:210px}.filters button,.toolbar button,.modal-actions button{height:36px;border:1px solid var(--green);border-radius:4px;background:#fff;color:var(--green);padding:0 15px;cursor:pointer;font:inherit}.filters button.primary,.toolbar button.primary,.modal-actions button.primary{background:var(--green);color:#fff}.filters button:hover,.toolbar button:hover,.modal-actions button:hover{border-color:var(--green-dark);background:var(--green-soft)}.filters button.primary:hover,.toolbar button.primary:hover,.modal-actions button.primary:hover{background:var(--green-dark);color:#fff}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}.stat{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:18px 20px}.stat-title{color:var(--muted);margin-bottom:9px}.stat-title span{margin-left:6px}.stat-value{font-size:28px;font-weight:650}.toolbar{display:flex;align-items:center;gap:10px;margin-bottom:12px}.toolbar .help{color:var(--muted);text-decoration:none}.table-wrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:6px}table{width:100%;min-width:1160px;border-collapse:collapse}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #edf1f3;vertical-align:middle;white-space:nowrap}th{color:#52616d;background:#fafbfc;font-weight:600}tbody tr:last-child td{border-bottom:0}.api-key{display:inline-flex;align-items:center;gap:7px;max-width:350px}.api-key code{display:inline-block;max-width:300px;overflow:hidden;text-overflow:ellipsis;vertical-align:middle;color:#52616d}.copy{border:0;background:transparent;color:var(--green);cursor:pointer;padding:2px}.metric{font-variant-numeric:tabular-nums}.tag{display:inline-block;padding:4px 9px;border-radius:4px;background:var(--green-soft);color:#12813c;font-size:12px}.tag.gray{background:#f0f3f5;color:#697781}.actions{display:flex;align-items:center;gap:10px}.actions button{border:0;background:transparent;color:var(--green);padding:0;cursor:pointer;font:inherit}.actions button.danger{color:var(--danger)}.empty{padding:34px!important;text-align:center;color:var(--muted)}.pager{display:flex;justify-content:flex-end;align-items:center;gap:10px;padding:12px 0;color:var(--muted)}.pager button{border:1px solid var(--line);background:#fff;border-radius:4px;padding:6px 10px;cursor:pointer}.pager button:disabled{opacity:.45;cursor:not-allowed}.status{min-height:20px;margin:4px 0 10px;color:var(--muted)}.status.error{color:var(--danger)}.status.ok{color:#087443}.modal{position:fixed;inset:0;z-index:20;display:flex;align-items:center;justify-content:center;padding:18px;background:rgba(20,30,38,.52)}.modal.hidden{display:none}.modal-box{width:min(760px,100%);max-height:calc(100vh - 36px);overflow:auto;background:#fff;border-radius:7px;padding:20px;box-shadow:0 18px 60px rgba(0,0,0,.25)}.modal-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.modal-head h2{margin:0;font-size:18px}.close{border:0;background:#eef2f4;border-radius:4px;padding:4px 10px;font-size:20px;cursor:pointer}.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}.form-grid .full{grid-column:1/-1}label.field{display:block;color:#52616d;margin:11px 0 6px}input.field,select.field{width:100%;height:38px;border:1px solid #cbd6dc;border-radius:4px;padding:0 10px;background:#fff;font:inherit}.switch-row{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-top:12px}.switch-row label{display:flex;align-items:center;gap:6px}.switch-row input{width:auto}.advanced{margin-top:14px;border-top:1px solid var(--line);padding-top:12px}.advanced summary{cursor:pointer;color:var(--green);font-weight:600}.modal-actions{display:flex;justify-content:flex-end;gap:9px;margin-top:18px}.modal-actions button.secondary{border-color:var(--line);color:#52616d}.secret{margin-top:12px;padding:12px;background:#fff8df;border:1px solid #ead38a;border-radius:4px;word-break:break-all}.command{white-space:pre-wrap;word-break:break-word;background:#17212b;color:#e9f2f6;border-radius:4px;padding:13px;min-height:120px}.test-result{min-height:22px;margin-top:10px}.test-result.error{color:var(--danger)}.test-result.ok{color:#087443}@media(max-width:950px){.stats{grid-template-columns:repeat(2,1fr)}}@media(max-width:620px){main{padding:12px}.stats{grid-template-columns:1fr}.filters{align-items:stretch}.filters>*{width:100%!important}.form-grid{grid-template-columns:1fr}.form-grid .full{grid-column:auto}.modal{padding:0}.modal-box{height:100%;max-height:none;border-radius:0}.toolbar{align-items:stretch;flex-wrap:wrap}.toolbar button{flex:1}}
</style></head><body><header><p class="crumb">中控菜单　/　发件 API</p><h1>发件 API</h1></header><main><div id="status" class="status"></div><section class="filters"><label>时间范围：</label><select id="time-range"><option value="7">近7天</option><option value="30">近30天</option><option value="all">全部</option><option value="custom">自定义</option></select><input id="start-date" type="date"><span>至</span><input id="end-date" type="date"><label>状态：</label><select id="active-filter"><option value="-1">全部</option><option value="1">可用</option><option value="0">停用</option></select><label>搜索：</label><input id="keyword" class="search" placeholder="请输入 API 名称"><button id="search">查询</button><button id="refresh-data">刷新数据</button></section><section class="stats"><div class="stat"><div class="stat-title">✈<span>发送总量</span></div><div id="stat-total" class="stat-value">0</div></div><div class="stat"><div class="stat-title">✉<span>平均打开率</span></div><div id="stat-open" class="stat-value">0%</div></div><div class="stat"><div class="stat-title">↗<span>平均点击率</span></div><div id="stat-click" class="stat-value">0%</div></div><div class="stat"><div class="stat-title">⊘<span>平均退信率</span></div><div id="stat-bounce" class="stat-value">0%</div></div></section><div class="toolbar"><button id="new-api" class="primary">新建 API</button><a class="help" href="https://www.billionmail.com/start/api_mail_guide.html" target="_blank" rel="noreferrer">Help ⓘ</a></div><div class="table-wrap"><table><thead><tr><th>API 名称</th><th>API 密钥</th><th>发送量</th><th>打开率</th><th>点击率</th><th>退信率</th><th>状态</th><th>操作</th></tr></thead><tbody id="api-list"></tbody></table></div><div class="pager"><button id="prev-page">‹</button><span id="page-info">1 / 1</span><button id="next-page">›</button><select id="page-size"><option value="10">10 / 页</option><option value="20">20 / 页</option><option value="50">50 / 页</option></select><span id="total-info">Total 0</span></div></main><div id="api-modal" class="modal hidden"><div class="modal-box"><div class="modal-head"><h2 id="api-modal-title">新建 API</h2><button class="close" data-close="api-modal">×</button></div><form id="api-form"><input id="api-id" type="hidden"><div class="form-grid"><div><label class="field">API 名称</label><input id="api-name" class="field" required placeholder="例如：Welcome"></div><div><label class="field">发件人</label><select id="api-sender" class="field" required></select></div><div><label class="field">显示名称</label><input id="api-sender-name" class="field" placeholder="例如：品牌名称"></div><div><label class="field">主题</label><input id="api-subject" class="field" placeholder="请输入邮件主题"></div><div><label class="field">邮件模板</label><select id="api-template" class="field"><option value="0">请选择邮件模板</option></select></div><div><label class="field">联系人分组</label><select id="api-group" class="field"><option value="0">不使用分组</option></select></div></div><div class="switch-row"><label><input id="api-active" type="checkbox" checked>启用 API</label></div><details class="advanced"><summary>高级功能</summary><div class="form-grid"><div><label class="field">IP 白名单</label><input id="api-ip" class="field" placeholder="例如：203.0.113.10, 203.0.113.0/24"></div><div><label class="field">过期时间</label><input id="api-expires" class="field" type="datetime-local"></div></div><div class="switch-row"><label><input id="api-unsubscribe" type="checkbox" checked>退订链接</label><label><input id="api-track-open" type="checkbox" checked>打开统计</label><label><input id="api-track-click" type="checkbox" checked>点击统计</label></div><div id="reset-key-row" class="switch-row hidden"><label><input id="api-reset-key" type="checkbox">保存时重置 API 密钥</label></div></details><div class="modal-actions"><button type="button" class="secondary" data-close="api-modal">取消</button><button type="submit" class="primary">保存</button></div></form><div id="new-secret" class="secret hidden"></div></div></div><div id="test-modal" class="modal hidden"><div class="modal-box"><div class="modal-head"><h2>Test API</h2><button class="close" data-close="test-modal">×</button></div><label class="field">测试邮件</label><input id="test-recipient" class="field" type="email" placeholder="请输入测试邮箱"><label class="field">Command</label><pre id="test-command" class="command"></pre><div class="modal-actions"><button id="copy-command" type="button" class="secondary">复制命令</button><button id="send-test" type="button" class="primary">发送测试邮件</button></div><div id="test-result" class="test-result"></div></div></div><script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)],esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),apiRoot=location.pathname.replace(/\/marketing(?:\/manage)?\/?$/,'/');let rows=[],groups=[],templates=[],rawKeys={},activeTest=null,state={page:1,pageSize:10,total:0};
async function api(path,options){const r=await fetch(apiRoot+path,options);const j=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw Error(j.error||r.statusText);return j}
function status(message,kind=''){const el=$('#status');el.textContent=message;el.className='status '+kind}
function localDate(value){const d=value?new Date(value):new Date();return new Date(d.getTime()-d.getTimezoneOffset()*60000).toISOString().slice(0,10)}
function setDateRange(){const type=$('#time-range').value;const end=new Date();const start=new Date();if(type==='7')start.setDate(end.getDate()-6);if(type==='30')start.setDate(end.getDate()-29);$('#start-date').disabled=type!=='custom';$('#end-date').disabled=type!=='custom';if(type==='all'){$('#start-date').value='';$('#end-date').value=''}else if(type!=='custom'){$('#start-date').value=localDate(start);$('#end-date').value=localDate(end)}}
function rangeParams(){return new URLSearchParams({start_time:$('#start-date').value,end_time:$('#end-date').value})}
function percent(value){return `${Number(value||0).toFixed(2).replace(/\.00$/,'')}%`}
function renderStats(x){$('#stat-total').textContent=Number(x.total_send||0).toLocaleString();$('#stat-open').textContent=percent(x.avg_open_rate);$('#stat-click').textContent=percent(x.avg_click_rate);$('#stat-bounce').textContent=percent(x.avg_bounce_rate)}
function renderRows(){const body=$('#api-list');if(!rows.length){body.innerHTML='<tr><td colspan="8" class="empty">暂无发件 API</td></tr>';return}body.innerHTML=rows.map(x=>{const key=rawKeys[x.id]||x.api_key||'未保存完整密钥';return `<tr><td><button class="actions-link" data-edit="${x.id}">${esc(x.api_name)}</button></td><td><span class="api-key"><code>${esc(key)}</code><button class="copy" data-copy-key="${x.id}" title="复制 API 密钥">▢</button></span></td><td class="metric">${Number(x.send_count||0).toLocaleString()}</td><td class="metric">${percent(x.open_rate)}</td><td class="metric">${percent(x.click_rate)}</td><td class="metric">${percent(x.bounce_rate)}</td><td><span class="tag ${x.active?'':'gray'}">${x.active?'可用':'停用'}</span></td><td><div class="actions"><button data-test="${x.id}">测试</button><button data-edit="${x.id}">编辑</button><button class="danger" data-delete="${x.id}">删除</button></div></td></tr>`}).join('')}
function renderPager(){const pages=Math.max(1,Math.ceil(state.total/state.pageSize));$('#page-info').textContent=`${state.page} / ${pages}`;$('#total-info').textContent=`Total ${state.total}`;$('#prev-page').disabled=state.page<=1;$('#next-page').disabled=state.page>=pages}
async function load(){try{status('正在加载...');const range=rangeParams();const common=`${range.toString()}&keyword=${encodeURIComponent($('#keyword').value.trim())}&active=${encodeURIComponent($('#active-filter').value)}&page=${state.page}&page_size=${state.pageSize}`;const [overview,list]=await Promise.all([api('api/marketing/api-overview?'+range.toString()),api('api/marketing/api-keys?'+common)]);renderStats(overview);rows=list.api_keys||list.list||[];state.total=Number(list.total||0);renderRows();renderPager();status(`已更新 ${new Date().toLocaleTimeString()}`,'ok')}catch(e){status(e.message,'error')}}
async function loadOptions(){const [m,g,t]=await Promise.all([api('api/mailboxes'),api('api/marketing/groups'),api('api/marketing/templates')]);$('#api-sender').innerHTML=m.mailboxes.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');groups=g.groups||[];templates=t.templates||[];$('#api-group').innerHTML='<option value="0">不使用分组</option>'+groups.map(x=>`<option value="${x.id}">${esc(x.name)}（${x.active}）</option>`).join('');$('#api-template').innerHTML='<option value="0">请选择邮件模板</option>'+templates.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join('')}
function resetForm(){['#api-id','#api-name','#api-sender-name','#api-subject','#api-ip','#api-expires'].forEach(id=>$(id).value='');$('#api-group').value='0';$('#api-template').value='0';$('#api-active').checked=true;$('#api-unsubscribe').checked=true;$('#api-track-open').checked=true;$('#api-track-click').checked=true;$('#api-reset-key').checked=false;$('#new-secret').classList.add('hidden');$('#reset-key-row').classList.add('hidden');$('#api-modal-title').textContent='新建 API'}
function openForm(row){resetForm();if(row){$('#api-modal-title').textContent='编辑 API';$('#api-id').value=row.id;$('#api-name').value=row.api_name||'';$('#api-sender').value=row.addresser||'';$('#api-sender-name').value=row.full_name||'';$('#api-subject').value=row.subject||'';$('#api-template').value=String(row.template_id||0);$('#api-group').value=String(row.group_id||0);$('#api-active').checked=!!row.active;$('#api-unsubscribe').checked=!!row.unsubscribe;$('#api-track-open').checked=!!row.track_open;$('#api-track-click').checked=!!row.track_click;$('#api-ip').value=(row.ip_whitelist||[]).join(', ');$('#api-expires').value=row.expires_at?String(row.expires_at).slice(0,16):'';$('#reset-key-row').classList.remove('hidden')}$('#api-modal').classList.remove('hidden')}
function commandText(){const recipient=$('#test-recipient').value.trim()||'$email';const key=rawKeys[activeTest?.id]||activeTest?.api_key||'<创建时保存的完整密钥>';const endpoint=location.origin+apiRoot+'api/v1/send';return `curl -k -X POST '${endpoint}' \\\n-H 'X-API-Key: ${key}' \\\n-H 'Content-Type: application/json' \\\n-d '{\n  "recipient": "${recipient}"\n}'`}
function openTest(row){activeTest=row;$('#test-recipient').value='';$('#test-result').textContent='';$('#test-result').className='test-result';$('#test-command').textContent=commandText();$('#test-modal').classList.remove('hidden')}
$('#time-range').onchange=()=>{setDateRange();state.page=1;load()};$('#search').onclick=()=>{state.page=1;load()};$('#refresh-data').onclick=()=>load();$('#keyword').onkeydown=e=>{if(e.key==='Enter'){$('#search').click()}};$('#start-date').onchange=()=>{$('#time-range').value='custom';state.page=1;load()};$('#end-date').onchange=()=>{$('#time-range').value='custom';state.page=1;load()};$('#page-size').onchange=e=>{state.pageSize=Number(e.target.value);state.page=1;load()};$('#prev-page').onclick=()=>{if(state.page>1){state.page--;load()}};$('#next-page').onclick=()=>{if(state.page<Math.ceil(state.total/state.pageSize)){state.page++;load()}};$('#new-api').onclick=()=>openForm(null);$('#test-recipient').oninput=()=>$('#test-command').textContent=commandText();
$('#api-template').onchange=()=>{const x=templates.find(t=>String(t.id)===$('#api-template').value);if(x){if(!$('#api-subject').value)$('#api-subject').value=x.subject||''}};
$('#api-form').onsubmit=async e=>{e.preventDefault();const templateId=Number($('#api-template').value||0);if(!templateId&&!$('#api-subject').value.trim()){status('请选择邮件模板或填写主题','error');return}const payload={name:$('#api-name').value,sender:$('#api-sender').value,sender_name:$('#api-sender-name').value,subject:$('#api-subject').value,template_id:templateId,group_id:Number($('#api-group').value||0),active:$('#api-active').checked,unsubscribe:$('#api-unsubscribe').checked,track_open:$('#api-track-open').checked,track_click:$('#api-track-click').checked,ip_whitelist:$('#api-ip').value,expires_at:$('#api-expires').value?new Date($('#api-expires').value).toISOString():'',reset_key:$('#api-reset-key').checked};try{const id=$('#api-id').value;const j=await api(id?'api/marketing/api-keys/'+id:'api/marketing/api-keys',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});if(j.key){rawKeys[j.id||id]=j.key;$('#new-secret').textContent='请立即保存新的 API 密钥：'+j.key;$('#new-secret').classList.remove('hidden')}await load();if(!j.key)$('#api-modal').classList.add('hidden');else status('API 已保存，请先保存密钥','ok')}catch(x){status(x.message,'error')}};
document.addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;try{if(b.dataset.close){const modal=document.getElementById(b.dataset.close);if(modal)modal.classList.add('hidden')}else if(b.dataset.edit){openForm(rows.find(x=>String(x.id)===b.dataset.edit))}else if(b.dataset.test){openTest(rows.find(x=>String(x.id)===b.dataset.test))}else if(b.dataset.delete){if(!confirm('确定停用此 API 吗？'))return;await api('api/marketing/api-keys/'+b.dataset.delete,{method:'DELETE'});await load()}else if(b.dataset.copyKey){const key=rawKeys[b.dataset.copyKey];if(!key){status('完整密钥仅在创建或重置时显示，请使用已保存的密钥','error');return}await navigator.clipboard.writeText(key);status('API 密钥已复制','ok')}else if(b.id==='copy-command'){await navigator.clipboard.writeText($('#test-command').textContent);$('#test-result').textContent='命令已复制'}else if(b.id==='send-test'){const to=$('#test-recipient').value.trim();if(!to){$('#test-result').textContent='请输入测试邮箱';$('#test-result').className='test-result error';return}const j=await api('api/marketing/api-keys/'+activeTest.id+'/test',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({recipient:to})});$('#test-result').textContent=j.sent?'测试邮件已发送':'测试邮件已提交';$('#test-result').className='test-result ok';await load()}}catch(x){if(b.id==='send-test'){$('#test-result').textContent=x.message;$('#test-result').className='test-result error'}else status(x.message,'error')}});
document.querySelectorAll('.modal').forEach(modal=>modal.addEventListener('click',e=>{if(e.target===modal)modal.classList.add('hidden')}));document.addEventListener('keydown',e=>{if(e.key==='Escape')document.querySelectorAll('.modal:not(.hidden)').forEach(modal=>modal.classList.add('hidden'))});setDateRange();Promise.all([loadOptions(),load()]).catch(e=>status(e.message,'error'));
</script></body></html>"""


MARKETING_LIST_HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>邮件营销</title>
<style>
:root{color-scheme:light;--ink:#1e2933;--muted:#70808c;--line:#e3e9ed;--green:#18a34a;--green-soft:#e7f6ec;--danger:#db3d3d;--bg:#fff}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px system-ui,-apple-system,"Segoe UI",sans-serif}header{padding:18px 24px 12px;border-bottom:1px solid var(--line)}header h1{font-size:20px;margin:0}.crumb{color:var(--muted);margin:0 0 15px}.tabs{height:42px;padding:0 24px;border-bottom:1px solid var(--line)}.tabs a{display:inline-block;height:42px;padding:12px 2px 10px;color:var(--green);border-bottom:2px solid var(--green);text-decoration:none;font-weight:600}main{padding:14px 24px 30px}.toolbar{display:flex;gap:10px;align-items:center;justify-content:space-between;margin-bottom:12px}.toolbar-left,.toolbar-right{display:flex;gap:8px;align-items:center}.toolbar button{border:0;border-radius:4px;padding:8px 15px;background:var(--green);color:#fff;cursor:pointer}.toolbar button.secondary{background:#fff;color:var(--green);border:1px solid var(--green)}.toolbar input{width:240px;border:1px solid var(--line);border-radius:4px;padding:8px 10px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:1120px}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid #eef1f3;vertical-align:middle;white-space:nowrap}th{background:#fafbfc;color:#52616d;font-weight:600;font-size:13px}.muted{color:var(--muted)}.success{color:var(--green)}.failure{color:var(--danger)}.status{display:inline-block;padding:3px 8px;border-radius:3px;background:var(--green-soft);color:#11823b;font-size:12px}.status.gray{background:#f1f3f5;color:#677581}.progress{width:126px;height:12px;background:#e8edf0;border-radius:8px;overflow:hidden}.progress span{display:block;height:100%;background:var(--green);text-align:center;color:#fff;font-size:9px;line-height:12px}.actions{display:flex;gap:8px}.actions button{border:0;background:transparent;color:var(--green);padding:0;cursor:pointer}.actions button.danger{color:var(--danger)}.empty{text-align:center;color:var(--muted);padding:35px}.modal{position:fixed;inset:0;background:rgba(20,30,38,.5);display:flex;align-items:center;justify-content:center;padding:16px}.modal.hidden{display:none}.modal-box{background:#fff;width:min(950px,100%);max-height:calc(100vh - 32px);overflow:auto;padding:18px;border-radius:6px}.modal-head{display:flex;justify-content:space-between;align-items:center}.modal-head button{border:0;background:#eef2f4;padding:4px 10px;border-radius:4px;font-size:20px}.error{color:var(--danger)}@media(max-width:800px){main{padding:12px}.toolbar{align-items:stretch;flex-direction:column}.toolbar-right,.toolbar input{width:100%}.toolbar input{flex:1}}
</style></head><body><header><p class="crumb">邮件营销</p><h1>邮件营销</h1></header><div class="tabs"><a href="./">任务</a></div><main><div id="status" class="muted"></div><div class="toolbar"><div class="toolbar-left"><button id="add-task">添加任务</button></div><div class="toolbar-right"><input id="search" placeholder="搜索邮件主题"><button id="refresh" class="secondary">刷新</button></div></div><div class="table-wrap"><table><thead><tr><th>时间</th><th>邮件主题</th><th>发件人</th><th>收件人</th><th>成功</th><th>失败</th><th>状态</th><th>备注</th><th>预计完成时间</th><th>进度</th><th>操作</th></tr></thead><tbody id="task-list"></tbody></table></div></main><div id="logs-modal" class="modal hidden"><div class="modal-box"><div class="modal-head"><h2 id="logs-title">任务记录</h2><button id="close-logs">×</button></div><div class="table-wrap"><table><thead><tr><th>收件人</th><th>状态</th><th>发送时间</th><th>打开</th><th>点击</th><th>错误</th></tr></thead><tbody id="logs-list"></tbody></table></div></div></div><script>
const $=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),apiRoot=location.pathname.replace(/\/marketing(?:\/manage)?\/?$/,'/');let tasks=[];
async function api(path,options){const r=await fetch(apiRoot+path,options);const j=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw Error(j.error||r.statusText);return j}
const labels={draft:'草稿',scheduled:'待发送',sending:'发送中',paused:'已暂停',completed:'已完成',canceled:'已取消'};
function time(value){return value?String(value).replace('T',' ').replace('+00:00',''):'--'}
function render(){const q=$('#search').value.trim().toLowerCase();const rows=tasks.filter(x=>!q||[x.name,x.subject,x.sender,x.note].some(v=>String(v||'').toLowerCase().includes(q)));$('#task-list').innerHTML=rows.length?rows.map(x=>{const done=Number(x.sent||0)+Number(x.failed||0),pct=x.total?Math.min(100,Math.floor(done/x.total*100)):0;const finish=x.rate_per_minute&&x.total>done?new Date(Date.now()+Math.ceil((x.total-done)/x.rate_per_minute)*60000).toISOString():x.status==='completed'?x.finished_at:x.send_at;return `<tr><td>${esc(time(x.created_at))}</td><td>${esc(x.subject)}</td><td>${esc(x.sender_name||x.sender)}</td><td>${x.total}</td><td class="success">${x.sent||0}</td><td class="failure">${x.failed||0}</td><td><span class="status ${x.status==='draft'||x.status==='canceled'?'gray':''}">${labels[x.status]||x.status}</span></td><td class="muted">${esc(x.note||'--')}</td><td>${esc(time(finish))}</td><td><div class="progress"><span style="width:${pct}%">${pct}%</span></div></td><td><div class="actions"><button data-logs="${x.id}">分析</button>${['draft','scheduled','paused'].includes(x.status)?`<button data-start="${x.id}">${x.status==='paused'?'继续':'发送'}</button>`:''}${x.status==='sending'?`<button data-pause="${x.id}">暂停</button>`:''}<button data-copy="${x.id}">复制</button><button data-delete="${x.id}" class="danger">删除</button></div></td></tr>`}).join(''):'<tr><td colspan="11" class="empty">暂无营销任务</td></tr>'}
async function load(){const j=await api('api/marketing/campaigns');tasks=j.campaigns;render();$('#status').textContent=`共 ${tasks.length} 个任务`}
$('#add-task').onclick=()=>{location.href=location.pathname.replace(/\/?$/,'/task/')};$('#refresh').onclick=()=>load().catch(e=>{$('#status').textContent=e.message;$('#status').className='error'});$('#search').oninput=render;$('#close-logs').onclick=()=>$('#logs-modal').classList.add('hidden');$('#logs-modal').onclick=e=>{if(e.target.id==='logs-modal')$('#logs-modal').classList.add('hidden')};document.addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;try{if(b.dataset.logs){const j=await api('api/marketing/campaigns/'+b.dataset.logs+'/logs');const x=tasks.find(t=>String(t.id)===b.dataset.logs);$('#logs-title').textContent=x?'任务记录：'+x.name:'任务记录';$('#logs-list').innerHTML=j.logs.length?j.logs.map(r=>`<tr><td>${esc(r.email)}</td><td>${r.status==='sent'?'<span class="success">成功</span>':'<span class="failure">失败</span>'}</td><td>${esc(time(r.sent_at))}</td><td>${esc(time(r.opened_at))}</td><td>${esc(time(r.clicked_at))}</td><td>${esc(r.error||'--')}</td></tr>`).join(''):'<tr><td colspan="6" class="empty">暂无记录</td></tr>';$('#logs-modal').classList.remove('hidden')}else if(b.dataset.start||b.dataset.pause){await api('api/marketing/campaigns/'+(b.dataset.start||b.dataset.pause)+'/action',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:b.dataset.start?'start':'pause'})});await load()}else if(b.dataset.copy){location.href=location.pathname.replace(/\/?$/,'/task/')+'?copy='+b.dataset.copy}else if(b.dataset.delete){if(!confirm('确定删除此任务吗？'))return;await api('api/marketing/campaigns/'+b.dataset.delete,{method:'DELETE'});await load()}}catch(x){$('#status').textContent=x.message;$('#status').className='error'}});load().catch(e=>{$('#status').textContent=e.message;$('#status').className='error'});
</script></body></html>"""


MARKETING_TASK_HTML = r"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>添加任务</title>
<style>
:root{color-scheme:light;--ink:#1e2933;--muted:#70808c;--line:#e3e9ed;--green:#18a34a;--green-dark:#0f863c;--bg:#f3f6f8}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px system-ui,-apple-system,"Segoe UI",sans-serif}header{padding:16px 22px 12px;background:#fff;border-bottom:1px solid var(--line)}header h1{font-size:20px;margin:0 0 6px}.crumb{color:var(--muted);margin:0}.back{float:right;color:var(--green);text-decoration:none;margin-top:-24px}main{max-width:1500px;margin:0 auto;padding:18px 20px 30px}.grid{display:grid;grid-template-columns:minmax(530px,1.05fr) minmax(430px,.95fr);gap:18px}.panel{background:#fff;border:1px solid var(--line);border-radius:6px;padding:18px;margin-bottom:16px}.panel h2{font-size:16px;margin:0 0 15px}.panel h3{font-size:14px;margin:17px 0 8px}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.sender{display:grid;grid-template-columns:1fr 1fr;gap:10px}label{display:block;color:#52616d;margin:10px 0 6px}input,select,textarea{width:100%;border:1px solid #cad5db;border-radius:4px;padding:9px;font:inherit;background:#fff}textarea{min-height:100px;resize:vertical}.inline{display:flex;gap:8px;align-items:center}.inline select{flex:1}.inline button{white-space:nowrap}.toolbar{display:flex;gap:5px;flex-wrap:wrap;padding:6px;background:#f1f4f6;border:1px solid #cad5db;border-bottom:0;border-radius:4px 4px 0 0}.toolbar button{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:3px;padding:6px 10px;cursor:pointer}.editor{min-height:250px;border:1px solid #cad5db;border-radius:0 0 4px 4px;padding:11px;background:#fff;outline:none;overflow:auto}.editor:empty:before{content:attr(data-placeholder);color:#9aa6b2}.check-row{display:flex;gap:16px;flex-wrap:wrap;margin:12px 0}.check-row label,.radio-row label{display:flex;align-items:center;gap:6px;margin:0;color:var(--ink)}.check-row input,.radio-row input{width:auto}.radio-row{display:flex;gap:18px;flex-wrap:wrap;padding:8px 0}.custom-time{display:none}.custom-time.show{display:block}.preview-box{background:#f5f6f7;min-height:620px;padding:16px}.preview-meta{text-align:center;color:var(--muted);line-height:1.7;min-height:70px}.preview{width:100%;height:510px;border:1px solid var(--line);background:#fff;border-radius:4px}.actions{display:flex;gap:10px;justify-content:flex-end;flex-wrap:wrap}.actions button,.primary{border:0;border-radius:4px;padding:9px 18px;background:var(--green);color:#fff;cursor:pointer}.actions button:hover,.primary:hover{background:var(--green-dark)}.secondary{background:#eef2f4!important;color:#52616d!important}.status{min-height:20px;color:var(--muted)}.ok{color:#087443}.error{color:#c43131}.test-row{display:grid;grid-template-columns:1fr auto;gap:8px}.test-row button{border:1px solid var(--line);background:#fff;border-radius:4px;padding:8px 13px;cursor:pointer;white-space:nowrap}.hint{color:var(--muted);font-size:12px;margin:6px 0}.hidden{display:none}@media(max-width:950px){.grid{grid-template-columns:1fr}.preview-box{min-height:0}.row,.sender{grid-template-columns:1fr}}@media(max-width:560px){main{padding:10px}.panel{padding:13px}.back{float:none;display:block;margin:7px 0 0}}
</style></head><body><header><p class="crumb">任务　/　添加任务</p><h1>添加任务</h1><a class="back" href="../">返回任务列表</a></header><main><div id="status" class="status"></div><div class="grid"><div><section class="panel"><h2>任务设置</h2><label>发件人</label><div class="sender"><select id="sender-domain"></select><select id="sender-box"></select></div><div class="row"><div><label>显示名称</label><input id="sender-name" placeholder="请输入显示名称"></div><div><label>主题</label><input id="subject" placeholder="请输入邮件主题"></div></div><label>收件人</label><div class="inline"><select id="group"><option value="">请选择收件人分组</option></select><button type="button" id="new-group" class="secondary">创建</button></div><div id="recipient-count" class="hint">发送邮件（0 收件人）</div><label>邮件模板</label><div class="inline"><select id="template"><option value="">请选择邮件模板</option></select><button type="button" id="new-template" class="secondary">创建</button></div><div class="check-row"><label><input id="warmup" type="checkbox">关联 IP 预热系统</label><label><input id="unsubscribe" type="checkbox" checked>退订链接</label><label><input id="track-open" type="checkbox" checked>打开统计</label><label><input id="track-click" type="checkbox" checked>点击统计</label></div><h3>线程数</h3><div class="radio-row"><label><input type="radio" name="threads" value="0" checked>自动</label><label><input type="radio" name="threads" value="5">自定义</label><input id="rate" type="number" min="0" max="6000" value="0" placeholder="每分钟上限，0不限速" style="max-width:180px"></div><label>邮件内容</label><div class="toolbar"><button type="button" data-cmd="bold"><b>B</b></button><button type="button" data-cmd="italic"><i>I</i></button><button type="button" data-cmd="underline"><u>U</u></button><button type="button" id="insert-link">插入链接</button><button type="button" id="insert-image">插入图片</button></div><div id="editor" class="editor" contenteditable="true" data-placeholder="请输入邮件正文"></div></section><section class="panel"><h2>发送设置</h2><h3>发送时间</h3><div class="radio-row"><label><input type="radio" name="send-time" value="now" checked>立即发送</label><label><input type="radio" name="send-time" value="later">选择日期时间</label></div><div id="custom-time" class="custom-time"><input id="send-at" type="datetime-local"></div><label>备注</label><input id="note" placeholder="请输入备注"><h3>测试邮件</h3><div class="test-row"><input id="test-email" type="email" placeholder="请输入测试邮箱"><button id="send-test" type="button">发送测试邮件</button></div><div id="test-status" class="hint"></div><div class="actions" style="margin-top:18px"><button id="cancel" type="button" class="secondary">返回</button><button id="confirm" type="button" class="primary">确认</button></div></section></div><section class="panel preview-box"><div class="preview-meta"><div>发件人：<span id="preview-from">--</span></div><div>收件人：<span id="preview-to">--</span></div><div>主题：<span id="preview-subject">--</span></div></div><iframe id="preview" class="preview" sandbox="allow-popups"></iframe></section></div></main><script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)],esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),apiRoot=location.pathname.replace(/\/marketing\/task\/?$/,'/');let boxes=[],groups=[],templates=[];
async function api(path,options){const r=await fetch(apiRoot+path,options);const j=await r.json().catch(()=>({error:r.statusText}));if(!r.ok)throw Error(j.error||r.statusText);return j}
function selectedSender(){return $('#sender-box').value||''}function selectedThreads(){return Number(($('input[name="threads"]:checked')||{}).value||0)}function updatePreview(){const sender=selectedSender(),body=$('#editor').innerHTML.trim();$('#preview-from').textContent=$('#sender-name').value?$('#sender-name').value+' <'+sender+'>':sender||'--';$('#preview-to').textContent=$('#group').selectedOptions[0]?.textContent||'--';$('#preview-subject').textContent=$('#subject').value||'--';MailViewer.preview($('#preview'),body)}
function populateSenders(){const domains=[...new Set(boxes.map(x=>x.split('@').slice(-1)[0]))].sort();$('#sender-domain').innerHTML=domains.map(x=>`<option value="${esc(x)}">${esc(x)}</option>`).join('');function change(){const d=$('#sender-domain').value;const filtered=boxes.filter(x=>x.endsWith('@'+d));$('#sender-box').innerHTML=filtered.map(x=>`<option value="${esc(x)}">${esc(x.split('@')[0])}</option>`).join('');updatePreview()}$('#sender-domain').onchange=change;$('#sender-box').onchange=updatePreview;change()}
async function loadData(){const [m,g,t]=await Promise.all([api('api/mailboxes'),api('api/marketing/groups'),api('api/marketing/templates')]);boxes=m.mailboxes;groups=g.groups;templates=t.templates;populateSenders();$('#group').innerHTML='<option value="">请选择收件人分组</option>'+groups.map(x=>`<option value="${x.id}">${esc(x.name)}（${x.active}）</option>`).join('');$('#template').innerHTML='<option value="">请选择邮件模板</option>'+templates.map(x=>`<option value="${x.id}">${esc(x.name)}</option>`).join('');$('#group').onchange=async()=>{const x=groups.find(v=>String(v.id)===$('#group').value);$('#recipient-count').textContent=x?`发送邮件（${x.active} 收件人）`:'发送邮件（0 收件人）';updatePreview()};$('#template').onchange=()=>{const x=templates.find(v=>String(v.id)===$('#template').value);if(x){$('#subject').value=x.subject;$('#editor').innerHTML=x.html_body||`<pre>${esc(x.text_body)}</pre>`;updatePreview()}}}
async function loadCopy(){const id=new URLSearchParams(location.search).get('copy');if(!id)return;const x=(await api('api/marketing/campaigns')).campaigns.find(v=>String(v.id)===id);if(!x)return;$('#sender-domain').value=x.sender.split('@').slice(-1)[0];$('#sender-domain').dispatchEvent(new Event('change'));$('#sender-box').value=x.sender;$('#sender-name').value=x.sender_name||'';$('#subject').value=x.subject;$('#group').value=x.group_id||'';$('#rate').value=x.rate_per_minute||0;$('#unsubscribe').checked=!!x.unsubscribe;$('#track-open').checked=!!x.track_open;$('#track-click').checked=!!x.track_click;$('#editor').innerHTML=x.html_body||`<pre>${esc(x.text_body)}</pre>`;$('#note').value=x.note||'';$('#recipient-count').textContent=x.total?`发送邮件（${x.total} 收件人）`:'发送邮件（0 收件人）';updatePreview()}
function payload(){const later=$('input[name="send-time"]:checked').value==='later';return {name:$('#subject').value||'营销任务',from:selectedSender(),sender_name:$('#sender-name').value,subject:$('#subject').value,group_id:$('#group').value||null,template_id:$('#template').value||null,html:$('#editor').innerHTML,text:$('#editor').innerText,unsubscribe:$('#unsubscribe').checked,warmup:$('#warmup').checked,track_open:$('#track-open').checked,track_click:$('#track-click').checked,threads:selectedThreads(),rate_per_minute:Number($('#rate').value||0),send_at:later&&$('#send-at').value?new Date($('#send-at').value).toISOString():'',public_url:location.origin+location.pathname.replace(/\/marketing\/task\/?$/,''),note:$('#note').value}}
$('#editor').oninput=updatePreview;['#sender-name','#subject'].forEach(id=>$(id).oninput=updatePreview);$$('[data-cmd]').forEach(b=>b.onclick=()=>{document.execCommand(b.dataset.cmd,false,null);updatePreview()});$('#insert-link').onclick=()=>{const u=prompt('请输入 https:// 链接');if(u&&/^https?:\/\//i.test(u))document.execCommand('createLink',false,u);updatePreview()};$('#insert-image').onclick=()=>{const u=prompt('请输入图片链接');if(u&&/^https?:\/\//i.test(u))document.execCommand('insertHTML',false,`<img src="${esc(u)}" alt="" style="max-width:100%">`);updatePreview()};$$('input[name="send-time"]').forEach(x=>x.onchange=()=>$('#custom-time').classList.toggle('show',x.value==='later'&&x.checked));
$('#new-group').onclick=async()=>{const name=prompt('请输入分组名称');if(!name)return;try{const j=await api('api/marketing/groups',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name})});await loadData();$('#group').value=j.id;$('#group').dispatchEvent(new Event('change'));}catch(e){$('#status').textContent=e.message;$('#status').className='error'}};$('#new-template').onclick=async()=>{const name=prompt('请输入模板名称');if(!name)return;try{const j=await api('api/marketing/templates',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name,subject:$('#subject').value,html:$('#editor').innerHTML,text:$('#editor').innerText})});await loadData();$('#template').value=j.id;$('#template').dispatchEvent(new Event('change'));}catch(e){$('#status').textContent=e.message;$('#status').className='error'}};
$('#send-test').onclick=async()=>{const to=$('#test-email').value.trim();if(!to){$('#test-status').textContent='请输入测试邮箱';return}try{const p=payload();p.to=to;p.group_id=null;p.template_id=null;const j=await api('api/send',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(p)});$('#test-status').textContent=j.sent?'测试邮件已发送':'测试邮件已提交';$('#test-status').className='hint ok'}catch(e){$('#test-status').textContent=e.message;$('#test-status').className='hint error'}};$('#cancel').onclick=()=>location.href='../';$('#confirm').onclick=async()=>{const b=$('#confirm');b.disabled=true;$('#status').textContent='正在保存任务...';try{const j=await api('api/marketing/campaigns',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload())});if($('input[name="send-time"]:checked').value==='now')await api('api/marketing/campaigns/'+j.id+'/action',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'start'})});location.href='../'}catch(e){$('#status').textContent=e.message;$('#status').className='error';b.disabled=false}};loadData().then(loadCopy).then(()=>{updatePreview();$('#status').textContent='已连接'}).catch(e=>{$('#status').textContent=e.message;$('#status').className='error'});
</script></body></html>"""


def parse_multipart_payload(content_type, body):
    envelope = (
        b"Content-Type: " + content_type.encode("utf-8", "replace")
        + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    message = BytesParser(policy=email.policy.default).parsebytes(envelope)
    if not message.is_multipart():
        raise ValueError("multipart 请求格式无效")
    payload = {}
    attachments = []
    for part in message.iter_parts():
        disposition = part.get("Content-Disposition", "")
        name = part.get_param("name", header="content-disposition")
        filename = part.get_filename()
        if not name:
            continue
        if filename:
            raw = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": decode_value(filename),
                "content_type": part.get_content_type(),
                "data_base64": base64.b64encode(raw).decode("ascii"),
            })
        else:
            value = part.get_content()
            if name in payload:
                payload[name] = f"{payload[name]},{value}"
            else:
                payload[name] = value
    if attachments:
        payload["attachments"] = attachments
    return payload


class Handler(BaseHTTPRequestHandler):
    server_version = "MailControl/1.0"

    def log_message(self, fmt, *args):
        return

    def authorized(self):
        trusted_user = self.headers.get("X-Remote-User", "").strip().lower()
        trusted_secret = self.headers.get("X-Mail-Control-Proxy-Secret", "")
        if (
            CONFIG.proxy_secret
            and trusted_secret
            and hmac.compare_digest(trusted_secret, CONFIG.proxy_secret)
        ):
            return is_global_admin(trusted_user)
        value = self.headers.get("Authorization", "")
        if not value.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(value[6:]).decode("utf-8")
            username, password = decoded.split(":", 1)
        except (ValueError, UnicodeError):
            return False
        return verify_mailu_admin(username, password)

    def require_auth(self):
        if self.authorized():
            return True
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="Mail Control"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def require_api_key(self):
        value = self.headers.get("X-API-Key", "") or self.headers.get("Authorization", "")
        if find_marketing_api_key(value):
            return True
        self.send_json({"error": "API 密钥无效、已停用或已过期"}, HTTPStatus.UNAUTHORIZED)
        return False

    def public_url(self):
        if CONFIG.public_url:
            return CONFIG.public_url
        proto = self.headers.get("X-Forwarded-Proto", "http").split(",", 1)[0].strip() or "http"
        host = self.headers.get("Host", "127.0.0.1").strip()
        prefix = self.headers.get("X-Forwarded-Prefix", "/mail-control").strip().rstrip("/") or "/mail-control"
        return f"{proto}://{host}{prefix}"

    def send_json(self, value, status=HTTPStatus.OK):
        self.send_content(json_bytes(value), "application/json; charset=utf-8", status)

    def send_content(self, body, content_type, status=HTTPStatus.OK, csp=None):
        compressed = False
        for item in self.headers.get("Accept-Encoding", "").lower().split(","):
            coding, *parameters = item.strip().split(";")
            if coding != "gzip":
                continue
            quality = next((p.strip()[2:] for p in parameters if p.strip().startswith("q=")), "1")
            try:
                if float(quality) > 0 and len(body) >= 1024:
                    body = gzip.compress(body, compresslevel=1)
                    compressed = True
            except ValueError:
                pass
            break
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Vary", "Accept-Encoding")
        if compressed:
            self.send_header("Content-Encoding", "gzip")
        if csp:
            self.send_header("Content-Security-Policy", csp)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_REQUEST:
            raise ValueError("请求体无效或过大")
        return self.rfile.read(length)

    def read_payload(self):
        content_type = self.headers.get("Content-Type", "application/json")
        body = self.read_body()
        if content_type.lower().startswith("application/json"):
            return json.loads(body.decode("utf-8"))
        if content_type.lower().startswith("multipart/form-data"):
            return parse_multipart_payload(content_type, body)
        raise ValueError("仅支持 application/json 或 multipart/form-data")

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/healthz":
            self.send_json({"ok": True, "service": "mail-control"})
            return
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path == "/track/open":
            try:
                if query.get("l", [""])[0]:
                    track_api_open(query.get("l", [""])[0])
                else:
                    track_open(query.get("c", [""])[0], query.get("r", [""])[0])
            except (ValueError, OSError, sqlite3.Error):
                pass
            pixel = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Content-Length", str(len(pixel)))
            self.end_headers()
            self.wfile.write(pixel)
            return
        if parsed.path == "/track/click":
            target = query.get("u", [""])[0]
            if urllib.parse.urlsplit(target).scheme.lower() not in {"http", "https"}:
                target = "/"
            try:
                if query.get("l", [""])[0]:
                    track_api_click(query.get("l", [""])[0])
                else:
                    track_click(query.get("c", [""])[0], query.get("r", [""])[0])
            except (ValueError, OSError, sqlite3.Error):
                pass
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", target)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # These fixed assets contain only theme code. The front proxy still requires
        # a signed-in Mailu user; all mail, settings and API routes retain their guards.
        def send_theme_asset(body, content_type):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "private, max-age=86400" if "v" in query else "private, max-age=300")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        if parsed.path.startswith("/ui/"):
            name = parsed.path[4:]
            if name in FLOW_UI_ASSETS:
                content_type = "text/css; charset=utf-8" if name.endswith(".css") else "application/javascript; charset=utf-8"
                body = FLOW_UI_ASSETS[name].encode("utf-8")
                # Assets are versioned by content digest, include no user data,
                # and remain behind the front proxy's existing login check.
                send_theme_asset(body, content_type)
            else:
                self.send_json({"error": "不存在的资源"}, HTTPStatus.NOT_FOUND)
            return
        if not self.require_auth():
            return
        try:
            if parsed.path == "/sidebar":
                fragment = '<style>' + FLOW_UI_ASSETS['flow-shell.css'] + '</style>' + flow_shell_markup(flow_shell_identity(self.headers), query.get('request_path', ['/admin/antispam/'])[0], '')
                self.send_content(fragment.encode('utf-8'), 'text/html; charset=utf-8')
            elif parsed.path == "/navigation.js":
                send_theme_asset(NAVIGATION_JS.encode("utf-8"), "application/javascript; charset=utf-8")
            elif parsed.path in {"/", "/index.html"}:
                body = html_bytes(HTML, query.get("embedded", ["0"])[0] == "1", username=flow_shell_identity(self.headers), request_path=parsed.path, request_query=parsed.query)
                self.send_content(body, "text/html; charset=utf-8", csp="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-src 'self' blob:")
            elif parsed.path in {"/custom-send", "/custom-send/"}:
                body = html_bytes(CUSTOM_SEND_HTML, query.get("embedded", ["0"])[0] == "1", username=flow_shell_identity(self.headers), request_path=parsed.path, request_query=parsed.query)
                self.send_content(body, "text/html; charset=utf-8", csp="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'")
            elif parsed.path in {"/global", "/global/"}:
                body = html_bytes(GLOBAL_HTML, query.get("embedded", ["0"])[0] == "1", username=flow_shell_identity(self.headers), request_path=parsed.path, request_query=parsed.query)
                self.send_content(body, "text/html; charset=utf-8", csp="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-src 'self' data: blob:")
            elif parsed.path in {"/api/body", "/api/attachment"}:
                mailbox = query.get("mailbox", [""])[0]
                path = (safe_message(mailbox, query["path"][0]) if query.get("path") else
                        global_message_path(mailbox, query.get("id", [""])[0], query.get("folder", [""])[0]))
                if parsed.path == "/api/body":
                    value = parse_message(path)
                    content = value["html"] or "<pre>" + html.escape(value["text"] or "(无正文)") + "</pre>"
                    document = ('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                                '<style>html,body{background:#fff;color:#17212b}body{margin:0;padding:16px;font:14px/1.65 system-ui,sans-serif;overflow-wrap:anywhere}'
                                'img,video{max-width:100%;height:auto}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{max-width:100%}</style></head><body>'
                                + content + '</body></html>')
                    self.send_content(document.encode("utf-8"), "text/html; charset=utf-8",
                                      csp="default-src 'none'; style-src 'self' 'unsafe-inline'; img-src data: https:; script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'; sandbox allow-same-origin allow-popups allow-popups-to-escape-sandbox")
                else:
                    part_index = int(query.get("part", ["-1"])[0])
                    message = BytesParser(policy=email.policy.default).parsebytes(path.read_bytes())
                    part = next((p for i,p in enumerate(message.walk()) if i == part_index), None)
                    if not part or not (part.get_content_disposition() == "attachment" or part.get_filename()):
                        raise ValueError("附件不存在")
                    data = part.get_payload(decode=True) or b""
                    filename = decode_value(part.get_filename() or "attachment")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + urllib.parse.quote(filename, safe=""))
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
            elif parsed.path == "/api/global/messages":
                self.send_json(list_global_messages(
                    mailbox=query.get("mailbox", [""])[0], domain=query.get("domain", [""])[0],
                    prefix=query.get("prefix", [""])[0], scope=query.get("scope", ["all"])[0],
                    folder=query.get("folder", [""])[0], query=query.get("q", [""])[0],
                    offset=max(0, int(query.get("offset", ["0"])[0])),
                    limit=min(100, max(1, int(query.get("limit", ["50"])[0])))))
            elif parsed.path == "/api/global/message":
                mailbox = query.get("mailbox", [""])[0]
                path = global_message_path(mailbox, query.get("id", [""])[0], query.get("folder", [""])[0])
                self.send_json({"mailbox": mailbox, "message": parse_message(path)})
            elif parsed.path == "/view":
                mailbox = query.get("mailbox", [""])[0]
                relative = query.get("path", [""])[0]
                safe_message(mailbox, relative)
                body = html_bytes(VIEW_HTML, query.get("embedded", ["0"])[0] == "1", username=flow_shell_identity(self.headers), request_path=parsed.path, request_query=parsed.query)
                self.send_content(body, "text/html; charset=utf-8", csp="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-src 'self' data: blob:")
            elif parsed.path in {"/accounts", "/accounts/"}:
                body = html_bytes(ACCOUNTS_HTML, query.get("embedded", ["0"])[0] == "1", username=flow_shell_identity(self.headers), request_path=parsed.path, request_query=parsed.query)
                self.send_content(body, "text/html; charset=utf-8", csp="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-src 'self' blob:")
            elif parsed.path in {"/marketing", "/marketing/"}:
                tab = query.get("tab", [""])[0]
                page = API_HTML if tab == "api" else MARKETING_HTML if tab in {"templates", "contacts"} else MARKETING_LIST_HTML
                body = html_bytes(page, query.get("embedded", ["0"])[0] == "1", username=flow_shell_identity(self.headers), request_path=parsed.path, request_query=parsed.query)
                self.send_content(body, "text/html; charset=utf-8", csp="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-src 'self' data: blob:")
            elif parsed.path in {"/marketing/task", "/marketing/task/"}:
                body = html_bytes(MARKETING_TASK_HTML, query.get("embedded", ["0"])[0] == "1", username=flow_shell_identity(self.headers), request_path=parsed.path, request_query=parsed.query)
                self.send_content(body, "text/html; charset=utf-8", csp="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-src 'self' data: blob:")
            elif parsed.path in {"/marketing/manage", "/marketing/manage/"}:
                page = API_HTML if query.get("tab", [""])[0] == "api" else MARKETING_HTML
                body = html_bytes(page, query.get("embedded", ["0"])[0] == "1", username=flow_shell_identity(self.headers), request_path=parsed.path, request_query=parsed.query)
                self.send_content(body, "text/html; charset=utf-8", csp="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-src 'self' data: blob:")
            elif parsed.path == "/api/status":
                self.send_json({"ok": True, "mailboxes": len(mailboxes())})
            elif parsed.path == "/api/mailboxes":
                self.send_json({"mailboxes": mailboxes()})
            elif parsed.path == "/api/domains":
                self.send_json({"domains": list_domains()})
            elif parsed.path == "/api/accounts":
                self.send_json({"domain": normalize_domain(query.get("domain", [""])[0]), "accounts": list_accounts(query.get("domain", [""])[0])})
            elif parsed.path == "/api/lists":
                self.send_json({"blacklist": read_map("blacklist"), "whitelist": read_map("whitelist")})
            elif parsed.path == "/api/marketing/summary":
                self.send_json(marketing_summary())
            elif parsed.path == "/api/marketing/groups":
                self.send_json({"groups": marketing_groups()})
            elif parsed.path == "/api/marketing/contacts":
                self.send_json({"contacts": marketing_contacts(query.get("group_id", [None])[0], query.get("q", [""])[0])})
            elif parsed.path == "/api/marketing/templates":
                self.send_json({"templates": marketing_templates()})
            elif parsed.path == "/api/marketing/campaigns":
                self.send_json({"campaigns": marketing_campaigns()})
            elif parsed.path.startswith("/api/marketing/campaigns/") and parsed.path.endswith("/logs"):
                campaign_id = parsed.path.split("/")[-2]
                self.send_json({"logs": marketing_campaign_logs(campaign_id)})
            elif parsed.path == "/api/marketing/api-keys":
                result = marketing_api_keys({
                    "page": query.get("page", ["1"])[0],
                    "page_size": query.get("page_size", ["10"])[0],
                    "keyword": query.get("keyword", [""])[0],
                    "active": query.get("active", ["-1"])[0],
                    "start_time": query.get("start_time", [""])[0],
                    "end_time": query.get("end_time", [""])[0],
                })
                self.send_json({"api_keys": result["list"], "total": result["total"], "page": result["page"], "page_size": result["page_size"]})
            elif parsed.path == "/api/marketing/api-overview":
                self.send_json(marketing_api_overview(query.get("start_time", [""])[0], query.get("end_time", [""])[0]))
            elif parsed.path == "/api/messages":
                mailbox = query.get("mailbox", [""])[0]
                scope = query.get("scope", ["new"])[0]
                if query.get("new_only", ["0"])[0] == "1":
                    scope = "new"
                if scope not in {"new", "all"}:
                    raise ValueError("邮件范围无效")
                folder = query.get("folder", [""])[0]
                search = query.get("q", [""])[0]
                offset = max(0, int(query.get("offset", ["0"])[0]))
                limit = min(100, max(1, int(query.get("limit", ["50"])[0])))
                listing = list_messages(mailbox, scope, folder, search, offset, limit)
                self.send_json({"mailbox": mailbox, "scope": scope, "offset": offset, "limit": limit, **listing})
            elif parsed.path == "/api/message":
                mailbox = query.get("mailbox", [""])[0]
                relative = query.get("path", [""])[0]
                self.send_json({"mailbox": mailbox, "path": relative, "message": parse_message(safe_message(mailbox, relative))})
            else:
                self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, OSError, sqlite3.Error) as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        api_endpoint = parsed.path in {"/api/v1/send", "/api/v1/batch-send"}
        if api_endpoint:
            if not self.require_api_key():
                return
        elif not self.require_auth():
            return
        try:
            payload = self.read_payload()
            if api_endpoint:
                api_value = self.headers.get("X-API-Key", "") or self.headers.get("Authorization", "")
                api_key = find_marketing_api_key(api_value)
                if not api_key:
                    raise ValueError("API 密钥无效")
                forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
                remote_ip = forwarded or self.headers.get("X-Real-IP", "").strip() or self.client_address[0]
                if not api_key_ip_allowed(api_key, remote_ip):
                    self.send_json({"error": "当前 IP 不在 API 白名单中"}, HTTPStatus.FORBIDDEN)
                    return
                self.send_json(send_api_message(payload, api_key, self.public_url()), HTTPStatus.OK)
            elif parsed.path == "/api/custom-send":
                self.send_json(custom_send_message(payload), HTTPStatus.OK)
            elif parsed.path == "/api/message/release":                self.send_json(release_message(payload.get("mailbox", ""), payload.get("path", "")), HTTPStatus.OK)
            elif parsed.path == "/api/lists":
                kind = payload.get("list")
                if kind not in CONFIG.list_files:
                    raise ValueError("名单类型无效")
                entry = normalize_entry(payload.get("entry"))
                entries = read_map(kind)
                if entry not in entries:
                    entries.append(entry)
                    write_map(kind, sorted(entries))
                    reload_rspamd()
                self.send_json({"ok": True, kind: read_map(kind)})
            elif parsed.path == "/api/send":
                self.send_json(send_message(payload), HTTPStatus.OK)
            elif parsed.path == "/api/accounts/batch-create":
                self.send_json(create_batch_accounts(payload), HTTPStatus.OK)
            elif parsed.path == "/api/marketing/groups":
                self.send_json(create_marketing_group(payload), HTTPStatus.CREATED)
            elif parsed.path == "/api/marketing/contacts/import":
                self.send_json(import_marketing_contacts(payload), HTTPStatus.OK)
            elif parsed.path == "/api/marketing/templates":
                self.send_json(save_marketing_template(payload), HTTPStatus.OK)
            elif parsed.path == "/api/marketing/campaigns":
                self.send_json(create_marketing_campaign(payload), HTTPStatus.CREATED)
            elif parsed.path.startswith("/api/marketing/campaigns/") and parsed.path.endswith("/action"):
                campaign_id = parsed.path.split("/")[-2]
                self.send_json(marketing_campaign_action(campaign_id, payload.get("action")), HTTPStatus.OK)
            elif parsed.path == "/api/marketing/api-keys":
                self.send_json(create_marketing_api_key(payload), HTTPStatus.CREATED)
            elif parsed.path.startswith("/api/marketing/api-keys/") and parsed.path.endswith("/test"):
                key_id = parsed.path.split("/")[-2]
                self.send_json(test_marketing_api_key(key_id, payload, self.public_url()), HTTPStatus.OK)
            elif parsed.path.startswith("/api/marketing/api-keys/"):
                payload["id"] = parsed.path.split("/")[-1]
                self.send_json(update_marketing_api_key(payload), HTTPStatus.OK)
            else:
                self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        except (ValueError, OSError, sqlite3.Error, smtplib.SMTPException, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def do_DELETE(self):
        if not self.require_auth():
            return
        try:
            payload = self.read_payload() if int(self.headers.get("Content-Length", "0")) > 0 else {}
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/api/global/messages":
                self.send_json(delete_global_messages(payload), HTTPStatus.OK)
                return
            if parsed.path == "/api/accounts/batch-delete":
                self.send_json(delete_batch_accounts(payload), HTTPStatus.OK)
                return
            if parsed.path == "/api/marketing/contacts":
                self.send_json(delete_marketing_contacts(payload), HTTPStatus.OK)
                return
            if parsed.path.startswith("/api/marketing/campaigns/"):
                self.send_json(delete_marketing_campaign(parsed.path.split("/")[-1]), HTTPStatus.OK)
                return
            if parsed.path.startswith("/api/marketing/templates/"):
                self.send_json(delete_marketing_template(parsed.path.split("/")[-1]), HTTPStatus.OK)
                return
            if parsed.path.startswith("/api/marketing/api-keys/"):
                self.send_json(delete_marketing_api_key(parsed.path.split("/")[-1]), HTTPStatus.OK)
                return
            kind = payload.get("list")
            if kind not in CONFIG.list_files:
                raise ValueError("名单类型无效")
            entry = normalize_entry(payload.get("entry"))
            entries = [x for x in read_map(kind) if x != entry]
            write_map(kind, entries)
            reload_rspamd()
            self.send_json({"ok": True, kind: entries})
        except (ValueError, OSError, sqlite3.Error, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def main():
    init_marketing_db()
    threading.Thread(target=marketing_scheduler, daemon=True, name="mail-marketing-scheduler").start()
    server = ThreadingHTTPServer((CONFIG.bind, CONFIG.port), Handler)
    try:
        server.serve_forever()
    finally:
        CAMPAIGN_STOP.set()
        server.server_close()


if __name__ == "__main__":
    main()
