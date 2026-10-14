#!/usr/bin/env python3
"""Read-only Postfix socketmap for an existing user's domain catch-all copy.

The service deliberately sits in front of Mailu's native ``podop:alias`` map.
It only returns a value for ``domaincopy <address>`` when the recipient resolves
to an existing Mailu user and that user's domain has the exact ``%`` wildcard
alias.  The original recipient is always retained, so LMTP and Dovecot Sieve
(including vacation replies) continue to process the mailbox.

No database writes are performed.  Each request opens SQLite in ``mode=ro`` so
changes made by Mailu become visible without a synchronisation job.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import re
import signal
import socket
import socketserver
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, Tuple


LOG = logging.getLogger("mailu-domain-copy")
DEFAULT_SOCKET = "/opt/mailu/data/overrides/postfix/mailu-domain-copy.sock"
MAX_QUERY = 10000
MAX_REPLY = 100000
MAX_NETSTRING = MAX_REPLY + 32
EMAIL_RE = re.compile(r"^([A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+)@([^@\s,<>]+)$")
MAP_NAME = "domaincopy"


class TemporaryLookupError(RuntimeError):
    """The map cannot safely answer and Postfix should retry."""


class ProtocolError(ValueError):
    """Malformed or oversized socketmap netstring."""


def _parse_address(value: str) -> Optional[Tuple[str, str]]:
    match = EMAIL_RE.fullmatch(value)
    if not match:
        return None
    local, domain = match.groups()
    if len(local) > 64 or local.startswith(".") or local.endswith(".") or ".." in local:
        return None
    try:
        domain = domain.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(domain) > 253 or "." not in domain or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")):
        return None
    return local.lower(), domain


def _split_destinations(value: object) -> List[str]:
    """Mailu stores CommaSeparatedList as comma separated text."""
    if value is None:
        return []
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _canonical(value: str) -> Optional[str]:
    parsed = _parse_address(value)
    if not parsed:
        return None
    local, domain = parsed
    return local + "@" + domain


@dataclass(frozen=True)
class UserRule:
    email: str
    enabled: bool
    forward_enabled: bool
    destinations: Tuple[str, ...]


class DomainCopyLookup:
    """A small, schema-tolerant read-only resolver for Mailu's SQLite DB."""

    def __init__(self, db_path: str, recipient_delimiter: str = "+"):
        self.db_path = str(db_path)
        self.recipient_delimiter = recipient_delimiter
        self._uri = Path(self.db_path).resolve().as_uri() + "?mode=ro"

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self._uri, uri=True, timeout=2.0)
            connection.row_factory = sqlite3.Row
            return connection
        except (OSError, sqlite3.Error) as exc:
            raise TemporaryLookupError("database unavailable") from exc

    @staticmethod
    def _columns(connection: sqlite3.Connection, table: str) -> Set[str]:
        try:
            return {row[1] for row in connection.execute("PRAGMA table_info(%s)" % table)}
        except sqlite3.Error as exc:
            raise TemporaryLookupError("database schema unavailable") from exc

    def _user(self, connection: sqlite3.Connection, email: str) -> Optional[UserRule]:
        columns = self._columns(connection, "user")
        required = {"email", "enabled", "forward_enabled", "forward_destination"}
        if not required.issubset(columns):
            raise TemporaryLookupError("user schema unavailable")
        selected = ["email", "enabled", "forward_enabled", "forward_destination"]
        try:
            row = connection.execute(
                "SELECT %s FROM user WHERE lower(email)=lower(?) LIMIT 1" % ",".join(selected),
                (email,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise TemporaryLookupError("user lookup failed") from exc
        if row is None:
            return None
        values = dict(row)
        return UserRule(
            email=str(values["email"]),
            enabled=bool(values.get("enabled", 1)),
            forward_enabled=bool(values.get("forward_enabled", 0)),
            destinations=tuple(_split_destinations(values.get("forward_destination"))),
        )

    def _wildcard(self, connection: sqlite3.Connection, domain: str) -> Tuple[str, ...]:
        """Return only the exact '%' alias on the canonical domain."""
        columns = self._columns(connection, "alias")
        required = {"email", "localpart", "domain_name", "wildcard", "destination"}
        if not required.issubset(columns):
            raise TemporaryLookupError("alias schema unavailable")
        # Mailu's Alias email is lowercased by IdnaEmail; lower() also handles
        # old databases without requiring a schema migration.
        try:
            rows = connection.execute(
                "SELECT destination FROM alias WHERE lower(domain_name)=? AND localpart='%' AND wildcard=1",
                (domain,),
            ).fetchall()
        except sqlite3.Error as exc:
            raise TemporaryLookupError("alias lookup failed") from exc
        result: List[str] = []
        for row in rows:
            result.extend(_split_destinations(row[0]))
        return tuple(result)

    def _resolve_user(self, connection: sqlite3.Connection, local: str, domain: str) -> Optional[UserRule]:
        direct = self._user(connection, local + "@" + domain)
        if direct:
            return direct
        # This mirrors Mailu's resolve_destination() for recipient delimiters:
        # a plus-tag has the base user as its source while retaining the exact
        # envelope recipient in the returned local copy destination.
        positions = [local.find(delimiter) for delimiter in self.recipient_delimiter if local.find(delimiter) >= 0]
        if not positions:
            return None
        base = local[:min(positions)]
        return self._user(connection, base + "@" + domain)

    def _resolve_domain(self, connection: sqlite3.Connection, domain: str) -> str:
        columns = self._columns(connection, "alternative")
        if not columns:
            raise TemporaryLookupError("alternative schema unavailable")
        if not {"name", "domain_name"}.issubset(columns):
            raise TemporaryLookupError("alternative schema unavailable")
        row = connection.execute("SELECT domain_name FROM alternative WHERE lower(name)=?", (domain,)).fetchone()
        return str(row[0]).lower() if row else domain

    def _stripped(self, local: str) -> Optional[str]:
        positions = [local.find(char) for char in self.recipient_delimiter if char in local]
        return local[:min(positions)] if positions else None

    def _alias(self, connection: sqlite3.Connection, local: Optional[str], domain: str):
        if local is None:
            return None
        columns = self._columns(connection, "alias")
        if not {"email", "localpart", "domain_name", "wildcard", "destination"}.issubset(columns):
            raise TemporaryLookupError("alias schema unavailable")
        # SQLite LIKE implements Mailu's % / _ SQL wildcard semantics. Mailu
        # orders precise aliases first, then the longest matching pattern.
        return connection.execute(
            "SELECT wildcard,destination FROM alias WHERE lower(domain_name)=? AND "
            "((wildcard=0 AND lower(localpart)=?) OR (wildcard=1 AND ? LIKE lower(localpart))) "
            "ORDER BY wildcard,length(localpart) DESC LIMIT 1", (domain, local, local)
        ).fetchone()

    def _owner(self, connection: sqlite3.Connection, address: str) -> str:
        local, domain = _parse_address(address)
        domain = self._resolve_domain(connection, domain)
        user = self._resolve_user(connection, local, domain)
        return user.email.lower() if user else local + "@" + domain

    def _graph_edges(self, connection: sqlite3.Connection, address: str) -> Iterable[str]:
        parsed = _parse_address(address)
        if not parsed:
            return ()
        local, domain = parsed
        domain = self._resolve_domain(connection, domain)
        user = self._resolve_user(connection, local, domain)
        if user:
            edges = list(user.destinations) if user.forward_enabled else []
            # Include this new map's rule as well as native forwarding, so two
            # domains copying into each other cannot create a new cycle.
            edges.extend(self._wildcard(connection, domain))
            owner = user.email.lower()
            return tuple(item for item in edges if _canonical(item) and self._owner(connection, item) != owner)
        pure = self._alias(connection, local, domain)
        if pure and not pure["wildcard"]:
            return tuple(_split_destinations(pure["destination"]))
        stripped = self._alias(connection, self._stripped(local), domain)
        chosen = stripped or pure
        return tuple(_split_destinations(chosen["destination"])) if chosen else ()

    def _would_cycle(self, connection: sqlite3.Connection, source: str, candidate: str) -> bool:
        """Reject an extra destination whose local rules lead back to source."""
        source_owner = self._owner(connection, source)
        first = _canonical(candidate)
        if not first:
            return True
        visiting: Set[str] = set()
        visited: Set[str] = set()
        def visit(address: str, depth: int) -> bool:
            current = _canonical(address)
            if not current:
                return False
            if self._owner(connection, current) == source_owner or current in visiting:
                return True
            if current in visited:
                return False
            if depth >= 64 or len(visited) + len(visiting) >= 256:
                return True
            visiting.add(current)
            if any(visit(edge, depth + 1) for edge in self._graph_edges(connection, current)):
                return True
            visiting.remove(current)
            visited.add(current)
            return False
        return visit(first, 0)

    def lookup(self, recipient: str) -> Optional[str]:
        """Return comma-separated Postfix destinations, or ``None`` (NOTFOUND)."""
        parsed = _parse_address(recipient)
        if not parsed:
            return None
        local, domain = parsed
        connection = self._connect()
        try:
            deadline = time.monotonic() + 4.0
            connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            # One request is one read transaction; live Mailu changes appear
            # on the next query but cannot alter half of this graph traversal.
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            domain = self._resolve_domain(connection, domain)
            user = self._resolve_user(connection, local, domain)
            if not user:
                return None
            catchall = self._wildcard(connection, domain)
            if not catchall:
                return None
            source = local + "@" + domain
            output: List[str] = [source]
            candidates = list(user.destinations) if user.forward_enabled else []
            candidates.extend(catchall)
            for item in candidates:
                destination = _canonical(item)
                if not destination or destination == source:
                    continue
                if self._would_cycle(connection, source, destination):
                    LOG.warning("skipped cyclic local destination for domain copy")
                    continue
                if destination not in output:
                    output.append(destination)
            return ",".join(output)
        except sqlite3.Error as exc:
            raise TemporaryLookupError("database lookup failed") from exc
        finally:
            connection.close()


def encode_netstring(value: bytes) -> bytes:
    if len(value) > MAX_NETSTRING:
        raise ProtocolError("netstring too large")
    return str(len(value)).encode("ascii") + b":" + value + b","


def read_netstring(stream, maximum: int = MAX_NETSTRING) -> bytes:
    digits = bytearray()
    while len(digits) < 7:
        char = stream.recv(1)
        if not char:
            raise EOFError
        if char == b":":
            break
        if char < b"0" or char > b"9":
            raise ProtocolError("invalid netstring length")
        digits.extend(char)
    else:
        raise ProtocolError("invalid netstring length")
    if not digits or (len(digits) > 1 and digits[:1] == b"0"):
        raise ProtocolError("invalid netstring length")
    length = int(digits)
    if length > maximum:
        raise ProtocolError("netstring too large")
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(min(4096, length - len(data)))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    if stream.recv(1) != b",":
        raise ProtocolError("invalid netstring terminator")
    return bytes(data)


class SocketMapHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5.0)
        try:
            # Postfix caches connections and may issue several requests.
            for _ in range(1024):
                request = read_netstring(self.request, MAX_QUERY + len(MAP_NAME) + 2).decode("utf-8")
                name, separator, key = request.partition(" ")
                if not separator or name != MAP_NAME or not key:
                    reply = b"NOTFOUND "
                else:
                    try:
                        value = self.server.lookup.lookup(key)  # type: ignore[attr-defined]
                        reply = (b"NOTFOUND " if value is None else b"OK " + value.encode("utf-8"))
                    except TemporaryLookupError:
                        LOG.error("database unavailable; temporary lookup failure")
                        reply = b"TEMP database unavailable"
                    except Exception as exc:
                        LOG.error("lookup exception of type %s; temporary lookup failure", type(exc).__name__)
                        reply = b"TEMP lookup failure"
                if len(reply) > MAX_REPLY:
                    reply = b"TEMP reply too large"
                self.request.sendall(encode_netstring(reply))
        except EOFError:
            return
        except socket.timeout:
            return
        except (ProtocolError, UnicodeError):
            try:
                self.request.sendall(encode_netstring(b"PERM malformed request"))
            except OSError:
                pass
        except OSError:
            return


class BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(64)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try: request.sendall(encode_netstring(b"TEMP server busy"))
            except OSError: pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        LOG.error("request worker failed")


class ThreadingUnixServer(BoundedThreads, getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)):
    allow_reuse_address = True


class ThreadingTCPServer(BoundedThreads, socketserver.TCPServer):
    allow_reuse_address = True


def prepare_socket(socket_path: Path) -> None:
    """Remove only a stale socket; never overwrite an active listener/file."""
    try:
        existing = socket_path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(existing.st_mode):
        raise RuntimeError("socket path exists and is not a socket")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.settimeout(1.0)
        probe.connect(str(socket_path))
    except ConnectionRefusedError:
        current = socket_path.lstat()
        if (current.st_dev, current.st_ino) != (existing.st_dev, existing.st_ino) or not stat.S_ISSOCK(current.st_mode):
            raise RuntimeError("socket path changed during stale-socket check")
        socket_path.unlink()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise RuntimeError("cannot prove existing socket is stale") from exc
    else:
        raise RuntimeError("socket is already served by a running process")
    finally:
        probe.close()


def _allowed_peer(request: socket.socket, allowlist: Sequence[str]) -> bool:
    if not allowlist:
        return False
    try:
        peer = ipaddress.ip_address(request.getpeername()[0])
        return any(peer in ipaddress.ip_network(item, strict=False) for item in allowlist)
    except (ValueError, OSError, IndexError):
        return False


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", default=os.environ.get("MAILU_COPY_DB", os.environ.get("MAIL_CONTROL_DB", "/opt/mailu/data/data/main.db")))
    parser.add_argument("--socket", default=os.environ.get("MAILU_COPY_SOCKET", DEFAULT_SOCKET))
    parser.add_argument("--bind", default=os.environ.get("MAILU_COPY_BIND", ""))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MAILU_COPY_PORT", "18081")))
    args = parser.parse_args(argv)
    logging.basicConfig(level=os.environ.get("MAILU_COPY_LOG_LEVEL", "INFO"), format="%(levelname)s mailu-domain-copy: %(message)s")
    allow = [item.strip() for item in os.environ.get("MAILU_COPY_ALLOW", "").split(",") if item.strip()]
    if args.bind:
        if not allow:
            raise SystemExit("MAILU_COPY_ALLOW is required for TCP mode")
        try:
            for item in allow: ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise SystemExit("MAILU_COPY_ALLOW must contain IP addresses or CIDRs")
    lookup = DomainCopyLookup(args.db, os.environ.get("RECIPIENT_DELIMITER", "+"))
    servers = []
    socket_path = Path(args.socket)
    owned_socket = None
    if args.socket:
        if not hasattr(socket, "AF_UNIX"):
            raise SystemExit("UNIX mode requires a platform with AF_UNIX")
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        prepare_socket(socket_path)
        server = ThreadingUnixServer(str(socket_path), SocketMapHandler)
        server.lookup = lookup  # type: ignore[attr-defined]
        os.chmod(args.socket, 0o666)
        owned_socket = socket_path.lstat()
        servers.append(server)
    if args.bind:
        class AllowedHandler(SocketMapHandler):
            def handle(self):
                if not _allowed_peer(self.request, allow):
                    try: self.request.sendall(encode_netstring(b"PERM peer not allowed"))
                    except OSError: pass
                    return
                super().handle()
        tcp = ThreadingTCPServer((args.bind, args.port), AllowedHandler)
        tcp.lookup = lookup  # type: ignore[attr-defined]
        servers.append(tcp)
    if not servers:
        raise SystemExit("UNIX socket is disabled only when --socket is empty")
    stopping = threading.Event()
    def stop(_signum, _frame):
        if stopping.is_set(): return
        stopping.set()
        for server in servers: server.shutdown()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    threads = [threading.Thread(target=server.serve_forever, name="domain-copy", daemon=True) for server in servers]
    for thread in threads: thread.start()
    try:
        stopping.wait()
    finally:
        for server in servers: server.server_close()
        try:
            if args.socket and owned_socket:
                current = socket_path.lstat()
                if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == (owned_socket.st_dev, owned_socket.st_ino):
                    socket_path.unlink()
        except OSError: pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
