"""Isolated SQLite and socketmap regression tests; never contact a mail server."""

import importlib.util
import pathlib
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest


SPEC = importlib.util.spec_from_file_location("mailu_domain_copy", pathlib.Path(__file__).parent / "tools/mailu_domain_copy.py")
copy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = copy
SPEC.loader.exec_module(copy)


class DomainCopyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db = pathlib.Path(self.temp.name) / "main.db"
        self.write("CREATE TABLE user(email TEXT PRIMARY KEY,enabled INTEGER,forward_enabled INTEGER,forward_destination TEXT)")
        self.write("CREATE TABLE alias(email TEXT PRIMARY KEY,localpart TEXT,domain_name TEXT,wildcard INTEGER,destination TEXT)")
        self.write("CREATE TABLE alternative(name TEXT PRIMARY KEY,domain_name TEXT)")
        self.user("source@one.example")
        self.user("target@two.example")
        self.alias("%@one.example", "target@two.example", True)
        self.lookup = copy.DomainCopyLookup(str(self.db))

    def tearDown(self):
        self.temp.cleanup()

    def write(self, sql, params=()):
        connection = sqlite3.connect(str(self.db))
        try:
            connection.execute(sql, params)
            connection.commit()
        finally:
            connection.close()

    def user(self, address, forward="", enabled=True, forwarding=None):
        self.write("INSERT OR REPLACE INTO user VALUES(?,?,?,?)", (address, int(enabled), int(bool(forward) if forwarding is None else forwarding), forward))

    def alias(self, address, destination, wildcard=False):
        local, domain = address.rsplit("@", 1)
        self.write("INSERT OR REPLACE INTO alias VALUES(?,?,?,?,?)", (address, local, domain, int(wildcard), destination))

    def test_01_existing_user_gets_one_local_and_one_domain_copy(self):
        self.assertEqual(self.lookup.lookup("source@one.example"), "source@one.example,target@two.example")

    def test_02_unknown_user_exact_alias_other_pattern_and_disabled_user_still_has_mailbox(self):
        self.alias("alias@one.example", "target@two.example")
        self.user("disabled@one.example", enabled=False)
        self.user("third@three.example")
        self.alias("prefix%@three.example", "target@two.example", True)
        for address in ("unknown@one.example", "alias@one.example", "third@three.example", "bad address", "@one.example"):
            with self.subTest(address=address): self.assertIsNone(self.lookup.lookup(address))
        self.assertEqual(self.lookup.lookup("disabled@one.example"), "disabled@one.example,target@two.example")

    def test_03_forwarding_enabled_order_deduplication_and_invalid_self(self):
        self.user("source@one.example", "first@outside.example,target@two.example,source@one.example,invalid")
        self.alias("%@one.example", "target@two.example,last@outside.example,first@outside.example", True)
        self.assertEqual(self.lookup.lookup("source@one.example"), "source@one.example,first@outside.example,target@two.example,last@outside.example")
        self.user("source@one.example", "first@outside.example", forwarding=False)
        self.assertNotIn("first@outside.example", self.lookup.lookup("source@one.example").split(",")[:2])

    def test_04_delimiters_exact_tagged_user_and_alternative_domain(self):
        self.assertEqual(self.lookup.lookup("source+tag@one.example"), "source+tag@one.example,target@two.example")
        self.user("source+tag@one.example", "tagged@outside.example")
        self.assertEqual(self.lookup.lookup("source+tag@one.example"), "source+tag@one.example,tagged@outside.example,target@two.example")
        self.assertEqual(copy.DomainCopyLookup(str(self.db), "-").lookup("source-tag@one.example"), "source-tag@one.example,target@two.example")
        self.assertIsNone(copy.DomainCopyLookup(str(self.db), "").lookup("source+unknown@one.example"))
        self.write("INSERT INTO alternative VALUES('alternate.example','one.example')")
        self.assertEqual(self.lookup.lookup("source@alternate.example"), "source@one.example,target@two.example")

    def test_05_each_query_observes_live_alias_and_new_user_changes(self):
        self.alias("%@one.example", "next@outside.example", True)
        self.assertEqual(self.lookup.lookup("source@one.example"), "source@one.example,next@outside.example")
        self.assertIsNone(self.lookup.lookup("new@one.example"))
        self.user("new@one.example")
        self.assertEqual(self.lookup.lookup("new@one.example"), "new@one.example,next@outside.example")

    def test_06_reverse_forward_through_precise_alias_is_rejected(self):
        self.user("target@two.example", "bridge@three.example")
        self.alias("bridge@three.example", "source+return@one.example")
        self.assertEqual(self.lookup.lookup("source@one.example"), "source@one.example")

    def test_07_native_wildcard_specificity_and_tagged_alias_graph(self):
        self.alias("%@one.example", "wanted+tag@three.example", True)
        self.alias("%@three.example", "source@one.example", True)
        self.alias("wanted@three.example", "safe@outside.example")
        self.assertIn("wanted+tag@three.example", self.lookup.lookup("source@one.example"))
        self.alias("wanted@three.example", "source@one.example")
        self.assertEqual(self.lookup.lookup("source@one.example"), "source@one.example")

    def test_08_domain_copy_reverse_rule_and_independent_local_cycle(self):
        self.alias("%@two.example", "source@one.example", True)
        self.assertEqual(self.lookup.lookup("source@one.example"), "source@one.example")
        self.write("DELETE FROM alias WHERE email='%@two.example'")
        self.user("target@two.example", "a@three.example")
        self.alias("a@three.example", "b@three.example")
        self.alias("b@three.example", "a@three.example")
        self.assertEqual(self.lookup.lookup("source@one.example"), "source@one.example")

    def test_09_database_is_read_only_and_missing_schema_is_temporary(self):
        before = self.db.read_bytes()
        self.lookup.lookup("source@one.example")
        self.assertEqual(before, self.db.read_bytes())
        connection = self.lookup._connect()
        try:
            with self.assertRaises(sqlite3.OperationalError): connection.execute("UPDATE user SET enabled=0")
        finally: connection.close()
        self.write("DROP TABLE alias")
        with self.assertRaises(copy.TemporaryLookupError): self.lookup.lookup("source@one.example")
        with self.assertRaises(copy.TemporaryLookupError): copy.DomainCopyLookup(str(self.db.parent / "missing.db")).lookup("source@one.example")

    def start_server(self):
        server = copy.ThreadingTCPServer(("127.0.0.1", 0), copy.SocketMapHandler)
        server.lookup = self.lookup
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return socket.create_connection(server.server_address, timeout=2)

    def test_10_socketmap_persistent_requests_name_scope_and_temp_reply(self):
        with self.start_server() as client:
            for request, expected in ((b"domaincopy source@one.example", b"OK source@one.example,target@two.example"), (b"other source@one.example", b"NOTFOUND "), (b"domaincopy unknown@one.example", b"NOTFOUND ")):
                client.sendall(copy.encode_netstring(request))
                self.assertEqual(copy.read_netstring(client), expected)
            self.write("DROP TABLE alias")
            client.sendall(copy.encode_netstring(b"domaincopy source@one.example"))
            self.assertTrue(copy.read_netstring(client).startswith(b"TEMP "))

    def test_11_netstring_fragmentation_utf8_length_and_invalid_limits(self):
        class Stream:
            def __init__(self, value): self.value = bytearray(value)
            def recv(self, n):
                value = bytes(self.value[:min(n, 1)])
                del self.value[:len(value)]
                return value
        self.assertEqual(copy.read_netstring(Stream(copy.encode_netstring("测试".encode()))), "测试".encode())
        for payload in (b"01:x,", b"x:y,", b"2:x,", b"1:x!", b"10001:"):
            with self.subTest(payload=payload):
                with self.assertRaises((copy.ProtocolError, EOFError)): copy.read_netstring(Stream(payload), maximum=10000)
        with self.start_server() as client:
            client.sendall(b"10099:")
            self.assertTrue(copy.read_netstring(client).startswith(b"PERM "))

    def test_12_peer_allowlist_and_existing_file_socket_guard(self):
        class Peer:
            def getpeername(self): return ("172.20.0.7", 11111)
        self.assertTrue(copy._allowed_peer(Peer(), ["172.20.0.7/32"]))
        self.assertFalse(copy._allowed_peer(Peer(), []))
        self.assertFalse(copy._allowed_peer(Peer(), ["172.20.0.8/32"]))
        guard = pathlib.Path(self.temp.name) / "socket-file"
        guard.write_text("preserve")
        with self.assertRaises(RuntimeError): copy.prepare_socket(guard)
        self.assertEqual(guard.read_text(), "preserve")
        if hasattr(socket, "AF_UNIX"):
            guard.unlink()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(str(guard)); listener.listen()
                with self.assertRaises(RuntimeError): copy.prepare_socket(guard)
                self.assertTrue(guard.exists())
            finally: listener.close()
            copy.prepare_socket(guard)
            self.assertFalse(guard.exists())


if __name__ == "__main__": unittest.main()
