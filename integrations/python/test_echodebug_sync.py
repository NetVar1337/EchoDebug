"""Tests for the shared sync client core against a fake relay (stdlib only).

Run: python3 -m unittest discover -s integrations/python -v
"""

import json
import os
import socket
import struct
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import echodebug_sync as core  # noqa: E402


def server_frame(op, payload):
    """An unmasked server-to-client frame."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    n = len(payload)
    if n < 126:
        head = bytes([0x80 | op, n])
    elif n < 1 << 16:
        head = bytes([0x80 | op, 126]) + struct.pack("!H", n)
    else:
        head = bytes([0x80 | op, 127]) + struct.pack("!Q", n)
    return head + payload


class FakeRelay:
    """Accepts one WebSocket client on /sync, checks the token, records its frames."""

    def __init__(self, token="tok"):
        self.token = token
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.frames = []
        self.conn = None
        self.got = threading.Condition()
        self.auth_header = None
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            req = b""
            while b"\r\n\r\n" not in req:
                req += c.recv(4096)
            lines = req.decode("latin-1").split("\r\n")
            hdrs = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:] if l)}
            self.auth_header = hdrs.get("authorization")
            if lines[0].split(" ")[1] != "/sync" or hdrs.get("authorization") != "Bearer " + self.token:
                c.sendall(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                c.close()
                continue
            acc = core.accept_key(hdrs["sec-websocket-key"])
            c.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n" % acc).encode())
            self.conn = c
            parser = core.FrameParser()
            while True:
                try:
                    data = c.recv(65536)
                except OSError:
                    break
                if not data:
                    break
                for op, payload in parser.feed(data):
                    if op == core.OP_TEXT:
                        msg = json.loads(payload.decode())
                        with self.got:
                            self.frames.append(msg)
                            self.got.notify_all()
                        if msg.get("type") == "hello":
                            self.send({"type": "hello_result", "success": True, "peer": 1, "protocol": 1, "directions": {"cursor_in": True}})

    def send(self, msg):
        self.conn.sendall(server_frame(core.OP_TEXT, json.dumps(msg)))

    def wait(self, pred, timeout=5.0):
        end = time.time() + timeout
        with self.got:
            while True:
                for f in self.frames:
                    if pred(f):
                        return f
                left = end - time.time()
                if left <= 0:
                    raise AssertionError("no matching frame in %r" % self.frames)
                self.got.wait(left)

    def close(self):
        self.srv.close()
        if self.conn:
            self.conn.close()


class Host:
    """Records what the session asks the 'disassembler' to do."""

    def __init__(self):
        self.calls = []
        self.ev = threading.Event()

    def on_cursor(self, ea):
        self.calls.append(("cursor", ea))
        self.ev.set()

    def on_name(self, ea, name):
        self.calls.append(("name", ea, name))
        self.ev.set()

    def on_comment(self, ea, text):
        self.calls.append(("comment", ea, text))
        self.ev.set()

    def on_types(self, decls, names):
        self.calls.append(("types", decls, tuple(names)))
        self.ev.set()

    def wait(self, n, timeout=5.0):
        end = time.time() + timeout
        while len(self.calls) < n and time.time() < end:
            self.ev.wait(0.05)
            self.ev.clear()
        return self.calls


class FramingTests(unittest.TestCase):
    def test_round_trip_all_lengths(self):
        for n in (0, 5, 125, 126, 1000, 65535, 65536, 70000):
            payload = bytes(i & 0xFF for i in range(n))
            frame = core.encode_frame(core.OP_BINARY, payload, mask=b"\x01\x02\x03\x04")
            self.assertTrue(frame[1] & 0x80, "client frames are masked")
            p = core.FrameParser()
            # byte by byte for a small one, in two halves for large ones
            out = []
            if n < 200:
                for b in frame:
                    out += p.feed(bytes([b]))
            else:
                out += p.feed(frame[: len(frame) // 2])
                out += p.feed(frame[len(frame) // 2:])
            self.assertEqual(out, [(core.OP_BINARY, payload)])

    def test_fragments_and_control_frames(self):
        p = core.FrameParser()
        frames = core.encode_frame(core.OP_TEXT, "hel", fin=False) + core.encode_frame(core.OP_PING, b"x") + core.encode_frame(core.OP_CONT, "lo")
        self.assertEqual(p.feed(frames), [(core.OP_PING, b"x"), (core.OP_TEXT, b"hello")])

    def test_accept_key_rfc_example(self):
        self.assertEqual(core.accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")


class MapperTests(unittest.TestCase):
    def test_rebase(self):
        base = [0x140000000]
        m = core.Mapper("game.exe", lambda: base[0], size=0x10000)
        self.assertEqual(m.to_rva(0x140001234), 0x1234)
        self.assertIsNone(m.to_rva(0x13FFFFFFF))
        self.assertIsNone(m.to_rva(0x140010000))
        self.assertEqual(m.to_ea("GAME.EXE", "0x1234"), 0x140001234)
        self.assertIsNone(m.to_ea("other.dll", "0x1234"))
        base[0] = 0x7FF600000000  # the user rebased the database
        self.assertEqual(m.to_ea("game.exe", "0x1234"), 0x7FF600001234)
        self.assertEqual(m.to_rva(0x7FF600001234), 0x1234)
        self.assertIsNone(core.parse_rva("zz"))
        self.assertEqual(core.parse_rva(16), 16)

    def test_config_dir_and_token(self):
        old = dict(os.environ)
        try:
            os.environ["ECHODEBUG_TOKEN"] = " abc "
            self.assertEqual(core.load_token(), "abc")
            del os.environ["ECHODEBUG_TOKEN"]
            os.environ["XDG_CONFIG_HOME"] = "/nonexistent-echodebug"
            if os.name != "nt":
                self.assertEqual(core.config_dir(), "/nonexistent-echodebug/EchoDebug")
                self.assertIsNone(core.load_token())
            os.environ["ECHODEBUG_PORT"] = "5000"
            self.assertEqual(core.relay_port(), 5000)
        finally:
            os.environ.clear()
            os.environ.update(old)


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.relay = FakeRelay()
        self.host = Host()
        self.base = [0x140000000]
        mapper = core.Mapper("game.exe", lambda: self.base[0], size=0x100000)
        self.logs = []
        self.s = core.SyncSession("ida", "9.1", mapper, self.host, post=lambda fn: fn(), log=self.logs.append, file="game.i64", port=self.relay.port, token="tok")
        self.s.start()
        hello = self.relay.wait(lambda f: f["type"] == "hello")
        self.assertEqual(hello["modules"][0], {"name": "game.exe", "base": "0x140000000", "size": 0x100000})
        self.assertEqual(self.relay.auth_header, "Bearer tok")
        end = time.time() + 5
        while not self.s.connected and time.time() < end:
            time.sleep(0.01)
        self.assertTrue(self.s.connected)

    def tearDown(self):
        self.s.stop()
        self.relay.close()

    def test_incoming_changes_are_applied_and_not_echoed(self):
        self.relay.send({"type": "cursor", "module": "game.exe", "rva": "0x10"})
        self.relay.send({"type": "name", "module": "game.exe", "rva": "0x20", "name": "decrypt"})
        self.relay.send({"type": "comment", "module": "game.exe", "rva": "0x20", "comment": "a\nb"})
        self.relay.send({"type": "cursor", "module": "other.dll", "rva": "0x10"})  # not ours: ignored
        self.relay.send({"type": "types", "decls": "struct A { int x; };", "names": ["A"]})
        calls = self.host.wait(4)
        self.assertEqual(calls, [("cursor", 0x140000010), ("name", 0x140000020, "decrypt"), ("comment", 0x140000020, "a\nb"), ("types", "struct A { int x; };", ("A",))])
        # the host's hooks report the same values back: nothing is sent
        self.assertFalse(self.s.send_cursor(0x140000010))
        self.assertFalse(self.s.send_name(0x140000020, "decrypt"))
        # a real change goes out
        self.assertTrue(self.s.send_name(0x140000020, "decrypt_v2"))
        f = self.relay.wait(lambda f: f["type"] == "name")
        self.assertEqual(f, {"type": "name", "module": "game.exe", "rva": "0x20", "name": "decrypt_v2"})
        self.assertTrue(self.s.send_cursor(0x140000030))
        self.assertEqual(self.relay.wait(lambda f: f["type"] == "cursor")["rva"], "0x30")
        self.assertTrue(self.s.send_comment(0x140000040, ""))
        self.assertFalse(self.s.send_cursor(0x1000), "outside the image")

    def test_hooks_fired_while_applying_are_ignored(self):
        sent = []

        class Echoing(Host):
            def on_name(inner, ea, name):  # noqa: N805
                # IDB_Hooks.renamed fires synchronously inside set_name
                sent.append(self.s.send_name(ea, name + "_hook"))
                Host.on_name(inner, ea, name)

        self.s.handlers = Echoing()
        self.relay.send({"type": "name", "module": "game.exe", "rva": "0x50", "name": "x"})
        self.s.handlers.wait(1)
        self.assertEqual(sent, [False])

    def test_host_errors_do_not_kill_the_session(self):
        class Broken(Host):
            def on_cursor(inner, ea):  # noqa: N805
                raise RuntimeError("no view")

        self.s.handlers = Broken()
        self.relay.send({"type": "cursor", "module": "game.exe", "rva": "0x60"})
        self.relay.send({"type": "name", "module": "game.exe", "rva": "0x60", "name": "ok"})
        self.assertEqual(self.s.handlers.wait(1), [("name", 0x140000060, "ok")])
        self.assertTrue(any("failed" in l for l in self.logs), self.logs)


class AuthTests(unittest.TestCase):
    def test_wrong_token_is_reported(self):
        relay = FakeRelay(token="right")
        try:
            ws = core.WebSocket("127.0.0.1", relay.port, "/sync", {"Authorization": "Bearer wrong"})
            with self.assertRaises(PermissionError):
                ws.connect()
        finally:
            relay.close()


if __name__ == "__main__":
    unittest.main()
