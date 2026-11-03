"""EchoDebug sync client core, shared by the IDA and Binary Ninja plugins.

Standard library only (IDA and Binary Ninja ship Python 3 without a WebSocket package): a small
RFC 6455 client, the relay token lookup, module + RVA mapping and a reconnecting session that
speaks the relay's `/sync` protocol (see integrations/README.md and PROTOCOL.md).

Thread model: one background thread per session reads frames and keeps the connection alive.
Every frame from the relay is handed to `post(fn)`, which the host implements to run `fn` on its
main thread (IDA: ida_kernwin.execute_sync, Binary Ninja: mainthread.execute_on_main_thread).
`send_*` may be called from any thread.
"""

import base64
import contextlib
import hashlib
import json
import os
import socket
import struct
import threading
import time

PROTOCOL = 1
DEFAULT_PORT = 47110
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PING_SECONDS = 15.0


# ---- configuration ------------------------------------------------------------------------------

def config_dir():
    """The EchoDebug config folder: %APPDATA%\\EchoDebug on Windows, $XDG_CONFIG_HOME or ~/.config/EchoDebug elsewhere."""
    if os.name == "nt" and os.environ.get("APPDATA"):
        return os.path.join(os.environ["APPDATA"], "EchoDebug")
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return os.path.join(xdg, "EchoDebug")
    return os.path.join(os.path.expanduser("~"), ".config", "EchoDebug")


def load_token():
    """ECHODEBUG_TOKEN, else <config>/relay-token, else None (relay auth off)."""
    t = os.environ.get("ECHODEBUG_TOKEN", "").strip()
    if t:
        return t
    try:
        with open(os.path.join(config_dir(), "relay-token"), "r") as f:
            t = f.read().strip()
            return t or None
    except OSError:
        return None


def relay_port():
    try:
        return int(os.environ.get("ECHODEBUG_PORT", DEFAULT_PORT))
    except ValueError:
        return DEFAULT_PORT


# ---- WebSocket framing ----------------------------------------------------------------------------

OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


class ConnectionClosed(Exception):
    pass


def accept_key(key):
    return base64.b64encode(hashlib.sha1((key + _GUID).encode("ascii")).digest()).decode("ascii")


def encode_frame(opcode, payload, mask=None, fin=True):
    """One frame. Clients must mask (RFC 6455 5.3): pass 4 bytes, or None for a random key."""
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    head = bytearray([(0x80 if fin else 0) | opcode])
    n = len(payload)
    if n < 126:
        head.append(0x80 | n)
    elif n < 1 << 16:
        head.append(0x80 | 126)
        head += struct.pack("!H", n)
    else:
        head.append(0x80 | 127)
        head += struct.pack("!Q", n)
    mask = os.urandom(4) if mask is None else mask
    head += mask
    body = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
    return bytes(head) + body


class FrameParser:
    """Feeds raw bytes, yields complete (opcode, payload) messages; reassembles fragments."""

    def __init__(self):
        self.buf = bytearray()
        self.frag_op = None
        self.frag = bytearray()

    def feed(self, data):
        self.buf += data
        out = []
        while True:
            f = self._one()
            if f is None:
                return out
            fin, op, payload = f
            if op >= 0x8:  # control frames are never fragmented
                out.append((op, payload))
            elif op == OP_CONT:
                self.frag += payload
                if fin and self.frag_op is not None:
                    out.append((self.frag_op, bytes(self.frag)))
                    self.frag_op, self.frag = None, bytearray()
            elif fin:
                out.append((op, payload))
            else:
                self.frag_op, self.frag = op, bytearray(payload)

    def _one(self):
        b = self.buf
        if len(b) < 2:
            return None
        fin, op = bool(b[0] & 0x80), b[0] & 0x0F
        masked, n = bool(b[1] & 0x80), b[1] & 0x7F
        i = 2
        if n == 126:
            if len(b) < 4:
                return None
            n = struct.unpack("!H", bytes(b[2:4]))[0]
            i = 4
        elif n == 127:
            if len(b) < 10:
                return None
            n = struct.unpack("!Q", bytes(b[2:10]))[0]
            i = 10
        mask = None
        if masked:
            if len(b) < i + 4:
                return None
            mask = bytes(b[i:i + 4])
            i += 4
        if len(b) < i + n:
            return None
        payload = bytes(b[i:i + n])
        if mask:
            payload = bytes(x ^ mask[j & 3] for j, x in enumerate(payload))
        del b[:i + n]
        return fin, op, payload


class WebSocket:
    """Minimal blocking WebSocket client for ws://127.0.0.1 (no TLS, no extensions)."""

    def __init__(self, host, port, path, headers=None, timeout=5.0):
        self.host, self.port, self.path = host, port, path
        self.headers = headers or {}
        self.timeout = timeout
        self.sock = None
        self.parser = FrameParser()
        self.lock = threading.Lock()

    def connect(self):
        s = socket.create_connection((self.host, self.port), timeout=self.timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        lines = [
            "GET %s HTTP/1.1" % self.path,
            "Host: %s:%d" % (self.host, self.port),
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Key: " + key,
            "Sec-WebSocket-Version: 13",
        ] + ["%s: %s" % kv for kv in self.headers.items()]
        s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                s.close()
                raise ConnectionClosed("connection closed during handshake")
            resp += chunk
            if len(resp) > 65536:
                s.close()
                raise ConnectionClosed("handshake response too large")
        head, rest = resp.split(b"\r\n\r\n", 1)
        status = head.split(b"\r\n", 1)[0].decode("latin-1")
        if " 101 " not in status + " ":
            s.close()
            code = status.split(" ")[1] if len(status.split(" ")) > 1 else "?"
            if code == "401":
                raise PermissionError("relay rejected the token (HTTP 401): check %s or ECHODEBUG_TOKEN" % os.path.join(config_dir(), "relay-token"))
            raise ConnectionClosed("handshake failed: " + status)
        hdrs = {}
        for line in head.split(b"\r\n")[1:]:
            k, _, v = line.decode("latin-1").partition(":")
            hdrs[k.strip().lower()] = v.strip()
        if hdrs.get("sec-websocket-accept") != accept_key(key):
            s.close()
            raise ConnectionClosed("bad Sec-WebSocket-Accept")
        self.sock = s
        self.pending = list(self.parser.feed(rest)) if rest else []

    def send_text(self, text):
        self._send(OP_TEXT, text)

    def _send(self, op, payload):
        with self.lock:
            if self.sock is None:
                raise ConnectionClosed("not connected")
            self.sock.sendall(encode_frame(op, payload))

    def recv(self, timeout):
        """The next text message, or None after `timeout` seconds without one."""
        while True:
            while self.pending:
                op, payload = self.pending.pop(0)
                if op == OP_TEXT or op == OP_BINARY:
                    return payload.decode("utf-8", "replace")
                if op == OP_PING:
                    self._send(OP_PONG, payload)
                elif op == OP_CLOSE:
                    self.close()
                    raise ConnectionClosed("closed by the relay")
            if self.sock is None:
                raise ConnectionClosed("not connected")
            self.sock.settimeout(timeout)
            try:
                data = self.sock.recv(65536)
            except socket.timeout:
                return None
            except OSError as e:
                self.close()
                raise ConnectionClosed(str(e))
            if not data:
                self.close()
                raise ConnectionClosed("connection closed")
            self.pending.extend(self.parser.feed(data))

    def close(self):
        with self.lock:
            s, self.sock = self.sock, None
        if s is not None:
            with contextlib.suppress(OSError):
                s.sendall(encode_frame(OP_CLOSE, b""))
            with contextlib.suppress(OSError):
                s.close()


# ---- mapping --------------------------------------------------------------------------------------

def parse_rva(v):
    if isinstance(v, int):
        return v if v >= 0 else None
    if isinstance(v, str):
        try:
            return int(v, 16)
        except ValueError:
            return None
    return None


class Mapper:
    """ea <-> RVA for one database. `image_base` is a callable so a rebase is picked up at once."""

    def __init__(self, module, image_base, size=None):
        self.module = module
        self.image_base = image_base
        self.size = size

    def matches(self, module):
        return module is not None and module.lower() == self.module.lower()

    def to_rva(self, ea):
        base = self.image_base()
        if ea < base:
            return None
        rva = ea - base
        size = self.size() if callable(self.size) else self.size
        if size is not None and rva >= size:
            return None
        return rva

    def to_ea(self, module, rva):
        if not self.matches(module):
            return None
        r = parse_rva(rva)
        return None if r is None else self.image_base() + r


# ---- session --------------------------------------------------------------------------------------

class SyncSession:
    """A reconnecting /sync connection for one database.

    handlers: object with optional on_cursor(ea), on_name(ea, name), on_comment(ea, text),
    on_types(decls, names), on_status(text). They run through `post` on the host's main thread.
    """

    def __init__(self, tool, version, mapper, handlers, post, log=print, file="", host="127.0.0.1", port=None, token=None):
        self.tool, self.version, self.mapper, self.handlers = tool, version, mapper, handlers
        self.post, self.log, self.file = post, log, file
        self.host, self.port = host, port or relay_port()
        self.token = token if token is not None else load_token()
        self.ws = None
        self.stop_event = threading.Event()
        self.thread = None
        self.connected = False
        self.directions = {}
        self._applying = 0
        # what both sides currently agree on, so echoes of applied values are not sent back
        self._known = {}
        self._known_lock = threading.Lock()
        self._last_cursor = None

    # -- lifecycle --
    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._run, name="echodebug-sync", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        ws = self.ws
        if ws:
            ws.close()
        if self.thread and self.thread is not threading.current_thread():
            self.thread.join(2.0)
        self.connected = False

    def _run(self):
        delay = 1.0
        while not self.stop_event.is_set():
            try:
                self._connect_once()
                delay = 1.0
            except PermissionError as e:
                self.log("EchoDebug sync: %s" % e)
                delay = 10.0
            except (OSError, ConnectionClosed) as e:
                if self.connected and not self.stop_event.is_set():
                    self.log("EchoDebug sync: disconnected (%s)" % e)
            self.connected = False
            self.ws = None
            if self.stop_event.wait(delay):
                break
            delay = min(delay * 2, 10.0)

    def _connect_once(self):
        headers = {"Authorization": "Bearer " + self.token} if self.token else {}
        ws = WebSocket(self.host, self.port, "/sync", headers)
        ws.connect()
        self.ws = ws
        size = self.mapper.size() if callable(self.mapper.size) else self.mapper.size
        mod = {"name": self.mapper.module, "base": "0x%x" % self.mapper.image_base()}
        if size:
            mod["size"] = size
        ws.send_text(json.dumps({"type": "hello", "tool": self.tool, "version": self.version, "file": self.file, "protocol": PROTOCOL, "modules": [mod]}))
        last_ping = time.time()
        while not self.stop_event.is_set():
            text = ws.recv(1.0)
            if time.time() - last_ping > PING_SECONDS:
                ws.send_text('{"type":"ping"}')
                last_ping = time.time()
            if text is None:
                continue
            try:
                msg = json.loads(text)
            except ValueError:
                continue
            if isinstance(msg, dict):
                self._dispatch(msg)

    def _dispatch(self, msg):
        ty = msg.get("type")
        if ty == "hello_result":
            self.connected = True
            self.directions = msg.get("directions") or {}
            self.log("EchoDebug sync: connected to ws://%s:%d/sync as %s (%s)" % (self.host, self.port, self.tool, self.mapper.module))
            return
        if ty == "config":
            self.directions = msg.get("directions") or self.directions
            return
        if ty == "error":
            self.log("EchoDebug sync: relay says: %s" % msg.get("message"))
            return
        if ty == "types":
            h = getattr(self.handlers, "on_types", None)
            if h:
                decls, names = msg.get("decls") or "", msg.get("names") or []
                self.post(lambda: self._applied(h, decls, names))
            return
        if ty not in ("cursor", "name", "comment"):
            return
        ea = self.mapper.to_ea(msg.get("module"), msg.get("rva"))
        rva = parse_rva(msg.get("rva"))
        if ea is None or rva is None:
            return
        if ty == "cursor":
            self._last_cursor = rva
            h = getattr(self.handlers, "on_cursor", None)
            if h:
                self.post(lambda: self._applied(h, ea))
            return
        value = msg.get(ty) or ""
        self._remember(ty, rva, value)
        h = getattr(self.handlers, "on_" + ty, None)
        if h:
            self.post(lambda: self._applied(h, ea, value))

    def _applied(self, fn, *args):
        self._applying += 1
        try:
            fn(*args)
        except Exception as e:  # a host API error must not kill the session
            self.log("EchoDebug sync: applying %s failed: %s" % (getattr(fn, "__name__", "change"), e))
        finally:
            self._applying -= 1
        return 0

    @property
    def applying(self):
        """True while a change from the relay is being applied (hooks fired by it are ignored)."""
        return self._applying > 0

    def _remember(self, kind, rva, value):
        with self._known_lock:
            self._known[(kind, rva)] = value

    def _is_known(self, kind, rva, value):
        with self._known_lock:
            return self._known.get((kind, rva)) == value

    # -- outgoing --
    def _send(self, frame):
        ws = self.ws
        if not ws or not self.connected:
            return False
        try:
            ws.send_text(json.dumps(frame))
            return True
        except (OSError, ConnectionClosed):
            return False

    def send_cursor(self, ea):
        if self.applying:
            return False
        rva = self.mapper.to_rva(ea)
        if rva is None or rva == self._last_cursor:
            return False
        self._last_cursor = rva
        return self._send({"type": "cursor", "module": self.mapper.module, "rva": "0x%x" % rva})

    def _send_mark(self, kind, ea, value):
        if self.applying:
            return False
        rva = self.mapper.to_rva(ea)
        value = value or ""
        if rva is None or self._is_known(kind, rva, value):
            return False
        if self._send({"type": kind, "module": self.mapper.module, "rva": "0x%x" % rva, kind: value}):
            self._remember(kind, rva, value)
            return True
        return False

    def send_name(self, ea, name):
        return self._send_mark("name", ea, name)

    def send_comment(self, ea, text):
        return self._send_mark("comment", ea, text)
