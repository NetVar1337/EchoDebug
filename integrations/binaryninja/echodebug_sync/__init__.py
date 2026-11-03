"""EchoDebug live sync for Binary Ninja (Python 3 plugin, UI required for cursor sync).

Install: copy this folder into Binary Ninja's plugins folder (Plugins > Open Plugin Folder) and
copy integrations/python/echodebug_sync.py into it next to this file. Then, with a binary open:
Plugins > EchoDebug > Start sync (or Stop sync).

- the cursor follows EchoDebug and drives it (UIContextNotification.OnAddressChange / bv.navigate);
- user symbols (BinaryDataNotification.symbol_added / symbol_updated / symbol_removed) and
  comments (address comments and function comments, compared on function_updated and on a short
  timer) go both ways;
- struct types pushed from EchoDebug are parsed with bv.parse_types_from_string and defined as
  user types.

Locations travel as file name + RVA (address - image base), so a rebased view still lines up with
the live module.
"""

import os
import sys
import threading

import binaryninja
from binaryninja import BinaryDataNotification, PluginCommand, Symbol, SymbolType, log_info, log_warn
from binaryninja import mainthread

try:
    from . import echodebug_sync as core
except ImportError:  # copied next to the plugin folder, or on sys.path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import echodebug_sync as core  # noqa: E402

try:
    from binaryninjaui import UIContext, UIContextNotification
except ImportError:  # headless: no cursor tracking
    UIContext = None
    UIContextNotification = object

COMMENT_POLL_SECONDS = 1.5


def _image_base(bv):
    base = getattr(bv, "image_base", None)
    return bv.start if base is None else base


def _log(text):
    log_info(text, "EchoDebug")


class _Apply:
    """What the relay asks Binary Ninja to do; runs on the main thread."""

    def __init__(self, bv, sync):
        self.bv = bv
        self.sync = sync

    def on_cursor(self, ea):
        if not self.bv.navigate(self.bv.view, ea) and UIContext is not None:
            ctx = UIContext.activeContext()
            frame = ctx.getCurrentViewFrame() if ctx else None
            if frame:
                frame.navigate(self.bv, ea)

    def on_name(self, ea, name):
        funcs = self.bv.get_functions_at(ea)
        if funcs:
            funcs[0].name = name or None
            return
        if name:
            self.bv.define_user_symbol(Symbol(SymbolType.DataSymbol, ea, name))
        else:
            sym = self.bv.get_symbol_at(ea)
            if sym is not None and not sym.auto:
                self.bv.undefine_user_symbol(sym)

    def on_comment(self, ea, text):
        funcs = self.bv.get_functions_containing(ea)
        if funcs:
            funcs[0].set_comment_at(ea, text)
        else:
            self.bv.set_comment_at(ea, text)
        self.sync.comments[ea] = text

    def on_types(self, decls, names):
        result = self.bv.parse_types_from_string(decls)
        for name, ty in result.types.items():
            self.bv.define_user_type(name, ty)
        _log("EchoDebug sync: defined %s" % ", ".join(str(n) for n in result.types.keys()))


class _Symbols(BinaryDataNotification):
    def __init__(self, sync):
        BinaryDataNotification.__init__(self)
        self.sync = sync

    def _send(self, sym, removed=False):
        if sym is None or sym.auto:
            return
        self.sync.session.send_name(sym.address, "" if removed else sym.name)

    def symbol_added(self, view, sym):
        self._send(sym)

    def symbol_updated(self, view, sym):
        self._send(sym)

    def symbol_removed(self, view, sym):
        self._send(sym, removed=True)

    def function_updated(self, view, func):
        self.sync.diff_comments(func.comments)


class _Cursor(UIContextNotification):
    def __init__(self, sync):
        UIContextNotification.__init__(self)
        self.sync = sync
        UIContext.registerNotification(self)

    def close(self):
        UIContext.unregisterNotification(self)

    def OnAddressChange(self, context, frame, view, location):
        if view is None:
            return
        try:
            data = view.getData()
        except Exception:
            return
        if data is None or data.file.filename != self.sync.bv.file.filename:
            return
        self.sync.session.send_cursor(location.getOffset())


class _Sync:
    def __init__(self, bv):
        self.bv = bv
        module = os.path.basename(bv.file.original_filename or bv.file.filename)
        mapper = core.Mapper(module, lambda: _image_base(bv), size=lambda: max(0, bv.end - _image_base(bv)))
        version = "Binary Ninja %s" % binaryninja.core_version()
        self.session = core.SyncSession("binja", version, mapper, _Apply(bv, self), post=mainthread.execute_on_main_thread, log=_log, file=bv.file.filename)
        self.symbols = _Symbols(self)
        self.cursor = None
        self.comments = {}
        self.stop_event = threading.Event()
        self.poller = None

    def start(self):
        self.comments = dict(self._all_comments())
        self.bv.register_notification(self.symbols)
        if UIContext is not None:
            self.cursor = _Cursor(self)
        else:
            log_warn("EchoDebug sync: no UI, the cursor is not synced", "EchoDebug")
        self.session.start()
        self.poller = threading.Thread(target=self._poll, name="echodebug-comments", daemon=True)
        self.poller.start()

    def stop(self):
        self.stop_event.set()
        self.bv.unregister_notification(self.symbols)
        if self.cursor is not None:
            self.cursor.close()
            self.cursor = None
        self.session.stop()

    def _all_comments(self):
        out = dict(self.bv.address_comments)
        for f in self.bv.functions:
            out.update(f.comments)
        return out

    def diff_comments(self, current):
        for ea, text in current.items():
            if self.comments.get(ea) != text:
                self.comments[ea] = text
                self.session.send_comment(ea, text)

    def _poll(self):
        # address (data) comments have no notification of their own
        while not self.stop_event.wait(COMMENT_POLL_SECONDS):
            try:
                cur = dict(self.bv.address_comments)
            except Exception:
                continue
            self.diff_comments(cur)
            for ea in [a for a in self.comments if a not in cur and not self.bv.get_functions_containing(a)]:
                del self.comments[ea]
                self.session.send_comment(ea, "")


_sessions = {}


def _start(bv):
    key = bv.file.filename
    if key in _sessions:
        log_warn("EchoDebug sync is already running for this file", "EchoDebug")
        return
    s = _Sync(bv)
    _sessions[key] = s
    s.start()


def _stop(bv):
    s = _sessions.pop(bv.file.filename, None)
    if s:
        s.stop()
        _log("EchoDebug sync: stopped")


PluginCommand.register("EchoDebug\\Start sync", "Sync the cursor, names, comments and types with EchoDebug", _start, lambda bv: bv.file.filename not in _sessions)
PluginCommand.register("EchoDebug\\Stop sync", "Disconnect from EchoDebug", _stop, lambda bv: bv.file.filename in _sessions)
