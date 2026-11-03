"""EchoDebug live sync for IDA Pro 9.x (IDAPython, Python 3).

Install: copy this file and integrations/python/echodebug_sync.py into IDA's plugins folder
(%APPDATA%\\Hex-Rays\\IDA Pro\\plugins on Windows, ~/.idapro/plugins elsewhere). Open a database,
then Edit > Plugins > EchoDebug sync (Ctrl-Alt-E) toggles the connection. Set
ECHODEBUG_SYNC_AUTOSTART=1 to connect whenever a database opens.

- the IDA cursor drives EchoDebug's disassembly and EchoDebug's cursor moves IDA (jumpto);
- user names (IDB_Hooks.renamed) and regular comments (IDB_Hooks.cmt_changed) go both ways;
- struct types pushed from EchoDebug are parsed into Local Types (idc.parse_decls).

Locations travel as the input file name + RVA (ea - image base), so a rebased database still
lines up with the live module.
"""

import os
import sys

import ida_bytes
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_name
import ida_nalt
import idc

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import echodebug_sync as core  # noqa: E402

PLUGIN_VERSION = "1.0"


def _log(text):
    ida_kernwin.msg(text + "\n")


def _post(fn):
    """Queues fn for IDA's main thread (database writes need MFF_WRITE; NOWAIT so stopping the
    session from the main thread can never wait on a queued call)."""
    ida_kernwin.execute_sync(lambda: fn() or 0, ida_kernwin.MFF_WRITE | ida_kernwin.MFF_NOWAIT)


class _Apply:
    """What the relay asks IDA to do; runs on the main thread."""

    def on_cursor(self, ea):
        ida_kernwin.jumpto(ea)

    def on_name(self, ea, name):
        flags = ida_name.SN_NOWARN | ida_name.SN_NOCHECK
        if name:
            flags |= ida_name.SN_FORCE
        if not ida_name.set_name(ea, name, flags):
            _log("EchoDebug sync: could not name 0x%x %r" % (ea, name))

    def on_comment(self, ea, text):
        ida_bytes.set_cmt(ea, text, False)

    def on_types(self, decls, names):
        errors = idc.parse_decls(decls, getattr(idc, "PT_SILENT", 0))
        if errors is None or errors < 0:
            _log("EchoDebug sync: the struct declarations could not be parsed")
        elif errors:
            _log("EchoDebug sync: %d errors while importing %s into Local Types" % (errors, ", ".join(names)))
        else:
            _log("EchoDebug sync: imported %s into Local Types" % ", ".join(names))


class _UiHooks(ida_kernwin.UI_Hooks):
    def __init__(self, session):
        ida_kernwin.UI_Hooks.__init__(self)
        self.session = session

    def screen_ea_changed(self, ea, prev_ea):
        if ea != ida_idaapi.BADADDR:
            self.session.send_cursor(ea)


class _IdbHooks(ida_idp.IDB_Hooks):
    def __init__(self, session, on_close):
        ida_idp.IDB_Hooks.__init__(self)
        self.session = session
        self.on_close = on_close

    def renamed(self, ea, new_name, local_name, *args):
        # local (function-scoped) labels and IDA's own auto names stay in IDA
        if not local_name and (not new_name or ida_bytes.has_user_name(ida_bytes.get_flags(ea))):
            self.session.send_name(ea, new_name or "")
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        if not repeatable_cmt:
            self.session.send_comment(ea, ida_bytes.get_cmt(ea, False) or "")
        return 0

    def closebase(self):
        self.on_close()
        return 0


class _Sync:
    def __init__(self, on_closed):
        self.on_closed = on_closed
        mapper = core.Mapper(ida_nalt.get_root_filename(), ida_nalt.get_imagebase, size=lambda: max(0, ida_ida.inf_get_max_ea() - ida_nalt.get_imagebase()))
        version = "IDA %s" % ida_kernwin.get_kernel_version()
        self.session = core.SyncSession("ida", version, mapper, _Apply(), post=_post, log=_log, file=idc.get_idb_path())
        self.ui = _UiHooks(self.session)
        self.idb = _IdbHooks(self.session, self._closed)

    def start(self):
        self.ui.hook()
        self.idb.hook()
        self.session.start()
        _log("EchoDebug sync: connecting to ws://127.0.0.1:%d/sync for %s" % (self.session.port, self.session.mapper.module))

    def _closed(self):
        self.stop()
        self.on_closed()

    def stop(self):
        self.ui.unhook()
        self.idb.unhook()
        self.session.stop()
        _log("EchoDebug sync: stopped")


class EchoDebugSyncPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Live sync of cursor, names, comments and types with EchoDebug"
    help = "Toggles the connection to the EchoDebug relay (/sync)"
    wanted_name = "EchoDebug sync"
    wanted_hotkey = "Ctrl-Alt-E"

    def init(self):
        self.sync = None
        if os.environ.get("ECHODEBUG_SYNC_AUTOSTART") == "1":
            self.run(0)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.sync:
            self.sync.stop()
            self.sync = None
            return
        self.sync = _Sync(self._closed)
        self.sync.start()

    def _closed(self):
        self.sync = None

    def term(self):
        if self.sync:
            self.sync.stop()
            self.sync = None


def PLUGIN_ENTRY():
    return EchoDebugSyncPlugin()
