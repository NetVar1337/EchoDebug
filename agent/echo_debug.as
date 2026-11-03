// echo_debug.as - EchoDebug backend agent for Echo's Universal API.
//
// Connects to the EchoDebug desktop app's relay at ws://127.0.0.1:<RELAY_PORT>/ext and serves the
// ext verbs from PROTOCOL.md (attach, write, regions, chain, value scanner, pointer scan, Unicorn
// emulation, dump, freeze). After every successful attach, Echo's built-in memory server is pointed
// at the relay's /agent endpoint with process::open_socket.
//
// Threading model
//   * ws callbacks run on Echo's connection thread, one message at a time.
//   * Long jobs (scan_new, scan_next, pointer_scan) and attach run on one-shot threads
//     (create_thread(0, ...)), one at a time through the job slot (g_job); concurrent requests get
//     3004. attach goes through the job slot because it is not documented whether process::attach /
//     process::open_socket are safe on the ws thread, and because serialising attach against scans
//     guarantees a scan never sees the target change underneath it.
//   * emulate and peb_walk also run through the job slot: the slot serialises them, so the
//     code-hook globals (g_emu_*) are only ever touched by one job thread at a time.
//   * scan_new first scans (not 'unknown') split the regions into shards worked by the job thread
//     and three helper threads (par_scan_new); shards merge in address order.
//   * Optional settings live in echodebug/agent.json (port, auto_attach, alerts), writes and freezes
//     are journaled to echodebug/journal.jsonl, and an "EchoDebug" tab in Echo's menu shows status
//     and the safety switches (pause freezes/watches, restore and detach, cancel the running job).
//   * Ticking threads (only creatable from main): keepalive at 1 tps (reconnect with backoff,
//     process-exit detection, AUTO_ATTACH retries, job watchdog) and freeze at 20 tps.
//   * Shared state: g_state_mx (attach state + job slot incl. the claimed JobParams — claim and
//     params are written under one lock so the watchdog can never recycle a slot mid-handoff),
//     g_scan_mx (published scan-state handle), g_freeze_mx (freeze list), g_send_mx (serialises
//     ws::send across threads). Locks never nest.
//   * A published ScanState is never mutated again. Jobs build a new one and swap the handle, so
//     readers only hold g_scan_mx long enough to copy the handle (pattern from the Echo docs).
//   * Freeze entries keep the bytes that were at the address before freezing; they are restored
//     on detach, on target exit and in on_unload (Echo docs: undo target modifications on unload).

const string AGENT_VERSION = "0.8.8";
const int RELAY_PORT = 47110;
const string AUTO_ATTACH = "";   // optional process name to attach on load

const int PROTOCOL_VERSION = 1;
const string TAG = "echodebug";
const string LOG_PREFIX = "[EchoDebug] ";

// Error codes (PROTOCOL.md)
const int E_UNKNOWN_VERB = 3000;
const int E_NOT_ATTACHED = 3001;
const int E_BAD_ARGS = 3002;
const int E_FAILED = 3003;
const int E_BUSY = 3004;
const int E_LIMIT = 3005;

// Address space / generic limits
const uint64 USER_LO = 0x10000;
const uint64 USER_HI = 0x7fffffffffff;
const uint64 CHUNK = 0x100000;                 // 1 MiB read granularity
const uint WALK_MAX_ITER = 2000000;            // virtual_query calls per walk
const uint WALK_MAX_REGIONS = 200000;
const uint64 WRITE_MAX = 0x100000;             // 1 MiB per write
const uint FREEZE_MAX_ENTRIES = 1024;
const uint FREEZE_MAX_BYTES = 4096;
const uint CHAIN_MAX_OFFSETS = 64;

// Watch list limits (agent-side sampler, emits watch_event on change)
const uint WATCH_MAX_ENTRIES = 256;
const uint WATCH_MAX_BYTES = 256;
const uint WATCH_HISTORY = 16;
const uint64 JOB_TIME_LIMIT_MS = 100000;       // the relay fails requests after 120 s
const uint64 JOB_WATCHDOG_MS = 125000;         // frees the slot if a job thread died mid-way (just past the relay's 120 s timeout)

// Value scanner limits
const uint MAX_CANDIDATES = 4000000;
const uint64 PREV_RAW_CAP = 0x4000000;         // 64 MiB of stored previous bytes (pattern types)
const uint64 SNAPSHOT_CAP = 0x10000000;        // 256 MiB of unknown-initial-value snapshots
const uint SAMPLE_MAX = 200;
const uint RESULTS_PAGE_MAX = 2000;
const uint MAX_PATTERN = 256;

// Pointer scan limits
const uint PS_MAX_NODES_PER_LEVEL = 50000;
const uint64 PS_MAX_SCAN_BYTES = 0x80000000;   // 2 GiB read across all levels
const uint64 PS_MAX_OFFSET_CAP = 0x10000;
const uint PS_MAX_RESULTS_CAP = 10000;
const uint PS_BLOOM_SIZE = 0x100000;           // 1M one-byte buckets keyed by page number

// Emulator limits
const uint64 EMU_STACK_SIZE = 0x100000;
const uint64 EMU_CODE_MAX = 0x100000;
const int64 EMU_MAX_INSNS = 5000000;
const int64 EMU_MAX_TIMEOUT_US = 5000000;
const int64 EMU_MAX_TRACE = 100000;
const int64 EMU_MAX_MEM_LOG = 20000;     // each entry carries before/after hex, so smaller than the trace cap
const uint EMU_MAX_BLOBS = 64;           // injected / read-back memory blobs
const uint64 EMU_MAX_BLOB_BYTES = 0x10000; // 64 KiB per blob

// Value types
const int VT_U8 = 0;
const int VT_U16 = 1;
const int VT_U32 = 2;
const int VT_U64 = 3;
const int VT_I8 = 4;
const int VT_I16 = 5;
const int VT_I32 = 6;
const int VT_I64 = 7;
const int VT_F32 = 8;
const int VT_F64 = 9;
const int VT_BYTES = 10;
const int VT_STRING = 11;
const int VT_WSTRING = 12;

// Compare ops
const int OP_EXACT = 0;
const int OP_UNKNOWN = 1;
const int OP_CHANGED = 2;
const int OP_UNCHANGED = 3;
const int OP_INCREASED = 4;
const int OP_DECREASED = 5;
const int OP_GREATER = 6;
const int OP_LESS = 7;
const int OP_BETWEEN = 8;

const uint RF_PRESENT = 1;
const uint RF_WRITABLE = 2;
const uint RF_EXEC = 4;

const string HEXD = "0123456789abcdef";

// ---------------------------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------------------------

mutex@ g_send_mx = create_mutex();
mutex@ g_state_mx = create_mutex();
mutex@ g_scan_mx = create_mutex();
mutex@ g_freeze_mx = create_mutex();

// attach state (g_state_mx)
bool g_attached = false;
uint64 g_pid = 0;
uint64 g_base = 0;
uint64 g_peb = 0;
string g_name = "";
bool g_auto_pending = false;

// job slot (g_state_mx). The params handle is claimed atomically with the slot: both are written
// under the same lock, so a recycled slot can never hand a job another request's params.
string g_job = "";
int64 g_job_id = 0;
uint g_job_seq = 0;
uint64 g_job_t0 = 0;
JobParams@ g_job_params;

// published scan state (g_scan_mx)
ScanState@ g_scan;

// freeze list (g_freeze_mx)
array<FreezeEntry@> g_freeze;

// watch list (g_watch_mx): sampled at 10 tps, watch_event emitted on change
mutex@ g_watch_mx = create_mutex();
array<WatchEntry@> g_watch;

// keepalive thread only
uint g_ka_tick = 0;
uint g_ka_next_try = 2;
uint g_ka_wait = 2;

// emulate hook state (only touched by the emulate job thread; the job slot serialises jobs)
uint64 g_emu_count = 0;
bool g_emu_trace_on = false;
uint g_emu_trace_limit = 0;
array<uint64> g_emu_trace;
// memory log: explicit memory operands decoded with Zydis before each instruction runs
bool g_emu_blank = false;
bool g_emu_mem_on = false;
uint g_emu_mem_limit = 0;
array<MemAccess@> g_emu_mem;
array<uint> g_emu_mem_pending;   // indexes of writes whose new value is read before the next instruction

// Cooperative cancel for long jobs (scans, pointer scans, emulation): set by the 'cancel' verb or
// the in-Echo panel, cleared when the next job is claimed.
atomic_bool@ g_cancel = create_atomic_bool(false);
uint64 g_emu_max = 0;

// g_pow2[e + 1074] == 2^e, used to decode IEEE-754 bits without a reinterpret cast.
array<double> g_pow2;

// ---------------------------------------------------------------------------------------------
// Classes
// ---------------------------------------------------------------------------------------------

class FreezeEntry
{
    uint64 address;
    array<uint8> data;
    array<uint8> original;   // bytes at `address` before the freeze, for restore on detach/unload
    bool has_original;
    bool failed;
    string mode;     // "set" (write data), "add" (value += step each tick), "clamp" (keep within min..max)
    string vtype;    // numeric type for add/clamp
    double step;
    double minv;
    double maxv;
    string group;
    bool paused;
    FreezeEntry() { address = 0; has_original = false; failed = false; mode = "set"; vtype = ""; step = 0; minv = 0; maxv = 0; group = ""; paused = false; }
}

class WatchEntry
{
    uint64 address;
    uint size;
    string label;
    array<uint8> prev;    // last sampled bytes
    bool has_prev;
    string vtype;         // optional numeric decode
    string cond;          // any | eq | ne | gt | lt | delta
    double cval;
    uint hits;
    array<string> history;   // last values (hex), newest last
    bool alert;
    WatchEntry() { address = 0; size = 4; has_prev = false; vtype = ""; cond = "any"; cval = 0; hits = 0; alert = false; }
}

// One decoded memory operand of an emulated instruction.
class MemAccess
{
    uint64 rip;
    uint64 address;
    uint size;
    bool r;
    bool w;
    string before;   // hex at `address` before the instruction ran ("" if unreadable)
    string after;    // writes only: hex after it ran
    MemAccess() { rip = 0; address = 0; size = 0; r = false; w = false; }
}

// Everything a job thread needs, claimed atomically with the job slot (g_state_mx).
class JobParams
{
    string attach_name;
    uint32 attach_pid;
    ScanSpec@ scan;
    ScanState@ old;
    PtrSpec@ ptr;
    EmuJob@ emu;
    JobParams() { attach_pid = 0; }
}

// A fully parsed emulate request; executed by run_emulate on the job thread.
class EmuJob
{
    uint64 start;
    uint64 stop;
    array<uint8> code;              // blank-emulator mode (uc::create); empty = process mode
    array<string> rnames;
    array<uint64> rvals;
    array<uint64> waddrs;           // injected blobs
    array<array<uint8> > wdata;
    array<uint64> raddrs;           // read-back blobs
    array<uint64> rsizes;
    int64 max_insns;
    int64 timeout_us;
    bool trace;
    int64 trace_limit;
    bool mem_log;
    int64 mem_log_limit;
    EmuExtras@ x;
    json_obj@ xmm_req;
    EmuJob()
    {
        @x = EmuExtras();
        start = 0; stop = 0; max_insns = 100000; timeout_us = 1000000;
        trace = false; trace_limit = 2000;
        mem_log = false; mem_log_limit = 2000;
    }
}

class RegionList
{
    array<uint64> base;
    array<uint64> size;
    array<uint> flags;
    uint64 total;
    RegionList() { total = 0; }
}

// A parsed scan request (scan_new / scan_next).
class ScanSpec
{
    int vtype;
    uint width;
    uint64 align;
    int op;
    double eps;
    uint64 raw1;          // integer target bits (fast exact path)
    uint64 t1;            // integer targets as order keys (see int_key)
    uint64 t2;
    double f1;            // float targets
    double f2;
    array<uint8> pattern; // bytes/string/wstring target
    uint64 lo;
    uint64 hi;
    bool writable_only;
    ScanSpec()
    {
        vtype = -1; width = 0; align = 1; op = OP_EXACT; eps = 0.0001;
        raw1 = 0; t1 = 0; t2 = 0; f1 = 0; f2 = 0;
        lo = USER_LO; hi = USER_HI; writable_only = true;
    }
}

// Result of a scan. Either a candidate list or (unknown first scan) a set of memory snapshots that
// is turned into candidates by the first scan_next.
class ScanState
{
    int vtype;
    uint width;
    uint64 align;
    double eps;
    array<uint8> pattern;
    array<uint64> addrs;
    array<uint64> prev;       // numeric types: raw bits at the last scan
    array<uint8> prev_raw;    // pattern types: bytes at the last scan, stride = width
    bool snap_mode;
    array<memory_buffer@> snaps;
    array<uint64> snap_base;
    array<uint64> snap_limit; // slots o < limit belong to this snapshot (the rest is overlap)
    uint64 snap_slots;
    bool truncated;

    ScanState(ScanSpec@ s)
    {
        vtype = s.vtype; width = s.width; align = s.align; eps = s.eps;
        snap_mode = false; snap_slots = 0; truncated = false;
    }

    uint64 count()
    {
        if (snap_mode) return snap_slots;
        return addrs.length();
    }

    string prev_hex(uint i)
    {
        if (is_pattern(vtype)) return hex_of(prev_raw, i * width, width);
        return bits_hex(prev[i], width);
    }
}

class PtrSpec
{
    uint64 target;
    int depth;
    uint64 max_offset;
    uint max_results;
    bool module_only_roots;
    PtrSpec() { target = 0; depth = 3; max_offset = 0x400; max_results = 500; module_only_roots = true; }
}

// Emits progress events every ~5% or 256 MiB, whichever comes first.
class Progress
{
    string job;
    uint64 total;
    uint64 step;
    uint64 next;
    Progress(const string &in j, uint64 t)
    {
        job = j; total = t;
        step = t / 20;
        if (step > 0x10000000) step = 0x10000000;
        if (step == 0) step = 1;
        next = step;
    }
    void update(uint64 done)
    {
        if (done < next) return;
        next = done + step;
        send_progress(job, done, total);
    }
}

// Reads scan_next candidates a page at a time; candidates are sorted by address, so neighbours
// usually share one read_buffer call instead of one host read each.
class PageReader
{
    uint64 page;
    memory_buffer@ buf;
    PageReader() { page = 1; }   // 1 is never a page base, forces the first load

    bool read(uint64 a, uint w, uint64 &out v)
    {
        v = 0;
        uint64 pg = a & ~uint64(0xFFF);
        uint64 off = a - pg;
        if (off + w > 0x1000) return read_direct(a, w, v);
        if (pg != page)
        {
            page = pg;
            @buf = process::read_buffer(pg, 0x1000);
        }
        if (buf is null) return false;
        v = buf_read(buf, off, w);
        return true;
    }

    // Same paging, but returns raw bytes (pattern scans).
    bool read_buf(uint64 a, uint w, array<uint8> &out v)
    {
        v.resize(0);
        uint64 pg = a & ~uint64(0xFFF);
        uint64 off = a - pg;
        if (off + w > 0x1000)
        {
            array<uint8>@ b = process::read_bytes(a, w);
            if (b is null || b.length() != w) return false;
            v = b;
            return true;
        }
        if (pg != page)
        {
            page = pg;
            @buf = process::read_buffer(pg, 0x1000);
        }
        if (buf is null) return false;
        v.resize(w);
        for (uint i = 0; i < w; i++) v[i] = buf.read_uint8(off + i);
        return true;
    }
}

// ---------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------

string ext_url() { return "ws://127.0.0.1:" + g_port + "/ext"; }
string native_url() { return "ws://127.0.0.1:" + g_port + "/agent"; }

uint64 umin(uint64 a, uint64 b) { return a < b ? a : b; }
uint64 align_up(uint64 v, uint64 a) { return (v + a - 1) & ~(a - 1); }

int hex_val(uint8 c)
{
    if (c >= 0x30 && c <= 0x39) return int(c) - 0x30;
    if (c >= 0x61 && c <= 0x66) return int(c) - 0x61 + 10;
    if (c >= 0x41 && c <= 0x46) return int(c) - 0x41 + 10;
    return -1;
}

bool has_hex_prefix(const string &in s)
{
    return s.length() >= 2 && s[0] == 0x30 && (s[1] == 0x78 || s[1] == 0x58);
}

// Strict: optional 0x, 1..16 hex digits, nothing else.
bool parse_hex_u64(const string &in s, uint64 &out v)
{
    v = 0;
    uint i = has_hex_prefix(s) ? 2 : 0;
    uint n = s.length();
    if (i >= n || n - i > 16) return false;
    for (; i < n; i++)
    {
        int d = hex_val(s[i]);
        if (d < 0) return false;
        v = (v << 4) | uint64(d);
    }
    return true;
}

bool parse_dec_u64(const string &in s, uint64 &out v)
{
    v = 0;
    if (s.length() == 0 || s.length() > 20) return false;
    for (uint i = 0; i < s.length(); i++)
    {
        uint8 c = s[i];
        if (c < 0x30 || c > 0x39) return false;
        uint64 d = uint64(c - 0x30);
        if (v > (uint64(0xFFFFFFFFFFFFFFFF) - d) / 10) return false;
        v = v * 10 + d;
    }
    return true;
}

// "[-]123" or "[-]0x7b" -> sign + magnitude
bool parse_signed_mag(const string &in s, bool &out neg, uint64 &out mag)
{
    neg = s.length() > 0 && s[0] == 0x2D;
    mag = 0;
    string t = neg ? s.substr(1) : s;
    if (has_hex_prefix(t)) return parse_hex_u64(t, mag);
    return parse_dec_u64(t, mag);
}

bool parse_i64(const string &in s, int64 &out v)
{
    v = 0;
    bool neg;
    uint64 mag;
    if (!parse_signed_mag(s, neg, mag)) return false;
    if (mag > uint64(0x8000000000000000) || (!neg && mag == uint64(0x8000000000000000))) return false;
    v = neg ? -int64(mag) : int64(mag);
    return true;
}

// Hex bytes, optionally space separated ("4883ec28" or "48 83 ec 28").
bool parse_hex_bytes(const string &in s, array<uint8> &out b)
{
    b.resize(0);
    int hi = -1;
    for (uint i = 0; i < s.length(); i++)
    {
        uint8 c = s[i];
        if (c == 0x20)
        {
            if (hi >= 0) return false;
            continue;
        }
        int d = hex_val(c);
        if (d < 0) return false;
        if (hi < 0) hi = d;
        else
        {
            b.insertLast(uint8((hi << 4) | d));
            hi = -1;
        }
    }
    return hi < 0;
}

// Lowercase, 0x-prefixed, unpadded (PROTOCOL.md address format).
string hex_addr(uint64 v)
{
    if (v == 0) return "0x0";
    string s = "";
    while (v != 0)
    {
        s = HEXD.substr(uint(v & 0xF), 1) + s;
        v >>= 4;
    }
    return "0x" + s;
}

string hex_of(const array<uint8> &in b, uint start, uint len)
{
    string s;
    s.resize(len * 2);
    for (uint i = 0; i < len; i++)
    {
        uint8 c = b[start + i];
        s[i * 2] = HEXD[c >> 4];
        s[i * 2 + 1] = HEXD[c & 0xF];
    }
    return s;
}

// Little-endian bytes of the low `w` bytes of `bits`, as hex.
string bits_hex(uint64 bits, uint w)
{
    string s;
    s.resize(w * 2);
    for (uint i = 0; i < w; i++)
    {
        uint c = uint((bits >> (8 * i)) & 0xFF);
        s[i * 2] = HEXD[c >> 4];
        s[i * 2 + 1] = HEXD[c & 0xF];
    }
    return s;
}

bool bytes_eq(const array<uint8> &in a, uint ao, const array<uint8> &in b, uint bo, uint n)
{
    for (uint i = 0; i < n; i++)
        if (a[ao + i] != b[bo + i]) return false;
    return true;
}

uint64 buf_read(memory_buffer@ b, uint64 o, uint w)
{
    if (w == 4) return b.read_uint32(o);
    if (w == 8) return b.read_uint64(o);
    if (w == 2) return b.read_uint16(o);
    return b.read_uint8(o);
}

bool read_direct(uint64 a, uint w, uint64 &out v)
{
    v = 0;
    array<uint8>@ b = process::read_bytes(a, w);
    if (b is null || b.length() != w) return false;
    for (uint i = 0; i < w; i++) v |= uint64(b[i]) << (8 * i);
    return true;
}

bool utf8_to_utf16le(const string &in s, array<uint8> &out o)
{
    o.resize(0);
    uint n = s.length();
    uint i = 0;
    while (i < n)
    {
        uint c = s[i];
        uint cp;
        uint extra;
        if (c < 0x80) { cp = c; extra = 0; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; extra = 1; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; extra = 2; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; extra = 3; }
        else return false;
        if (i + extra >= n && extra > 0) return false;
        for (uint k = 1; k <= extra; k++)
        {
            uint cc = s[i + k];
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        i += extra + 1;
        if (cp >= 0x10000)
        {
            cp -= 0x10000;
            uint hs = 0xD800 + (cp >> 10);
            uint ls = 0xDC00 + (cp & 0x3FF);
            o.insertLast(uint8(hs & 0xFF)); o.insertLast(uint8(hs >> 8));
            o.insertLast(uint8(ls & 0xFF)); o.insertLast(uint8(ls >> 8));
        }
        else
        {
            o.insertLast(uint8(cp & 0xFF)); o.insertLast(uint8(cp >> 8));
        }
    }
    return true;
}

// ---------------------------------------------------------------------------------------------
// Value types and numeric comparison
// ---------------------------------------------------------------------------------------------

int vt_parse(const string &in s)
{
    if (s == "u8") return VT_U8;
    if (s == "u16") return VT_U16;
    if (s == "u32") return VT_U32;
    if (s == "u64") return VT_U64;
    if (s == "i8") return VT_I8;
    if (s == "i16") return VT_I16;
    if (s == "i32") return VT_I32;
    if (s == "i64") return VT_I64;
    if (s == "f32") return VT_F32;
    if (s == "f64") return VT_F64;
    if (s == "bytes") return VT_BYTES;
    if (s == "string") return VT_STRING;
    if (s == "wstring") return VT_WSTRING;
    return -1;
}

int op_parse(const string &in s)
{
    if (s == "exact") return OP_EXACT;
    if (s == "unknown") return OP_UNKNOWN;
    if (s == "changed") return OP_CHANGED;
    if (s == "unchanged") return OP_UNCHANGED;
    if (s == "increased") return OP_INCREASED;
    if (s == "decreased") return OP_DECREASED;
    if (s == "greater") return OP_GREATER;
    if (s == "less") return OP_LESS;
    if (s == "between") return OP_BETWEEN;
    return -1;
}

uint vt_width(int vt)
{
    if (vt == VT_U8 || vt == VT_I8) return 1;
    if (vt == VT_U16 || vt == VT_I16) return 2;
    if (vt == VT_U32 || vt == VT_I32 || vt == VT_F32) return 4;
    if (vt == VT_U64 || vt == VT_I64 || vt == VT_F64) return 8;
    return 0;
}

bool is_float(int vt) { return vt == VT_F32 || vt == VT_F64; }
bool is_pattern(int vt) { return vt >= VT_BYTES; }
bool is_signed(int vt) { return vt >= VT_I8 && vt <= VT_I64; }
bool op_needs_value(int op) { return op == OP_EXACT || op == OP_GREATER || op == OP_LESS || op == OP_BETWEEN; }

// Maps an integer value to a uint64 whose unsigned order equals the type's order: signed values are
// sign-extended and get their sign bit flipped.
uint64 int_key(int vt, uint w, uint64 bits)
{
    if (!is_signed(vt)) return bits;
    if (w < 8)
    {
        uint64 sb = uint64(1) << (w * 8 - 1);
        if ((bits & sb) != 0) bits |= ~((sb << 1) - 1);
    }
    return bits ^ uint64(0x8000000000000000);
}

uint64 width_mask(uint w)
{
    if (w >= 8) return uint64(0xFFFFFFFFFFFFFFFF);
    return (uint64(1) << (w * 8)) - 1;
}

// Accepts anything that fits the width as either signed or unsigned (e.g. u8 "-1" -> 0xff).
bool int_bits_from(bool neg, uint64 mag, uint w, uint64 &out bits)
{
    bits = 0;
    if (neg)
    {
        if (mag > (uint64(1) << (w * 8 - 1))) return false;
        bits = (~mag + 1) & width_mask(w);
        return true;
    }
    if (mag > width_mask(w)) return false;
    bits = mag;
    return true;
}

void init_pow2()
{
    g_pow2.resize(2098);
    double p = 1.0;
    for (int e = 0; e <= 1023; e++) { g_pow2[uint(e + 1074)] = p; p *= 2.0; }
    p = 1.0;
    for (int e = -1; e >= -1074; e--) { p /= 2.0; g_pow2[uint(e + 1074)] = p; }
}

// IEEE-754 bits -> double. Returns false for NaN/Inf so they never satisfy an ordering compare.
bool flt_decode(uint w, uint64 bits, double &out v)
{
    v = 0;
    if (w == 4)
    {
        uint e = uint((bits >> 23) & 0xFF);
        uint64 m = bits & 0x7FFFFF;
        if (e == 0xFF) return false;
        if (e == 0) v = double(m) * g_pow2[925];                         // m * 2^-149
        else v = double(m | 0x800000) * g_pow2[e + 924];                 // (2^23+m) * 2^(e-150)
        if ((bits & 0x80000000) != 0) v = -v;
        return true;
    }
    uint e = uint((bits >> 52) & 0x7FF);
    uint64 m = bits & uint64(0xFFFFFFFFFFFFF);
    if (e == 0x7FF) return false;
    if (e == 0) v = double(m) * g_pow2[0];                               // m * 2^-1074
    else v = double(m | uint64(0x10000000000000)) * g_pow2[e - 1];       // (2^52+m) * 2^(e-1075)
    if ((bits & uint64(0x8000000000000000)) != 0) v = -v;
    return true;
}

// Compares a current value (raw bits) against the spec's targets or the previous raw bits.
bool test_num(int op, ScanSpec@ s, uint64 cur, uint64 prev)
{
    if (op == OP_CHANGED) return cur != prev;
    if (op == OP_UNCHANGED) return cur == prev;
    uint w = s.width;
    if (is_float(s.vtype))
    {
        double c;
        if (!flt_decode(w, cur, c)) return false;
        if (op == OP_EXACT)
        {
            double d = c - s.f1;
            if (d < 0) d = -d;
            return d <= s.eps;
        }
        if (op == OP_GREATER) return c > s.f1;
        if (op == OP_LESS) return c < s.f1;
        if (op == OP_BETWEEN) return c >= s.f1 && c <= s.f2;
        double p;
        if (!flt_decode(w, prev, p)) return false;
        if (op == OP_INCREASED) return c > p;
        if (op == OP_DECREASED) return c < p;
        return false;
    }
    uint64 k = int_key(s.vtype, w, cur);
    if (op == OP_EXACT) return k == s.t1;
    if (op == OP_GREATER) return k > s.t1;
    if (op == OP_LESS) return k < s.t1;
    if (op == OP_BETWEEN) return k >= s.t1 && k <= s.t2;
    uint64 pk = int_key(s.vtype, w, prev);
    if (op == OP_INCREASED) return k > pk;
    if (op == OP_DECREASED) return k < pk;
    return false;
}

// ---------------------------------------------------------------------------------------------
// JSON request helpers
// ---------------------------------------------------------------------------------------------

bool has_key(json_obj@ r, const string &in k)
{
    return r.has(k) && r.type(k) != json_type::null_value;
}

// Address: "0x..." hex string (PROTOCOL.md) or a non-negative JSON number.
bool get_addr(json_obj@ r, const string &in k, uint64 &out v)
{
    v = 0;
    if (!has_key(r, k)) return false;
    json_type t = r.type(k);
    if (t == json_type::string) return parse_hex_u64(r.get_string(k), v);
    if (t == json_type::number)
    {
        if (r.get_double(k) < 0) return false;
        v = r.get_uint64(k);
        return true;
    }
    return false;
}

bool opt_addr(json_obj@ r, const string &in k, uint64 def, uint64 &out v)
{
    v = def;
    if (!has_key(r, k)) return true;
    return get_addr(r, k, v);
}

// Integer: JSON number, or a "[-]123" / "[-]0x7b" string.
bool opt_int(json_obj@ r, const string &in k, int64 def, int64 &out v)
{
    v = def;
    if (!has_key(r, k)) return true;
    json_type t = r.type(k);
    if (t == json_type::number) { v = r.get_int64(k); return true; }
    if (t == json_type::string) return parse_i64(r.get_string(k), v);
    return false;
}

bool opt_bool(json_obj@ r, const string &in k, bool def, bool &out v)
{
    v = def;
    if (!has_key(r, k)) return true;
    if (r.type(k) != json_type::boolean) return false;
    v = r.get_bool(k);
    return true;
}

bool opt_str(json_obj@ r, const string &in k, const string &in def, string &out v)
{
    v = def;
    if (!has_key(r, k)) return true;
    if (r.type(k) != json_type::string) return false;
    v = r.get_string(k);
    return true;
}

bool opt_double(json_obj@ r, const string &in k, double def, double &out v)
{
    v = def;
    if (!has_key(r, k)) return true;
    json_type t = r.type(k);
    if (t == json_type::number) { v = r.get_double(k); return true; }
    if (t == json_type::string)
    {
        string s = r.get_string(k);
        uint n = 0;
        v = parseFloat(s, n);
        return s.length() > 0 && n == s.length();
    }
    return false;
}

// Parses r[k] as a value of type vt into integer bits, a double or a byte pattern.
bool parse_value(json_obj@ r, const string &in k, int vt, uint64 &out bits, double &out f, array<uint8> &out pat)
{
    bits = 0;
    f = 0;
    pat.resize(0);
    if (!has_key(r, k)) return false;
    json_type t = r.type(k);
    if (is_float(vt)) return opt_double(r, k, 0, f);
    if (is_pattern(vt))
    {
        if (t != json_type::string) return false;
        string s = r.get_string(k);
        bool ok;
        if (vt == VT_BYTES) ok = parse_hex_bytes(s, pat);
        else if (vt == VT_WSTRING) ok = utf8_to_utf16le(s, pat);
        else
        {
            ok = true;
            for (uint i = 0; i < s.length(); i++) pat.insertLast(s[i]);
        }
        return ok && pat.length() > 0 && pat.length() <= MAX_PATTERN;
    }
    uint w = vt_width(vt);
    bool neg = false;
    uint64 mag = 0;
    if (t == json_type::number)
    {
        double d = r.get_double(k);
        // integer types reject fractional JSON numbers (e.g. -0.5 must not truncate to 0)
        if (d != double(r.get_int64(k)) && d != double(r.get_uint64(k))) return false;
        if (d < 0) { neg = true; mag = uint64(-r.get_int64(k)); }
        else mag = r.get_uint64(k);
    }
    else if (t == json_type::string)
    {
        if (!parse_signed_mag(r.get_string(k), neg, mag)) return false;
    }
    else return false;
    return int_bits_from(neg, mag, w, bits);
}

// ---------------------------------------------------------------------------------------------
// Sending
// ---------------------------------------------------------------------------------------------

void send_json(json_obj@ o)
{
    string s = json::stringify(o);
    if (!ws::is_connected())
    {
        // replies die with the connection (the relay already failed them); events are kept
        if (o.get_string("type") != "event") return;
        g_evq_mx.lock();
        g_evq.insertLast(s);
        if (g_evq.length() > EVQ_MAX) g_evq.removeAt(0);
        g_evq_mx.unlock();
        return;
    }
    g_send_mx.lock();
    ws::send(s);
    g_send_mx.unlock();
}

json_obj@ ok_reply(const string &in verb, int64 id)
{
    json_obj@ o = json_obj();
    o.set("type", verb + "_result");
    o.set("id", id);
    o.set("success", true);
    return o;
}

void send_error(int64 id, int code, const string &in message, const string &in detail = "")
{
    json_obj@ o = json_obj();
    o.set("type", "error");
    o.set("id", id);
    o.set("code", code);
    o.set("message", message);
    o.set("detail", detail);
    send_json(o);
}

void bad_args(int64 id, const string &in detail) { send_error(id, E_BAD_ARGS, "bad arguments", detail); }

json_obj@ new_event(const string &in name)
{
    json_obj@ o = json_obj();
    o.set("type", "event");
    o.set("event", name);
    return o;
}

void emit_log(const string &in level, const string &in msg)
{
    if (level == "error") console::error(LOG_PREFIX + msg);
    else if (level == "warn") console::warn(LOG_PREFIX + msg);
    else console::log(LOG_PREFIX + msg);
    json_obj@ o = new_event("log");
    o.set("level", level);
    o.set("message", msg);
    send_json(o);
}

void send_progress(const string &in job, uint64 done, uint64 total)
{
    json_obj@ o = new_event("progress");
    o.set("job", job);
    o.set("done", done);
    o.set("total", total);
    send_json(o);
}

json_obj@ region_json(uint64 base, uint64 size, bool p, bool w, bool x)
{
    json_obj@ o = json_obj();
    o.set("base", hex_addr(base));
    o.set("size", size);
    o.set("present", p);
    o.set("writable", w);
    o.set("executable", x);
    return o;
}

void send_hello()
{
    g_state_mx.lock_shared();
    bool a = g_attached;
    uint64 pid = g_pid;
    uint64 base = g_base;
    uint64 peb = g_peb;
    string nm = g_name;
    g_state_mx.unlock_shared();
    json_obj@ o = new_event("hello");
    o.set("version", AGENT_VERSION);
    o.set("protocol", PROTOCOL_VERSION);
    o.set("user", util::get_username());
    o.set("attached", a);
    o.set("pid", a ? pid : uint64(0));
    o.set("base", hex_addr(a ? base : uint64(0)));
    o.set("peb", hex_addr(a ? peb : uint64(0)));
    o.set("name", a ? nm : "");
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Attach state and job slot
// ---------------------------------------------------------------------------------------------

bool is_attached()
{
    g_state_mx.lock_shared();
    bool a = g_attached;
    g_state_mx.unlock_shared();
    return a && process::is_alive();
}

bool require_attached(int64 id)
{
    if (is_attached()) return true;
    send_error(id, E_NOT_ATTACHED, "not attached", "attach to a process first");
    return false;
}

// Claims the job slot and its params under one lock: a job never observes another request's params.
bool claim_job(const string &in kind, int64 id, JobParams@ p, uint &out seq)
{
    g_state_mx.lock();
    bool ok = g_job == "";
    if (ok)
    {
        g_job = kind;
        g_job_id = id;
        g_job_seq++;
        g_job_t0 = util::tickcount();
        @g_job_params = p;
        g_cancel.store(false);
    }
    seq = g_job_seq;
    g_state_mx.unlock();
    return ok;
}

// Only clears the slot if it still belongs to `seq` (the watchdog may have recycled it).
void release_job(uint seq)
{
    g_state_mx.lock();
    if (g_job_seq == seq) { g_job = ""; @g_job_params = null; }
    g_state_mx.unlock();
}

bool job_busy()
{
    g_state_mx.lock_shared();
    bool b = g_job != "";
    g_state_mx.unlock_shared();
    return b;
}

bool time_up(uint64 t0) { return g_cancel.load() || util::tickcount() - t0 > JOB_TIME_LIMIT_MS; }

ScanState@ get_scan()
{
    g_scan_mx.lock_shared();
    ScanState@ s = g_scan;
    g_scan_mx.unlock_shared();
    return s;
}

void publish_scan(ScanState@ s)
{
    g_scan_mx.lock();
    @g_scan = s;
    g_scan_mx.unlock();
}

void clear_freeze()
{
    g_freeze_mx.lock();
    g_freeze.resize(0);
    g_freeze_mx.unlock();
}

void clear_watch()
{
    g_watch_mx.lock();
    g_watch.resize(0);
    g_watch_mx.unlock();
}

// Writes the pre-freeze bytes back to the target and empties the list. Call while still attached.
void restore_freeze()
{
    g_freeze_mx.lock();
    for (uint i = 0; i < g_freeze.length(); i++)
    {
        FreezeEntry@ e = g_freeze[i];
        if (e.has_original) process::write_bytes(e.original, e.address);
    }
    g_freeze.resize(0);
    g_freeze_mx.unlock();
}

bool was_attached()
{
    g_state_mx.lock_shared();
    bool a = g_attached;
    g_state_mx.unlock_shared();
    return a;
}

// Attaches by name (pid ignored) or by pid (name == ""). Runs on a job thread.
bool do_attach(const string &in name, uint32 pid, bool &out sock)
{
    sock = false;
    // Re-attaching to a different target must not leak frozen values into it: restore the old
    // target's bytes before the attach redirects memory access.
    if (was_attached()) restore_freeze();
    uint64 apid = 0;
    uint64 abase = 0;
    uint64 apeb = 0;
    if (name != "")
    {
        attach_data d = process::attach(name);
        apid = d.pid; abase = d.base_address; apeb = d.peb_address;
    }
    else
    {
        attach_data d = process::attach(pid);
        apid = d.pid; abase = d.base_address; apeb = d.peb_address;
    }
    if (apid == 0) return false;

    string pname = name;
    if (pname == "")
    {
        array<module_entry>@ mods = process::get_module_list();
        if (mods !is null)
            for (uint i = 0; i < mods.length(); i++)
                if (mods[i].base == abase) { pname = mods[i].name; break; }
    }

    // false also means "a socket is already active", which is fine after a re-attach.
    sock = process::open_socket(native_url());

    // Addresses from a previous target are meaningless now.
    publish_scan(null);
    clear_freeze();
    clear_watch();

    g_state_mx.lock();
    g_attached = true;
    g_pid = apid; g_base = abase; g_peb = apeb; g_name = pname;
    g_auto_pending = false;
    g_state_mx.unlock();

    console::log(LOG_PREFIX + "attached to " + pname + " (pid " + apid + ")");
    alert::show_tag("EchoDebug: attached to " + pname, TAG, 80, 200, 255);
    json_obj@ ev = new_event("attached");
    ev.set("pid", apid);
    ev.set("base", hex_addr(abase));
    ev.set("name", pname);
    send_json(ev);
    return true;
}

void mark_detached(const string &in why)
{
    g_state_mx.lock();
    g_attached = false;
    g_pid = 0; g_base = 0; g_peb = 0; g_name = "";
    g_state_mx.unlock();
    publish_scan(null);
    clear_freeze();
    clear_watch();
    emud_mark_stale();
    console::log(LOG_PREFIX + "detached (" + why + ")");
    alert::show_tag("EchoDebug: detached (" + why + ")", TAG, 255, 160, 40);
    send_json(new_event("detached"));
}

void job_main()
{
    g_state_mx.lock_shared();
    string kind = g_job;
    int64 id = g_job_id;
    uint seq = g_job_seq;
    JobParams@ p = g_job_params;
    g_state_mx.unlock_shared();

    if (kind == "attach") run_attach(id, p);
    else if (kind == "auto_attach")
    {
        bool sock;
        if (!do_attach(p.attach_name, 0, sock)) console::log(LOG_PREFIX + "waiting for " + p.attach_name);
    }
    else if (kind == "scan_new") run_scan_new(id, p.scan);
    else if (kind == "scan_next") run_scan_next(id, p.scan, p.old);
    else if (kind == "pointer_scan") run_pointer_scan(id, p.ptr);
    else if (kind == "emulate") run_emulate(id, p.emu);
    else if (kind == "peb_walk") run_peb_walk(id);

    release_job(seq);
}

// ---------------------------------------------------------------------------------------------
// Region walking
// ---------------------------------------------------------------------------------------------

// Collects regions intersecting [lo, hi) in ascending order. With `clip` the entries are cut to
// [lo, hi). Returns true when truncated (max_count, iteration or time guard hit). The time guard
// matters: this runs on a ws/job thread and the relay fails requests after 120 s.
bool walk_regions(uint64 t0, uint64 lo, uint64 hi, bool present_only, bool writable_only, uint max_count, bool clip, RegionList@ rl)
{
    uint64 addr = lo;
    uint64 stride = 0x1000;
    for (uint iter = 0; addr < hi; iter++)
    {
        if (iter >= WALK_MAX_ITER || time_up(t0)) return true;
        memory_region m = process::virtual_query(addr);
        uint64 rend = m.base + m.size;
        if (m.size == 0 || rend <= addr)
        {
            // Failed or non-advancing query: probe forward with a growing stride.
            addr += stride;
            if (stride < 0x40000000) stride <<= 1;
            continue;
        }
        stride = 0x1000;
        if ((!present_only || m.present) && (!writable_only || m.writable))
        {
            if (rl.base.length() >= max_count) return true;
            uint64 b = m.base;
            uint64 e = rend;
            if (clip)
            {
                if (b < lo) b = lo;
                if (e > hi) e = hi;
            }
            uint f = 0;
            if (m.present) f |= RF_PRESENT;
            if (m.writable) f |= RF_WRITABLE;
            if (m.executable) f |= RF_EXEC;
            rl.base.insertLast(b);
            rl.size.insertLast(e - b);
            rl.flags.insertLast(f);
            rl.total += e - b;
        }
        addr = rend;
    }
    return false;
}

// ---------------------------------------------------------------------------------------------
// Simple verbs
// ---------------------------------------------------------------------------------------------

void h_attach(json_obj@ r, int64 id)
{
    string name;
    if (!opt_str(r, "name", "", name)) { bad_args(id, "name must be a string"); return; }
    int64 pid = 0;
    if (!opt_int(r, "pid", 0, pid)) { bad_args(id, "pid must be a number"); return; }
    if (name == "" && pid == 0) { bad_args(id, "attach requires 'name' or 'pid'"); return; }
    if (name == "" && (pid < 0 || pid > int64(0xFFFFFFFF))) { bad_args(id, "pid out of range"); return; }
    JobParams@ p = JobParams();
    p.attach_name = name;
    p.attach_pid = uint32(pid);
    uint seq;
    if (!claim_job("attach", id, p, seq)) { send_error(id, E_BUSY, "busy", "another job is running"); return; }
    create_thread(0, @job_main);
}

void run_attach(int64 id, JobParams@ p)
{
    string name = p.attach_name;
    uint32 pid = p.attach_pid;
    bool sock;
    if (!do_attach(name, pid, sock))
    {
        send_error(id, E_FAILED, "attach failed", name != "" ? "process not found: " + name : "no process with pid " + pid);
        return;
    }
    g_state_mx.lock_shared();
    json_obj@ o = ok_reply("attach", id);
    o.set("pid", g_pid);
    o.set("base", hex_addr(g_base));
    o.set("peb", hex_addr(g_peb));
    o.set("name", g_name);
    g_state_mx.unlock_shared();
    o.set("native_socket", sock);
    send_json(o);
}

void h_detach(json_obj@ r, int64 id)
{
    if (job_busy()) { send_error(id, E_BUSY, "busy", "wait for the running job to finish"); return; }
    g_state_mx.lock();
    g_auto_pending = false;
    g_state_mx.unlock();
    if (was_attached()) restore_freeze();   // undo frozen values before the attach is gone
    process::detach();
    mark_detached("requested");
    send_json(ok_reply("detach", id));
}

void h_alive(json_obj@ r, int64 id)
{
    g_state_mx.lock_shared();
    bool a = g_attached;
    uint64 pid = g_pid;
    g_state_mx.unlock_shared();
    json_obj@ o = ok_reply("alive", id);
    o.set("alive", a && process::is_alive());
    o.set("pid", pid);
    send_json(o);
}

void h_write(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 addr;
    if (!get_addr(r, "address", addr)) { bad_args(id, "write requires 'address'"); return; }
    string hex;
    if (!opt_str(r, "data", "", hex)) { bad_args(id, "data must be a hex string"); return; }
    bool force;
    if (!opt_bool(r, "force", false, force)) { bad_args(id, "force must be a bool"); return; }
    array<uint8> bytes;
    if (!parse_hex_bytes(hex, bytes) || bytes.length() == 0) { bad_args(id, "data must be non-empty hex"); return; }
    if (bytes.length() > WRITE_MAX) { send_error(id, E_LIMIT, "limit exceeded", "write is limited to 1 MiB"); return; }
    // Echo writes physical memory: page protections do not apply and a bad address will not
    // simply fail. Unless forced, refuse writes that land in unmapped space (Echo docs golden rule).
    if (!force)
    {
        memory_region m0 = process::virtual_query(addr);
        memory_region m1 = process::virtual_query(addr + uint64(bytes.length()) - 1);
        if (!m0.present || !m1.present)
        {
            send_error(id, E_FAILED, "write target not mapped",
                       hex_addr(addr) + " .. " + hex_addr(addr + uint64(bytes.length()) - 1));
            return;
        }
    }
    array<uint8>@ before = process::read_bytes(addr, bytes.length());
    if (!process::write_bytes(bytes, addr)) { send_error(id, E_FAILED, "write failed", hex_addr(addr)); return; }
    journal("write", addr, before is null ? "" : hex_of(before, 0, before.length()), hex_of(bytes, 0, bytes.length()));
    memory_region m = process::virtual_query(addr);
    json_obj@ o = ok_reply("write", id);
    o.set("written", bytes.length());
    o.set("region", region_json(m.base, m.size, m.present, m.writable, m.executable));
    send_json(o);
}

void h_query(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 addr;
    if (!get_addr(r, "address", addr)) { bad_args(id, "query requires 'address'"); return; }
    memory_region m = process::virtual_query(addr);
    json_obj@ o = ok_reply("query", id);
    o.set("region", region_json(m.base, m.size, m.present, m.writable, m.executable));
    send_json(o);
}

void h_regions(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 lo;
    uint64 hi;
    int64 maxn;
    bool present_only;
    if (!opt_addr(r, "start", USER_LO, lo) || !opt_addr(r, "end", USER_HI, hi) ||
        !opt_int(r, "max", 20000, maxn) || !opt_bool(r, "present_only", true, present_only))
    {
        bad_args(id, "start/end must be addresses, max a number, present_only a bool");
        return;
    }
    if (hi <= lo || maxn <= 0) { bad_args(id, "need start < end and max > 0"); return; }
    if (maxn > int64(WALK_MAX_REGIONS)) maxn = WALK_MAX_REGIONS;

    RegionList@ rl = RegionList();
    bool trunc = walk_regions(util::tickcount(), lo, hi, present_only, false, uint(maxn), false, rl);
    json_obj@ arr = json::array();
    for (uint i = 0; i < rl.base.length(); i++)
    {
        uint f = rl.flags[i];
        arr.push(region_json(rl.base[i], rl.size[i], (f & RF_PRESENT) != 0, (f & RF_WRITABLE) != 0, (f & RF_EXEC) != 0));
    }
    json_obj@ o = ok_reply("regions", id);
    o.set("regions", arr);
    o.set("truncated", trunc);
    send_json(o);
}

// chain semantics (pointer_scan emits offsets in exactly this order):
//   cur = base
//   for each off in offsets: value = *(uint64*)cur; cur = value + off
//   final = cur
// e.g. base=game.exe+0x1234, offsets=[0x10, 0x8]  ->  final = *(*(base) + 0x10) + 0x8
void h_chain(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 base;
    if (!get_addr(r, "base", base)) { bad_args(id, "chain requires 'base'"); return; }
    if (!r.has("offsets") || r.type("offsets") != json_type::array) { bad_args(id, "offsets must be an array"); return; }
    json_obj@ offs = r.get_obj("offsets");
    if (offs.length() > CHAIN_MAX_OFFSETS) { send_error(id, E_LIMIT, "limit exceeded", "at most 64 offsets"); return; }
    array<int64> off;
    for (uint i = 0; i < offs.length(); i++)
    {
        json_type t = offs.type_at(i);
        int64 v = 0;
        if (t == json_type::number) v = offs.get_int64_at(i);
        else if (t != json_type::string || !parse_i64(offs.get_string_at(i), v)) { bad_args(id, "offsets must be numbers"); return; }
        off.insertLast(v);
    }

    json_obj@ hops = json::array();
    uint64 cur = base;
    bool ok = true;
    for (uint i = 0; i < off.length(); i++)
    {
        uint64 value = 0;
        bool rd = process::read_uint64(cur, value);
        json_obj@ h = json_obj();
        h.set("address", hex_addr(cur));
        h.set("value", hex_addr(value));
        hops.push(h);
        if (!rd || value == 0) { ok = false; break; }
        cur = value + uint64(off[i]);   // two's-complement add handles negative offsets
    }
    json_obj@ o = ok_reply("chain", id);
    o.set("hops", hops);
    o.set("final", hex_addr(cur));
    o.set("ok", ok);
    send_json(o);
}

void h_dump(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    string mod;
    string fname;
    if (!opt_str(r, "module", "", mod) || !opt_str(r, "filename", "", fname)) { bad_args(id, "module/filename must be strings"); return; }
    if (fname == "") { bad_args(id, "dump requires 'filename'"); return; }
    // Echo sandboxes file paths; keep the name flat so the reply path is exact.
    if (fname.findFirst("/") >= 0 || fname.findFirst("\\") >= 0 || fname.findFirst(":") >= 0 || fname.findFirst("..") >= 0)
    {
        bad_args(id, "filename must not contain path separators");
        return;
    }
    bool ok = mod != "" ? process::dump(mod, fname) : process::dump(fname);
    if (!ok) { send_error(id, E_FAILED, "dump failed", mod != "" ? mod : "main module"); return; }
    json_obj@ o = ok_reply("dump", id);
    o.set("path", "dmp/" + fname);
    send_json(o);
}

void h_freeze(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 addr;
    if (!get_addr(r, "address", addr)) { bad_args(id, "freeze requires 'address'"); return; }
    bool enabled;
    if (!opt_bool(r, "enabled", true, enabled)) { bad_args(id, "enabled must be a bool"); return; }
    string hex;
    if (!opt_str(r, "data", "", hex)) { bad_args(id, "data must be a hex string"); return; }
    string mode, vt, group;
    double step, minv, maxv;
    if (!opt_str(r, "mode", "set", mode) || !opt_str(r, "value_type", "", vt) || !opt_str(r, "group", "", group) ||
        !opt_double(r, "step", 1, step) || !opt_double(r, "min", 0, minv) || !opt_double(r, "max", 0, maxv))
    { bad_args(id, "mode set|add|clamp, value_type, group, step/min/max numbers"); return; }
    if (mode != "set" && mode != "add" && mode != "clamp") { bad_args(id, "mode must be set, add or clamp"); return; }
    if (mode != "set" && vt_width(vt) == 0) { bad_args(id, "add/clamp need a numeric value_type"); return; }
    array<uint8> bytes;
    if (enabled && mode != "set")
    {
        array<uint8>@ cur = process::read_bytes(addr, vt_width(vt));
        if (cur is null) { send_error(id, E_FAILED, "read failed", hex_addr(addr)); return; }
        bytes = cur;
    }
    else if (enabled)
    {
        if (!parse_hex_bytes(hex, bytes) || bytes.length() == 0) { bad_args(id, "data must be non-empty hex"); return; }
        if (bytes.length() > FREEZE_MAX_BYTES) { send_error(id, E_LIMIT, "limit exceeded", "freeze data is limited to 4096 bytes"); return; }
    }

    bool full = false;
    json_obj@ patched_ev;   // journal event for the app's patch journal (sent after unlock)
    g_freeze_mx.lock();
    int idx = -1;
    for (uint i = 0; i < g_freeze.length(); i++)
        if (g_freeze[i].address == addr) { idx = int(i); break; }
    if (enabled)
    {
        if (idx >= 0)
        {
            g_freeze[uint(idx)].data = bytes;
            g_freeze[uint(idx)].failed = false;
            FreezeEntry@ fe = g_freeze[uint(idx)];
            fe.mode = mode; fe.vtype = vt; fe.step = step; fe.minv = minv; fe.maxv = maxv; fe.group = group; fe.paused = false;
        }
        else if (g_freeze.length() >= FREEZE_MAX_ENTRIES) full = true;
        else
        {
            FreezeEntry@ e = FreezeEntry();
            e.address = addr;
            e.data = bytes;
            // capture the pre-freeze bytes once, so detach/unload can restore them
            array<uint8>@ orig = process::read_bytes(addr, bytes.length());
            if (orig !is null && orig.length() == bytes.length()) { e.original = orig; e.has_original = true; }
            e.mode = mode; e.vtype = vt; e.step = step; e.minv = minv; e.maxv = maxv; e.group = group;
            g_freeze.insertLast(e);
        }
        if (!full)
        {
            // one journal event per enable: old = pre-freeze bytes when captured, else previous data
            FreezeEntry@ e = idx >= 0 ? g_freeze[uint(idx)] : g_freeze[g_freeze.length() - 1];
            patched_ev = new_event("patched");
            patched_ev.set("address", hex_addr(addr));
            patched_ev.set("old", e.has_original ? hex_of(e.original, 0, e.original.length())
                                                 : hex_of(e.data, 0, e.data.length()));
            patched_ev.set("new", hex_of(bytes, 0, bytes.length()));
        }
    }
    else if (idx >= 0) g_freeze.removeAt(uint(idx));
    uint n = g_freeze.length();
    g_freeze_mx.unlock();

    if (full) { send_error(id, E_LIMIT, "limit exceeded", "at most 1024 frozen entries"); return; }
    if (patched_ev !is null) { send_json(patched_ev); journal("freeze", addr, patched_ev.get_string("old"), patched_ev.get_string("new")); }
    json_obj@ o = ok_reply("freeze", id);
    o.set("frozen", n);
    send_json(o);
}

void h_freeze_list(json_obj@ r, int64 id)
{
    json_obj@ arr = json::array();
    g_freeze_mx.lock_shared();
    for (uint i = 0; i < g_freeze.length(); i++)
    {
        json_obj@ e = json_obj();
        e.set("address", hex_addr(g_freeze[i].address));
        e.set("data", hex_of(g_freeze[i].data, 0, g_freeze[i].data.length()));
        e.set("mode", g_freeze[i].mode);
        if (g_freeze[i].vtype != "") e.set("value_type", g_freeze[i].vtype);
        if (g_freeze[i].mode == "add") e.set("step", g_freeze[i].step);
        if (g_freeze[i].mode == "clamp") { e.set("min", g_freeze[i].minv); e.set("max", g_freeze[i].maxv); }
        if (g_freeze[i].group != "") e.set("group", g_freeze[i].group);
        e.set("paused", g_freeze[i].paused);
        arr.push(e);
    }
    g_freeze_mx.unlock_shared();
    json_obj@ o = ok_reply("freeze_list", id);
    o.set("entries", arr);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Watch list: the agent samples these addresses at 10 tps and emits watch_event on change
// ---------------------------------------------------------------------------------------------

void h_watch(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 addr;
    if (!get_addr(r, "address", addr)) { bad_args(id, "watch requires 'address'"); return; }
    int64 sz;
    if (!opt_int(r, "size", 4, sz)) { bad_args(id, "size must be a number"); return; }
    if (sz < 1 || sz > int64(WATCH_MAX_BYTES)) { send_error(id, E_LIMIT, "limit exceeded", "watch size must be 1..256"); return; }
    string vt, cond;
    double cval;
    bool alert;
    if (!opt_str(r, "value_type", "", vt) || !opt_str(r, "condition", "any", cond) || !opt_double(r, "value", 0, cval) || !opt_bool(r, "alert", false, alert))
    { bad_args(id, "value_type string, condition any|eq|ne|gt|lt|delta, value number, alert bool"); return; }
    if (vt != "" && vt_width(vt) == 0) { bad_args(id, "value_type must be u8..u64, i8..i64, f32 or f64"); return; }
    if (cond != "any" && vt == "") { bad_args(id, "conditions need a numeric value_type"); return; }
    if (cond != "any" && cond != "eq" && cond != "ne" && cond != "gt" && cond != "lt" && cond != "delta") { bad_args(id, "unknown condition " + cond); return; }
    if (vt != "" && uint(sz) < vt_width(vt)) sz = int64(vt_width(vt));
    string label;
    if (!opt_str(r, "label", "", label)) { bad_args(id, "label must be a string"); return; }

    g_watch_mx.lock();
    int idx = -1;
    for (uint i = 0; i < g_watch.length(); i++)
        if (g_watch[i].address == addr) { idx = int(i); break; }
    if (idx >= 0)
    {
        g_watch[uint(idx)].size = uint(sz);
        if (label != "") g_watch[uint(idx)].label = label;
        g_watch[uint(idx)].vtype = vt; g_watch[uint(idx)].cond = cond; g_watch[uint(idx)].cval = cval; g_watch[uint(idx)].alert = alert;
    }
    else if (g_watch.length() >= WATCH_MAX_ENTRIES)
    {
        g_watch_mx.unlock();
        send_error(id, E_LIMIT, "limit exceeded", "at most 256 watched addresses");
        return;
    }
    else
    {
        WatchEntry@ e = WatchEntry();
        e.address = addr;
        e.size = uint(sz);
        e.label = label;
        e.vtype = vt; e.cond = cond; e.cval = cval; e.alert = alert;
        // seed with the current value so the first event only fires on a real change
        array<uint8>@ b = process::read_bytes(addr, uint(sz));
        if (b !is null && b.length() == uint(sz)) { e.prev = b; e.has_prev = true; }
        g_watch.insertLast(e);
    }
    uint n = g_watch.length();
    g_watch_mx.unlock();
    json_obj@ o = ok_reply("watch", id);
    o.set("watched", n);
    send_json(o);
}

void h_unwatch(json_obj@ r, int64 id)
{
    uint64 addr;
    if (!get_addr(r, "address", addr)) { bad_args(id, "unwatch requires 'address'"); return; }
    g_watch_mx.lock();
    for (uint i = 0; i < g_watch.length(); i++)
        if (g_watch[i].address == addr) { g_watch.removeAt(i); break; }
    uint n = g_watch.length();
    g_watch_mx.unlock();
    json_obj@ o = ok_reply("unwatch", id);
    o.set("watched", n);
    send_json(o);
}

void h_watch_list(json_obj@ r, int64 id)
{
    json_obj@ arr = json::array();
    g_watch_mx.lock_shared();
    for (uint i = 0; i < g_watch.length(); i++)
    {
        json_obj@ e = json_obj();
        e.set("address", hex_addr(g_watch[i].address));
        e.set("size", g_watch[i].size);
        e.set("label", g_watch[i].label);
        e.set("last", g_watch[i].has_prev ? hex_of(g_watch[i].prev, 0, g_watch[i].prev.length()) : "");
        e.set("hits", g_watch[i].hits);
        if (g_watch[i].vtype != "") e.set("value_type", g_watch[i].vtype);
        if (g_watch[i].cond != "any") { e.set("condition", g_watch[i].cond); e.set("value", g_watch[i].cval); }
        json_obj@ hist = json::array();
        for (uint k = 0; k < g_watch[i].history.length(); k++) hist.push(g_watch[i].history[k]);
        e.set("history", hist);
        arr.push(e);
    }
    g_watch_mx.unlock_shared();
    json_obj@ o = ok_reply("watch_list", id);
    o.set("entries", arr);
    send_json(o);
}

// 10 tps: sample watched addresses, emit watch_event on change.
void watch_tick()
{
    if (!is_attached() || g_pause_watch) return;
    g_watch_mx.lock();
    for (uint i = 0; i < g_watch.length(); i++)
    {
        WatchEntry@ e = g_watch[i];
        array<uint8>@ cur = process::read_bytes(e.address, e.size);
        if (cur is null || cur.length() != e.size) continue;
        if (e.has_prev && bytes_eq(cur, 0, e.prev, 0, e.size)) continue;
        string old = e.has_prev ? hex_of(e.prev, 0, e.prev.length()) : "";
        double ov = 0, nv = 0;
        bool num = e.vtype != "" && num_decode(e.vtype, cur, nv) && (!e.has_prev || num_decode(e.vtype, e.prev, ov));
        bool fire = true;
        if (e.cond != "any" && num)
        {
            if (e.cond == "eq") fire = nv == e.cval;
            else if (e.cond == "ne") fire = nv != e.cval;
            else if (e.cond == "gt") fire = nv > e.cval;
            else if (e.cond == "lt") fire = nv < e.cval;
            else if (e.cond == "delta") fire = e.has_prev && (nv - ov >= e.cval || ov - nv >= e.cval);
        }
        e.prev = cur;
        e.has_prev = true;
        string nh = hex_of(cur, 0, cur.length());
        e.history.insertLast(nh);
        if (e.history.length() > WATCH_HISTORY) e.history.removeAt(0);
        if (!fire) continue;
        e.hits++;
        uint hits = e.hits;
        bool al = e.alert;
        string lbl = e.label;
        uint64 ad = e.address;
        string vt = e.vtype;
        g_watch_mx.unlock();
        json_obj@ ev = new_event("watch_event");
        ev.set("address", hex_addr(ad));
        if (lbl != "") ev.set("label", lbl);
        ev.set("old", old);
        ev.set("new", nh);
        ev.set("hits", hits);
        if (num) { ev.set("old_value", ov); ev.set("new_value", nv); ev.set("value_type", vt); }
        send_json(ev);
        if (al) notify((lbl != "" ? lbl : hex_addr(ad)) + (num ? " = " + nv : " changed"), 255, 220, 80);
        g_watch_mx.lock();
    }
    g_watch_mx.unlock();
}

// ---------------------------------------------------------------------------------------------
// Typed read: one call returns a decoded value instead of raw hex
// ---------------------------------------------------------------------------------------------

void h_read_typed(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 addr;
    if (!get_addr(r, "address", addr)) { bad_args(id, "read_typed requires 'address'"); return; }
    string vt;
    if (!opt_str(r, "type", "", vt)) { bad_args(id, "read_typed requires 'type'"); return; }
    int64 len = 0;
    if (!opt_int(r, "length", 0, len)) { bad_args(id, "length must be a number"); return; }

    json_obj@ o = ok_reply("read_typed", id);
    o.set("address", hex_addr(addr));
    o.set("type", vt);
    if (vt == "u8" || vt == "u16" || vt == "u32" || vt == "u64" ||
        vt == "i8" || vt == "i16" || vt == "i32" || vt == "i64" || vt == "f32" || vt == "f64")
    {
        uint w = vt == "u8" || vt == "i8" ? 1 : vt == "u16" || vt == "i16" ? 2 : vt == "f32" ? 4 : 8;
        if (vt == "u32" || vt == "i32") w = 4;
        array<uint8>@ b = process::read_bytes(addr, w);
        if (b is null || b.length() != w) { o.set("ok", false); send_json(o); return; }
        uint64 bits = 0;
        for (uint i = 0; i < w; i++) bits |= uint64(b[i]) << (8 * i);
        o.set("ok", true);
        o.set("raw", bits_hex(bits, w));
        if (vt == "f32" || vt == "f64")
        {
            double v;
            o.set("value", flt_decode(w, bits, v) ? util::format_string("{}", v) : "NaN/Inf");
        }
        else if (vt == "i8" || vt == "i16" || vt == "i32" || vt == "i64")
        {
            int64 sv = int64(bits);
            if (w < 8) sv = (sv << (64 - w * 8)) >> (64 - w * 8);   // sign-extend
            o.set("value", util::format_string("{}", sv));
        }
        else o.set("value", util::format_string("{}", bits));
    }
    else if (vt == "string" || vt == "wstring")
    {
        uint n = uint(len > 0 ? len : (vt == "string" ? 256 : 512));
        if (n > 4096) n = 4096;
        array<uint8>@ b = process::read_bytes(addr, n);
        if (b is null || b.length() == 0) { o.set("ok", false); send_json(o); return; }
        if (vt == "string")
        {
            string s;
            bool rd = process::read_string(addr, s);   // null-terminated, 256 char max
            uint k = 0;
            while (k < b.length() && b[k] != 0) k++;
            o.set("ok", rd);
            o.set("value", s);
            o.set("raw", hex_of(b, 0, k));
        }
        else
        {
            uint k = 0;
            while (k + 1 < b.length() && (b[k] != 0 || b[k + 1] != 0)) k += 2;
            array<uint8> w2;
            for (uint i = 0; i < k; i++) w2.insertLast(b[i]);
            o.set("ok", true);
            o.set("value", util::wide_to_string(w2, true));
            o.set("raw", hex_of(b, 0, k));
        }
    }
    else if (vt == "bytes")
    {
        uint n = uint(len > 0 ? len : 16);
        if (n > 4096) { send_error(id, E_LIMIT, "limit exceeded", "bytes length must be 1..4096"); return; }
        array<uint8>@ b = process::read_bytes(addr, n);
        if (b is null || b.length() != n) { o.set("ok", false); send_json(o); return; }
        o.set("ok", true);
        o.set("value", hex_of(b, 0, n));
    }
    else { bad_args(id, "unknown type: " + vt + " (u8..u64, i8..i64, f32, f64, string, wstring, bytes)"); return; }
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Region statistics: aggregate the region walk by protection flags
// ---------------------------------------------------------------------------------------------

void h_region_stats(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 lo;
    uint64 hi;
    if (!opt_addr(r, "start", USER_LO, lo) || !opt_addr(r, "end", USER_HI, hi) || hi <= lo)
    {
        bad_args(id, "start/end must be addresses with start < end");
        return;
    }
    uint64 t0 = util::tickcount();
    RegionList@ rl = RegionList();
    bool trunc = walk_regions(t0, lo, hi, false, false, WALK_MAX_REGIONS, true, rl);
    uint n_present = 0, n_write = 0, n_exec = 0, n_rw = 0, n_rx = 0;
    uint64 b_present = 0, b_write = 0, b_exec = 0;
    for (uint i = 0; i < rl.base.length(); i++)
    {
        uint f = rl.flags[i];
        bool p = (f & RF_PRESENT) != 0, w = (f & RF_WRITABLE) != 0, x = (f & RF_EXEC) != 0;
        if (p) { n_present++; b_present += rl.size[i]; }
        if (w) { n_write++; b_write += rl.size[i]; }
        if (x) { n_exec++; b_exec += rl.size[i]; }
        if (w && !x) n_rw++;
        if (x && !w) n_rx++;
    }
    json_obj@ o = ok_reply("region_stats", id);
    o.set("regions", rl.base.length());
    o.set("present", n_present);
    o.set("writable", n_write);
    o.set("executable", n_exec);
    o.set("rw_regions", n_rw);
    o.set("rx_regions", n_rx);
    o.set("present_bytes", b_present);
    o.set("writable_bytes", b_write);
    o.set("executable_bytes", b_exec);
    o.set("truncated", trunc);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Value scanner
// ---------------------------------------------------------------------------------------------

json_obj@ build_sample(ScanState@ st)
{
    json_obj@ a = json::array();
    if (st.snap_mode) return a;   // unknown first scan: nothing to show until scan_next
    uint n = st.addrs.length();
    if (n > SAMPLE_MAX) n = SAMPLE_MAX;
    for (uint i = 0; i < n; i++)
    {
        json_obj@ o = json_obj();
        o.set("address", hex_addr(st.addrs[i]));
        o.set("value", st.prev_hex(i));
        a.push(o);
    }
    return a;
}

void send_scan_reply(const string &in verb, int64 id, ScanState@ st, const string &in note)
{
    json_obj@ o = ok_reply(verb, id);
    o.set("count", st.count());
    o.set("sample", build_sample(st));
    o.set("truncated", st.truncated);
    if (note != "") o.set("note", note);
    send_json(o);
}

bool valid_alignment(int64 a) { return a >= 1 && a <= 4096 && (a & (a - 1)) == 0; }

// Fills targets of `s` from value/value2 for its op. Returns "" or an error detail.
string parse_targets(json_obj@ r, ScanSpec@ s)
{
    if (!op_needs_value(s.op)) return "";
    double f;
    array<uint8> pat;
    uint64 bits;
    if (!parse_value(r, "value", s.vtype, bits, f, pat)) return "missing or invalid 'value' for this value_type";
    s.raw1 = bits;
    s.t1 = int_key(s.vtype, s.width, bits);
    s.f1 = f;
    s.pattern = pat;
    if (s.op == OP_BETWEEN)
    {
        if (!parse_value(r, "value2", s.vtype, bits, f, pat)) return "between requires a valid 'value2'";
        s.t2 = int_key(s.vtype, s.width, bits);
        s.f2 = f;
        if (s.t1 > s.t2) { uint64 t = s.t1; s.t1 = s.t2; s.t2 = t; }
        if (s.f1 > s.f2) { double t = s.f1; s.f1 = s.f2; s.f2 = t; }
    }
    return "";
}

void h_scan_new(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    ScanSpec@ s = ScanSpec();
    string vts;
    string cmp;
    if (!opt_str(r, "value_type", "", vts) || !opt_str(r, "compare", "exact", cmp)) { bad_args(id, "value_type/compare must be strings"); return; }
    s.vtype = vt_parse(vts);
    if (s.vtype < 0) { bad_args(id, "unknown value_type: " + vts); return; }
    s.op = op_parse(cmp);
    if (s.op != OP_EXACT && s.op != OP_UNKNOWN && s.op != OP_GREATER && s.op != OP_LESS && s.op != OP_BETWEEN)
    {
        bad_args(id, "scan_new compare must be exact, unknown, greater, less or between");
        return;
    }
    bool pattern = is_pattern(s.vtype);
    if (pattern && s.op != OP_EXACT) { bad_args(id, vts + " scans only support compare 'exact'"); return; }
    s.width = vt_width(s.vtype);
    string err = parse_targets(r, s);
    if (err != "") { bad_args(id, err); return; }
    if (pattern) s.width = s.pattern.length();

    int64 al;
    if (!opt_int(r, "alignment", pattern ? int64(1) : int64(s.width), al) || !valid_alignment(al)) { bad_args(id, "alignment must be a power of two in 1..4096"); return; }
    s.align = uint64(al);
    double eps;
    if (!opt_double(r, "float_epsilon", 0.0001, eps) || eps < 0) { bad_args(id, "float_epsilon must be >= 0"); return; }
    s.eps = eps;
    bool wo;
    if (!opt_bool(r, "writable_only", true, wo)) { bad_args(id, "writable_only must be a bool"); return; }
    s.writable_only = wo;

    string mod;
    if (!opt_str(r, "module", "", mod)) { bad_args(id, "module must be a string"); return; }
    if (mod != "")
    {
        uint64 mb = process::get_module_base(mod);
        uint64 ms = mb != 0 ? uint64(process::get_module_size(mb)) : uint64(0);
        if (mb == 0 || ms == 0) { bad_args(id, "module not found: " + mod); return; }
        s.lo = mb;
        s.hi = mb + ms;
    }
    else
    {
        uint64 lo;
        uint64 hi;
        if (!opt_addr(r, "start", USER_LO, lo) || !opt_addr(r, "end", USER_HI, hi) || hi <= lo)
        {
            bad_args(id, "start/end must be addresses with start < end");
            return;
        }
        s.lo = lo;
        s.hi = hi;
    }

    JobParams@ p = JobParams();
    @p.scan = s;
    uint seq;
    if (!claim_job("scan_new", id, p, seq)) { send_error(id, E_BUSY, "busy", "another job is running"); return; }
    create_thread(0, @job_main);
}

// Numeric first-scan over one chunk. Returns true once the candidate cap is hit.
bool scan_num_chunk(memory_buffer@ buf, uint64 pos, uint64 first, uint64 limit, ScanSpec@ s, ScanState@ st, uint cap)
{
    uint w = s.width;
    uint64 al = s.align;
    bool fast = !is_float(s.vtype) && s.op == OP_EXACT;
    uint64 want = s.raw1;
    for (uint64 o = first; o < limit; o += al)
    {
        uint64 bits;
        if (w == 4) bits = buf.read_uint32(o);
        else if (w == 8) bits = buf.read_uint64(o);
        else if (w == 2) bits = buf.read_uint16(o);
        else bits = buf.read_uint8(o);
        if (fast ? bits != want : !test_num(s.op, s, bits, 0)) continue;
        st.addrs.insertLast(pos + o);
        st.prev.insertLast(bits);
        if (st.addrs.length() >= cap) return true;
    }
    return false;
}

bool pat_at(memory_buffer@ buf, uint64 o, const array<uint8> &in p)
{
    for (uint k = 1; k < p.length(); k++)
        if (buf.read_uint8(o + k) != p[k]) return false;
    return true;
}

bool add_pat_hit(ScanState@ st, uint64 a, const array<uint8> &in p, uint cap)
{
    st.addrs.insertLast(a);
    for (uint k = 0; k < p.length(); k++) st.prev_raw.insertLast(p[k]);
    return st.addrs.length() >= cap;
}

// Byte-pattern first-scan over one chunk. With alignment 1 it tests 8 bytes at a time for the first
// pattern byte (SWAR "has byte"), which skips most of memory without per-byte script work.
bool scan_pat_chunk(memory_buffer@ buf, uint64 pos, uint64 first, uint64 limit, uint64 want, ScanSpec@ s, ScanState@ st, uint cap)
{
    uint8 p0 = s.pattern[0];
    uint64 al = s.align;
    uint64 bc = uint64(p0) * uint64(0x0101010101010101);
    uint64 o = first;
    while (o < limit)
    {
        if (al == 1 && o + 8 <= want)
        {
            uint64 x = buf.read_uint64(o) ^ bc;
            if (((x - uint64(0x0101010101010101)) & ~x & uint64(0x8080808080808080)) == 0) { o += 8; continue; }
            uint64 blk = o + 8;
            for (; o < blk && o < limit; o++)
                if (buf.read_uint8(o) == p0 && pat_at(buf, o, s.pattern) && add_pat_hit(st, pos + o, s.pattern, cap)) return true;
            continue;
        }
        if (buf.read_uint8(o) == p0 && pat_at(buf, o, s.pattern) && add_pat_hit(st, pos + o, s.pattern, cap)) return true;
        o += al;
    }
    return false;
}

void run_scan_new(int64 id, ScanSpec@ s)
{
    uint64 t0 = util::tickcount();
    RegionList@ rl = RegionList();
    bool trunc = walk_regions(t0, s.lo, s.hi, true, s.writable_only, WALK_MAX_REGIONS, true, rl);
    string note = trunc ? "region list truncated" : "";

    ScanState@ st = ScanState(s);
    st.pattern = s.pattern;
    bool pattern = is_pattern(s.vtype);
    bool unknown = s.op == OP_UNKNOWN;
    st.snap_mode = unknown;
    uint cap = MAX_CANDIDATES;
    if (pattern && PREV_RAW_CAP / s.width < cap) cap = uint(PREV_RAW_CAP / s.width);

    if (par_scan_new(id, s, rl, st, note))
    {
        send_progress("scan_new", rl.total, rl.total);
        publish_scan(st);
        send_scan_reply("scan_new", id, st, note);
        notify("scan finished: " + st.count() + " results", 120, 255, 160);
        return;
    }
    uint64 w = s.width;
    uint64 al = s.align;
    uint64 snap_bytes = 0;
    uint64 done = 0;
    bool stop = false;
    Progress pg("scan_new", rl.total);

    for (uint ri = 0; ri < rl.base.length() && !stop; ri++)
    {
        uint64 re = rl.base[ri] + rl.size[ri];
        for (uint64 pos = rl.base[ri]; pos < re; pos += CHUNK)
        {
            if (time_up(t0)) { stop = true; trunc = true; note = "time limit reached"; break; }
            uint64 core = umin(CHUNK, re - pos);
            // Read w-1 extra bytes so values straddling the chunk boundary are still seen.
            uint64 want = umin(CHUNK + w - 1, re - pos);
            done += core;
            pg.update(done);
            if (want < w) continue;
            memory_buffer@ buf = process::read_buffer(pos, want);
            if (buf is null) continue;
            uint64 limit = umin(want - w + 1, core);
            uint64 first = align_up(pos, al) - pos;
            if (unknown)
            {
                if (snap_bytes + want > SNAPSHOT_CAP) { stop = true; trunc = true; note = "snapshot cap (256 MiB) reached"; break; }
                snap_bytes += want;
                st.snaps.insertLast(buf);
                st.snap_base.insertLast(pos);
                st.snap_limit.insertLast(limit);
                if (first < limit) st.snap_slots += (limit - first + al - 1) / al;
                continue;
            }
            bool full = pattern ? scan_pat_chunk(buf, pos, first, limit, want, s, st, cap)
                                : scan_num_chunk(buf, pos, first, limit, s, st, cap);
            if (full) { stop = true; trunc = true; note = "candidate cap reached"; break; }
        }
    }
    send_progress("scan_new", rl.total, rl.total);
    st.truncated = trunc;
    publish_scan(st);
    send_scan_reply("scan_new", id, st, note);
}

void h_scan_next(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    ScanState@ old = get_scan();
    if (old is null) { bad_args(id, "no active scan; run scan_new first"); return; }
    string cmp;
    if (!opt_str(r, "compare", "", cmp)) { bad_args(id, "compare must be a string"); return; }
    int op = op_parse(cmp);
    if (op < 0 || op == OP_UNKNOWN) { bad_args(id, "unknown compare for scan_next: " + cmp); return; }
    if (is_pattern(old.vtype) && op != OP_EXACT && op != OP_CHANGED && op != OP_UNCHANGED)
    {
        bad_args(id, "compare '" + cmp + "' needs a numeric value_type");
        return;
    }
    ScanSpec@ s = ScanSpec();
    s.vtype = old.vtype;
    s.width = old.width;
    s.align = old.align;
    s.op = op;
    double eps;
    if (!opt_double(r, "float_epsilon", old.eps, eps) || eps < 0) { bad_args(id, "float_epsilon must be >= 0"); return; }
    s.eps = eps;
    string err = parse_targets(r, s);
    if (err != "") { bad_args(id, err); return; }
    if (is_pattern(s.vtype) && op == OP_EXACT && s.pattern.length() != s.width)
    {
        bad_args(id, "value must have the same byte length as the first scan (" + s.width + ")");
        return;
    }

    JobParams@ p = JobParams();
    @p.scan = s;
    @p.old = old;
    uint seq;
    if (!claim_job("scan_next", id, p, seq)) { send_error(id, E_BUSY, "busy", "another job is running"); return; }
    create_thread(0, @job_main);
}

void run_scan_next(int64 id, ScanSpec@ s, ScanState@ old)
{
    uint64 t0 = util::tickcount();
    ScanState@ st = ScanState(s);
    if (s.op == OP_EXACT) st.pattern = s.pattern;
    else st.pattern = old.pattern;
    uint w = s.width;
    uint64 al = s.align;
    bool trunc = false;
    string note = "";

    if (old.snap_mode)
    {
        // First scan_next after an unknown-initial-value scan: diff snapshots against live memory.
        uint64 total = 0;
        for (uint i = 0; i < old.snaps.length(); i++) total += old.snap_limit[i];
        Progress pg("scan_next", total);
        uint64 done = 0;
        bool stop = false;
        for (uint i = 0; i < old.snaps.length() && !stop; i++)
        {
            if (time_up(t0)) { trunc = true; note = "time limit reached"; break; }
            memory_buffer@ sb = old.snaps[i];
            uint64 base = old.snap_base[i];
            uint64 lim = old.snap_limit[i];
            done += lim;
            pg.update(done);
            memory_buffer@ lb = process::read_buffer(base, sb.size());
            if (lb is null) continue;
            for (uint64 o = align_up(base, al) - base; o < lim; o += al)
            {
                uint64 c = buf_read(lb, o, w);
                if (!test_num(s.op, s, c, buf_read(sb, o, w))) continue;
                st.addrs.insertLast(base + o);
                st.prev.insertLast(c);
                if (st.addrs.length() >= MAX_CANDIDATES) { stop = true; trunc = true; note = "candidate cap reached"; break; }
            }
        }
        send_progress("scan_next", total, total);
    }
    else
    {
        uint n = old.addrs.length();
        Progress pg("scan_next", n);
        bool pattern = is_pattern(s.vtype);
        PageReader pr;
        for (uint i = 0; i < n; i++)
        {
            if ((i & 0xFFFF) == 0)
            {
                if (time_up(t0)) { trunc = true; note = "time limit reached"; break; }
                pg.update(i);
            }
            uint64 a = old.addrs[i];
            if (pattern)
            {
                array<uint8> cur;
                if (!pr.read_buf(a, w, cur)) continue;
                bool eq = (s.op == OP_EXACT) ? bytes_eq(cur, 0, s.pattern, 0, w) : bytes_eq(cur, 0, old.prev_raw, i * w, w);
                if ((s.op == OP_CHANGED) == eq) continue;
                if (add_pat_hit(st, a, cur, MAX_CANDIDATES)) break;
                continue;
            }
            uint64 c;
            if (!pr.read(a, w, c)) continue;
            if (!test_num(s.op, s, c, old.prev[i])) continue;
            st.addrs.insertLast(a);
            st.prev.insertLast(c);
        }
        send_progress("scan_next", n, n);
    }
    st.truncated = trunc;
    publish_scan(st);
    send_scan_reply("scan_next", id, st, note);
}

void h_scan_results(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    int64 off;
    int64 lim;
    if (!opt_int(r, "offset", 0, off) || !opt_int(r, "limit", 100, lim) || off < 0 || lim < 0) { bad_args(id, "offset/limit must be non-negative numbers"); return; }
    if (lim > int64(RESULTS_PAGE_MAX)) lim = RESULTS_PAGE_MAX;

    json_obj@ arr = json::array();
    json_obj@ o = ok_reply("scan_results", id);
    ScanState@ st = get_scan();
    if (st is null)
    {
        o.set("count", uint(0));
        o.set("results", arr);
        send_json(o);
        return;
    }
    o.set("count", st.count());
    if (!st.snap_mode)
    {
        uint n = st.addrs.length();
        for (uint i = uint(umin(uint64(off), n)); i < n && i < uint64(off + lim); i++)
        {
            json_obj@ e = json_obj();
            e.set("address", hex_addr(st.addrs[i]));
            array<uint8>@ cur = process::read_bytes(st.addrs[i], st.width);
            e.set("value", (cur !is null && cur.length() == st.width) ? hex_of(cur, 0, st.width) : "");
            e.set("previous", st.prev_hex(i));
            arr.push(e);
        }
    }
    o.set("results", arr);
    send_json(o);
}

void h_scan_clear(json_obj@ r, int64 id)
{
    if (job_busy()) { send_error(id, E_BUSY, "busy", "wait for the running job to finish"); return; }
    publish_scan(null);
    send_json(ok_reply("scan_clear", id));
}

// ---------------------------------------------------------------------------------------------
// Pointer scan
// ---------------------------------------------------------------------------------------------
//
// Reverse BFS from the target. Level d finds every 8-byte aligned slot L in writable memory whose
// value v satisfies t - max_offset <= v <= t for some node t of level d-1. Each hit is a node
// (address L, parent t, offset t - v). A hit inside a module image is a root and becomes a result;
// other hits seed the next level. For a root L matched against node j with offset o:
//
//   offsets = [o, off(j), off(parent(j)), ..., off(level-1 node)]
//
// which is exactly what chain() walks: *(L) + o == addr(j), *(addr(j)) + off(j) == addr(parent(j)),
// ..., ending at the target. So chain(module_base + module_offset, offsets).final == target.

void h_pointer_scan(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    PtrSpec@ p = PtrSpec();
    int64 depth;
    int64 maxoff;
    int64 maxres;
    uint64 target;
    bool mor;
    if (!get_addr(r, "target", target)) { bad_args(id, "pointer_scan requires 'target'"); return; }
    if (!opt_int(r, "max_depth", 3, depth) || !opt_int(r, "max_offset", 0x400, maxoff) ||
        !opt_int(r, "max_results", 500, maxres) || !opt_bool(r, "module_only_roots", true, mor))
    {
        bad_args(id, "max_depth/max_offset/max_results must be numbers, module_only_roots a bool");
        return;
    }
    if (depth < 1 || maxoff < 0 || maxres < 1) { bad_args(id, "need max_depth >= 1, max_offset >= 0, max_results >= 1"); return; }
    if (depth > 5 || maxoff > int64(PS_MAX_OFFSET_CAP) || maxres > int64(PS_MAX_RESULTS_CAP))
    {
        send_error(id, E_LIMIT, "limit exceeded", "max_depth <= 5, max_offset <= 0x10000, max_results <= 10000");
        return;
    }
    p.target = target;
    p.module_only_roots = mor;
    p.depth = int(depth);
    p.max_offset = uint64(maxoff);
    p.max_results = uint(maxres);

    JobParams@ jp = JobParams();
    @jp.ptr = p;
    uint seq;
    if (!claim_job("pointer_scan", id, jp, seq)) { send_error(id, E_BUSY, "busy", "another job is running"); return; }
    create_thread(0, @job_main);
}

void run_pointer_scan(int64 id, PtrSpec@ p)
{
    uint64 t0 = util::tickcount();
    array<uint64> mb;
    array<uint64> me;
    array<string> mn;
    array<module_entry>@ mods = process::get_module_list();
    if (mods !is null)
        for (uint i = 0; i < mods.length(); i++)
        {
            mb.insertLast(mods[i].base);
            me.insertLast(mods[i].base + mods[i].size);
            mn.insertLast(mods[i].name);
        }

    RegionList@ rl = RegionList();
    bool trunc = walk_regions(t0, USER_LO, USER_HI, true, true, WALK_MAX_REGIONS, true, rl);
    string note = trunc ? "region list truncated" : "";

    // Node store; node 0 is the target. Each level's nodes are appended in ascending address order
    // (regions and offsets are walked upwards), so every level is a sorted slice for binary search.
    array<uint64> n_addr = { p.target };
    array<int> n_parent = { -1 };
    array<int64> n_off = { 0 };
    uint lvl_begin = 0;
    uint lvl_end = 1;
    uint64 maxoff = p.max_offset;

    json_obj@ results = json::array();
    uint nres = 0;
    uint64 scanned = 0;
    bool stop = false;
    Progress pg("pointer_scan", rl.total * uint64(p.depth));

    for (int depth = 1; depth <= p.depth && !stop; depth++)
    {
        uint64 vmin = n_addr[lvl_begin] > maxoff ? n_addr[lvl_begin] - maxoff : uint64(0);
        uint64 vmax = n_addr[lvl_end - 1];
        // Cheap pre-filter: a byte per (page number mod 1M) for every page some [t - maxoff, t] touches.
        array<uint8> bloom(PS_BLOOM_SIZE, 0);
        for (uint j = lvl_begin; j < lvl_end; j++)
        {
            uint64 t = n_addr[j];
            uint64 lo = t > maxoff ? t - maxoff : uint64(0);
            for (uint64 pgn = lo >> 12; pgn <= (t >> 12); pgn++) bloom[uint(pgn & 0xFFFFF)] = 1;
        }
        uint next_begin = n_addr.length();
        bool level_full = false;

        for (uint ri = 0; ri < rl.base.length() && !stop; ri++)
        {
            uint64 re = rl.base[ri] + rl.size[ri];
            for (uint64 pos = rl.base[ri]; pos < re && !stop; pos += CHUNK)
            {
                uint64 len = umin(CHUNK, re - pos);
                if (time_up(t0)) { stop = true; trunc = true; note = "time limit reached"; break; }
                if (scanned + len > PS_MAX_SCAN_BYTES) { stop = true; trunc = true; note = "scan byte budget (2 GiB) reached"; break; }
                scanned += len;
                pg.update(scanned);
                memory_buffer@ buf = process::read_buffer(pos, len);
                if (buf is null) continue;
                for (uint64 o = 0; o + 8 <= len; o += 8)
                {
                    uint64 v = buf.read_uint64(o);
                    if (v < vmin || v > vmax) continue;
                    if (bloom[uint((v >> 12) & 0xFFFFF)] == 0) continue;
                    // lower_bound: first node with address >= v
                    uint a = lvl_begin;
                    uint b = lvl_end;
                    while (a < b)
                    {
                        uint mid = (a + b) >> 1;
                        if (n_addr[mid] < v) a = mid + 1;
                        else b = mid;
                    }
                    uint64 loc = pos + o;
                    for (uint j = a; j < lvl_end && n_addr[j] - v <= maxoff; j++)
                    {
                        if (loc == n_addr[j]) continue;   // self reference
                        int mi = -1;
                        for (uint k = 0; k < mb.length(); k++)
                            if (loc >= mb[k] && loc < me[k]) { mi = int(k); break; }
                        if (mi >= 0 || !p.module_only_roots)
                        {
                            if (nres >= p.max_results) { stop = true; trunc = true; note = "max_results reached"; break; }
                            json_obj@ offs = json::array();
                            offs.push(int64(n_addr[j] - v));
                            int k = int(j);
                            while (k > 0) { offs.push(n_off[uint(k)]); k = n_parent[uint(k)]; }
                            json_obj@ res = json_obj();
                            res.set("module", mi >= 0 ? mn[uint(mi)] : "");
                            res.set("module_offset", mi >= 0 ? loc - mb[uint(mi)] : loc);
                            res.set("offsets", offs);
                            results.push(res);
                            nres++;
                        }
                        if (mi < 0 && depth < p.depth)
                        {
                            if (n_addr.length() - next_begin >= PS_MAX_NODES_PER_LEVEL)
                            {
                                if (!level_full) { level_full = true; trunc = true; if (note == "") note = "per-level candidate cap (50000) reached"; }
                            }
                            else
                            {
                                n_addr.insertLast(loc);
                                n_parent.insertLast(int(j));
                                n_off.insertLast(int64(n_addr[j] - v));
                            }
                        }
                    }
                    if (stop) break;
                }
            }
        }
        lvl_begin = next_begin;
        lvl_end = n_addr.length();
        if (lvl_begin == lvl_end) break;
    }

    send_progress("pointer_scan", scanned, scanned);
    @g_ptr_last = results;
    notify("pointer scan finished: " + results.length() + " paths", 120, 255, 160);
    json_obj@ o = ok_reply("pointer_scan", id);
    o.set("results", results);
    o.set("truncated", trunc);
    if (note != "") o.set("note", note);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Emulator (Unicorn)
// ---------------------------------------------------------------------------------------------

bool emu_reg(const string &in n, x86_reg &out r)
{
    if (n == "rax") { r = x86_reg::rax; return true; }
    if (n == "rbx") { r = x86_reg::rbx; return true; }
    if (n == "rcx") { r = x86_reg::rcx; return true; }
    if (n == "rdx") { r = x86_reg::rdx; return true; }
    if (n == "rsi") { r = x86_reg::rsi; return true; }
    if (n == "rdi") { r = x86_reg::rdi; return true; }
    if (n == "rbp") { r = x86_reg::rbp; return true; }
    if (n == "rsp") { r = x86_reg::rsp; return true; }
    if (n == "rip") { r = x86_reg::rip; return true; }
    if (n == "eflags") { r = x86_reg::eflags; return true; }
    if (n == "r8") { r = x86_reg::r8; return true; }
    if (n == "r9") { r = x86_reg::r9; return true; }
    if (n == "r10") { r = x86_reg::r10; return true; }
    if (n == "r11") { r = x86_reg::r11; return true; }
    if (n == "r12") { r = x86_reg::r12; return true; }
    if (n == "r13") { r = x86_reg::r13; return true; }
    if (n == "r14") { r = x86_reg::r14; return true; }
    if (n == "r15") { r = x86_reg::r15; return true; }
    return false;
}

string uc_error_name(int e)
{
    if (e == uc::error::ok) return "ok";
    if (e == uc::error::nomem) return "nomem";
    if (e == uc::error::arch) return "arch";
    if (e == uc::error::handle) return "handle";
    if (e == uc::error::mode) return "mode";
    if (e == uc::error::version) return "version";
    if (e == uc::error::read_unmapped) return "read_unmapped";
    if (e == uc::error::write_unmapped) return "write_unmapped";
    if (e == uc::error::fetch_unmapped) return "fetch_unmapped";
    if (e == uc::error::fetch_prot) return "fetch_prot";
    if (e == uc::error::read_prot) return "read_prot";
    if (e == uc::error::write_prot) return "write_prot";
    if (e == uc::error::map) return "map";
    if (e == uc::error::hook) return "hook";
    if (e == uc::error::insn_invalid) return "insn_invalid";
    return "unknown";
}

bool emu_hook(uint64 h, uint64 address, uint32 size)
{
    g_emu_count++;
    if (g_cancel.load()) { uc::stop(h); return false; }
    if ((g_emu_count & 0x3FFFF) == 0) send_progress("emulate", g_emu_count, g_emu_max);
    if (!emux_code(h, g_emu_x, address, size)) return true;   // a stand-in returned to the caller
    if (g_emu_trace_on && g_emu_trace.length() < g_emu_trace_limit) g_emu_trace.insertLast(address);
    if (g_emu_mem_on) emu_log_mem(h, address, size);
    return true;   // the instruction limit is enforced by uc::start's count argument
}

// Bytes at `a` as the emulator sees them; pages it has not faulted in yet still hold the target's bytes.
string emu_peek(uint64 h, uint64 a, uint n)
{
    array<uint8> b;
    b.resize(n);
    if (uc::mem_read(h, a, n, b)) return hex_of(b, 0, n);
    if (g_emu_blank) return "";
    array<uint8>@ p = process::read_bytes(a, n);
    return (p is null || p.length() < n) ? "" : hex_of(p, 0, n);
}

void emu_flush_writes(uint64 h)
{
    for (uint i = 0; i < g_emu_mem_pending.length(); i++)
    {
        MemAccess@ m = g_emu_mem[g_emu_mem_pending[i]];
        m.after = emu_peek(h, m.address, m.size);
    }
    g_emu_mem_pending.resize(0);
}

// Operand width from Zydis' Intel text ("dword ptr [...]"); the binding exposes no operand size.
uint emu_ptr_size(const string &in t)
{
    if (t.findFirst("zmmword ptr") >= 0) return 64;
    if (t.findFirst("ymmword ptr") >= 0) return 32;
    if (t.findFirst("xmmword ptr") >= 0) return 16;
    if (t.findFirst("tbyte ptr") >= 0) return 10;
    if (t.findFirst("qword ptr") >= 0) return 8;
    if (t.findFirst("dword ptr") >= 0) return 4;
    if (t.findFirst("word ptr") >= 0) return 2;
    if (t.findFirst("byte ptr") >= 0) return 1;
    return 8;
}

// Value of a Zydis address register; only 64-bit GPRs and rip occur in x64 addressing in practice.
bool emu_addr_reg(uint64 h, int zreg, uint64 next_rip, uint64 &out v)
{
    v = 0;
    if (zreg == 0) return true;
    string n = zydis::reg_name(zreg);
    if (n == "rip") { v = next_rip; return true; }
    x86_reg reg;
    if (!emu_reg(n, reg)) return false;
    return uc::reg_read64(h, reg, v);
}

void emu_log_mem(uint64 h, uint64 address, uint32 size)
{
    emu_flush_writes(h);   // the previous instruction has executed by now
    if (g_emu_mem.length() >= g_emu_mem_limit) return;
    array<uint8> code;
    code.resize(size);
    if (!uc::mem_read(h, address, size, code)) return;
    array<disasm_insn@> insns;
    if (!zydis::disasm(code, address, insns) || insns.length() == 0) return;
    disasm_insn@ insn = insns[0];
    if (insn.text.findFirst("lea ") == 0 || insn.text.findFirst("nop") == 0) return;   // address math, no access
    for (uint8 i = 0; i < insn.operand_count_visible && g_emu_mem.length() < g_emu_mem_limit; i++)
    {
        disasm_operand op = insn.get_op(i);
        if (op.type != op_type::mem) continue;
        bool r = (op.action & (int(op_action::read) | int(op_action::condread))) != 0;
        bool w = (op.action & (int(op_action::write) | int(op_action::condwrite))) != 0;
        if (!r && !w) continue;
        uint64 base = 0;
        uint64 index = 0;
        uint64 next_rip = address + size;
        if (!emu_addr_reg(h, op.mem_base, next_rip, base) || !emu_addr_reg(h, op.mem_index, next_rip, index)) continue;
        uint64 ea = base + index * op.mem_scale + uint64(op.mem_disp);
        string seg = op.mem_segment == 0 ? "" : zydis::reg_name(op.mem_segment);
        uint64 sb = 0;
        if (seg == "gs") uc::reg_read64(h, x86_reg::gs_base, sb);
        else if (seg == "fs") uc::reg_read64(h, x86_reg::fs_base, sb);
        ea += sb;
        MemAccess@ m = MemAccess();
        m.rip = address;
        m.address = ea;
        m.size = emu_ptr_size(insn.text);
        m.r = r;
        m.w = w;
        m.before = emu_peek(h, ea, m.size);
        if (w) g_emu_mem_pending.insertLast(g_emu_mem.length());
        g_emu_mem.insertLast(m);
    }
}

// High, normally unused addresses; in process mode pick one the target has not mapped.
uint64 pick_stack_base(bool blank)
{
    array<uint64> c = { 0x7ff000000000, 0x6ff000000000, 0x5ff000000000, 0x4ff000000000 };
    if (blank) return c[0];
    for (uint i = 0; i < c.length(); i++)
    {
        memory_region a = process::virtual_query(c[i]);
        memory_region b = process::virtual_query(c[i] + EMU_STACK_SIZE - 1);
        if (!a.present && !b.present) return c[i];
    }
    return c[0];
}

// Validates the request on the ws thread, then hands a parsed EmuJob to the job slot: emulation can
// run for seconds, and the slot keeps it from blocking every other verb meanwhile.
void h_emulate(json_obj@ r, int64 id)
{
    EmuJob@ e = EmuJob();
    if (!get_addr(r, "start", e.start) || !get_addr(r, "end", e.stop)) { bad_args(id, "emulate requires 'start' and 'end'"); return; }
    string codehex;
    if (!opt_str(r, "code", "", codehex)) { bad_args(id, "code must be a hex string"); return; }
    bool blank = codehex != "";
    if (blank)
    {
        if (!parse_hex_bytes(codehex, e.code) || e.code.length() == 0) { bad_args(id, "code must be hex"); return; }
        if (e.code.length() > EMU_CODE_MAX) { send_error(id, E_LIMIT, "limit exceeded", "code is limited to 1 MiB"); return; }
    }
    else if (!require_attached(id)) return;

    if (!opt_int(r, "max_insns", 100000, e.max_insns) || !opt_int(r, "timeout_us", 1000000, e.timeout_us) ||
        !opt_int(r, "trace_limit", 2000, e.trace_limit) || !opt_bool(r, "trace", false, e.trace) ||
        !opt_int(r, "mem_log_limit", 2000, e.mem_log_limit) || !opt_bool(r, "mem_log", false, e.mem_log))
    {
        bad_args(id, "max_insns/timeout_us/trace_limit/mem_log_limit must be numbers, trace/mem_log bools");
        return;
    }
    if (e.max_insns < 1 || e.timeout_us < 1 || e.trace_limit < 0 || e.mem_log_limit < 0) { bad_args(id, "max_insns and timeout_us must be >= 1"); return; }
    if (e.max_insns > EMU_MAX_INSNS || e.timeout_us > EMU_MAX_TIMEOUT_US || e.trace_limit > EMU_MAX_TRACE || e.mem_log_limit > EMU_MAX_MEM_LOG)
    {
        send_error(id, E_LIMIT, "limit exceeded", "max_insns <= 5000000, timeout_us <= 5000000, trace_limit <= 100000, mem_log_limit <= 20000");
        return;
    }

    if (has_key(r, "regs"))
    {
        if (r.type("regs") != json_type::object) { bad_args(id, "regs must be an object"); return; }
        json_obj@ regs = r.get_obj("regs");
        array<string>@ keys = regs.keys();
        for (uint i = 0; i < keys.length(); i++)
        {
            x86_reg reg;
            uint64 v;
            if (!emu_reg(keys[i], reg)) { bad_args(id, "unknown register: " + keys[i]); return; }
            if (!get_addr(regs, keys[i], v)) { bad_args(id, "register values must be hex strings: " + keys[i]); return; }
            e.rnames.insertLast(keys[i]);
            e.rvals.insertLast(v);
        }
    }

    // Memory blobs: "write" injects bytes before the run, "read" reads them back after.
    if (has_key(r, "write"))
    {
        if (r.type("write") != json_type::array) { bad_args(id, "write must be an array"); return; }
        json_obj@ arr = r.get_obj("write");
        if (arr.length() > EMU_MAX_BLOBS) { send_error(id, E_LIMIT, "limit exceeded", "at most 64 write blobs"); return; }
        for (uint i = 0; i < arr.length(); i++)
        {
            json_obj@ blob = arr.get_obj_at(i);
            if (blob is null) { bad_args(id, "write entries must be objects"); return; }
            uint64 a;
            if (!get_addr(blob, "address", a)) { bad_args(id, "write entries need an address"); return; }
            string hex;
            if (!opt_str(blob, "data", "", hex)) { bad_args(id, "write entries need hex data"); return; }
            array<uint8> bytes;
            if (!parse_hex_bytes(hex, bytes) || bytes.length() == 0) { bad_args(id, "write data must be non-empty hex"); return; }
            if (bytes.length() > EMU_MAX_BLOB_BYTES) { send_error(id, E_LIMIT, "limit exceeded", "a write blob is limited to 64 KiB"); return; }
            e.waddrs.insertLast(a);
            e.wdata.insertLast(bytes);
        }
    }
    if (has_key(r, "read"))
    {
        if (r.type("read") != json_type::array) { bad_args(id, "read must be an array"); return; }
        json_obj@ arr = r.get_obj("read");
        if (arr.length() > EMU_MAX_BLOBS) { send_error(id, E_LIMIT, "limit exceeded", "at most 64 read blobs"); return; }
        for (uint i = 0; i < arr.length(); i++)
        {
            json_obj@ blob = arr.get_obj_at(i);
            if (blob is null) { bad_args(id, "read entries must be objects"); return; }
            uint64 a;
            if (!get_addr(blob, "address", a)) { bad_args(id, "read entries need an address"); return; }
            uint64 n = EMU_MAX_BLOB_BYTES;
            if (!opt_addr(blob, "size", n, n)) { bad_args(id, "read size must be an address or number"); return; }
            if (n == 0 || n > EMU_MAX_BLOB_BYTES) { send_error(id, E_LIMIT, "limit exceeded", "read size must be 1..65536"); return; }
            e.raddrs.insertLast(a);
            e.rsizes.insertLast(n);
        }
    }

    string px = emux_parse(r, e.x, e.trace_limit);
    if (px != "") { bad_args(id, px); return; }
    if (has_key(r, "xmm")) @e.xmm_req = r;
    JobParams@ p = JobParams();
    @p.emu = e;
    uint seq;
    if (!claim_job("emulate", id, p, seq)) { send_error(id, E_BUSY, "busy", "another job is running"); return; }
    create_thread(0, @job_main);
}

// Runs on the job thread; the job slot serialises it, so the g_emu_* hook state stays single-writer.
void run_emulate(int64 id, EmuJob@ e)
{
    bool blank = e.code.length() > 0;
    uint64 h = blank ? uc::create() : uc::create_process();
    if (h == 0) { send_error(id, E_FAILED, "emulator creation failed"); return; }

    bool ok = true;
    if (blank)
    {
        uint64 page = e.start & ~uint64(0xFFF);
        uint64 pend = align_up(e.start + e.code.length(), 0x1000);
        ok = uc::mem_map(h, page, pend - page, uint(uc::prot::all)) && uc::mem_write(h, e.start, e.code);
    }
    // setup_stack writes `end` as the return address, so a final `ret` lands on the stop address.
    ok = ok && uc::setup_stack(h, pick_stack_base(blank), EMU_STACK_SIZE, e.stop);
    if (ok && uc::mem_query(h, e.stop) < 0)
        ok = uc::mem_map(h, e.stop & ~uint64(0xFFF), 0x1000, uint(uc::prot::read | uc::prot::exec));
    g_emu_count = 0;
    g_emu_trace.resize(0);
    g_emu_trace_on = e.trace;
    g_emu_trace_limit = uint(e.trace_limit);
    g_emu_blank = blank;
    g_emu_mem.resize(0);
    g_emu_mem_pending.resize(0);
    g_emu_mem_on = e.mem_log;
    g_emu_mem_limit = uint(e.mem_log_limit);
    ok = ok && uc::hook_code(h, @emu_hook);
    @g_emu_x = e.x;
    g_emu_x.blank = blank;
    emux_reset_run(g_emu_x);
    if (ok && g_emu_x.zero_unmapped) ok = uc::hook_memory_unmapped(h, @emu_unmapped_hook);
    // Inject the blobs before the run: map the page if the emulator has not faulted it in yet.
    for (uint i = 0; i < e.waddrs.length() && ok; i++)
    {
        uint64 a = e.waddrs[i];
        if (uc::mem_query(h, a) < 0)
        {
            uint64 page = a & ~uint64(0xFFF);
            uint64 span = align_up(a + e.wdata[i].length(), 0x1000) - page;
            ok = uc::mem_map(h, page, span, uint(uc::prot::all));
        }
        if (ok) ok = uc::mem_write(h, a, e.wdata[i]);
    }
    for (uint i = 0; i < e.rnames.length() && ok; i++)
    {
        x86_reg reg;
        emu_reg(e.rnames[i], reg);
        ok = uc::reg_write64(h, reg, e.rvals[i]);
    }
    if (!ok)
    {
        uc::close(h);
        send_error(id, E_FAILED, "emulator setup failed", "mapping code/stack or writing registers failed");
        return;
    }

    string xerr = e.xmm_req is null ? "" : emux_set_xmm(h, e.xmm_req);
    if (xerr != "") { uc::close(h); bad_args(id, xerr); return; }
    emux_prepare(h, g_emu_x);
    g_emu_max = uint64(e.max_insns);
    int res = uc::start(h, e.start, e.stop, uint64(e.timeout_us), uint64(e.max_insns));
    emu_flush_writes(h);   // the last instruction's writes

    array<string> names = { "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags" };
    json_obj@ regs_out = json_obj();
    uint64 rip = 0;
    for (uint i = 0; i < names.length(); i++)
    {
        x86_reg reg;
        emu_reg(names[i], reg);
        uint64 v = 0;
        uc::reg_read64(h, reg, v);
        if (names[i] == "rip") rip = v;
        regs_out.set(names[i], hex_addr(v));
    }
    uint64 fault = uc::fault_address(h);
    json_obj@ xmm_out = emux_xmm_json(h);

    // Read the requested blobs back before the handle is closed.
    json_obj@ mem_out = json::array();
    for (uint i = 0; i < e.raddrs.length(); i++)
    {
        array<uint8> bytes;
        bytes.resize(e.rsizes[i]);
        bool got = uc::mem_read(h, e.raddrs[i], uint(e.rsizes[i]), bytes);
        json_obj@ entry = json_obj();
        entry.set("address", hex_addr(e.raddrs[i]));
        entry.set("size", e.rsizes[i]);
        entry.set("ok", got);
        entry.set("data", got ? hex_of(bytes, 0, uint(e.rsizes[i])) : "");
        mem_out.push(entry);
    }
    uc::close(h);

    json_obj@ tr = json::array();
    for (uint i = 0; i < g_emu_trace.length(); i++) tr.push(hex_addr(g_emu_trace[i]));

    json_obj@ o = ok_reply("emulate", id);
    o.set("error", res);
    o.set("error_name", uc_error_name(res));
    o.set("fault_address", hex_addr(fault));
    o.set("regs", regs_out);
    o.set("trace", tr);
    if (e.mem_log)
    {
        json_obj@ ml = json::array();
        for (uint i = 0; i < g_emu_mem.length(); i++)
        {
            MemAccess@ m = g_emu_mem[i];
            json_obj@ x = json_obj();
            x.set("rip", hex_addr(m.rip));
            x.set("address", hex_addr(m.address));
            x.set("size", m.size);
            x.set("access", m.r && m.w ? "rw" : (m.w ? "w" : "r"));
            x.set("before", m.before);
            if (m.w) x.set("after", m.after);
            ml.push(x);
        }
        o.set("mem_log", ml);
        o.set("mem_log_truncated", g_emu_mem.length() >= g_emu_mem_limit && g_emu_mem_limit > 0);
    }
    o.set("instructions", g_emu_count);
    o.set("mem", mem_out);
    // Unicorn reports a timeout or instruction-limit stop as "ok"; this tells them apart.
    o.set("reached_end", res == uc::error::ok && rip == e.stop);
    emux_report(o, g_emu_x, xmm_out);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Emulated debugger: one persistent Unicorn session (emu_start / emu_step / emu_run / emu_break /
// emu_set / emu_read / emu_state / emu_close). Process-backed sessions fault pages in from the
// target on demand and never modify it. Only the ws thread touches the session handle; runs are
// bounded by timeout_us (<= 5 s), so a long run delays other verbs by at most that much.
// ---------------------------------------------------------------------------------------------

uint64 g_emud = 0;                 // session handle (0 = none)
bool g_emud_blank = false;
array<uint64> g_emud_bps;          // breakpoint addresses
uint64 g_emud_skip = 0;            // a resumed run does not stop on the breakpoint it sits on
bool g_emud_skip_on = false;
uint64 g_emud_hit = 0;
bool g_emud_hit_on = false;
uint64 g_emud_count = 0;           // instructions executed over the session's lifetime
uint64 g_emud_last = 0;            // address of the last instruction the hook saw
uint64 g_emud_stack = 0;
array<uint64> g_emud_dirty;        // pages written through emu_set
mutex@ g_emud_mx = create_mutex();
bool g_emud_stale = false;         // set by mark_detached (any thread); the ws thread closes the handle

const uint64 EMUD_RET = 0x1000;    // a ret from the start function lands here ("returned")

int u64_index(const array<uint64> &in a, uint64 v)
{
    for (uint i = 0; i < a.length(); i++)
        if (a[i] == v) return int(i);
    return -1;
}

bool emud_hook(uint64 h, uint64 address, uint32 size)
{
    if (g_cancel.load()) { uc::stop(h); return false; }
    int bp = u64_index(g_emud_bps, address);
    if (g_emud_skip_on && address == g_emud_skip) { g_emud_skip_on = false; }
    else if (bp >= 0 && emud_cond_true(h, uint(bp) < g_emud_conds.length() ? g_emud_conds[uint(bp)] : ""))
    {
        g_emud_hit = address;
        g_emud_hit_on = true;
        g_emud_last = address;
        uc::stop(h);
        return false;
    }
    else if (emud_watch_hit(h, address, size))
    {
        g_emud_wp_hit_on = true;
        g_emud_last = address;
        uc::stop(h);
        return false;
    }
    g_emud_skip_on = false;
    g_emud_count++;
    g_emud_last = address;
    emux_code(h, g_emud_x, address, size);
    return true;
}

void emud_close()
{
    if (g_emud != 0) uc::close(g_emud);
    g_emud = 0;
    g_emud_conds.resize(0);
    g_emud_wp_addr.resize(0); g_emud_wp_size.resize(0); g_emud_wp_mode.resize(0);
    g_emud_snaps.resize(0);
    g_emud_bps.resize(0);
    g_emud_dirty.resize(0);
    g_emud_count = 0;
}

void emud_mark_stale()
{
    g_emud_mx.lock();
    g_emud_stale = true;
    g_emud_mx.unlock();
}

// Closes a session invalidated by a detach; true when a session is usable.
bool emud_ready(int64 id)
{
    g_emud_mx.lock();
    bool stale = g_emud_stale;
    g_emud_stale = false;
    g_emud_mx.unlock();
    if (stale && !g_emud_blank) emud_close();
    if (g_emud == 0) { send_error(id, E_FAILED, "operation failed", "no emulator session: emu_start first"); return false; }
    return true;
}

bool emud_ensure(uint64 a, uint64 n)
{
    if (uc::mem_query(g_emud, a) >= 0 && uc::mem_query(g_emud, a + n - 1) >= 0)
    {
        array<uint8> probe;
        if (uc::mem_read(g_emud, a, 1, probe)) return true;
    }
    if (!g_emud_blank)
    {
        // process-backed: a read through the emulator faults the page in; fall back to mapping a copy
        array<uint8>@ src = process::read_bytes(a & ~uint64(0xFFF), uint(align_up(a + n, 0x1000) - (a & ~uint64(0xFFF))));
        if (src !is null && uc::mem_map(g_emud, a & ~uint64(0xFFF), src.length(), uint(uc::prot::all)))
            return uc::mem_write(g_emud, a & ~uint64(0xFFF), src);
    }
    uint64 page = a & ~uint64(0xFFF);
    return uc::mem_map(g_emud, page, align_up(a + n, 0x1000) - page, uint(uc::prot::all));
}

json_obj@ emud_state(const string &in verb, int64 id, json_obj@ stop)
{
    json_obj@ o = ok_reply(verb, id);
    array<string> names = { "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags" };
    json_obj@ regs = json_obj();
    uint64 rip = 0;
    uint64 rsp = 0;
    for (uint i = 0; i < names.length(); i++)
    {
        x86_reg reg;
        emu_reg(names[i], reg);
        uint64 v = 0;
        uc::reg_read64(g_emud, reg, v);
        if (names[i] == "rip") rip = v;
        if (names[i] == "rsp") rsp = v;
        regs.set(names[i], hex_addr(v));
    }
    o.set("regs", regs);
    o.set("rip", hex_addr(rip));
    o.set("instructions", g_emud_count);
    o.set("stop", stop);
    json_obj@ next = json::array();
    array<uint8> code;
    if (rip != EMUD_RET && uc::mem_read(g_emud, rip, 64, code))
    {
        array<disasm_insn@> insns;
        if (zydis::disasm(code, rip, insns))
        {
            uint off = 0;
            for (uint i = 0; i < insns.length() && i < 6; i++)
            {
                json_obj@ x = json_obj();
                x.set("address", hex_addr(rip + off));
                x.set("bytes", hex_of(code, off, insns[i].length));
                x.set("text", insns[i].text);
                next.push(x);
                off += insns[i].length;
            }
        }
    }
    o.set("next", next);
    json_obj@ stack = json::array();
    array<uint8> sb;
    if (uc::mem_read(g_emud, rsp, 64, sb))
        for (uint i = 0; i < 8; i++)
        {
            uint64 v = 0;
            for (uint k = 0; k < 8; k++) v |= uint64(sb[i * 8 + k]) << (8 * k);
            json_obj@ x = json_obj();
            x.set("address", hex_addr(rsp + i * 8));
            x.set("value", hex_addr(v));
            stack.push(x);
        }
    o.set("stack", stack);
    json_obj@ bps = json::array();
    for (uint i = 0; i < g_emud_bps.length(); i++) bps.push(hex_addr(g_emud_bps[i]));
    o.set("breakpoints", bps);
    json_obj@ dirty = json::array();
    for (uint i = 0; i < g_emud_dirty.length(); i++) dirty.push(hex_addr(g_emud_dirty[i]));
    o.set("dirty_pages", dirty);
    return o;
}

json_obj@ emud_stop(const string &in reason)
{
    json_obj@ s = json_obj();
    s.set("reason", reason);
    return s;
}

// Applies "regs" and "write" from r; "" on success, else the problem.
string emud_apply(json_obj@ r)
{
    if (has_key(r, "regs"))
    {
        if (r.type("regs") != json_type::object) return "regs must be an object";
        json_obj@ regs = r.get_obj("regs");
        array<string>@ keys = regs.keys();
        for (uint i = 0; i < keys.length(); i++)
        {
            x86_reg reg;
            uint64 v;
            if (!emu_reg(keys[i], reg)) return "unknown register: " + keys[i];
            if (!get_addr(regs, keys[i], v)) return "register values must be hex strings: " + keys[i];
            if (!uc::reg_write64(g_emud, reg, v)) return "cannot write " + keys[i];
        }
    }
    if (has_key(r, "write"))
    {
        if (r.type("write") != json_type::array) return "write must be an array";
        json_obj@ arr = r.get_obj("write");
        if (arr.length() > EMU_MAX_BLOBS) return "at most 64 write blobs";
        for (uint i = 0; i < arr.length(); i++)
        {
            json_obj@ blob = arr.get_obj_at(i);
            if (blob is null) return "write entries must be objects";
            uint64 a;
            string hex;
            array<uint8> bytes;
            if (!get_addr(blob, "address", a) || !opt_str(blob, "data", "", hex) || !parse_hex_bytes(hex, bytes) || bytes.length() == 0)
                return "each write needs an address and non-empty hex data";
            if (bytes.length() > EMU_MAX_BLOB_BYTES) return "a write blob is limited to 64 KiB";
            if (!emud_ensure(a, bytes.length()) || !uc::mem_write(g_emud, a, bytes)) return "cannot write at " + hex_addr(a);
            for (uint64 p = a & ~uint64(0xFFF); p < a + bytes.length(); p += 0x1000)
                if (u64_index(g_emud_dirty, p) < 0) g_emud_dirty.insertLast(p);
        }
        uc::flush_code(g_emud);   // patched code must not run from a stale translation
    }
    return "";
}

void h_emu_start(json_obj@ r, int64 id)
{
    uint64 start;
    if (!get_addr(r, "start", start)) { bad_args(id, "emu_start requires 'start'"); return; }
    string codehex;
    if (!opt_str(r, "code", "", codehex)) { bad_args(id, "code must be a hex string"); return; }
    array<uint8> code;
    bool blank = codehex != "";
    if (blank && (!parse_hex_bytes(codehex, code) || code.length() == 0 || code.length() > EMU_CODE_MAX)) { bad_args(id, "code must be hex, up to 1 MiB"); return; }
    if (!blank && !require_attached(id)) return;
    emud_close();
    g_emud_mx.lock();
    g_emud_stale = false;
    g_emud_mx.unlock();
    g_emud = blank ? uc::create() : uc::create_process();
    if (g_emud == 0) { send_error(id, E_FAILED, "emulator creation failed"); return; }
    g_emud_blank = blank;
    bool ok = true;
    if (blank)
    {
        uint64 page = start & ~uint64(0xFFF);
        ok = uc::mem_map(g_emud, page, align_up(start + code.length(), 0x1000) - page, uint(uc::prot::all)) && uc::mem_write(g_emud, start, code);
    }
    g_emud_stack = pick_stack_base(blank);
    // the return address is a mapped, never-executed page: reaching it ends the function cleanly
    ok = ok && uc::setup_stack(g_emud, g_emud_stack, EMU_STACK_SIZE, EMUD_RET);
    if (ok && uc::mem_query(g_emud, EMUD_RET) < 0) ok = uc::mem_map(g_emud, EMUD_RET, 0x1000, uint(uc::prot::read | uc::prot::exec));
    ok = ok && uc::reg_write64(g_emud, x86_reg::rip, start) && uc::hook_code(g_emud, @emud_hook);
    if (!ok) { emud_close(); send_error(id, E_FAILED, "emulator setup failed", "mapping code/stack failed"); return; }
    string problem = emud_apply(r);
    if (problem == "") problem = emux_set_xmm(g_emud, r);
    @g_emud_x = EmuExtras();
    g_emud_x.blank = blank;
    if (problem == "") problem = emux_parse(r, g_emud_x, 2000);
    if (problem != "") { emud_close(); bad_args(id, problem); return; }
    if (g_emud_x.zero_unmapped) uc::hook_memory_unmapped(g_emud, @emud_unmapped_hook);
    emux_prepare(g_emud, g_emud_x);
    if (has_key(r, "breakpoints") && r.type("breakpoints") == json_type::array)
    {
        json_obj@ arr = r.get_obj("breakpoints");
        for (uint i = 0; i < arr.length(); i++)
        {
            uint64 a;
            if (parse_hex_u64(arr.get_string_at(i), a) && u64_index(g_emud_bps, a) < 0) g_emud_bps.insertLast(a);
        }
    }
    g_emud_count = 0;
    g_emud_last = start;
    send_json(emud_state("emu_start", id, emud_stop("start")));
}

// emu_step (count, default 1) and emu_run (until, max_insns): run from rip, stopping at breakpoints.
void h_emu_go(json_obj@ r, int64 id, bool step)
{
    if (!emud_ready(id)) return;
    int64 count = 1;
    int64 timeout = 2000000;
    uint64 until = 0;
    if (step) { if (!opt_int(r, "count", 1, count)) { bad_args(id, "count must be a number"); return; } }
    else
    {
        if (!opt_int(r, "max_insns", 1000000, count) || !opt_addr(r, "until", 0, until)) { bad_args(id, "max_insns must be a number, until an address"); return; }
    }
    if (!opt_int(r, "timeout_us", 2000000, timeout)) { bad_args(id, "timeout_us must be a number"); return; }
    if (count < 1) count = 1;
    if (count > EMU_MAX_INSNS * 10) count = EMU_MAX_INSNS * 10;
    if (timeout < 1000) timeout = 1000;
    if (timeout > EMU_MAX_TIMEOUT_US) timeout = EMU_MAX_TIMEOUT_US;
    uint64 rip = 0;
    uc::reg_read64(g_emud, x86_reg::rip, rip);
    if (rip == EMUD_RET) { send_json(emud_state(step ? "emu_step" : "emu_run", id, emud_stop("returned"))); return; }
    g_emud_skip = rip;
    g_emud_skip_on = true;
    g_emud_hit_on = false;
    g_emud_wp_hit_on = false;
    emux_reset_run(g_emud_x);
    emux_prepare_regs(g_emud, g_emud_x);
    uint64 before = g_emud_count;
    int res = uc::start(g_emud, rip, until == 0 ? EMUD_RET : until, uint64(timeout), uint64(count));
    uint64 now = 0;
    uc::reg_read64(g_emud, x86_reg::rip, now);
    uint64 ran = g_emud_count - before;
    json_obj@ stop;
    if (g_emud_hit_on) { @stop = emud_stop("breakpoint"); stop.set("address", hex_addr(g_emud_hit)); uc::reg_write64(g_emud, x86_reg::rip, g_emud_hit); }
    else if (g_emud_wp_hit_on) { @stop = emud_stop("watchpoint"); stop.set("hit", g_emud_wp_hit); uc::reg_write64(g_emud, x86_reg::rip, g_emud_last); }
    else if (g_cancel.load()) @stop = emud_stop("cancelled");
    else if (now == EMUD_RET) @stop = emud_stop("returned");
    else if (res != uc::error::ok)
    {
        @stop = emud_stop("fault");
        stop.set("error_name", uc_error_name(res));
        stop.set("fault_address", hex_addr(uc::fault_address(g_emud)));
        stop.set("fault_rip", hex_addr(g_emud_last));
        uc::reg_write64(g_emud, x86_reg::rip, g_emud_last);
    }
    else if (until != 0 && now == until) { @stop = emud_stop("until"); stop.set("address", hex_addr(until)); }
    else if (int64(ran) >= count) @stop = emud_stop(count == 1 ? "step" : "count");
    else @stop = emud_stop("timeout");
    stop.set("ran", ran);
    json_obj@ o = emud_state(step ? "emu_step" : "emu_run", id, stop);
    emux_report(o, g_emud_x, emux_xmm_json(g_emud));
    send_json(o);
}

void h_emu_break(json_obj@ r, int64 id)
{
    if (!emud_ready(id)) return;
    bool clear = false;
    bool on = true;
    if (!opt_bool(r, "clear", false, clear) || !opt_bool(r, "enabled", true, on)) { bad_args(id, "clear/enabled must be bools"); return; }
    if (clear) g_emud_bps.resize(0);
    if (has_key(r, "address"))
    {
        uint64 a;
        if (!get_addr(r, "address", a)) { bad_args(id, "address must be a 0x address"); return; }
        string cond;
        if (!opt_str(r, "condition", "", cond)) { bad_args(id, "condition must be a string like rax==0x10"); return; }
        while (g_emud_conds.length() < g_emud_bps.length()) g_emud_conds.insertLast("");
        int at = u64_index(g_emud_bps, a);
        if (at >= 0) { g_emud_bps.removeAt(uint(at)); g_emud_conds.removeAt(uint(at)); }
        if (on) { g_emud_bps.insertLast(a); g_emud_conds.insertLast(cond); }
    }
    json_obj@ o = emud_state("emu_break", id, emud_stop("edit"));
    json_obj@ conds = json_obj();
    for (uint i = 0; i < g_emud_bps.length() && i < g_emud_conds.length(); i++)
        if (g_emud_conds[i] != "") conds.set(hex_addr(g_emud_bps[i]), g_emud_conds[i]);
    o.set("conditions", conds);
    send_json(o);
}

void h_emu_set(json_obj@ r, int64 id)
{
    if (!emud_ready(id)) return;
    string problem = emud_apply(r);
    if (problem != "") { bad_args(id, problem); return; }
    send_json(emud_state("emu_set", id, emud_stop("edit")));
}

void h_emu_read(json_obj@ r, int64 id)
{
    if (!emud_ready(id)) return;
    uint64 a;
    uint64 n = 256;
    if (!get_addr(r, "address", a) || !opt_addr(r, "size", 256, n)) { bad_args(id, "emu_read requires 'address' (and a numeric size)"); return; }
    if (n == 0 || n > EMU_MAX_BLOB_BYTES) { send_error(id, E_LIMIT, "limit exceeded", "size must be 1..65536"); return; }
    array<uint8> b;
    if (!uc::mem_read(g_emud, a, uint(n), b))
    {
        if (!emud_ensure(a, n) || !uc::mem_read(g_emud, a, uint(n), b)) { send_error(id, E_FAILED, "operation failed", hex_addr(a) + " is not mapped in the emulator or the process"); return; }
    }
    json_obj@ o = ok_reply("emu_read", id);
    o.set("address", hex_addr(a));
    o.set("size", n);
    o.set("data", hex_of(b, 0, uint(n)));
    send_json(o);
}

void h_emu_state(json_obj@ r, int64 id)
{
    if (!emud_ready(id)) return;
    send_json(emud_state("emu_state", id, emud_stop("state")));
}

void h_emu_close(json_obj@ r, int64 id)
{
    bool had = g_emud != 0;
    emud_close();
    json_obj@ o = ok_reply("emu_close", id);
    o.set("closed", had);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Batch / bulk verbs: one round trip for work the app otherwise does with many small requests.
// ---------------------------------------------------------------------------------------------

const uint SIGB_MAX_PATTERNS = 512;
const uint SIGB_MAX_HITS = 64;
const uint64 DISFN_MAX_BYTES = 0x4000;
const uint RF_MAX_FIELDS = 1024;

uint64 module_or_main(const string &in mod)
{
    if (mod == "") return g_base;
    return process::get_module_base(mod);
}

// sig_scan_batch: every IDA pattern scanned in Echo (process::find_signatures) in one request.
void h_sig_scan_batch(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    string mod;
    int64 max_hits = 16;
    if (!opt_str(r, "module", "", mod) || !opt_int(r, "max_hits", 16, max_hits)) { bad_args(id, "module must be a string, max_hits a number"); return; }
    if (!has_key(r, "patterns") || r.type("patterns") != json_type::array) { bad_args(id, "sig_scan_batch requires 'patterns' (array of IDA patterns)"); return; }
    json_obj@ pats = r.get_obj("patterns");
    if (pats.length() > SIGB_MAX_PATTERNS) { send_error(id, E_LIMIT, "limit exceeded", "at most 512 patterns"); return; }
    if (max_hits < 1) max_hits = 1;
    if (max_hits > SIGB_MAX_HITS) max_hits = SIGB_MAX_HITS;
    uint64 base = module_or_main(mod);
    if (base == 0) { send_error(id, E_FAILED, "module not found", mod); return; }
    json_obj@ out = json::array();
    for (uint i = 0; i < pats.length(); i++)
    {
        string p = pats.get_string_at(i);
        json_obj@ e = json_obj();
        e.set("pattern", p);
        json_obj@ hits = json::array();
        uint total = 0;
        array<uint64>@ found = p == "" ? null : process::find_signatures(base, p);
        if (found !is null)
        {
            total = found.length();
            for (uint k = 0; k < found.length() && k < uint(max_hits); k++) hits.push(hex_addr(found[k]));
        }
        e.set("count", total);
        e.set("results", hits);
        out.push(e);
    }
    json_obj@ o = ok_reply("sig_scan_batch", id);
    o.set("module_base", hex_addr(base));
    o.set("results", out);
    send_json(o);
}

// disasm_function: decode from `address` to the first ret (zydis::disasm_func), one read.
void h_disasm_function(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 a;
    uint64 n = 0x1000;
    if (!get_addr(r, "address", a) || !opt_addr(r, "max_bytes", 0x1000, n)) { bad_args(id, "disasm_function requires 'address' (max_bytes optional)"); return; }
    if (n == 0 || n > DISFN_MAX_BYTES) { send_error(id, E_LIMIT, "limit exceeded", "max_bytes must be 1..16384"); return; }
    array<uint8>@ b = process::read_bytes(a, uint(n));
    if (b is null || b.length() == 0) { send_error(id, E_FAILED, "read failed", hex_addr(a)); return; }
    array<disasm_insn@> insns;
    bool complete = zydis::disasm_func(b, a, insns);
    json_obj@ arr = json::array();
    uint off = 0;
    for (uint i = 0; i < insns.length(); i++)
    {
        json_obj@ x = json_obj();
        x.set("address", hex_addr(a + off));
        x.set("length", insns[i].length);
        x.set("bytes", hex_of(b, off, insns[i].length));
        x.set("text", insns[i].text);
        arr.push(x);
        off += insns[i].length;
    }
    json_obj@ o = ok_reply("disasm_function", id);
    o.set("count", insns.length());
    o.set("size", off);
    o.set("complete", complete);
    o.set("results", arr);
    send_json(o);
}

// read_fields: many typed fields of one struct from a single process::read_buffer snapshot.
void h_read_fields(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 a;
    uint64 size = 0;
    if (!get_addr(r, "address", a) || !opt_addr(r, "size", 0, size)) { bad_args(id, "read_fields requires 'address'"); return; }
    if (!has_key(r, "fields") || r.type("fields") != json_type::array) { bad_args(id, "read_fields requires 'fields' ([{offset, type}])"); return; }
    json_obj@ fs = r.get_obj("fields");
    if (fs.length() > RF_MAX_FIELDS) { send_error(id, E_LIMIT, "limit exceeded", "at most 1024 fields"); return; }
    // the snapshot covers every field (u64 width for the last one when size is not given)
    for (uint i = 0; i < fs.length(); i++)
    {
        json_obj@ f = fs.get_obj_at(i);
        uint64 off = 0;
        if (f is null || !get_addr(f, "offset", off)) { bad_args(id, "each field needs a numeric offset"); return; }
        if (off + 8 > size) size = off + 8;
    }
    if (size == 0 || size > EMU_MAX_BLOB_BYTES) { send_error(id, E_LIMIT, "limit exceeded", "fields must lie within 64 KiB"); return; }
    memory_buffer@ mb = process::read_buffer(a, size);
    if (mb is null) { send_error(id, E_FAILED, "read failed", hex_addr(a)); return; }
    json_obj@ out = json::array();
    for (uint i = 0; i < fs.length(); i++)
    {
        json_obj@ f = fs.get_obj_at(i);
        uint64 off = 0;
        get_addr(f, "offset", off);
        string t = "u64";
        opt_str(f, "type", "u64", t);
        json_obj@ e = json_obj();
        e.set("offset", off);
        e.set("type", t);
        if (t == "u8") e.set("value", util::format_string("{}", mb.read_uint8(off)));
        else if (t == "u16") e.set("value", util::format_string("{}", mb.read_uint16(off)));
        else if (t == "u32") e.set("value", util::format_string("{}", mb.read_uint32(off)));
        else if (t == "i8") e.set("value", util::format_string("{}", mb.read_int8(off)));
        else if (t == "i16") e.set("value", util::format_string("{}", mb.read_int16(off)));
        else if (t == "i32") e.set("value", util::format_string("{}", mb.read_int32(off)));
        else if (t == "i64") e.set("value", util::format_string("{}", mb.read_int64(off)));
        else if (t == "f32") e.set("value", util::format_string("{}", mb.read_float(off)));
        else if (t == "f64") e.set("value", util::format_string("{}", mb.read_double(off)));
        else if (t == "ptr" || t == "u64") e.set("value", t == "ptr" ? hex_addr(mb.read_uint64(off)) : util::format_string("{}", mb.read_uint64(off)));
        else { bad_args(id, "unknown field type: " + t + " (u8..u64, i8..i64, f32, f64, ptr)"); return; }
        out.push(e);
    }
    json_obj@ o = ok_reply("read_fields", id);
    o.set("address", hex_addr(a));
    o.set("fields", out);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Emulation extras, shared by emulate jobs (job thread) and the emu_* session (ws thread); each
// owns its own EmuExtras, so the two never share state:
//   * register-change traces (trace_regs): per instruction, the GPRs that changed
//   * API stand-ins (stubs): common Win32 / CRT calls are simulated and return to the caller
//   * unpacking layers (layers): writes to pages that later execute (write-then-execute)
//   * unmapped policy (on_unmapped: "zero"): unmapped reads map a zero page and are logged
//   * xmm0..xmm15 in requests and replies
// ---------------------------------------------------------------------------------------------

const uint EMUX_MAX_API_LOG = 2000;
const uint EMUX_MAX_LAYERS = 256;
const uint EMUX_MAX_FAULTS = 256;
const uint64 EMUX_HEAP = 0x5f0000000000;

array<string> g_gpr_names = { "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };

class EmuExtras
{
    bool regs_on;
    uint regs_limit;
    array<uint64> prev;
    json_obj@ reg_trace;
    bool stubs;
    hash_map@ stub_at;          // address -> API name
    json_obj@ api_calls;
    uint api_count;
    uint64 heap_next;
    bool layers;
    hash_set_uint64@ written;   // pages written during the run
    hash_set_uint64@ entered;   // written pages that later executed (one layer each)
    json_obj@ layer_out;
    bool zero_unmapped;
    json_obj@ faults;
    uint fault_count;
    bool blank;
    EmuExtras()
    {
        regs_on = false; regs_limit = 0; stubs = false; api_count = 0; heap_next = EMUX_HEAP;
        layers = false; zero_unmapped = false; fault_count = 0; blank = false;
        @reg_trace = json::array(); @api_calls = json::array(); @layer_out = json::array(); @faults = json::array();
        @stub_at = create_hash_map(); @written = create_hash_set_uint64(); @entered = create_hash_set_uint64();
        prev.resize(16);
    }
}

EmuExtras@ g_emu_x = EmuExtras();    // emulate job
EmuExtras@ g_emud_x = EmuExtras();   // emu_* session

// Reads the extras options; "" on success, else the problem.
string emux_parse(json_obj@ r, EmuExtras@ x, int64 trace_limit)
{
    bool v;
    if (!opt_bool(r, "trace_regs", false, v)) return "trace_regs must be a bool";
    x.regs_on = v;
    x.regs_limit = uint(trace_limit > 0 ? trace_limit : 2000);
    if (!opt_bool(r, "stubs", false, v)) return "stubs must be a bool";
    x.stubs = v;
    if (!opt_bool(r, "layers", false, v)) return "layers must be a bool";
    x.layers = v;
    string un;
    if (!opt_str(r, "on_unmapped", "stop", un) || (un != "stop" && un != "zero")) return "on_unmapped must be 'stop' or 'zero'";
    x.zero_unmapped = un == "zero";
    return "";
}

// The register-change baseline is the state at the start of each run.
void emux_prepare_regs(uint64 h, EmuExtras@ x)
{
    x.prev.resize(16);
    for (uint i = 0; i < 16; i++) x.prev[i] = emux_reg(h, g_gpr_names[i]);
}

void emux_reset_run(EmuExtras@ x)
{
    @x.reg_trace = json::array();
    @x.api_calls = json::array();
    x.api_count = 0;
    @x.layer_out = json::array();
    @x.faults = json::array();
    x.fault_count = 0;
}

void emux_stub_module(EmuExtras@ x, const string &in mod, const array<string> &in names)
{
    uint64 base = process::get_module_base(mod);
    if (base == 0) return;
    for (uint i = 0; i < names.length(); i++)
    {
        uint64 a = process::get_module_export(base, names[i]);
        if (a != 0) x.stub_at.set_string(a, names[i]);
    }
}

// Resolves the stand-in table from the attached process (blank emulators have no imports to hit).
void emux_prepare(uint64 h, EmuExtras@ x)
{
    x.prev.resize(16);
    for (uint i = 0; i < 16; i++)
    {
        x86_reg reg;
        emu_reg(g_gpr_names[i], reg);
        uint64 v = 0;
        uc::reg_read64(h, reg, v);
        x.prev[i] = v;
    }
    if (!x.stubs || x.blank) return;
    @x.stub_at = create_hash_map();
    array<string> k32 = { "VirtualAlloc", "VirtualFree", "VirtualProtect", "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
                          "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "Sleep", "GetTickCount", "GetTickCount64",
                          "QueryPerformanceCounter", "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetCurrentProcess",
                          "GetCurrentProcessId", "GetCurrentThreadId", "GetProcessHeap", "HeapAlloc", "HeapFree", "OutputDebugStringA" };
    emux_stub_module(x, "kernel32.dll", k32);
    emux_stub_module(x, "kernelbase.dll", k32);
    array<string> nt = { "RtlAllocateHeap", "RtlFreeHeap", "memcpy", "memmove", "memset", "strlen", "wcslen" };
    emux_stub_module(x, "ntdll.dll", nt);
    array<string> crt = { "memcpy", "memmove", "memset", "strlen", "wcslen", "malloc", "calloc", "free" };
    emux_stub_module(x, "msvcrt.dll", crt);
    emux_stub_module(x, "ucrtbase.dll", crt);
    emux_stub_module(x, "vcruntime140.dll", crt);
}

bool emux_read(uint64 h, EmuExtras@ x, uint64 a, uint n, array<uint8> &out b)
{
    if (n == 0) { b.resize(0); return true; }
    if (uc::mem_read(h, a, n, b)) return true;
    if (x.blank) return false;
    array<uint8>@ p = process::read_bytes(a, n);
    if (p is null || p.length() < n) return false;
    b = p;
    return true;
}

// Writes into the emulator, faulting the pages in from the process first (or zeroes).
bool emux_write(uint64 h, EmuExtras@ x, uint64 a, const array<uint8> &in b)
{
    if (b.length() == 0) return true;
    for (uint64 p = a & ~uint64(0xFFF); p < a + b.length(); p += 0x1000)
    {
        if (uc::mem_query(h, p) >= 0) { array<uint8> t; if (uc::mem_read(h, p, 1, t)) continue; }
        array<uint8>@ src = x.blank ? null : process::read_bytes(p, 0x1000);
        if (!uc::mem_map(h, p, 0x1000, uint(uc::prot::all))) return false;
        if (src !is null && src.length() == 0x1000) uc::mem_write(h, p, src);
    }
    return uc::mem_write(h, a, b);
}

string lower_ascii(const string &in s)
{
    string o = s;
    for (uint i = 0; i < o.length(); i++)
        if (o[i] >= 65 && o[i] <= 90) o[i] = o[i] + 32;
    return o;
}

int str_index(const array<string> &in a, const string &in v)
{
    for (uint i = 0; i < a.length(); i++)
        if (a[i] == v) return int(i);
    return -1;
}

array<string> split_str(const string &in s, const string &in sep)
{
    array<string> out;
    uint start = 0;
    for (;;)
    {
        int at = s.findFirst(sep, start);
        if (at < 0) { out.insertLast(s.substr(start)); break; }
        out.insertLast(s.substr(start, uint(at) - start));
        start = uint(at) + sep.length();
    }
    return out;
}

string chr8(uint8 c)
{
    string s = " ";
    s[0] = c;
    return s;
}

string emux_cstr(uint64 h, EmuExtras@ x, uint64 a, bool wide)
{
    if (a == 0) return "";
    array<uint8> b;
    if (!emux_read(h, x, a, 512, b)) return "";
    string s;
    if (wide)
    {
        for (uint i = 0; i + 1 < b.length() && (b[i] != 0 || b[i + 1] != 0); i += 2) s += chr8(b[i]);
    }
    else for (uint i = 0; i < b.length() && b[i] != 0; i++) s += chr8(b[i]);
    return s;
}

uint64 emux_alloc(uint64 h, EmuExtras@ x, uint64 n)
{
    uint64 size = align_up(n == 0 ? 1 : n, 0x1000);
    uint64 a = x.heap_next;
    if (!uc::mem_map(h, a, size, uint(uc::prot::all))) return 0;
    x.heap_next += size + 0x1000;   // a guard gap between blocks
    return a;
}

uint64 emux_reg(uint64 h, const string &in n)
{
    x86_reg reg;
    uint64 v = 0;
    if (emu_reg(n, reg)) uc::reg_read64(h, reg, v);
    return v;
}

// Simulates the API at `address`, then returns to the caller (Win64 ABI: rcx, rdx, r8, r9 -> rax).
void emux_stub(uint64 h, EmuExtras@ x, uint64 address, const string &in name)
{
    uint64 a1 = emux_reg(h, "rcx"), a2 = emux_reg(h, "rdx"), a3 = emux_reg(h, "r8"), a4 = emux_reg(h, "r9");
    uint64 ret = 0;
    string note = "";
    if (name == "VirtualAlloc" || name == "malloc" || name == "HeapAlloc" || name == "RtlAllocateHeap" || name == "calloc")
    {
        uint64 n = name == "VirtualAlloc" ? a2 : (name == "malloc" ? a1 : (name == "calloc" ? a1 * a2 : a3));
        ret = (name == "VirtualAlloc" && a1 != 0) ? a1 : emux_alloc(h, x, n);
        if (name == "VirtualAlloc" && a1 != 0 && uc::mem_query(h, a1) < 0) uc::mem_map(h, a1 & ~uint64(0xFFF), align_up(a2, 0x1000), uint(uc::prot::all));
        note = hex_addr(n) + " bytes";
    }
    else if (name == "VirtualFree" || name == "HeapFree" || name == "RtlFreeHeap" || name == "free") ret = 1;
    else if (name == "VirtualProtect")
    {
        if (a4 != 0) { array<uint8> old = { 0x40, 0, 0, 0 }; emux_write(h, x, a4, old); }
        ret = 1;
    }
    else if (name == "memcpy" || name == "memmove")
    {
        array<uint8> b;
        if (a3 <= 0x1000000 && emux_read(h, x, a2, uint(a3), b)) emux_write(h, x, a1, b);
        ret = a1;
    }
    else if (name == "memset")
    {
        array<uint8> b;
        if (a3 <= 0x1000000) { b.resize(uint(a3)); for (uint i = 0; i < b.length(); i++) b[i] = uint8(a2 & 0xFF); emux_write(h, x, a1, b); }
        ret = a1;
    }
    else if (name == "strlen") ret = emux_cstr(h, x, a1, false).length();
    else if (name == "wcslen") ret = emux_cstr(h, x, a1, true).length();
    else if (name == "GetProcAddress")
    {
        string fn = emux_cstr(h, x, a2, false);
        ret = a2 < 0x10000 ? 0 : process::get_module_export(a1, fn);
        note = fn;
    }
    else if (name == "GetModuleHandleA" || name == "GetModuleHandleW" || name.findFirst("LoadLibrary") == 0)
    {
        string mod = emux_cstr(h, x, a1, name.substr(name.length() - 1) == "W");
        ret = mod == "" ? g_base : process::get_module_base(mod);
        note = mod;
    }
    else if (name == "GetTickCount" || name == "GetTickCount64") ret = util::tickcount();
    else if (name == "QueryPerformanceCounter")
    {
        uint64 t = util::tickcount() * 10000;
        array<uint8> b;
        for (uint i = 0; i < 8; i++) b.insertLast(uint8((t >> (8 * i)) & 0xFF));
        if (a1 != 0) emux_write(h, x, a1, b);
        ret = 1;
    }
    else if (name == "CheckRemoteDebuggerPresent")
    {
        array<uint8> zero = { 0, 0, 0, 0 };
        if (a2 != 0) emux_write(h, x, a2, zero);
        ret = 1;
    }
    else if (name == "GetCurrentProcess") ret = uint64(0xFFFFFFFFFFFFFFFF);
    else if (name == "GetCurrentProcessId") ret = g_pid;
    else if (name == "GetProcessHeap") ret = 0x10000;
    else ret = 0;   // IsDebuggerPresent, Sleep, OutputDebugStringA, GetCurrentThreadId, ...
    // return to the caller: pop the return address
    uint64 rsp = emux_reg(h, "rsp");
    array<uint8> rb;
    uint64 back = 0;
    if (emux_read(h, x, rsp, 8, rb)) for (uint i = 0; i < 8; i++) back |= uint64(rb[i]) << (8 * i);
    uc::reg_write64(h, x86_reg::rax, ret);
    uc::reg_write64(h, x86_reg::rsp, rsp + 8);
    uc::reg_write64(h, x86_reg::rip, back);
    x.api_count++;
    if (x.api_calls.length() < EMUX_MAX_API_LOG)
    {
        json_obj@ c = json_obj();
        c.set("api", name);
        c.set("address", hex_addr(address));
        c.set("return_to", hex_addr(back));
        c.set("result", hex_addr(ret));
        c.set("args", hex_addr(a1) + ", " + hex_addr(a2) + ", " + hex_addr(a3) + ", " + hex_addr(a4));
        if (note != "") c.set("note", note);
        x.api_calls.push(c);
    }
}

// Memory operands of the instruction at `address` (effective addresses, sizes, write flags).
void emux_mem_ops(uint64 h, uint64 address, uint32 size, array<uint64> &out eas, array<uint> &out sizes, array<bool> &out writes)
{
    eas.resize(0); sizes.resize(0); writes.resize(0);
    array<uint8> code;
    if (!uc::mem_read(h, address, size, code)) return;
    array<disasm_insn@> insns;
    if (!zydis::disasm(code, address, insns) || insns.length() == 0) return;
    disasm_insn@ insn = insns[0];
    if (insn.text.findFirst("lea ") == 0 || insn.text.findFirst("nop") == 0) return;
    for (uint8 i = 0; i < insn.operand_count_visible; i++)
    {
        disasm_operand op = insn.get_op(i);
        if (op.type != op_type::mem) continue;
        bool r = (op.action & (int(op_action::read) | int(op_action::condread))) != 0;
        bool w = (op.action & (int(op_action::write) | int(op_action::condwrite))) != 0;
        if (!r && !w) continue;
        uint64 base = 0, index = 0;
        uint64 next_rip = address + size;
        if (!emu_addr_reg(h, op.mem_base, next_rip, base) || !emu_addr_reg(h, op.mem_index, next_rip, index)) continue;
        uint64 ea = base + index * op.mem_scale + uint64(op.mem_disp);
        string seg = op.mem_segment == 0 ? "" : zydis::reg_name(op.mem_segment);
        uint64 sb = 0;
        if (seg == "gs") uc::reg_read64(h, x86_reg::gs_base, sb);
        else if (seg == "fs") uc::reg_read64(h, x86_reg::fs_base, sb);
        eas.insertLast(ea + sb);
        sizes.insertLast(emu_ptr_size(insn.text));
        writes.insertLast(w);
    }
}

// Per-instruction work for the extras.
// Returns false when a stand-in ran (execution continues at the caller).
bool emux_code(uint64 h, EmuExtras@ x, uint64 address, uint32 size)
{
    if (x.stubs && x.stub_at.contains(address))
    {
        string name;
        x.stub_at.get_string(address, name);
        emux_stub(h, x, address, name);
        return false;
    }
    if (x.layers)
    {
        uint64 page = address & ~uint64(0xFFF);
        if (x.written.contains(page) && !x.entered.contains(page))
        {
            x.entered.insert(page);
            if (x.layer_out.length() < EMUX_MAX_LAYERS)
            {
                json_obj@ l = json_obj();
                l.set("entry", hex_addr(address));
                l.set("page", hex_addr(page));
                x.layer_out.push(l);
            }
        }
        array<uint64> eas;
        array<uint> sizes;
        array<bool> writes;
        emux_mem_ops(h, address, size, eas, sizes, writes);
        for (uint i = 0; i < eas.length(); i++)
            if (writes[i]) { x.written.insert(eas[i] & ~uint64(0xFFF)); x.written.insert((eas[i] + sizes[i] - 1) & ~uint64(0xFFF)); }
    }
    if (x.regs_on && x.reg_trace.length() < x.regs_limit)
    {
        json_obj@ ch = json_obj();
        uint n = 0;
        for (uint i = 0; i < 16; i++)
        {
            x86_reg reg;
            emu_reg(g_gpr_names[i], reg);
            uint64 v = 0;
            uc::reg_read64(h, reg, v);
            if (v != x.prev[i]) { ch.set(g_gpr_names[i], hex_addr(v)); x.prev[i] = v; n++; }
        }
        json_obj@ e = json_obj();
        e.set("rip", hex_addr(address));
        if (n > 0) e.set("changes", ch);
        x.reg_trace.push(e);
    }
    return true;
}

// on_unmapped "zero": map a zero page at the fault and continue; every fault is logged.
bool emux_unmapped(EmuExtras@ x, uint64 h, uint64 address)
{
    x.fault_count++;
    if (x.faults.length() < EMUX_MAX_FAULTS)
    {
        json_obj@ f = json_obj();
        f.set("address", hex_addr(address));
        f.set("rip", hex_addr(emux_reg(h, "rip")));
        x.faults.push(f);
    }
    if (!x.zero_unmapped) return false;
    return uc::mem_map(h, address & ~uint64(0xFFF), 0x1000, uint(uc::prot::all));
}

bool emu_unmapped_hook(uint64 h, uc::mem_type type, uint64 address, uint32 size, uint64 value) { return emux_unmapped(g_emu_x, h, address); }
bool emud_unmapped_hook(uint64 h, uc::mem_type type, uint64 address, uint32 size, uint64 value) { return emux_unmapped(g_emud_x, h, address); }

// "xmm": { "xmm0": "<32 hex chars>" } -> emulator registers; "" or the problem.
string emux_set_xmm(uint64 h, json_obj@ r)
{
    if (!has_key(r, "xmm")) return "";
    if (r.type("xmm") != json_type::object) return "xmm must be an object";
    json_obj@ xm = r.get_obj("xmm");
    array<string>@ keys = xm.keys();
    for (uint i = 0; i < keys.length(); i++)
    {
        x86_reg reg;
        if (!xmm_reg(keys[i], reg)) return "unknown xmm register: " + keys[i];
        array<uint8> b;
        string hx;
        if (!opt_str(xm, keys[i], "", hx) || !parse_hex_bytes(hx, b) || b.length() != 16) return keys[i] + " must be 16 bytes of hex";
        if (!uc::reg_write128(h, reg, b)) return "cannot write " + keys[i];
    }
    return "";
}

bool xmm_reg(const string &in n, x86_reg &out r)
{
    array<x86_reg> regs = { x86_reg::xmm0, x86_reg::xmm1, x86_reg::xmm2, x86_reg::xmm3, x86_reg::xmm4, x86_reg::xmm5, x86_reg::xmm6, x86_reg::xmm7,
                            x86_reg::xmm8, x86_reg::xmm9, x86_reg::xmm10, x86_reg::xmm11, x86_reg::xmm12, x86_reg::xmm13, x86_reg::xmm14, x86_reg::xmm15 };
    for (uint i = 0; i < 16; i++)
        if (n == "xmm" + i) { r = regs[i]; return true; }
    return false;
}

json_obj@ emux_xmm_json(uint64 h)
{
    json_obj@ o = json_obj();
    for (uint i = 0; i < 16; i++)
    {
        x86_reg reg;
        xmm_reg("xmm" + i, reg);
        array<uint8> b;
        if (uc::reg_read128(h, reg, b) && b.length() == 16) o.set("xmm" + i, hex_of(b, 0, 16));
    }
    return o;
}

// Adds the extras' results to a reply (xmm read while the handle is still open).
void emux_report(json_obj@ o, EmuExtras@ x, json_obj@ xmm)
{
    if (x.regs_on) o.set("reg_trace", x.reg_trace);
    if (x.stubs) { o.set("api_calls", x.api_calls); o.set("api_call_count", x.api_count); }
    if (x.layers) o.set("layers", x.layer_out);
    if (x.fault_count > 0) { o.set("faults", x.faults); o.set("fault_count", x.fault_count); }
    if (xmm !is null) o.set("xmm", xmm);
}

// ---------------------------------------------------------------------------------------------
// emu_* session additions: conditional breakpoints, memory watchpoints, snapshots
// ---------------------------------------------------------------------------------------------

array<string> g_emud_conds;        // parallel to g_emud_bps: "" or "rax==0x10"
array<uint64> g_emud_wp_addr;
array<uint64> g_emud_wp_size;
array<uint> g_emud_wp_mode;        // 1 read, 2 write, 3 both
bool g_emud_wp_hit_on = false;
json_obj@ g_emud_wp_hit;

class EmuSnap
{
    string name;
    array<uint64> regs;
    array<array<uint8> > xmm;
    array<uint64> bases;
    array<array<uint8> > data;
    uint64 count;
    uint64 bytes;
    EmuSnap() { count = 0; bytes = 0; }
}
array<EmuSnap@> g_emud_snaps;
const uint EMUD_MAX_SNAPS = 8;
const uint64 EMUD_SNAP_BYTES = 0x8000000;   // 128 MiB across one snapshot

// "rax==0x10", "rcx!=0", "rdx<0x100", "r8&0x1" (bit test): evaluated against the session registers.
bool emud_cond_true(uint64 h, const string &in c)
{
    if (c == "") return true;
    array<string> ops = { "==", "!=", "<=", ">=", "<", ">", "&" };
    for (uint i = 0; i < ops.length(); i++)
    {
        int at = c.findFirst(ops[i]);
        if (at <= 0) continue;
        string lhs = c.substr(0, uint(at));
        string rhs = c.substr(uint(at) + ops[i].length());
        uint64 v;
        if (!parse_hex_u64(rhs, v) && !parse_dec_u64(rhs, v)) return true;   // malformed: stop anyway
        uint64 cur = emux_reg(h, lhs);
        if (ops[i] == "==") return cur == v;
        if (ops[i] == "!=") return cur != v;
        if (ops[i] == "<=") return cur <= v;
        if (ops[i] == ">=") return cur >= v;
        if (ops[i] == "<") return cur < v;
        if (ops[i] == ">") return cur > v;
        return (cur & v) != 0;
    }
    return true;
}

// true when the instruction at `address` touches a watched range the way the watch asks.
bool emud_watch_hit(uint64 h, uint64 address, uint32 size)
{
    if (g_emud_wp_addr.length() == 0) return false;
    array<uint64> eas;
    array<uint> sizes;
    array<bool> writes;
    emux_mem_ops(h, address, size, eas, sizes, writes);
    for (uint i = 0; i < eas.length(); i++)
        for (uint k = 0; k < g_emud_wp_addr.length(); k++)
        {
            bool overlap = eas[i] < g_emud_wp_addr[k] + g_emud_wp_size[k] && eas[i] + sizes[i] > g_emud_wp_addr[k];
            uint want = g_emud_wp_mode[k];
            bool kind = writes[i] ? (want & 2) != 0 : (want & 1) != 0;
            if (overlap && kind)
            {
                @g_emud_wp_hit = json_obj();
                g_emud_wp_hit.set("rip", hex_addr(address));
                g_emud_wp_hit.set("address", hex_addr(eas[i]));
                g_emud_wp_hit.set("size", sizes[i]);
                g_emud_wp_hit.set("access", writes[i] ? "write" : "read");
                g_emud_wp_hit.set("watch", hex_addr(g_emud_wp_addr[k]));
                return true;
            }
        }
    return false;
}

void h_emu_watch(json_obj@ r, int64 id)
{
    if (!emud_ready(id)) return;
    bool clear = false, on = true;
    if (!opt_bool(r, "clear", false, clear) || !opt_bool(r, "enabled", true, on)) { bad_args(id, "clear/enabled must be bools"); return; }
    if (clear) { g_emud_wp_addr.resize(0); g_emud_wp_size.resize(0); g_emud_wp_mode.resize(0); }
    if (has_key(r, "address"))
    {
        uint64 a, n = 8;
        string mode;
        if (!get_addr(r, "address", a) || !opt_addr(r, "size", 8, n) || !opt_str(r, "access", "rw", mode)) { bad_args(id, "emu_watch needs address, size?, access? (r|w|rw)"); return; }
        uint m = mode == "r" ? 1 : (mode == "w" ? 2 : 3);
        int at = u64_index(g_emud_wp_addr, a);
        if (at >= 0) { g_emud_wp_addr.removeAt(uint(at)); g_emud_wp_size.removeAt(uint(at)); g_emud_wp_mode.removeAt(uint(at)); }
        if (on) { g_emud_wp_addr.insertLast(a); g_emud_wp_size.insertLast(n == 0 ? 1 : n); g_emud_wp_mode.insertLast(m); }
    }
    json_obj@ o = ok_reply("emu_watch", id);
    json_obj@ arr = json::array();
    for (uint i = 0; i < g_emud_wp_addr.length(); i++)
    {
        json_obj@ w = json_obj();
        w.set("address", hex_addr(g_emud_wp_addr[i]));
        w.set("size", g_emud_wp_size[i]);
        w.set("access", g_emud_wp_mode[i] == 1 ? "r" : (g_emud_wp_mode[i] == 2 ? "w" : "rw"));
        arr.push(w);
    }
    o.set("watchpoints", arr);
    send_json(o);
}

void h_emu_snapshot(json_obj@ r, int64 id)
{
    if (!emud_ready(id)) return;
    string name;
    if (!opt_str(r, "name", "default", name)) { bad_args(id, "name must be a string"); return; }
    EmuSnap@ s = EmuSnap();
    s.name = name;
    s.count = g_emud_count;
    array<string> names = { "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags" };
    for (uint i = 0; i < names.length(); i++) s.regs.insertLast(emux_reg(g_emud, names[i]));
    for (uint i = 0; i < 16; i++)
    {
        x86_reg reg;
        xmm_reg("xmm" + i, reg);
        array<uint8> b;
        uc::reg_read128(g_emud, reg, b);
        s.xmm.insertLast(b);
    }
    array<uc_memory_region> regions;
    if (!uc::mem_regions(g_emud, regions)) { send_error(id, E_FAILED, "operation failed", "cannot list emulator memory"); return; }
    for (uint i = 0; i < regions.length(); i++)
    {
        uint64 n = regions[i].end - regions[i].address;
        if ((n & 0xFFF) == 0xFFF) n++;   // the end is inclusive in Unicorn
        if (s.bytes + n > EMUD_SNAP_BYTES) { send_error(id, E_LIMIT, "limit exceeded", "the session maps more than 128 MiB"); return; }
        array<uint8> b;
        if (!uc::mem_read(g_emud, regions[i].address, uint(n), b)) continue;
        s.bases.insertLast(regions[i].address);
        s.data.insertLast(b);
        s.bytes += n;
    }
    for (uint i = 0; i < g_emud_snaps.length(); i++)
        if (g_emud_snaps[i].name == name) { g_emud_snaps.removeAt(i); break; }
    if (g_emud_snaps.length() >= EMUD_MAX_SNAPS) g_emud_snaps.removeAt(0);
    g_emud_snaps.insertLast(s);
    json_obj@ o = ok_reply("emu_snapshot", id);
    o.set("name", name);
    o.set("regions", s.bases.length());
    o.set("bytes", s.bytes);
    o.set("instructions", s.count);
    json_obj@ list = json::array();
    for (uint i = 0; i < g_emud_snaps.length(); i++) list.push(g_emud_snaps[i].name);
    o.set("snapshots", list);
    send_json(o);
}

void h_emu_restore(json_obj@ r, int64 id)
{
    if (!emud_ready(id)) return;
    string name;
    if (!opt_str(r, "name", "default", name)) { bad_args(id, "name must be a string"); return; }
    EmuSnap@ s;
    for (uint i = 0; i < g_emud_snaps.length(); i++)
        if (g_emud_snaps[i].name == name) @s = g_emud_snaps[i];
    if (s is null) { send_error(id, E_FAILED, "operation failed", "no snapshot named " + name); return; }
    for (uint i = 0; i < s.bases.length(); i++) uc::mem_write(g_emud, s.bases[i], s.data[i]);
    array<string> names = { "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags" };
    for (uint i = 0; i < names.length(); i++)
    {
        x86_reg reg;
        emu_reg(names[i], reg);
        uc::reg_write64(g_emud, reg, s.regs[i]);
    }
    for (uint i = 0; i < 16 && i < s.xmm.length(); i++)
    {
        x86_reg reg;
        xmm_reg("xmm" + i, reg);
        if (s.xmm[i].length() == 16) uc::reg_write128(g_emud, reg, s.xmm[i]);
    }
    g_emud_count = s.count;
    uc::flush_code(g_emud);
    send_json(emud_state("emu_restore", id, emud_stop("restored")));
}

// ---------------------------------------------------------------------------------------------
// Page hashing (the relay's page monitor uses it instead of reading every page over the socket)
// ---------------------------------------------------------------------------------------------

const uint64 HASH_MAX_BYTES = 0x4000000;   // 64 MiB per request

// 64-bit FNV-1a over the page's qwords (unreadable pages hash to 0).
uint64 page_hash(memory_buffer@ buf, uint64 off)
{
    uint64 h = uint64(0xcbf29ce484222325);
    for (uint64 o = off; o < off + 0x1000; o += 8)
    {
        h ^= buf.read_uint64(o);
        h *= uint64(0x100000001b3);
    }
    return h | 1;
}

void h_hash_pages(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    if (!has_key(r, "ranges") || r.type("ranges") != json_type::array) { bad_args(id, "hash_pages requires 'ranges' ([{address, size}])"); return; }
    json_obj@ ranges = r.get_obj("ranges");
    json_obj@ out = json::array();
    uint64 total = 0;
    for (uint i = 0; i < ranges.length(); i++)
    {
        json_obj@ g = ranges.get_obj_at(i);
        uint64 a, n;
        if (g is null || !get_addr(g, "address", a) || !get_addr(g, "size", n)) { bad_args(id, "each range needs address and size"); return; }
        a &= ~uint64(0xFFF);
        n = align_up(n, 0x1000);
        total += n;
        if (total > HASH_MAX_BYTES) { send_error(id, E_LIMIT, "limit exceeded", "at most 64 MiB per request"); return; }
        // hashes packed as 16 hex digits per page keep the reply small
        string packed;
        for (uint64 pos = a; pos < a + n; pos += CHUNK)
        {
            uint64 len = umin(CHUNK, a + n - pos);
            memory_buffer@ buf = process::read_buffer(pos, len);
            for (uint64 o = 0; o < len; o += 0x1000)
            {
                uint64 h = 0;
                if (buf !is null) h = page_hash(buf, o);
                else
                {
                    memory_buffer@ one = process::read_buffer(pos + o, 0x1000);
                    if (one !is null) h = page_hash(one, 0);
                }
                packed += bits_hex_be(h);
            }
        }
        json_obj@ e = json_obj();
        e.set("address", hex_addr(a));
        e.set("pages", n / 0x1000);
        e.set("hashes", packed);
        out.push(e);
    }
    json_obj@ o = ok_reply("hash_pages", id);
    o.set("ranges", out);
    send_json(o);
}

// 16 hex digits, most significant first.
string bits_hex_be(uint64 v)
{
    string s = "";
    string d = "0123456789abcdef";
    for (int i = 15; i >= 0; i--) s += d.substr(uint((v >> (4 * i)) & 0xF), 1);
    return s;
}

// ---------------------------------------------------------------------------------------------
// Typed values for watches and freezes
// ---------------------------------------------------------------------------------------------

uint vt_width(const string &in vt)
{
    if (vt == "u8" || vt == "i8") return 1;
    if (vt == "u16" || vt == "i16") return 2;
    if (vt == "u32" || vt == "i32" || vt == "f32") return 4;
    if (vt == "u64" || vt == "i64" || vt == "f64") return 8;
    return 0;
}

// Little-endian bytes -> number as a double (ints sign-extended for i*).
bool num_decode(const string &in vt, const array<uint8> &in b, double &out v)
{
    uint w = vt_width(vt);
    if (w == 0 || b.length() < w) return false;
    uint64 bits = 0;
    for (uint i = 0; i < w; i++) bits |= uint64(b[i]) << (8 * i);
    if (vt == "f32" || vt == "f64") return flt_decode(w, bits, v);
    if (vt.substr(0, 1) == "i")
    {
        int64 sv = int64(bits);
        if (w < 8) sv = (sv << (64 - w * 8)) >> (64 - w * 8);
        v = double(sv);
        return true;
    }
    v = double(bits);
    return true;
}

bool num_read(const string &in vt, uint64 a, double &out v)
{
    array<uint8>@ b = process::read_bytes(a, vt_width(vt));
    return b !is null && num_decode(vt, b, v);
}

bool num_write(const string &in vt, uint64 a, double v)
{
    if (vt == "f32") return process::write_float(a, float(v));
    if (vt == "f64") return process::write_double(a, v);
    if (vt == "u8") return process::write_uint8(a, uint8(int64(v)));
    if (vt == "i8") return process::write_int8(a, int8(int64(v)));
    if (vt == "u16") return process::write_uint16(a, uint16(int64(v)));
    if (vt == "i16") return process::write_int16(a, int16(int64(v)));
    if (vt == "u32") return process::write_uint32(a, uint32(int64(v)));
    if (vt == "i32") return process::write_int32(a, int32(int64(v)));
    if (vt == "u64") return process::write_uint64(a, uint64(v));
    if (vt == "i64") return process::write_int64(a, int64(v));
    return false;
}

// ---------------------------------------------------------------------------------------------
// Freeze groups
// ---------------------------------------------------------------------------------------------

void h_freeze_group(json_obj@ r, int64 id)
{
    string group;
    bool on;
    if (!opt_str(r, "group", "", group) || group == "" || !opt_bool(r, "enabled", true, on)) { bad_args(id, "freeze_group needs 'group' and 'enabled'"); return; }
    uint n = 0;
    g_freeze_mx.lock();
    for (uint i = 0; i < g_freeze.length(); i++)
        if (g_freeze[i].group == group) { g_freeze[i].paused = !on; n++; }
    g_freeze_mx.unlock();
    json_obj@ o = ok_reply("freeze_group", id);
    o.set("group", group);
    o.set("enabled", on);
    o.set("entries", n);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Memory snapshots kept in the agent: only changed ranges cross the socket
// ---------------------------------------------------------------------------------------------

class MemSnap
{
    string name;
    uint64 base;
    uint64 size;
    array<uint64> q;      // the range as qwords
    array<bool> ok;       // per 64 KiB chunk: readable at snapshot time
    MemSnap() { base = 0; size = 0; }
}
array<MemSnap@> g_snaps;
mutex@ g_snap_mx = create_mutex();
const uint64 SNAP_MAX_BYTES = 0x1000000;   // 16 MiB per snapshot
const uint SNAP_MAX = 8;
const uint64 SNAP_CHUNK = 0x10000;

bool snap_fill(uint64 base, uint64 size, array<uint64> &out q, array<bool> &out ok)
{
    q.resize(uint(size / 8));
    ok.resize(uint((size + SNAP_CHUNK - 1) / SNAP_CHUNK));
    for (uint64 pos = 0; pos < size; pos += SNAP_CHUNK)
    {
        uint64 len = umin(SNAP_CHUNK, size - pos);
        memory_buffer@ buf = process::read_buffer(base + pos, len);
        ok[uint(pos / SNAP_CHUNK)] = buf !is null;
        for (uint64 o = 0; o + 8 <= len; o += 8) q[uint((pos + o) / 8)] = buf is null ? 0 : buf.read_uint64(o);
    }
    return true;
}

// address/size, or module (its whole image)
string snap_range(json_obj@ r, uint64 &out base, uint64 &out size)
{
    string mod;
    if (!opt_str(r, "module", "", mod)) return "module must be a string";
    if (mod != "")
    {
        array<module_entry>@ mods = process::get_module_list();
        for (uint i = 0; mods !is null && i < mods.length(); i++)
            if (lower_ascii(mods[i].name) == lower_ascii(mod)) { base = mods[i].base; size = mods[i].size; return ""; }
        return "module not found: " + mod;
    }
    if (!get_addr(r, "address", base) || !get_addr(r, "size", size)) return "pass address and size, or module";
    return "";
}

void h_mem_snapshot(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    string name;
    if (!opt_str(r, "name", "default", name)) { bad_args(id, "name must be a string"); return; }
    uint64 base = 0, size = 0;
    string why = snap_range(r, base, size);
    if (why != "") { bad_args(id, why); return; }
    base &= ~uint64(7);
    size = align_up(size, 8);
    if (size == 0 || size > SNAP_MAX_BYTES) { send_error(id, E_LIMIT, "limit exceeded", "a snapshot covers 8 bytes .. 16 MiB"); return; }
    MemSnap@ s = MemSnap();
    s.name = name; s.base = base; s.size = size;
    snap_fill(base, size, s.q, s.ok);
    g_snap_mx.lock();
    for (uint i = 0; i < g_snaps.length(); i++)
        if (g_snaps[i].name == name) { g_snaps.removeAt(i); break; }
    if (g_snaps.length() >= SNAP_MAX) g_snaps.removeAt(0);
    g_snaps.insertLast(s);
    g_snap_mx.unlock();
    json_obj@ o = ok_reply("mem_snapshot", id);
    o.set("name", name);
    o.set("address", hex_addr(base));
    o.set("size", size);
    send_json(o);
}

void h_mem_diff(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    string name;
    bool update;
    int64 max_ranges;
    if (!opt_str(r, "name", "default", name) || !opt_bool(r, "update", false, update) || !opt_int(r, "max_ranges", 2000, max_ranges)) { bad_args(id, "name string, update bool, max_ranges number"); return; }
    MemSnap@ s;
    g_snap_mx.lock();
    for (uint i = 0; i < g_snaps.length(); i++)
        if (g_snaps[i].name == name) @s = g_snaps[i];
    g_snap_mx.unlock();
    if (s is null) { send_error(id, E_FAILED, "operation failed", "no snapshot named " + name); return; }
    array<uint64> cur;
    array<bool> ok;
    snap_fill(s.base, s.size, cur, ok);
    json_obj@ out = json::array();
    uint64 changed = 0;
    uint n = cur.length();
    uint i = 0;
    while (i < n)
    {
        if (cur[i] == s.q[i] || !ok[uint(uint64(i) * 8 / SNAP_CHUNK)]) { i++; continue; }
        uint j = i;
        // merge changed qwords separated by at most one unchanged qword
        while (j + 1 < n && (cur[j + 1] != s.q[j + 1] || (j + 2 < n && cur[j + 2] != s.q[j + 2]))) j++;
        changed += uint64(j - i + 1) * 8;
        if (out.length() < uint(max_ranges))
        {
            json_obj@ e = json_obj();
            e.set("address", hex_addr(s.base + uint64(i) * 8));
            e.set("size", (j - i + 1) * 8);
            string oh, nh;
            for (uint k = i; k <= j && k < i + 4; k++) { oh += bits_hex(s.q[k], 8); nh += bits_hex(cur[k], 8); }
            e.set("old", oh);
            e.set("new", nh);
            out.push(e);
        }
        i = j + 1;
    }
    if (update) { s.q = cur; s.ok = ok; }
    json_obj@ o = ok_reply("mem_diff", id);
    o.set("name", name);
    o.set("changed_bytes", changed);
    o.set("ranges", out);
    o.set("truncated", out.length() >= uint(max_ranges));
    send_json(o);
}

void h_mem_snapshot_list(json_obj@ r, int64 id)
{
    json_obj@ arr = json::array();
    g_snap_mx.lock();
    for (uint i = 0; i < g_snaps.length(); i++)
    {
        json_obj@ e = json_obj();
        e.set("name", g_snaps[i].name);
        e.set("address", hex_addr(g_snaps[i].base));
        e.set("size", g_snaps[i].size);
        arr.push(e);
    }
    g_snap_mx.unlock();
    json_obj@ o = ok_reply("mem_snapshot_list", id);
    o.set("snapshots", arr);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Pointer maps: save pointer-scan results, intersect runs across restarts
// ---------------------------------------------------------------------------------------------

json_obj@ g_ptr_last;   // results of the last pointer_scan
const string DATA_DIR = "echodebug";

string ptr_key(json_obj@ e)
{
    string k = e.get_string("module") + "|" + hex_addr(e.get_uint64("module_offset"));
    json_obj@ offs = e.get_obj("offsets");
    for (uint i = 0; offs !is null && i < offs.length(); i++) k += "|" + offs.get_double_at(i);
    return k;
}

void h_ptr_save(json_obj@ r, int64 id)
{
    string name;
    if (!opt_str(r, "name", "", name) || name == "") { bad_args(id, "ptr_save needs 'name'"); return; }
    if (g_ptr_last is null) { send_error(id, E_FAILED, "operation failed", "run pointer_scan first"); return; }
    dir::create(DATA_DIR);
    if (!file::write(DATA_DIR + "/pointers_" + name + ".json", json::stringify(g_ptr_last))) { send_error(id, E_FAILED, "operation failed", "cannot write the pointer map"); return; }
    json_obj@ o = ok_reply("ptr_save", id);
    o.set("name", name);
    o.set("paths", g_ptr_last.length());
    send_json(o);
}

json_obj@ ptr_load(const string &in name)
{
    if (name == "@last") return g_ptr_last;
    string text;
    if (!file::read(DATA_DIR + "/pointers_" + name + ".json", text)) return null;
    string err;
    return json::parse(text, err);
}

void h_ptr_compare(json_obj@ r, int64 id)
{
    if (!has_key(r, "names") || r.type("names") != json_type::array) { bad_args(id, "ptr_compare needs 'names' (saved maps; '@last' is the last scan)"); return; }
    json_obj@ names = r.get_obj("names");
    if (names.length() < 2) { bad_args(id, "compare at least two maps"); return; }
    json_obj@ first = ptr_load(names.get_string_at(0));
    if (first is null) { send_error(id, E_FAILED, "operation failed", "cannot load " + names.get_string_at(0)); return; }
    array<string> keep;
    array<json_obj@> keep_e;
    for (uint i = 0; i < first.length(); i++) { keep.insertLast(ptr_key(first.get_obj_at(i))); keep_e.insertLast(first.get_obj_at(i)); }
    for (uint m = 1; m < names.length(); m++)
    {
        json_obj@ other = ptr_load(names.get_string_at(m));
        if (other is null) { send_error(id, E_FAILED, "operation failed", "cannot load " + names.get_string_at(m)); return; }
        array<string> ks;
        for (uint i = 0; i < other.length(); i++) ks.insertLast(ptr_key(other.get_obj_at(i)));
        for (int i = int(keep.length()) - 1; i >= 0; i--)
            if (str_index(ks, keep[uint(i)]) < 0) { keep.removeAt(uint(i)); keep_e.removeAt(uint(i)); }
    }
    json_obj@ out = json::array();
    for (uint i = 0; i < keep_e.length(); i++) out.push(keep_e[i]);
    json_obj@ o = ok_reply("ptr_compare", id);
    o.set("common", out);
    o.set("count", out.length());
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Object instances by vtable, MSVC RTTI names
// ---------------------------------------------------------------------------------------------

// vtable -> ".?AVName@@" via the Complete Object Locator at vtable[-1] (x64: self-relative RVAs).
string msvc_rtti_name(uint64 vt)
{
    uint64 col = 0;
    if (!process::read_uint64(vt - 8, col) || col == 0) return "";
    uint32 sig = 0, td_rva = 0, self_rva = 0;
    if (!process::read_uint32(col, sig) || sig != 1) return "";
    if (!process::read_uint32(col + 12, td_rva) || !process::read_uint32(col + 20, self_rva)) return "";
    uint64 base = col - uint64(self_rva);
    string name;
    if (!process::read_string(base + td_rva + 16, name)) return "";
    return name;
}

// ".?AVGame@Player@@" -> "Player::Game"... keep it readable: strip the decoration, reverse scopes
string msvc_pretty(const string &in raw)
{
    if (raw.length() < 5 || raw.substr(0, 4) != ".?AV" && raw.substr(0, 4) != ".?AU") return raw;
    string body = raw.substr(4);
    int end = body.findFirst("@@");
    if (end >= 0) body = body.substr(0, uint(end));
    array<string> parts = split_str(body, "@");
    string out = "";
    for (int i = int(parts.length()) - 1; i >= 0; i--) out += (out == "" ? "" : "::") + parts[uint(i)];
    return out;
}

void h_rtti_name(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 a;
    bool is_object;
    if (!get_addr(r, "address", a) || !opt_bool(r, "object", false, is_object)) { bad_args(id, "rtti_name needs 'address' (a vtable, or an object with object=true)"); return; }
    uint64 vt = a;
    if (is_object && !process::read_uint64(a, vt)) { send_error(id, E_FAILED, "read failed", hex_addr(a)); return; }
    string raw = msvc_rtti_name(vt);
    json_obj@ o = ok_reply("rtti_name", id);
    o.set("vtable", hex_addr(vt));
    o.set("raw", raw);
    o.set("name", msvc_pretty(raw));
    send_json(o);
}

// Every 8-aligned qword in writable memory equal to the vtable: the objects of that class.
void h_find_instances(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 vt;
    int64 max;
    if (!get_addr(r, "vtable", vt) || !opt_int(r, "max", 1000, max)) { bad_args(id, "find_instances needs 'vtable' (max optional)"); return; }
    if (max < 1) max = 1;
    if (max > 100000) max = 100000;
    uint64 t0 = util::tickcount();
    RegionList@ rl = RegionList();
    walk_regions(t0, USER_LO, USER_HI, true, true, WALK_MAX_REGIONS, true, rl);
    json_obj@ out = json::array();
    bool trunc = false;
    for (uint ri = 0; ri < rl.base.length() && !trunc; ri++)
    {
        uint64 re = rl.base[ri] + rl.size[ri];
        for (uint64 pos = rl.base[ri]; pos < re && !trunc; pos += CHUNK)
        {
            if (time_up(t0)) { trunc = true; break; }
            uint64 len = umin(CHUNK, re - pos);
            memory_buffer@ buf = process::read_buffer(pos, len);
            if (buf is null) continue;
            for (uint64 o = 0; o + 8 <= len; o += 8)
                if (buf.read_uint64(o) == vt)
                {
                    out.push(hex_addr(pos + o));
                    if (out.length() >= uint(max)) { trunc = true; break; }
                }
        }
    }
    string raw = msvc_rtti_name(vt);
    json_obj@ o = ok_reply("find_instances", id);
    o.set("vtable", hex_addr(vt));
    o.set("class", msvc_pretty(raw));
    o.set("count", out.length());
    o.set("instances", out);
    o.set("truncated", trunc);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Cross-references inside the agent: rel32 calls/jumps, RIP-relative operands, absolute pointers
// ---------------------------------------------------------------------------------------------

void h_xref_scan(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    uint64 target;
    string mod;
    int64 max;
    bool abs_ptrs;
    if (!get_addr(r, "target", target) || !opt_str(r, "module", "", mod) || !opt_int(r, "max", 500, max) || !opt_bool(r, "pointers", true, abs_ptrs))
    { bad_args(id, "xref_scan needs 'target' (module, max, pointers optional)"); return; }
    uint64 lo = USER_LO, hi = USER_HI;
    if (mod != "")
    {
        uint64 b = process::get_module_base(mod);
        if (b == 0) { send_error(id, E_FAILED, "module not found", mod); return; }
        array<module_entry>@ mods = process::get_module_list();
        for (uint i = 0; mods !is null && i < mods.length(); i++)
            if (mods[i].base == b) { lo = b; hi = b + mods[i].size; }
    }
    uint64 t0 = util::tickcount();
    RegionList@ rl = RegionList();
    walk_regions(t0, lo, hi, true, false, WALK_MAX_REGIONS, true, rl);
    json_obj@ out = json::array();
    bool trunc = false;
    for (uint ri = 0; ri < rl.base.length() && !trunc; ri++)
    {
        bool exec = (rl.flags[ri] & RF_EXEC) != 0;
        if (!exec && !abs_ptrs) continue;
        uint64 re = rl.base[ri] + rl.size[ri];
        for (uint64 pos = rl.base[ri]; pos < re && !trunc; pos += CHUNK)
        {
            if (time_up(t0)) { trunc = true; break; }
            uint64 len = umin(CHUNK + 16, re - pos);
            memory_buffer@ buf = process::read_buffer(pos, len);
            if (buf is null) continue;
            uint64 core = umin(CHUNK, len);
            for (uint64 o = 0; o + 4 <= core; o++)
            {
                uint64 ip = pos + o;
                if (exec)
                {
                    int64 d = int64(buf.read_int32(o));
                    // disp32 ending the instruction (k = 0) or followed by an imm8 / imm32
                    for (uint k = 0; k < 3; k++)
                    {
                        uint64 tail = k == 0 ? 0 : (k == 1 ? 1 : 4);
                        if (ip + 4 + tail + uint64(d) != target) continue;
                        uint8 b1 = o >= 1 ? buf.read_uint8(o - 1) : 0;
                        string kind = tail == 0 && b1 == 0xE8 ? "call" : (tail == 0 && b1 == 0xE9 ? "jmp" : "riprel");
                        json_obj@ e = json_obj();
                        e.set("address", hex_addr(kind == "riprel" ? ip : ip - 1));
                        e.set("kind", kind);
                        out.push(e);
                        break;
                    }
                }
                if (abs_ptrs && (o & 7) == 0 && o + 8 <= core && buf.read_uint64(o) == target)
                {
                    json_obj@ e = json_obj();
                    e.set("address", hex_addr(ip));
                    e.set("kind", "pointer");
                    out.push(e);
                }
                if (out.length() >= uint(max)) { trunc = true; break; }
            }
        }
    }
    json_obj@ o = ok_reply("xref_scan", id);
    o.set("target", hex_addr(target));
    o.set("count", out.length());
    o.set("results", out);
    o.set("truncated", trunc);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// Multi-threaded first scan: workers take contiguous region shards; shards merge in order
// ---------------------------------------------------------------------------------------------

const uint SCAN_WORKERS = 4;   // the job thread plus three helpers
RegionList@ g_par_rl;
ScanSpec@ g_par_spec;
array<ScanState@> g_par_out;
array<uint> g_par_lo;
array<uint> g_par_hi;
uint g_par_next = 0;
uint g_par_done = 0;
uint64 g_par_t0 = 0;
uint64 g_par_bytes = 0;
bool g_par_stop = false;
mutex@ g_par_mx = create_mutex();

void par_scan_shard(uint k)
{
    ScanSpec@ s = g_par_spec;
    ScanState@ st = g_par_out[k];
    bool pattern = is_pattern(s.vtype);
    uint64 w = s.width;
    uint64 al = s.align;
    uint cap = MAX_CANDIDATES;
    if (pattern && PREV_RAW_CAP / s.width < cap) cap = uint(PREV_RAW_CAP / s.width);
    for (uint ri = g_par_lo[k]; ri < g_par_hi[k]; ri++)
    {
        uint64 re = g_par_rl.base[ri] + g_par_rl.size[ri];
        for (uint64 pos = g_par_rl.base[ri]; pos < re; pos += CHUNK)
        {
            if (g_par_stop || time_up(g_par_t0) || g_cancel.load()) { st.truncated = true; return; }
            uint64 core = umin(CHUNK, re - pos);
            uint64 want = umin(CHUNK + w - 1, re - pos);
            g_par_mx.lock();
            g_par_bytes += core;
            g_par_mx.unlock();
            if (want < w) continue;
            memory_buffer@ buf = process::read_buffer(pos, want);
            if (buf is null) continue;
            uint64 limit = umin(want - w + 1, core);
            uint64 first = align_up(pos, al) - pos;
            bool full = pattern ? scan_pat_chunk(buf, pos, first, limit, want, s, st, cap)
                                : scan_num_chunk(buf, pos, first, limit, s, st, cap);
            if (full) { st.truncated = true; g_par_stop = true; return; }
        }
    }
}

void par_worker()
{
    for (;;)
    {
        g_par_mx.lock();
        uint k = g_par_next;
        if (k < g_par_out.length()) g_par_next++;
        g_par_mx.unlock();
        if (k >= g_par_out.length()) break;
        par_scan_shard(k);
    }
    g_par_mx.lock();
    g_par_done++;
    g_par_mx.unlock();
}

// Numeric/pattern first scans over many regions; false when the scan should stay sequential.
bool par_scan_new(int64 id, ScanSpec@ s, RegionList@ rl, ScanState@ st, string &out note)
{
    if (s.op == OP_UNKNOWN || rl.base.length() < 8) return false;
    uint shards = SCAN_WORKERS * 4;
    @g_par_rl = rl;
    @g_par_spec = s;
    g_par_out.resize(0); g_par_lo.resize(0); g_par_hi.resize(0);
    uint n = rl.base.length();
    for (uint k = 0; k < shards; k++)
    {
        g_par_out.insertLast(ScanState(s));
        g_par_lo.insertLast(n * k / shards);
        g_par_hi.insertLast(n * (k + 1) / shards);
    }
    g_par_next = 0; g_par_done = 0; g_par_stop = false; g_par_bytes = 0;
    g_par_t0 = util::tickcount();
    for (uint i = 1; i < SCAN_WORKERS; i++) create_thread(0, @par_worker);
    par_worker();
    Progress pg("scan_new", rl.total);
    for (;;)
    {
        g_par_mx.lock();
        uint done = g_par_done;
        uint64 bytes = g_par_bytes;
        g_par_mx.unlock();
        pg.update(bytes);
        if (done >= SCAN_WORKERS) break;
        if (util::tickcount() - g_par_t0 > JOB_TIME_LIMIT_MS + 5000) { note = "a scan worker did not finish"; break; }
    }
    bool trunc = false;
    uint cap = MAX_CANDIDATES;
    for (uint k = 0; k < g_par_out.length(); k++)
    {
        ScanState@ p = g_par_out[k];
        trunc = trunc || p.truncated;
        for (uint i = 0; i < p.addrs.length() && st.addrs.length() < cap; i++)
        {
            st.addrs.insertLast(p.addrs[i]);
            if (is_pattern(s.vtype)) { for (uint b = 0; b < s.width; b++) st.prev_raw.insertLast(p.prev_raw[i * s.width + b]); }
            else st.prev.insertLast(p.prev[i]);
        }
    }
    if (trunc && note == "") note = g_cancel.load() ? "cancelled" : "candidate cap or time limit reached";
    st.truncated = trunc;
    g_par_out.resize(0);
    return true;
}

// ---------------------------------------------------------------------------------------------
// Settings file, write journal, event queue, stats, cancel
// ---------------------------------------------------------------------------------------------

int g_port = RELAY_PORT;
string g_auto_attach = AUTO_ATTACH;
bool g_alerts = true;
bool g_pause_freeze = false;
bool g_pause_watch = false;
const string CONFIG_FILE = "echodebug/agent.json";
const string JOURNAL_FILE = "echodebug/journal.jsonl";

void load_config()
{
    string text;
    if (!file::read(CONFIG_FILE, text)) return;
    string err;
    json_obj@ c = json::parse(text, err);
    if (c is null) { console::warn(LOG_PREFIX + "ignoring " + CONFIG_FILE + ": " + err); return; }
    int64 port;
    if (opt_int(c, "port", RELAY_PORT, port) && port > 0 && port < 65536) g_port = int(port);
    string aa;
    if (opt_str(c, "auto_attach", AUTO_ATTACH, aa)) g_auto_attach = aa;
    bool al;
    if (opt_bool(c, "alerts", true, al)) g_alerts = al;
}

bool save_config()
{
    json_obj@ c = json_obj();
    c.set("port", g_port);
    c.set("auto_attach", g_auto_attach);
    c.set("alerts", g_alerts);
    dir::create(DATA_DIR);
    return file::write(CONFIG_FILE, json::stringify(c));
}

void h_agent_config(json_obj@ r, int64 id)
{
    int64 port;
    string aa;
    bool al;
    if (!opt_int(r, "port", g_port, port) || !opt_str(r, "auto_attach", g_auto_attach, aa) || !opt_bool(r, "alerts", g_alerts, al)) { bad_args(id, "port number, auto_attach string, alerts bool"); return; }
    if (port <= 0 || port >= 65536) { bad_args(id, "port must be 1..65535"); return; }
    bool port_changed = int(port) != g_port;
    g_port = int(port); g_auto_attach = aa; g_alerts = al;
    bool saved = save_config();
    json_obj@ o = ok_reply("agent_config", id);
    o.set("port", g_port);
    o.set("auto_attach", g_auto_attach);
    o.set("alerts", g_alerts);
    o.set("saved", saved);
    o.set("note", port_changed ? "the new port is used on the next script load" : "");
    send_json(o);
}

void journal(const string &in kind, uint64 addr, const string &in old_hex, const string &in new_hex)
{
    json_obj@ e = json_obj();
    e.set("t", util::system_time());
    e.set("kind", kind);
    e.set("target", g_name);
    e.set("address", hex_addr(addr));
    e.set("old", old_hex);
    e.set("new", new_hex);
    dir::create(DATA_DIR);
    file::append(JOURNAL_FILE, json::stringify(e) + "\n");
}

void h_journal(json_obj@ r, int64 id)
{
    int64 limit;
    bool clear;
    if (!opt_int(r, "limit", 200, limit) || !opt_bool(r, "clear", false, clear)) { bad_args(id, "limit number, clear bool"); return; }
    string text;
    file::read(JOURNAL_FILE, text);
    array<string> lines = split_str(text, "\n");
    json_obj@ out = json::array();
    uint start = lines.length() > uint(limit) + 1 ? lines.length() - uint(limit) - 1 : 0;
    for (uint i = start; i < lines.length(); i++)
    {
        if (lines[i] == "") continue;
        string err;
        json_obj@ e = json::parse(lines[i], err);
        if (e !is null) out.push(e);
    }
    if (clear) file::remove(JOURNAL_FILE);
    json_obj@ o = ok_reply("journal", id);
    o.set("entries", out);
    o.set("cleared", clear);
    send_json(o);
}

// events raised while the app is away are kept (newest 500) and sent on reconnect
array<string> g_evq;
mutex@ g_evq_mx = create_mutex();
const uint EVQ_MAX = 500;

void flush_events()
{
    g_evq_mx.lock();
    array<string> q = g_evq;
    g_evq.resize(0);
    g_evq_mx.unlock();
    for (uint i = 0; i < q.length(); i++)
    {
        g_send_mx.lock();
        ws::send(q[i]);
        g_send_mx.unlock();
    }
    if (q.length() > 0) console::log(LOG_PREFIX + "sent " + q.length() + " queued events");
}

// per-verb call counts and handler time (ws thread)
array<string> g_stat_verb;
array<uint64> g_stat_n;
array<uint64> g_stat_ms;

void stat_add(const string &in verb, uint64 ms)
{
    int at = str_index(g_stat_verb, verb);
    if (at < 0) { g_stat_verb.insertLast(verb); g_stat_n.insertLast(0); g_stat_ms.insertLast(0); at = int(g_stat_verb.length()) - 1; }
    g_stat_n[uint(at)]++;
    g_stat_ms[uint(at)] += ms;
}

void h_stats(json_obj@ r, int64 id)
{
    json_obj@ verbs = json::array();
    for (uint i = 0; i < g_stat_verb.length(); i++)
    {
        json_obj@ e = json_obj();
        e.set("verb", g_stat_verb[i]);
        e.set("calls", g_stat_n[i]);
        e.set("ms", g_stat_ms[i]);
        verbs.push(e);
    }
    g_state_mx.lock_shared();
    string job = g_job;
    uint64 since = g_job == "" ? 0 : util::tickcount() - g_job_t0;
    g_state_mx.unlock_shared();
    json_obj@ o = ok_reply("stats", id);
    o.set("verbs", verbs);
    o.set("job", job);
    o.set("job_ms", since);
    o.set("queued_events", g_evq.length());
    o.set("frozen", g_freeze.length());
    o.set("watched", g_watch.length());
    o.set("snapshots", g_snaps.length());
    send_json(o);
}

void h_cancel(json_obj@ r, int64 id)
{
    g_state_mx.lock_shared();
    string job = g_job;
    g_state_mx.unlock_shared();
    if (job != "") g_cancel.store(true);
    json_obj@ o = ok_reply("cancel", id);
    o.set("job", job);
    o.set("cancelling", job != "");
    send_json(o);
}

void notify(const string &in msg, int r, int g, int b)
{
    if (g_alerts) alert::show_tag("EchoDebug: " + msg, TAG, r, g, b);
}

// ---------------------------------------------------------------------------------------------
// Panel inside Echo (ui::): status, settings and the safety switches, no desktop app needed
// ---------------------------------------------------------------------------------------------

checkbox g_ui_alerts;
checkbox g_ui_pause_freeze;
checkbox g_ui_pause_watch;

void ui_alerts_cb(bool v) { g_alerts = v; save_config(); }
void ui_pause_freeze_cb(bool v) { g_pause_freeze = v; }
void ui_pause_watch_cb(bool v) { g_pause_watch = v; }

void ui_status()
{
    g_state_mx.lock_shared();
    string t = g_attached ? g_name + " (pid " + g_pid + ")" : "no target";
    string job = g_job;
    g_state_mx.unlock_shared();
    string msg = "relay " + (ws::is_connected() ? "connected" : "offline") + " on port " + g_port + " · " + t
               + " · " + g_freeze.length() + " frozen · " + g_watch.length() + " watched" + (job != "" ? " · running " + job : "");
    alert::show_tag("EchoDebug: " + msg, TAG, 120, 200, 255);
    console::log(LOG_PREFIX + msg);
}

void ui_reconnect() { ws::reconnect(); }

void ui_cancel()
{
    g_cancel.store(true);
    alert::show_tag("EchoDebug: cancelling the running job", TAG, 255, 200, 80);
}

// restore frozen bytes and detach, from inside Echo
void ui_panic()
{
    if (was_attached())
    {
        restore_freeze();
        clear_freeze();
        clear_watch();
        process::detach();
        mark_detached("panic button");
    }
    alert::show_tag("EchoDebug: restored frozen values and detached", TAG, 255, 120, 80);
}

void ui_save() { alert::show_tag(save_config() ? "EchoDebug: settings saved" : "EchoDebug: could not save settings", TAG, 120, 255, 120); }

void build_menu()
{
    ui::add_tab("EchoDebug");
    ui::add_category("Status");
    ui::add_button("Show status", @ui_status);
    ui::add_button("Reconnect to the app", @ui_reconnect);
    ui::add_button("Cancel running job", @ui_cancel);
    ui::add_category("Safety");
    g_ui_pause_freeze = ui::add_checkbox("Pause freezes", false, @ui_pause_freeze_cb);
    g_ui_pause_watch = ui::add_checkbox("Pause watches", false, @ui_pause_watch_cb);
    ui::add_button("Restore frozen values and detach", @ui_panic);
    ui::add_category("Settings");
    g_ui_alerts = ui::add_checkbox("Alerts for watch hits and finished jobs", g_alerts, @ui_alerts_cb);
    ui::add_button("Save settings", @ui_save);
}

// Re-points Echo's native memory server at the relay. The relay asks for this when its /agent
// side has no connection but the agent is attached (e.g. after an app restart, the old
// process::open_socket connection is dead and must be re-opened).
void h_reopen_socket(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    bool ok = process::open_socket(native_url());
    json_obj@ ev = new_event("native_socket");
    ev.set("ok", ok);
    send_json(ev);
    if (!ok) emit_log("warn", "native memory socket could not be re-opened (still active on Echo's side); re-attach or reload the script to restore it");
    json_obj@ o = ok_reply("reopen_socket", id);
    o.set("ok", ok);
    send_json(o);
}

// Resolves one export of a loaded module: process::get_module_base + process::get_module_export.
void h_resolve_export(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    string mod;
    string name;
    if (!opt_str(r, "module", "", mod) || !opt_str(r, "name", "", name)) { bad_args(id, "module/name must be strings"); return; }
    if (mod == "") { bad_args(id, "resolve_export requires 'module'"); return; }
    if (name == "") { bad_args(id, "resolve_export requires 'name'"); return; }
    uint64 base = process::get_module_base(mod);
    if (base == 0) { send_error(id, E_FAILED, "module not found", mod); return; }
    uint64 addr = process::get_module_export(base, name);
    if (addr == 0) { send_error(id, E_FAILED, "export not found", mod + "!" + name); return; }
    json_obj@ o = ok_reply("resolve_export", id);
    o.set("address", hex_addr(addr));
    o.set("module_base", hex_addr(base));
    send_json(o);
}

void h_peb_walk(json_obj@ r, int64 id)
{
    if (!require_attached(id)) return;
    JobParams@ p = JobParams();
    uint seq;
    if (!claim_job("peb_walk", id, p, seq)) { send_error(id, E_BUSY, "busy", "another job is running"); return; }
    create_thread(0, @job_main);
}

// Walks PEB->Ldr->InLoadOrderModuleList inside a process-backed emulator (uc::create_process),
// using the stubs from the Echo docs. Cross-checks process::get_module_list and yields FullDllName.
void run_peb_walk(int64 id)
{
    uint64 h = uc::create_process();
    if (h == 0) { send_error(id, E_FAILED, "emulator creation failed", "no process attached"); return; }

    const uint64 INIT = 0x1000, READ = 0x2000, NAME = 0x3000, STOP = 0x6000;
    // gs:[0x60] -> PEB -> Ldr -> &InLoadOrderModuleList; sentinel in rcx, first entry in rdi
    array<uint8> stub_init = {
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x40, 0x18,
        0x48, 0x8D, 0x40, 0x10,
        0x48, 0x89, 0xC1,
        0x48, 0x8B, 0x38,
        0xC3
    };
    // rdi = LDR_DATA_TABLE_ENTRY: DllBase/EntryPoint/SizeOfImage, advance rdi to next entry
    array<uint8> stub_read = {
        0x48, 0x8B, 0x47, 0x30,
        0x48, 0x8B, 0x5F, 0x38,
        0x8B, 0x4F, 0x40,
        0x48, 0x8B, 0x3F,
        0xC3
    };
    // rax = FullDllName.Buffer ([rdi+0x50])
    array<uint8> stub_name = { 0x48, 0x8B, 0x47, 0x50, 0xC3 };

    bool ok = uc::mem_map(h, INIT, 0x1000, uint(uc::prot::all))
        && uc::mem_map(h, READ, 0x1000, uint(uc::prot::all))
        && uc::mem_map(h, NAME, 0x1000, uint(uc::prot::all))
        && uc::mem_map(h, STOP, 0x1000, uint(uc::prot::all))
        && uc::setup_stack(h, 0x10000, 0x2000, STOP)
        && uc::mem_write(h, INIT, stub_init)
        && uc::mem_write(h, READ, stub_read)
        && uc::mem_write(h, NAME, stub_name);

    json_obj@ mods = json::array();
    if (ok)
    {
        ok = uc::start(h, INIT, STOP) == uc::error::ok;
        uint64 sentinel = 0, flink = 0;
        if (ok)
        {
            uc::reg_read64(h, x86_reg::rcx, sentinel);
            uc::reg_read64(h, x86_reg::rdi, flink);
        }
        uint guard = 0;
        while (ok && flink != sentinel && flink != 0 && guard < 4096)
        {
            guard++;
            uc::reg_write64(h, x86_reg::rdi, flink);
            if (uc::start(h, READ, STOP) != uc::error::ok) break;
            uint64 dll_base = 0, entry = 0, size = 0, next = 0;
            uc::reg_read64(h, x86_reg::rax, dll_base);
            uc::reg_read64(h, x86_reg::rbx, entry);
            uc::reg_read64(h, x86_reg::rcx, size);
            uc::reg_read64(h, x86_reg::rdi, next);
            string name = "";
            uc::reg_write64(h, x86_reg::rdi, flink);
            if (uc::start(h, NAME, STOP) == uc::error::ok)
            {
                uint64 name_ptr = 0;
                uc::reg_read64(h, x86_reg::rax, name_ptr);
                if (name_ptr != 0)
                {
                    array<uint8> w;
                    w.resize(512);
                    if (uc::mem_read(h, name_ptr, 512, w))
                    {
                        uint n = 0;
                        while (n + 1 < 512 && (w[n] != 0 || w[n + 1] != 0)) n += 2;
                        w.resize(n);
                        name = util::wide_to_string(w, true);
                    }
                }
            }
            json_obj@ m = json_obj();
            m.set("base", hex_addr(dll_base));
            m.set("entry", hex_addr(entry));
            m.set("size", size);
            m.set("name", name);
            mods.push(m);
            flink = next;
        }
    }
    uc::close(h);
    if (!ok) { send_error(id, E_FAILED, "peb walk failed"); return; }
    json_obj@ o = ok_reply("peb_walk", id);
    o.set("count", mods.length());
    o.set("modules", mods);
    send_json(o);
}

// ---------------------------------------------------------------------------------------------
// WebSocket plumbing
// ---------------------------------------------------------------------------------------------

void on_open()
{
    console::log(LOG_PREFIX + "connected to relay " + ext_url());
    alert::show_tag("EchoDebug: connected to app", TAG, 80, 255, 120);
    send_hello();
    flush_events();
    // Re-announce the attach so the relay's status/target refresh after a reconnect or script reload.
    g_state_mx.lock_shared();
    bool a = g_attached;
    uint64 pid = g_pid;
    uint64 base = g_base;
    string nm = g_name;
    g_state_mx.unlock_shared();
    if (a)
    {
        json_obj@ ev = new_event("attached");
        ev.set("pid", pid);
        ev.set("base", hex_addr(base));
        ev.set("name", nm);
        send_json(ev);
    }
}

void on_message(string msg)
{
    string err;
    json_obj@ r = json::parse(msg, err);
    if (r is null) { send_error(0, E_BAD_ARGS, "invalid JSON", err); return; }
    int64 id = r.get_int64("id");
    string type = r.get_string("type");
    uint64 t0 = util::tickcount();
    dispatch(type, r, id);
    stat_add(type, util::tickcount() - t0);
}

void dispatch(const string &in type, json_obj@ r, int64 id)
{
    if (type == "attach") h_attach(r, id);
    else if (type == "detach") h_detach(r, id);
    else if (type == "alive") h_alive(r, id);
    else if (type == "write") h_write(r, id);
    else if (type == "query") h_query(r, id);
    else if (type == "regions") h_regions(r, id);
    else if (type == "chain") h_chain(r, id);
    else if (type == "scan_new") h_scan_new(r, id);
    else if (type == "scan_next") h_scan_next(r, id);
    else if (type == "scan_results") h_scan_results(r, id);
    else if (type == "scan_clear") h_scan_clear(r, id);
    else if (type == "pointer_scan") h_pointer_scan(r, id);
    else if (type == "emulate") h_emulate(r, id);
    else if (type == "emu_start") h_emu_start(r, id);
    else if (type == "emu_step") h_emu_go(r, id, true);
    else if (type == "emu_run") h_emu_go(r, id, false);
    else if (type == "emu_break") h_emu_break(r, id);
    else if (type == "emu_set") h_emu_set(r, id);
    else if (type == "emu_read") h_emu_read(r, id);
    else if (type == "emu_state") h_emu_state(r, id);
    else if (type == "emu_close") h_emu_close(r, id);
    else if (type == "emu_watch") h_emu_watch(r, id);
    else if (type == "emu_snapshot") h_emu_snapshot(r, id);
    else if (type == "emu_restore") h_emu_restore(r, id);
    else if (type == "dump") h_dump(r, id);
    else if (type == "freeze") h_freeze(r, id);
    else if (type == "freeze_list") h_freeze_list(r, id);
    else if (type == "reopen_socket") h_reopen_socket(r, id);
    else if (type == "resolve_export") h_resolve_export(r, id);
    else if (type == "peb_walk") h_peb_walk(r, id);
    else if (type == "watch") h_watch(r, id);
    else if (type == "unwatch") h_unwatch(r, id);
    else if (type == "watch_list") h_watch_list(r, id);
    else if (type == "read_typed") h_read_typed(r, id);
    else if (type == "region_stats") h_region_stats(r, id);
    else if (type == "sig_scan_batch") h_sig_scan_batch(r, id);
    else if (type == "disasm_function") h_disasm_function(r, id);
    else if (type == "read_fields") h_read_fields(r, id);
    else if (type == "hash_pages") h_hash_pages(r, id);
    else if (type == "freeze_group") h_freeze_group(r, id);
    else if (type == "mem_snapshot") h_mem_snapshot(r, id);
    else if (type == "mem_diff") h_mem_diff(r, id);
    else if (type == "mem_snapshot_list") h_mem_snapshot_list(r, id);
    else if (type == "ptr_save") h_ptr_save(r, id);
    else if (type == "ptr_compare") h_ptr_compare(r, id);
    else if (type == "find_instances") h_find_instances(r, id);
    else if (type == "rtti_name") h_rtti_name(r, id);
    else if (type == "xref_scan") h_xref_scan(r, id);
    else if (type == "agent_config") h_agent_config(r, id);
    else if (type == "journal") h_journal(r, id);
    else if (type == "stats") h_stats(r, id);
    else if (type == "cancel") h_cancel(r, id);
    else send_error(id, E_UNKNOWN_VERB, "unknown verb", type);
}

void on_disconnect()
{
    console::warn(LOG_PREFIX + "relay disconnected, retrying");
    alert::show_tag("EchoDebug: app disconnected, retrying", TAG, 255, 160, 40);
}

void on_error(string msg)
{
    console::warn(LOG_PREFIX + "ws error: " + msg);
}

// ---------------------------------------------------------------------------------------------
// Ticking threads
// ---------------------------------------------------------------------------------------------

void try_auto_attach()
{
    JobParams@ p = JobParams();
    p.attach_name = g_auto_attach;
    uint seq;
    if (!claim_job("auto_attach", 0, p, seq)) return;
    create_thread(0, @job_main);   // attach on a one-shot thread, not the 1 tps tick thread
}

// 1 tps: reconnect with backoff (the app may start after Echo), detect target exit, retry
// AUTO_ATTACH, and free the job slot if a job thread died without releasing it.
void keepalive_tick()
{
    g_ka_tick++;
    if (ws::is_connected()) g_ka_wait = 2;
    else if (g_ka_tick >= g_ka_next_try)
    {
        ws::reconnect();
        g_ka_next_try = g_ka_tick + g_ka_wait;
        if (g_ka_wait < 16) g_ka_wait *= 2;
    }

    g_state_mx.lock();
    bool died = g_attached && !process::is_alive();   // even mid-job: the target is gone either way
    if (died && g_auto_attach != "") g_auto_pending = true;
    bool auto_try = g_auto_pending && !g_attached && g_job == "" && g_ka_tick % 5 == 0;
    bool stuck = g_job != "" && util::tickcount() - g_job_t0 > JOB_WATCHDOG_MS;
    if (stuck) { g_job = ""; @g_job_params = null; }
    g_state_mx.unlock();

    if (died)
    {
        restore_freeze();   // undo frozen values while the attach is still alive
        process::detach();
        mark_detached("process exited");
    }
    if (stuck) emit_log("warn", "job watchdog released a stuck job slot");
    if (auto_try) try_auto_attach();
}

// 20 tps: rewrite frozen values; report each failing entry once until it succeeds again.
uint g_freeze_ticks = 0;

void freeze_tick()
{
    g_freeze_ticks++;
    if (!is_attached() || g_pause_freeze) return;
    array<uint64> failed;
    g_freeze_mx.lock();
    for (uint i = 0; i < g_freeze.length(); i++)
    {
        FreezeEntry@ e = g_freeze[i];
        if (e.paused) continue;
        bool ok = true;
        if (e.mode == "set") ok = process::write_bytes(e.data, e.address);
        else
        {
            double v;
            if (!num_read(e.vtype, e.address, v)) ok = false;
            else
            {
                double nv = v;
                if (e.mode == "add") { if (g_freeze_ticks % 20 == 0) nv = v + e.step; }   // step per second (20 Hz tick)
                else { if (nv < e.minv) nv = e.minv; if (nv > e.maxv) nv = e.maxv; }
                if (nv != v) ok = num_write(e.vtype, e.address, nv);
            }
        }
        if (!ok && !e.failed) failed.insertLast(e.address);
        e.failed = !ok;
    }
    g_freeze_mx.unlock();
    for (uint i = 0; i < failed.length(); i++)
    {
        json_obj@ ev = new_event("freeze_error");
        ev.set("address", hex_addr(failed[i]));
        send_json(ev);
    }
}

// ---------------------------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------------------------

// Load-time check of the hand-rolled numeric helpers (no other test harness runs AngelScript).
string self_test()
{
    double v;
    if (!flt_decode(4, 0x3F800000, v) || v != 1.0) return "f32 1.0";
    if (!flt_decode(8, uint64(0xC000000000000000), v) || v != -2.0) return "f64 -2.0";
    if (!flt_decode(4, 0x00000001, v) || v <= 0.0) return "f32 subnormal";
    if (flt_decode(4, 0x7FC00000, v)) return "f32 NaN";
    uint64 b;
    if (!int_bits_from(true, 1, 2, b) || b != 0xFFFF) return "i16 -1";
    if (int_bits_from(false, 256, 1, b)) return "u8 overflow";
    if (int_key(VT_I32, 4, 0xFFFFFFFF) >= int_key(VT_I32, 4, 0)) return "i32 order";
    int64 i;
    if (!parse_i64("-0x10", i) || i != -16) return "parse_i64";
    array<uint8> w;
    if (!utf8_to_utf16le("Ab", w) || w.length() != 4 || w[0] != 0x41 || w[1] != 0) return "utf16";
    if (hex_addr(0x7ff600001000) != "0x7ff600001000" || bits_hex(0x0102, 2) != "0201") return "hex";
    return "";
}

bool main()
{
    init_pow2();
    string bad = self_test();
    if (bad != "") console::error(LOG_PREFIX + "self-test failed: " + bad);

    load_config();
    build_menu();
    if (g_auto_attach != "")
    {
        g_auto_pending = true;
        try_auto_attach();
    }
    ws::connect(ext_url(), @on_open, @on_message, @on_disconnect, @on_error);
    create_thread(1, @keepalive_tick);
    create_thread(20, @freeze_tick);
    create_thread(10, @watch_tick);
    console::log(LOG_PREFIX + "agent v" + AGENT_VERSION + " loaded, relay " + ext_url());
    return true;
}

void on_unload()
{
    // Echo docs: on_unload is where external effects on the target are undone, and the golden
    // rule is to detach there. Restore frozen values first — the writes need the attach alive.
    if (was_attached())
    {
        restore_freeze();
        process::detach();
    }
    ws::disconnect();
    alert::dismiss(TAG);
}
