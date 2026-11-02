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

const string AGENT_VERSION = "0.7.0";
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
const uint WATCH_MAX_BYTES = 16;
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
    FreezeEntry() { address = 0; has_original = false; failed = false; }
}

class WatchEntry
{
    uint64 address;
    uint size;
    string label;
    array<uint8> prev;    // last sampled bytes
    bool has_prev;
    WatchEntry() { address = 0; size = 4; has_prev = false; }
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
    EmuJob()
    {
        start = 0; stop = 0; max_insns = 100000; timeout_us = 1000000;
        trace = false; trace_limit = 2000;
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

string ext_url() { return "ws://127.0.0.1:" + RELAY_PORT + "/ext"; }
string native_url() { return "ws://127.0.0.1:" + RELAY_PORT + "/agent"; }

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

bool time_up(uint64 t0) { return util::tickcount() - t0 > JOB_TIME_LIMIT_MS; }

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
    if (!process::write_bytes(bytes, addr)) { send_error(id, E_FAILED, "write failed", hex_addr(addr)); return; }
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
    array<uint8> bytes;
    if (enabled)
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
    if (patched_ev !is null) send_json(patched_ev);
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
    if (sz < 1 || sz > int64(WATCH_MAX_BYTES)) { send_error(id, E_LIMIT, "limit exceeded", "watch size must be 1..16"); return; }
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
    if (!is_attached()) return;
    g_watch_mx.lock();
    for (uint i = 0; i < g_watch.length(); i++)
    {
        WatchEntry@ e = g_watch[i];
        array<uint8>@ cur = process::read_bytes(e.address, e.size);
        if (cur is null || cur.length() != e.size) continue;
        if (e.has_prev && bytes_eq(cur, 0, e.prev, 0, e.size)) continue;
        string old = e.has_prev ? hex_of(e.prev, 0, e.prev.length()) : "";
        e.prev = cur;
        e.has_prev = true;
        g_watch_mx.unlock();
        json_obj@ ev = new_event("watch_event");
        ev.set("address", hex_addr(e.address));
        if (e.label != "") ev.set("label", e.label);
        ev.set("old", old);
        ev.set("new", hex_of(cur, 0, cur.length()));
        send_json(ev);
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
    if (g_emu_trace_on && g_emu_trace.length() < g_emu_trace_limit) g_emu_trace.insertLast(address);
    return true;   // the instruction limit is enforced by uc::start's count argument
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
        !opt_int(r, "trace_limit", 2000, e.trace_limit) || !opt_bool(r, "trace", false, e.trace))
    {
        bad_args(id, "max_insns/timeout_us/trace_limit must be numbers, trace a bool");
        return;
    }
    if (e.max_insns < 1 || e.timeout_us < 1 || e.trace_limit < 0) { bad_args(id, "max_insns and timeout_us must be >= 1"); return; }
    if (e.max_insns > EMU_MAX_INSNS || e.timeout_us > EMU_MAX_TIMEOUT_US || e.trace_limit > EMU_MAX_TRACE)
    {
        send_error(id, E_LIMIT, "limit exceeded", "max_insns <= 5000000, timeout_us <= 5000000, trace_limit <= 100000");
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
    ok = ok && uc::hook_code(h, @emu_hook);
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

    int res = uc::start(h, e.start, e.stop, uint64(e.timeout_us), uint64(e.max_insns));

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
    o.set("instructions", g_emu_count);
    o.set("mem", mem_out);
    // Unicorn reports a timeout or instruction-limit stop as "ok"; this tells them apart.
    o.set("reached_end", res == uc::error::ok && rip == e.stop);
    send_json(o);
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
    p.attach_name = AUTO_ATTACH;
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
    if (died && AUTO_ATTACH != "") g_auto_pending = true;
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
void freeze_tick()
{
    if (!is_attached()) return;
    array<uint64> failed;
    g_freeze_mx.lock();
    for (uint i = 0; i < g_freeze.length(); i++)
    {
        FreezeEntry@ e = g_freeze[i];
        bool ok = process::write_bytes(e.data, e.address);
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

    if (AUTO_ATTACH != "")
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
