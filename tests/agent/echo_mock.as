// echo_mock.as - script-side stand-ins for the parts of Echo's Universal API that
// agent/echo_debug.as uses, so the agent compiles and runs in the test host (host.cpp).
//
// Declarations follow Echo's API (as documented by echo-angelscript-lsp's decls). Behaviour is the
// minimum the tests need: one fake target with a small writable memory block, a scriptable
// Unicorn/Zydis pair for the emulator, captured ws::send output and a small JSON implementation.
// Threads with tps 0 run synchronously so job verbs (scan_new, emulate, ...) finish inside the call.

// ---------------------------------------------------------------------------------------------
// Test-facing mock state
// ---------------------------------------------------------------------------------------------

array<string> g_mock_sent;            // every ws::send payload, oldest first
array<string> g_mock_log;             // console output
bool g_mock_alive = true;             // process::is_alive()
uint32 g_mock_pid = 4242;             // what process::attach returns (0 = attach fails)
const uint64 MOCK_BASE = 0x140000000; // fake target image / memory block
array<uint8> g_mock_mem;              // bytes at MOCK_BASE (present + writable)
uint64 g_mock_tick = 1000;

void mock_reset()
{
    g_mock_sent.resize(0);
    g_mock_log.resize(0);
    g_mock_alive = true;
    g_mock_pid = 4242;
    g_mock_mem.resize(0);
    g_mock_mem.resize(0x2000);
    g_mock_uc_steps.resize(0);
    g_mock_uc_blocks.resize(0);
    g_mock_uc_regs.resize(0);
    g_mock_uc_regs.resize(64);
    g_mock_uc_start_result = 0;
    @g_mock_uc_hook = null;
    g_mock_insns.resize(0);
    // agent globals that tests may leave behind
    g_attached = false; g_pid = 0; g_base = 0; g_peb = 0; g_name = "";
    g_job = ""; @g_job_params = null;
    @g_scan = null;
    g_freeze.resize(0);
    g_watch.resize(0);
    init_pow2();
}

// Parsed copy of the newest ws::send payload (null if nothing was sent).
json_obj@ mock_last()
{
    if (g_mock_sent.length() == 0) return null;
    string err;
    return json::parse(g_mock_sent[g_mock_sent.length() - 1], err);
}

// Attaches the agent to the fake target the same way the attach verb does.
void mock_attach()
{
    bool sock;
    do_attach("target.exe", 0, sock);
    g_mock_sent.resize(0);
}

// ---------------------------------------------------------------------------------------------
// Threading
// ---------------------------------------------------------------------------------------------

funcdef void thread_callback();

void create_thread(int tps, thread_callback@ cb)
{
    if (tps == 0 && cb !is null) cb();   // one-shot job threads run inline; ticking threads never start
}

// ---------------------------------------------------------------------------------------------
// Hash containers (linear lists: the tests only hold a handful of keys)
// ---------------------------------------------------------------------------------------------

class hash_map
{
    array<uint64> keys;
    array<string> vals;
    int find(uint64 k) const { for (uint i = 0; i < keys.length(); i++) if (keys[i] == k) return int(i); return -1; }
    bool contains(uint64 k) const { return find(k) >= 0; }
    void set_string(uint64 k, const string &in v)
    {
        int i = find(k);
        if (i >= 0) vals[i] = v;
        else { keys.insertLast(k); vals.insertLast(v); }
    }
    bool get_string(uint64 k, string &out v) const
    {
        int i = find(k);
        if (i < 0) return false;
        v = vals[i];
        return true;
    }
}

hash_map@ create_hash_map() { return hash_map(); }


class mutex
{
    void lock() {}
    void unlock() {}
    bool try_lock() { return true; }
    void lock_shared() {}
    void unlock_shared() {}
}

mutex@ create_mutex() { return mutex(); }

void on_render(thread_callback@ cb) {}   // render callbacks never run in tests

// ---------------------------------------------------------------------------------------------
// Render, menu (ui::)
// ---------------------------------------------------------------------------------------------

namespace render
{
    void draw_text_outlined(int x, int y, string text, int r, int g, int b, int a) {}
}

funcdef void checkbox_callback(bool value);
funcdef void button_callback();

class checkbox { bool value = false; }
class button {}

namespace ui
{
    void add_tab(string label) {}
    void add_category(string label) {}
    checkbox add_checkbox(string label, bool default_value) { checkbox c; c.value = default_value; return c; }
    checkbox add_checkbox(string label, bool default_value, checkbox_callback@ callback) { return add_checkbox(label, default_value); }
    checkbox add_checkbox(string label, bool default_value, string config_key) { return add_checkbox(label, default_value); }
    checkbox add_checkbox(string label, bool default_value, checkbox_callback@ callback, string config_key) { return add_checkbox(label, default_value); }
    button add_button(string label, button_callback@ callback) { return button(); }
    void add_tooltip(checkbox cb, string text) {}
    void set(checkbox cb, bool value) { cb.value = value; }
    bool get(checkbox cb) { return cb.value; }
}

// ---------------------------------------------------------------------------------------------
// Logging, alerts, util
// ---------------------------------------------------------------------------------------------

namespace console
{
    void log(const string &in msg) { g_mock_log.insertLast(msg); }
    void warn(const string &in msg) { g_mock_log.insertLast("warn: " + msg); }
    void error(const string &in msg) { g_mock_log.insertLast("error: " + msg); }
}

namespace alert
{
    void show_tag(string msg, string tag, int r, int g, int b) {}
    void dismiss(string tag) {}
}

namespace util
{
    string get_username() { return "tester"; }
    uint64 tickcount() { return g_mock_tick; }
    uint64 system_time() { return 1700000000000 + g_mock_tick; }
    // Echo's format_string is variadic; the agent only formats one value with "{}".
    string format_string(string fmt, double v) { return formatFloat(v, "", 0, 6); }
    string format_string(string fmt, int64 v) { return formatInt(v); }
    string format_string(string fmt, uint64 v) { return formatUInt(v); }
    string wide_to_string(array<uint8> bytes, bool stop_at_null = false)
    {
        string s;
        for (uint i = 0; i + 1 < bytes.length(); i += 2)
        {
            uint c = bytes[i] | (uint(bytes[i + 1]) << 8);
            if (c == 0 && stop_at_null) break;
            s += c < 0x80 ? formatChar(c) : "?";
        }
        return s;
    }
}

// ---------------------------------------------------------------------------------------------
// Files (in-memory: path -> contents)
// ---------------------------------------------------------------------------------------------

array<string> g_mock_file_names;
array<string> g_mock_file_data;

int mock_file(const string &in path)
{
    for (uint i = 0; i < g_mock_file_names.length(); i++) if (g_mock_file_names[i] == path) return int(i);
    return -1;
}

namespace file
{
    bool read(string path, string &out text)
    {
        int i = mock_file(path);
        text = i < 0 ? "" : g_mock_file_data[i];
        return i >= 0;
    }
    bool write(string path, string text)
    {
        int i = mock_file(path);
        if (i >= 0) g_mock_file_data[i] = text;
        else { g_mock_file_names.insertLast(path); g_mock_file_data.insertLast(text); }
        return true;
    }
    bool append(string path, string text)
    {
        string cur;
        read(path, cur);
        return write(path, cur + text);
    }
    bool remove(string path)
    {
        int i = mock_file(path);
        if (i < 0) return false;
        g_mock_file_names.removeAt(i);
        g_mock_file_data.removeAt(i);
        return true;
    }
}

namespace dir
{
    bool create(string path) { return true; }
}

string formatChar(uint c)
{
    string s = " ";
    s[0] = uint8(c);
    return s;
}

// ---------------------------------------------------------------------------------------------
// WebSocket
// ---------------------------------------------------------------------------------------------

funcdef void connect_callback();
funcdef void message_callback(string msg);
funcdef void disconnect_callback();
funcdef void error_callback(string msg);

namespace ws
{
    void connect(string url, connect_callback@ a, message_callback@ b, disconnect_callback@ c, error_callback@ d) {}
    void reconnect() {}
    void disconnect() {}
    bool is_connected() { return true; }
    void send(string msg) { g_mock_sent.insertLast(msg); }
}

// ---------------------------------------------------------------------------------------------
// Process (one fake target: [MOCK_BASE, MOCK_BASE + g_mock_mem.length()) is mapped RW)
// ---------------------------------------------------------------------------------------------

class attach_data
{
    uint32 pid;
    uint64 peb_address;
    uint64 base_address;
}

class module_entry
{
    string name;
    uint64 base;
    uint64 size;
}

class memory_region
{
    uint64 base;
    uint64 size;
    bool present;
    bool writable;
    bool executable;
}

class memory_buffer
{
    array<uint8> data;
    uint64 rd(uint64 o, uint w)
    {
        uint64 v = 0;
        for (uint i = 0; i < w; i++) v |= uint64(data[uint(o) + i]) << (8 * i);
        return v;
    }
    uint8 read_uint8(uint64 o) { return uint8(rd(o, 1)); }
    uint16 read_uint16(uint64 o) { return uint16(rd(o, 2)); }
    uint32 read_uint32(uint64 o) { return uint32(rd(o, 4)); }
    uint64 read_uint64(uint64 o) { return rd(o, 8); }
    int8 read_int8(uint64 o) { return int8(rd(o, 1)); }
    int16 read_int16(uint64 o) { return int16(rd(o, 2)); }
    int32 read_int32(uint64 o) { return int32(rd(o, 4)); }
    int64 read_int64(uint64 o) { return int64(rd(o, 8)); }
    float read_float(uint64 o) { return fpFromIEEE(uint(rd(o, 4))); }
    double read_double(uint64 o) { return fpFromIEEE(rd(o, 8)); }
    uint64 size() { return data.length(); }
}

bool mock_mapped(uint64 a, uint64 n)
{
    return n > 0 && a >= MOCK_BASE && a + n <= MOCK_BASE + g_mock_mem.length();
}

namespace process
{
    attach_data attach(string name) { attach_data d; d.pid = g_mock_pid; d.base_address = MOCK_BASE; d.peb_address = 0x1000; return d; }
    attach_data attach(uint32 pid) { return attach("pid"); }
    bool is_alive() { return g_mock_alive; }
    void detach() {}

    array<uint8>@ read_bytes(uint64 address, uint32 size)
    {
        if (!mock_mapped(address, size)) return null;
        array<uint8> b(size);
        for (uint i = 0; i < size; i++) b[i] = g_mock_mem[uint(address - MOCK_BASE) + i];
        return b;
    }

    memory_buffer@ read_buffer(uint64 address, uint64 size)
    {
        array<uint8>@ b = read_bytes(address, uint(size));
        if (b is null) return null;
        memory_buffer m;
        m.data = b;
        return m;
    }

    uint64 read_uint64(uint64 address)
    {
        array<uint8>@ b = read_bytes(address, 8);
        if (b is null) return 0;
        uint64 v = 0;
        for (uint i = 0; i < 8; i++) v |= uint64(b[i]) << (8 * i);
        return v;
    }

    bool read_uint64(uint64 address, uint64 &out v)
    {
        v = read_uint64(address);
        return mock_mapped(address, 8);
    }

    bool read_uint32(uint64 address, uint32 &out v)
    {
        array<uint8>@ b = read_bytes(address, 4);
        v = 0;
        if (b is null) return false;
        for (uint i = 0; i < 4; i++) v |= uint32(b[i]) << (8 * i);
        return true;
    }

    bool read_string(uint64 address, string &out v)
    {
        v = "";
        if (!mock_mapped(address, 1)) return false;
        for (uint i = uint(address - MOCK_BASE); i < g_mock_mem.length() && g_mock_mem[i] != 0; i++) v += formatChar(g_mock_mem[i]);
        return true;
    }

    bool write_bytes(array<uint8> bytes, uint64 address)
    {
        if (!mock_mapped(address, bytes.length())) return false;
        for (uint i = 0; i < bytes.length(); i++) g_mock_mem[uint(address - MOCK_BASE) + i] = bytes[i];
        return true;
    }

    bool write_le(uint64 address, uint64 v, uint w)
    {
        array<uint8> b(w);
        for (uint i = 0; i < w; i++) b[i] = uint8(v >> (8 * i));
        return write_bytes(b, address);
    }
    bool write_uint8(uint64 a, uint8 v) { return write_le(a, v, 1); }
    bool write_int8(uint64 a, int8 v) { return write_le(a, uint64(v), 1); }
    bool write_uint16(uint64 a, uint16 v) { return write_le(a, v, 2); }
    bool write_int16(uint64 a, int16 v) { return write_le(a, uint64(v), 2); }
    bool write_uint32(uint64 a, uint32 v) { return write_le(a, v, 4); }
    bool write_int32(uint64 a, int32 v) { return write_le(a, uint64(v), 4); }
    bool write_uint64(uint64 a, uint64 v) { return write_le(a, v, 8); }
    bool write_int64(uint64 a, int64 v) { return write_le(a, uint64(v), 8); }
    bool write_float(uint64 a, float v) { return write_le(a, fpToIEEE(v), 4); }
    bool write_double(uint64 a, double v) { return write_le(a, fpToIEEE(v), 8); }

    // Byte patterns ("48 8B ?? 05"; ? or ?? = any byte) over the module at `base`.
    array<uint64>@ find_signatures(uint64 base, string pattern)
    {
        array<string> toks = pattern.split(" ");
        array<int> pat;
        for (uint i = 0; i < toks.length(); i++)
        {
            if (toks[i] == "") continue;
            if (toks[i] == "?" || toks[i] == "??") { pat.insertLast(-1); continue; }
            uint n = 0;
            pat.insertLast(int(parseInt(toks[i], 16, n)));
        }
        array<uint64> hits;
        if (base != MOCK_BASE || pat.length() == 0) return hits;
        for (uint o = 0; o + pat.length() <= g_mock_mem.length(); o++)
        {
            bool ok = true;
            for (uint k = 0; k < pat.length() && ok; k++) ok = pat[k] < 0 || g_mock_mem[o + k] == uint8(pat[k]);
            if (ok) hits.insertLast(MOCK_BASE + o);
        }
        return hits;
    }

    memory_region virtual_query(uint64 address)
    {
        memory_region m;
        uint64 end = MOCK_BASE + g_mock_mem.length();
        m.present = mock_mapped(address, 1);
        m.writable = m.present;
        m.executable = false;
        if (m.present) { m.base = MOCK_BASE; m.size = g_mock_mem.length(); }
        else if (address < MOCK_BASE) { m.base = address & ~uint64(0xFFF); m.size = MOCK_BASE - m.base; }
        else { m.base = address & ~uint64(0xFFF); m.size = USER_HI + 1 - m.base; if (m.base < end) m.base = end; }
        return m;
    }

    uint64 get_module_base(string name) { return name == "target.exe" ? MOCK_BASE : 0; }
    uint32 get_module_size(uint64 base) { return base == MOCK_BASE ? g_mock_mem.length() : 0; }
    uint64 get_module_export(uint64 base, string name) { return 0; }

    array<module_entry>@ get_module_list()
    {
        array<module_entry> mods(1);
        mods[0].name = "target.exe";
        mods[0].base = MOCK_BASE;
        mods[0].size = g_mock_mem.length();
        return mods;
    }

    bool open_socket(const string url) { return true; }
    bool dump(string filename) { return false; }
    bool dump(string module_name, string filename) { return false; }
}

// ---------------------------------------------------------------------------------------------
// Unicorn: flat mapped blocks, registers in an array, start() replays scripted steps
// ---------------------------------------------------------------------------------------------

enum x86_reg
{
    rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, eflags,
    r8, r9, r10, r11, r12, r13, r14, r15,
    cs, ds, es, fs, gs, ss,
    fs_base, gs_base,
    xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15,
    ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm8, ymm9, ymm10, ymm11, ymm12, ymm13, ymm14, ymm15
}

class uc_memory_region
{
    uint64 address;
    uint64 end;
    uint32 perms;
}

funcdef bool code_hook_fn(uint64 h, uint64 address, uint32 size);

// One emulated instruction: the hook sees it, then its effects apply.
class MockStep
{
    uint64 address;
    uint32 size;
    uint64 write_addr;     // optional memory write performed by the instruction
    array<uint8> write_data;
}

class MockBlock
{
    uint64 base;
    array<uint8> data;
}

array<MockStep@> g_mock_uc_steps;
array<MockBlock@> g_mock_uc_blocks;
array<uint64> g_mock_uc_regs;
int g_mock_uc_start_result = 0;
code_hook_fn@ g_mock_uc_hook;

MockBlock@ mock_uc_block(uint64 a, uint64 n)
{
    for (uint i = 0; i < g_mock_uc_blocks.length(); i++)
    {
        MockBlock@ b = g_mock_uc_blocks[i];
        if (a >= b.base && a + n <= b.base + b.data.length()) return b;
    }
    return null;
}

namespace uc
{
    enum prot { none = 0, read = 1, write = 2, exec = 4, all = 7 }

    enum error
    {
        ok, nomem, arch, handle, mode, version, read_unmapped, write_unmapped, fetch_unmapped,
        fetch_prot, read_prot, write_prot, map, hook, insn_invalid
    }

    enum mem_type { read, write, fetch, read_unmapped, write_unmapped, fetch_unmapped, write_prot, read_prot, fetch_prot, read_after }
    funcdef bool mem_hook_fn(uint64 h, mem_type type, uint64 address, uint32 size, uint64 value);

    uint64 create() { return 1; }
    // unmapped-access hooks are accepted but never fire (the mock has no faulting accesses)
    bool hook_memory_unmapped(uint64 h, mem_hook_fn@ cb) { return true; }
    void stop(uint64 h) {}
    void flush_code(uint64 h) {}
    // vector registers and the region list are not modelled: reads fail, no regions
    bool reg_read128(uint64 h, x86_reg reg, array<uint8> &out data) { return false; }
    bool reg_read256(uint64 h, x86_reg reg, array<uint8> &out data) { return false; }
    bool reg_write128(uint64 h, x86_reg reg, const array<uint8> &in data) { return false; }
    bool mem_regions(uint64 h, array<uc_memory_region> &out regions) { regions.resize(0); return true; }
    uint64 create_process() { return 2; }
    void close(uint64 h) {}
    bool setup_stack(uint64 h, uint64 base, uint64 size, uint64 stop_address)
    {
        g_mock_uc_regs[int(x86_reg::rsp)] = base + size - 8;
        return true;
    }

    int start(uint64 h, uint64 begin, uint64 end, uint64 timeout = 0, uint64 count = 0)
    {
        g_mock_uc_regs[int(x86_reg::rip)] = begin;
        for (uint i = 0; i < g_mock_uc_steps.length(); i++)
        {
            MockStep@ s = g_mock_uc_steps[i];
            if (g_mock_uc_hook !is null) g_mock_uc_hook(h, s.address, s.size);
            if (s.write_data.length() > 0) mem_write(h, s.write_addr, s.write_data);
            g_mock_uc_regs[int(x86_reg::rip)] = s.address + s.size;
        }
        if (g_mock_uc_start_result == 0) g_mock_uc_regs[int(x86_reg::rip)] = end;
        return g_mock_uc_start_result;
    }

    uint64 fault_address(uint64 h) { return 0; }
    bool hook_code(uint64 h, code_hook_fn@ cb, uint64 begin = 1, uint64 end = 0) { @g_mock_uc_hook = cb; return true; }

    bool reg_read64(uint64 h, x86_reg reg, uint64 &out val) { val = g_mock_uc_regs[int(reg)]; return true; }
    bool reg_write64(uint64 h, x86_reg reg, uint64 val) { g_mock_uc_regs[int(reg)] = val; return true; }

    bool mem_map(uint64 h, uint64 address, uint64 size, uint perms)
    {
        MockBlock b;
        b.base = address;
        b.data.resize(uint(size));
        g_mock_uc_blocks.insertLast(b);
        return true;
    }

    bool mem_write(uint64 h, uint64 address, const array<uint8> &in data)
    {
        MockBlock@ b = mock_uc_block(address, data.length());
        if (b is null) return false;
        for (uint i = 0; i < data.length(); i++) b.data[uint(address - b.base) + i] = data[i];
        return true;
    }

    bool mem_read(uint64 h, uint64 address, uint32 size, array<uint8> &out data)
    {
        MockBlock@ b = mock_uc_block(address, size);
        if (b is null) return false;
        data.resize(size);
        for (uint i = 0; i < size; i++) data[i] = b.data[uint(address - b.base) + i];
        return true;
    }

    int mem_query(uint64 h, uint64 address) { return mock_uc_block(address, 1) is null ? -1 : 7; }
}

// ---------------------------------------------------------------------------------------------
// Zydis: disasm returns the canned instruction registered for an address
// ---------------------------------------------------------------------------------------------

enum op_type { unused, reg, mem, ptr, imm }
enum op_action { read = 1, write = 2, readwrite = 3, condread = 4, condwrite = 8, read_condwrite = 9, condread_write = 6 }

class disasm_operand
{
    int type;
    int visibility;
    int action;
    int reg;
    int mem_segment;
    int mem_base;
    int mem_index;
    uint8 mem_scale;
    int64 mem_disp;
    bool mem_has_disp;
}

class disasm_insn
{
    uint64 runtime_address;
    uint8 length;
    string text;
    uint8 operand_count;
    uint8 operand_count_visible;
    array<disasm_operand> ops;
    disasm_operand get_op(uint8 idx) const { return ops[idx]; }
}

array<disasm_insn@> g_mock_insns;

// Zydis register ids used by the mocks: index into this table (0 = none).
const array<string> MOCK_ZREGS = { "", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "gs", "fs", "eax" };

int mock_zreg(const string &in n)
{
    for (uint i = 0; i < MOCK_ZREGS.length(); i++) if (MOCK_ZREGS[i] == n) return int(i);
    return -1;
}

namespace zydis
{
    string reg_name(int reg) { return reg >= 0 && uint(reg) < MOCK_ZREGS.length() ? MOCK_ZREGS[reg] : "?"; }

    bool disasm(const array<uint8>@ &in bytes, uint64 rip, array<disasm_insn@> &out insns)
    {
        insns.resize(0);
        for (uint i = 0; i < g_mock_insns.length(); i++)
            if (g_mock_insns[i].runtime_address == rip) insns.insertLast(g_mock_insns[i]);
        return insns.length() > 0;
    }

    // Canned instructions from `rip` onward, laid end to end, up to and including the first ret.
    bool disasm_func(const array<uint8>@ &in bytes, uint64 rip, array<disasm_insn@> &out insns)
    {
        insns.resize(0);
        uint64 a = rip;
        while (a < rip + bytes.length())
        {
            disasm_insn@ hit = null;
            for (uint i = 0; i < g_mock_insns.length() && hit is null; i++)
                if (g_mock_insns[i].runtime_address == a) @hit = g_mock_insns[i];
            if (hit is null || hit.length == 0) return false;
            insns.insertLast(hit);
            if (hit.text == "ret") return true;
            a += hit.length;
        }
        return false;
    }
}

// ---------------------------------------------------------------------------------------------
// JSON (json_obj + json::parse / stringify)
// ---------------------------------------------------------------------------------------------

enum json_type { null_value, boolean, number, string, object, array }

class json_val
{
    json_type t;
    string s;
    double d;
    int64 i;
    uint64 u;
    bool is_uint;   // printed as unsigned
    bool is_int;    // integral number
    bool b;
    json_obj@ o;
}

class json_obj
{
    bool is_array = false;
    array<string> ks;
    array<json_val@> vs;

    int idx(const string &in k) const
    {
        for (uint n = 0; n < ks.length(); n++) if (ks[n] == k) return int(n);
        return -1;
    }
    json_val@ at_key(const string &in k) const { int n = idx(k); return n < 0 ? null : vs[n]; }
    json_val@ at(uint n) const { return n < vs.length() ? vs[n] : null; }
    void put(const string &in k, json_val@ v)
    {
        int n = idx(k);
        if (n >= 0) { @vs[n] = v; return; }
        ks.insertLast(k);
        vs.insertLast(v);
    }

    bool has(string key) { return idx(key) >= 0; }
    uint length() { return vs.length(); }
    json_type type(string key) { json_val@ v = at_key(key); return v is null ? json_type::null_value : v.t; }
    json_type type_at(uint n) { json_val@ v = at(n); return v is null ? json_type::null_value : v.t; }
    array<string>@ keys() { array<string> r = ks; return r; }

    string get_string(string k) { json_val@ v = at_key(k); return v is null || v.t != json_type::string ? "" : v.s; }
    double get_double(string k) { json_val@ v = at_key(k); return v is null || v.t != json_type::number ? 0 : v.d; }
    int get_int(string k) { return int(get_int64(k)); }
    int64 get_int64(string k) { json_val@ v = at_key(k); return v is null || v.t != json_type::number ? 0 : v.i; }
    uint64 get_uint64(string k) { json_val@ v = at_key(k); return v is null || v.t != json_type::number ? 0 : v.u; }
    bool get_bool(string k) { json_val@ v = at_key(k); return v !is null && v.t == json_type::boolean && v.b; }
    json_obj@ get_obj(string k) { json_val@ v = at_key(k); return v is null ? null : v.o; }

    string get_string_at(uint n) { json_val@ v = at(n); return v is null || v.t != json_type::string ? "" : v.s; }
    double get_double_at(uint n) { json_val@ v = at(n); return v is null || v.t != json_type::number ? 0 : v.d; }
    int64 get_int64_at(uint n) { json_val@ v = at(n); return v is null || v.t != json_type::number ? 0 : v.i; }
    uint64 get_uint64_at(uint n) { json_val@ v = at(n); return v is null || v.t != json_type::number ? 0 : v.u; }
    json_obj@ get_obj_at(uint n) { json_val@ v = at(n); return v is null ? null : v.o; }

    void set(string k, string v) { put(k, jstr(v)); }
    void set(string k, double v) { put(k, jdbl(v)); }
    void set(string k, int v) { put(k, jint(v)); }
    void set(string k, uint v) { put(k, juint(v)); }
    void set(string k, int64 v) { put(k, jint(v)); }
    void set(string k, uint64 v) { put(k, juint(v)); }
    void set(string k, bool v) { put(k, jbool(v)); }
    void set(string k, json_obj@ v) { put(k, jobj(v)); }
    void set_null(string k) { put(k, json_val()); }

    void push(string v) { vs.insertLast(jstr(v)); }
    void push(int64 v) { vs.insertLast(jint(v)); }
    void push(uint64 v) { vs.insertLast(juint(v)); }
    void push(bool v) { vs.insertLast(jbool(v)); }
    void push(json_obj@ v) { vs.insertLast(jobj(v)); }
}

json_val@ jstr(const string &in s) { json_val v; v.t = json_type::string; v.s = s; return v; }
json_val@ jbool(bool b) { json_val v; v.t = json_type::boolean; v.b = b; return v; }
json_val@ jdbl(double d) { json_val v; v.t = json_type::number; v.d = d; v.i = int64(d); v.u = d < 0 ? uint64(int64(d)) : uint64(d); v.is_int = d == double(v.i); return v; }
json_val@ jint(int64 i) { json_val v; v.t = json_type::number; v.d = double(i); v.i = i; v.u = uint64(i); v.is_int = true; return v; }
json_val@ juint(uint64 u) { json_val v; v.t = json_type::number; v.d = double(u); v.i = int64(u); v.u = u; v.is_int = true; v.is_uint = true; return v; }
json_val@ jobj(json_obj@ o)
{
    json_val v;
    if (o is null) return v;
    v.t = o.is_array ? json_type::array : json_type::object;
    @v.o = o;
    return v;
}

namespace json
{
    json_obj@ array() { json_obj o; o.is_array = true; return o; }

    string stringify(json_obj@ obj, bool beautify = false) { return obj is null ? "null" : jdump_obj(obj); }

    json_obj@ parse(string text, string &out error)
    {
        JsonParser p;
        p.s = text;
        error = "";
        json_val@ v = p.value();
        p.ws();
        if (v is null || p.pos != text.length() || v.o is null) { error = "parse error at " + p.pos; return null; }
        return v.o;
    }
}

string jquote(const string &in s)
{
    string r = "\"";
    for (uint n = 0; n < s.length(); n++)
    {
        uint8 c = s[n];
        if (c == 0x22) r += "\\\"";
        else if (c == 0x5C) r += "\\\\";
        else if (c == 0x0A) r += "\\n";
        else if (c < 0x20) r += "\\u00" + HEXD.substr(c >> 4, 1) + HEXD.substr(c & 0xF, 1);
        else r += formatChar(c);
    }
    return r + "\"";
}

string jdump(json_val@ v)
{
    if (v.t == json_type::string) return jquote(v.s);
    if (v.t == json_type::boolean) return v.b ? "true" : "false";
    if (v.t == json_type::number)
    {
        if (v.is_uint) return formatUInt(v.u);
        if (v.is_int) return formatInt(v.i);
        return formatFloat(v.d, "", 0, 17);
    }
    if (v.o !is null) return jdump_obj(v.o);
    return "null";
}

string jdump_obj(json_obj@ o)
{
    string r = o.is_array ? "[" : "{";
    for (uint n = 0; n < o.vs.length(); n++)
    {
        if (n > 0) r += ",";
        if (!o.is_array) r += jquote(o.ks[n]) + ":";
        r += jdump(o.vs[n]);
    }
    return r + (o.is_array ? "]" : "}");
}

class JsonParser
{
    string s;
    uint pos = 0;

    void ws() { while (pos < s.length() && (s[pos] == 0x20 || s[pos] == 0x0A || s[pos] == 0x0D || s[pos] == 0x09)) pos++; }
    bool eat(uint8 c) { ws(); if (pos < s.length() && s[pos] == c) { pos++; return true; } return false; }
    bool word(const string &in w) { if (s.substr(pos, w.length()) != w) return false; pos += w.length(); return true; }

    json_val@ value()
    {
        ws();
        if (pos >= s.length()) return null;
        uint8 c = s[pos];
        if (c == 0x7B) return object();
        if (c == 0x5B) return arr();
        if (c == 0x22) { string t; if (!str(t)) return null; return jstr(t); }
        if (word("true")) return jbool(true);
        if (word("false")) return jbool(false);
        if (word("null")) return json_val();
        return number();
    }

    json_val@ object()
    {
        json_obj o;
        pos++;
        if (eat(0x7D)) return jobj(o);
        do
        {
            ws();
            string k;
            if (!str(k) || !eat(0x3A)) return null;
            json_val@ v = value();
            if (v is null) return null;
            o.put(k, v);
        } while (eat(0x2C));
        return eat(0x7D) ? jobj(o) : null;
    }

    json_val@ arr()
    {
        json_obj@ o = json::array();
        pos++;
        if (eat(0x5D)) return jobj(o);
        do
        {
            json_val@ v = value();
            if (v is null) return null;
            o.vs.insertLast(v);
        } while (eat(0x2C));
        return eat(0x5D) ? jobj(o) : null;
    }

    bool str(string &out t)
    {
        t = "";
        if (pos >= s.length() || s[pos] != 0x22) return false;
        pos++;
        while (pos < s.length())
        {
            uint8 c = s[pos++];
            if (c == 0x22) return true;
            if (c != 0x5C) { t += formatChar(c); continue; }
            if (pos >= s.length()) return false;
            uint8 e = s[pos++];
            if (e == 0x6E) t += "\n";
            else if (e == 0x74) t += "\t";
            else if (e == 0x75)
            {
                uint64 cp;
                if (pos + 4 > s.length() || !parse_hex_u64(s.substr(pos, 4), cp)) return false;
                pos += 4;
                t += cp < 0x80 ? formatChar(uint(cp)) : "?";
            }
            else t += formatChar(e);
        }
        return false;
    }

    json_val@ number()
    {
        uint b = pos;
        bool integral = true;
        while (pos < s.length())
        {
            uint8 c = s[pos];
            if (c == 0x2E || c == 0x65 || c == 0x45) integral = false;
            else if (!(c == 0x2D || c == 0x2B || (c >= 0x30 && c <= 0x39))) break;
            pos++;
        }
        string t = s.substr(b, pos - b);
        if (t.length() == 0) return null;
        if (integral)
        {
            bool neg;
            uint64 mag;
            if (!parse_signed_mag(t, neg, mag)) return null;
            return neg ? jint(-int64(mag)) : juint(mag);
        }
        uint n = 0;
        double d = parseFloat(t, n);
        if (n != t.length()) return null;
        return jdbl(d);
    }
}
