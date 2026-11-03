// agent_tests.as - tests for agent/echo_debug.as, run by host.cpp against echo_mock.as.
// Every zero-argument function in namespace `tests` is a test; mock_reset() runs before each.
// check(cond, what) records a failure and keeps going; script exceptions fail the test.

namespace tests
{

// --- helpers ----------------------------------------------------------------------------------

// Feeds a raw relay message to the agent and returns its newest reply.
json_obj@ request(const string &in msg)
{
    uint before = g_mock_sent.length();
    on_message(msg);
    if (g_mock_sent.length() == before) return null;
    return mock_last();
}

void expect_error(const string &in msg, int code, const string &in detail = "")
{
    json_obj@ r = request(msg);
    if (r is null) { check(false, "no reply to " + msg); return; }
    bool ok = r.get_string("type") == "error" && r.get_int("code") == code &&
              (detail == "" || r.get_string("detail").findFirst(detail) >= 0);
    check(ok, msg + " -> expected " + code + " '" + detail + "', got " + g_mock_sent[g_mock_sent.length() - 1]);
}

json_obj@ expect_ok(const string &in msg, const string &in type)
{
    json_obj@ r = request(msg);
    bool ok = r !is null && r.get_string("type") == type && r.get_bool("success");
    check(ok, msg + " -> expected " + type + ", got " + (g_mock_sent.length() > 0 ? g_mock_sent[g_mock_sent.length() - 1] : "nothing"));
    return ok ? r : null;
}

bool near(double a, double b) { double d = a - b; return (d < 0 ? -d : d) <= 1e-12 * (b < 0 ? -b : (b == 0 ? 1 : b)); }

// --- built-in self test -----------------------------------------------------------------------

void self_test_passes() { check(self_test() == "", "self_test(): " + self_test()); }

// --- hex / number parsing and formatting --------------------------------------------------------

void parse_hex_u64_strict()
{
    uint64 v;
    check(parse_hex_u64("0x7ff600001000", v) && v == 0x7ff600001000, "0x-prefixed");
    check(parse_hex_u64("DEADbeef", v) && v == 0xdeadbeef, "mixed case, no prefix");
    check(parse_hex_u64("0XfF", v) && v == 0xff, "0X prefix");
    check(parse_hex_u64("ffffffffffffffff", v) && v == uint64(0xFFFFFFFFFFFFFFFF), "16 digits");
    check(!parse_hex_u64("1ffffffffffffffff", v), "17 digits rejected");
    check(!parse_hex_u64("", v), "empty rejected");
    check(!parse_hex_u64("0x", v), "bare prefix rejected");
    check(!parse_hex_u64("12g4", v), "non-hex rejected");
    check(!parse_hex_u64(" 12", v), "whitespace rejected");
}

void parse_dec_and_i64()
{
    uint64 u;
    check(parse_dec_u64("18446744073709551615", u) && u == uint64(0xFFFFFFFFFFFFFFFF), "u64 max");
    check(!parse_dec_u64("18446744073709551616", u), "u64 overflow rejected");
    check(!parse_dec_u64("-1", u) && !parse_dec_u64("", u) && !parse_dec_u64("1.5", u), "non-digits rejected");
    int64 i;
    check(parse_i64("-9223372036854775808", i) && i == int64(-9223372036854775807) - 1, "i64 min");
    check(parse_i64("9223372036854775807", i) && i == 9223372036854775807, "i64 max");
    check(!parse_i64("9223372036854775808", i), "i64 max + 1 rejected");
    check(parse_i64("-0x10", i) && i == -16, "negative hex");
    check(parse_i64("0x7b", i) && i == 123, "hex");
    check(!parse_i64("--1", i), "double sign rejected");
}

void parse_hex_bytes_forms()
{
    array<uint8> b;
    check(parse_hex_bytes("4883ec28", b) && b.length() == 4 && b[0] == 0x48 && b[3] == 0x28, "packed");
    check(parse_hex_bytes("48 83 EC 28", b) && b.length() == 4 && b[2] == 0xec, "spaced, uppercase");
    check(parse_hex_bytes("", b) && b.length() == 0, "empty is valid (callers reject length 0)");
    check(!parse_hex_bytes("488", b), "odd nibble count rejected");
    check(!parse_hex_bytes("4 8", b), "space inside a byte rejected");
    check(!parse_hex_bytes("zz", b), "non-hex rejected");
}

void hex_formatting()
{
    check(hex_addr(0) == "0x0", "hex_addr(0)");
    check(hex_addr(0x7ff600001000) == "0x7ff600001000", "hex_addr lowercase unpadded");
    check(hex_addr(uint64(0xFFFFFFFFFFFFFFFF)) == "0xffffffffffffffff", "hex_addr max");
    array<uint8> b = { 0x00, 0xab, 0x10, 0xff };
    check(hex_of(b, 1, 2) == "ab10", "hex_of slice");
    check(hex_of(b, 0, 0) == "", "hex_of empty");
    check(bits_hex(0x0102, 2) == "0201", "bits_hex little-endian");
    check(bits_hex(uint64(0x1122334455667788), 8) == "8877665544332211", "bits_hex u64");
}

void utf16_encoding()
{
    array<uint8> w;
    check(utf8_to_utf16le("Aé", w) && w.length() == 4 && w[2] == 0xe9 && w[3] == 0x00, "U+00E9");
    check(utf8_to_utf16le("😀", w) && w.length() == 4 && w[0] == 0x3d && w[1] == 0xd8 && w[2] == 0x00 && w[3] == 0xde, "surrogate pair");
}

// --- address parsing from JSON ------------------------------------------------------------------

void get_addr_forms()
{
    string err;
    json_obj@ r = json::parse('{"s":"0x1000","n":4096,"neg":-1,"bad":"zz","b":true,"nul":null}', err);
    uint64 v;
    check(get_addr(r, "s", v) && v == 0x1000, "hex string");
    check(get_addr(r, "n", v) && v == 4096, "number");
    check(!get_addr(r, "neg", v), "negative number rejected");
    check(!get_addr(r, "bad", v), "non-hex string rejected");
    check(!get_addr(r, "b", v), "bool rejected");
    check(!get_addr(r, "nul", v) && !get_addr(r, "missing", v), "null / missing rejected");
    check(opt_addr(r, "missing", 0x55, v) && v == 0x55, "opt_addr default");
    check(opt_addr(r, "nul", 0x55, v) && v == 0x55, "opt_addr treats null as missing");
    int64 i;
    check(opt_int(r, "s", 0, i) && i == 0x1000, "opt_int from hex string");
    check(!opt_int(r, "b", 0, i), "opt_int rejects bool");
}

// --- scanner value decoding and comparison ------------------------------------------------------

void value_type_tables()
{
    check(vt_parse("u8") == VT_U8 && vt_parse("wstring") == VT_WSTRING && vt_parse("U8") == -1, "vt_parse");
    check(op_parse("between") == OP_BETWEEN && op_parse("nope") == -1, "op_parse");
    check(vt_width(VT_I16) == 2 && vt_width(VT_F32) == 4 && vt_width(VT_F64) == 8 && vt_width(VT_BYTES) == 0, "vt_width");
}

void int_key_orders_signed_values()
{
    check(int_key(VT_I8, 1, 0xFF) < int_key(VT_I8, 1, 0x00), "i8 -1 < 0");
    check(int_key(VT_I8, 1, 0x80) < int_key(VT_I8, 1, 0xFF), "i8 -128 < -1");
    check(int_key(VT_I32, 4, 0x7FFFFFFF) > int_key(VT_I32, 4, 0), "i32 max > 0");
    check(int_key(VT_I64, 8, uint64(0x8000000000000000)) == 0, "i64 min maps to 0");
    check(int_key(VT_U8, 1, 0xFF) == 0xFF, "unsigned keys are the raw bits");
}

void int_bits_from_widths()
{
    uint64 b;
    check(int_bits_from(true, 1, 1, b) && b == 0xFF, "u8 -1 -> ff");
    check(int_bits_from(true, 128, 1, b) && b == 0x80, "-128 fits a byte");
    check(!int_bits_from(true, 129, 1, b), "-129 does not fit a byte");
    check(int_bits_from(false, 0xFFFF, 2, b) && b == 0xFFFF, "u16 max");
    check(!int_bits_from(false, 0x10000, 2, b), "u16 overflow");
    check(int_bits_from(true, uint64(0x8000000000000000), 8, b) && b == uint64(0x8000000000000000), "i64 min");
}

void parse_value_types()
{
    string err;
    json_obj@ r = json::parse('{"m1":-1,"half":-0.5,"big":70000,"hex":"0x7b","f":"1.5","fn":2.25,"bytes":"de ad","str":"Ab","w":"Ab","empty":""}', err);
    uint64 bits;
    double f;
    array<uint8> pat;
    check(parse_value(r, "m1", VT_U8, bits, f, pat) && bits == 0xFF, "u8 from -1");
    check(!parse_value(r, "half", VT_I32, bits, f, pat), "fractional number rejected for ints");
    check(!parse_value(r, "big", VT_I16, bits, f, pat), "out of range for i16");
    check(parse_value(r, "hex", VT_U32, bits, f, pat) && bits == 123, "hex string");
    check(parse_value(r, "f", VT_F32, bits, f, pat) && f == 1.5, "float from string");
    check(parse_value(r, "fn", VT_F64, bits, f, pat) && f == 2.25, "float from number");
    check(!parse_value(r, "fn", VT_U32, bits, f, pat), "2.25 is not an integer");
    check(parse_value(r, "bytes", VT_BYTES, bits, f, pat) && pat.length() == 2 && pat[0] == 0xde, "bytes pattern");
    check(parse_value(r, "str", VT_STRING, bits, f, pat) && pat.length() == 2 && pat[1] == 0x62, "string pattern");
    check(parse_value(r, "w", VT_WSTRING, bits, f, pat) && pat.length() == 4 && pat[2] == 0x62 && pat[3] == 0, "wstring pattern");
    check(!parse_value(r, "empty", VT_BYTES, bits, f, pat), "empty pattern rejected");
    check(!parse_value(r, "missing", VT_U8, bits, f, pat), "missing value rejected");
}

void test_num_integers()
{
    ScanSpec s;
    s.vtype = VT_I32; s.width = 4;
    s.t1 = int_key(VT_I32, 4, 0xFFFFFFF6); // -10
    s.t2 = int_key(VT_I32, 4, 10);
    check(test_num(OP_EXACT, s, 0xFFFFFFF6, 0), "exact -10");
    check(test_num(OP_LESS, s, 0xFFFFFFF0, 0), "-16 < -10");
    check(!test_num(OP_GREATER, s, 0xFFFFFFF0, 0), "-16 not > -10");
    check(test_num(OP_BETWEEN, s, 0, 0) && !test_num(OP_BETWEEN, s, 11, 0), "between -10..10");
    check(test_num(OP_INCREASED, s, 1, 0xFFFFFFFF), "-1 -> 1 increased (signed)");
    check(test_num(OP_DECREASED, s, 0xFFFFFFFF, 1), "1 -> -1 decreased (signed)");
    check(test_num(OP_CHANGED, s, 1, 2) && test_num(OP_UNCHANGED, s, 2, 2), "changed / unchanged on raw bits");
}

void test_num_floats()
{
    ScanSpec s;
    s.vtype = VT_F32; s.width = 4; s.eps = 0.001;
    s.f1 = 1.0; s.f2 = 2.0;
    check(test_num(OP_EXACT, s, 0x3F800000, 0), "1.0 exact");
    check(test_num(OP_EXACT, s, 0x3F800010, 0), "1.0 + tiny within eps");
    check(!test_num(OP_EXACT, s, 0x3F810000, 0), "1.0078 outside eps");
    check(test_num(OP_BETWEEN, s, 0x3FC00000, 0), "1.5 between 1 and 2");
    check(!test_num(OP_GREATER, s, 0x7FC00000, 0) && !test_num(OP_LESS, s, 0x7FC00000, 0), "NaN never orders");
    check(!test_num(OP_GREATER, s, 0x7F800000, 0), "+Inf never orders");
    check(test_num(OP_INCREASED, s, 0x40000000, 0x3F800000), "1 -> 2 increased");
}

// --- IEEE-754 decoding via g_pow2 ---------------------------------------------------------------

void pow2_table()
{
    check(g_pow2.length() == 2098, "table size");
    check(g_pow2[1074] == 1.0 && g_pow2[1084] == 1024.0 && g_pow2[1073] == 0.5, "2^0, 2^10, 2^-1");
    check(g_pow2[0] > 0 && g_pow2[0] * 0.5 == 0, "2^-1074 is the smallest subnormal");
}

void flt_decode_f32()
{
    double v;
    check(flt_decode(4, 0x3F000000, v) && v == 0.5, "0.5");
    check(flt_decode(4, 0xC0490FDB, v) && near(v, -3.1415927410125732), "-pi");
    check(flt_decode(4, 0x7F7FFFFF, v) && near(v, 3.4028234663852886e38), "f32 max");
    check(flt_decode(4, 0x00000001, v) && v == g_pow2[925], "smallest subnormal = 2^-149");
    check(flt_decode(4, 0x00800000, v) && v == g_pow2[1074 - 126], "smallest normal = 2^-126");
    check(flt_decode(4, 0x80000000, v) && v == 0, "-0");
    check(!flt_decode(4, 0x7F800000, v) && !flt_decode(4, 0xFF800000, v) && !flt_decode(4, 0x7FC00000, v), "Inf/NaN rejected");
}

void flt_decode_f64()
{
    double v;
    check(flt_decode(8, uint64(0x3FF8000000000000), v) && v == 1.5, "1.5");
    check(flt_decode(8, uint64(0x400921FB54442D18), v) && v == 3.141592653589793, "pi exact");
    check(flt_decode(8, uint64(0x7FEFFFFFFFFFFFFF), v) && near(v, 1.7976931348623157e308), "f64 max");
    check(flt_decode(8, 1, v) && v == g_pow2[0], "smallest subnormal = 2^-1074");
    check(!flt_decode(8, uint64(0x7FF0000000000000), v) && !flt_decode(8, uint64(0x7FF8000000000000), v), "Inf/NaN rejected");
}

// --- request validation over the wire -------------------------------------------------------------

void protocol_basics()
{
    expect_error('{"type":"bogus","id":7}', E_UNKNOWN_VERB, "bogus");
    expect_error('not json', E_BAD_ARGS);
    check(mock_last().get_int64("id") == 0, "invalid JSON is answered with id 0");
    expect_error('{"type":"write","id":1,"address":"0x140000000","data":"90"}', E_NOT_ATTACHED);
}

void attach_reply()
{
    json_obj@ r = expect_ok('{"type":"attach","id":3,"name":"target.exe"}', "attach_result");
    if (r is null) return;
    check(r.get_int64("id") == 3 && r.get_uint64("pid") == 4242 && r.get_string("base") == "0x140000000", "attach fields");
    check(is_attached(), "attached afterwards");
    mock_reset();
    g_mock_pid = 0;
    expect_error('{"type":"attach","id":4,"name":"nope.exe"}', E_FAILED, "process not found");
}

void write_validation()
{
    mock_attach();
    expect_error('{"type":"write","id":1}', E_BAD_ARGS, "requires 'address'");
    expect_error('{"type":"write","id":1,"address":"0x140000000","data":""}', E_BAD_ARGS, "non-empty");
    expect_error('{"type":"write","id":1,"address":"0x140000000","data":"9"}', E_BAD_ARGS, "non-empty");
    expect_error('{"type":"write","id":1,"address":"0x140000000","data":7}', E_BAD_ARGS, "hex string");
    expect_error('{"type":"write","id":1,"address":"0x140000000","data":"90","force":"yes"}', E_BAD_ARGS, "bool");
    expect_error('{"type":"write","id":1,"address":"0x10","data":"90"}', E_FAILED);
    // straddles the end of the mapped block: refused unless forced
    expect_error('{"type":"write","id":1,"address":"0x140001fff","data":"9090"}', E_FAILED);
    json_obj@ r = expect_ok('{"type":"write","id":2,"address":"0x140000010","data":"de ad be ef"}', "write_result");
    check(r !is null && r.get_int("written") == 4, "written count");
    check(g_mock_mem[0x10] == 0xde && g_mock_mem[0x13] == 0xef, "bytes landed in target memory");
}

void scan_validation()
{
    mock_attach();
    expect_error('{"type":"scan_new","id":1,"value_type":"u128","value":1}', E_BAD_ARGS, "unknown value_type");
    expect_error('{"type":"scan_new","id":1,"value_type":"u32","compare":"changed"}', E_BAD_ARGS, "scan_new compare");
    expect_error('{"type":"scan_new","id":1,"value_type":"bytes","compare":"greater","value":"90"}', E_BAD_ARGS, "only support compare 'exact'");
    expect_error('{"type":"scan_new","id":1,"value_type":"u32"}', E_BAD_ARGS, "'value'");
    expect_error('{"type":"scan_new","id":1,"value_type":"u32","compare":"between","value":1}', E_BAD_ARGS, "value2");
    expect_error('{"type":"scan_new","id":1,"value_type":"u32","value":1,"alignment":3}', E_BAD_ARGS, "power of two");
    expect_error('{"type":"scan_new","id":1,"value_type":"f32","value":1,"float_epsilon":-1}', E_BAD_ARGS, "float_epsilon");
    expect_error('{"type":"scan_new","id":1,"value_type":"u32","value":1,"start":"0x2000","end":"0x1000"}', E_BAD_ARGS, "start < end");
    expect_error('{"type":"scan_new","id":1,"value_type":"u32","value":1,"module":"other.dll"}', E_BAD_ARGS, "module not found");
    check(g_job == "", "rejected requests never claim the job slot");
}

void scan_finds_values()
{
    mock_attach();
    // 1337 (u32) at +0x100 and +0x204, -5 (i16) at +0x300
    g_mock_mem[0x100] = 0x39; g_mock_mem[0x101] = 0x05;
    g_mock_mem[0x204] = 0x39; g_mock_mem[0x205] = 0x05;
    g_mock_mem[0x300] = 0xFB; g_mock_mem[0x301] = 0xFF;
    json_obj@ r = expect_ok('{"type":"scan_new","id":9,"value_type":"u32","value":1337}', "scan_new_result");
    if (r !is null)
    {
        check(r.get_int("count") == 2, "two u32 hits, got " + r.get_int("count"));
        json_obj@ s = r.get_obj("sample");
        check(s !is null && s.length() == 2 && s.get_obj_at(0).get_string("address") == "0x140000100", "sample address");
    }
    @r = expect_ok('{"type":"scan_new","id":10,"value_type":"i16","compare":"between","value":"-10","value2":-1,"module":"target.exe"}', "scan_new_result");
    check(r !is null && r.get_int("count") == 1, "i16 between -10..-1 finds -5 only");
    check(g_job == "", "job slot released after the scan");
}

void emulate_validation()
{
    expect_error('{"type":"emulate","id":1,"end":"0x2000","code":"90"}', E_BAD_ARGS, "'start' and 'end'");
    expect_error('{"type":"emulate","id":1,"start":"0x1000","end":"0x2000","code":"xyz"}', E_BAD_ARGS, "code must be hex");
    expect_error('{"type":"emulate","id":1,"start":"0x1000","end":"0x2000"}', E_NOT_ATTACHED);
    string base = '{"type":"emulate","id":1,"start":"0x1000","end":"0x2000","code":"90",';
    expect_error(base + '"max_insns":0}', E_BAD_ARGS, ">= 1");
    expect_error(base + '"max_insns":5000001}', E_LIMIT);
    expect_error(base + '"mem_log_limit":20001}', E_LIMIT);
    expect_error(base + '"trace":1}', E_BAD_ARGS, "bools");
    expect_error(base + '"regs":{"eax":"0x1"}}', E_BAD_ARGS, "unknown register");
    expect_error(base + '"regs":{"rax":true}}', E_BAD_ARGS, "register values");
    expect_error(base + '"regs":[1]}', E_BAD_ARGS, "regs must be an object");
    expect_error(base + '"write":[{"address":"0x3000","data":""}]}', E_BAD_ARGS, "non-empty hex");
    expect_error(base + '"write":[5]}', E_BAD_ARGS, "must be objects");
    expect_error(base + '"read":[{"address":"0x3000","size":0}]}', E_LIMIT, "1..65536");
    expect_error(base + '"read":[{"address":"0x3000","size":65537}]}', E_LIMIT, "1..65536");
    check(g_job == "", "rejected requests never claim the job slot");
}

void emulate_blank_run()
{
    json_obj@ r = expect_ok('{"type":"emulate","id":5,"start":"0x1000","end":"0x2000","code":"4889c8c3","regs":{"rcx":"0x1234"},'
                            '"write":[{"address":"0x3000","data":"aabb"}],"read":[{"address":"0x3000","size":2}]}', "emulate_result");
    if (r is null) return;
    check(r.get_string("error_name") == "ok" && r.get_bool("reached_end"), "reached end");
    json_obj@ regs = r.get_obj("regs");
    check(regs.get_string("rcx") == "0x1234" && regs.get_string("rip") == "0x2000", "registers reported");
    json_obj@ mem = r.get_obj("mem");
    check(mem.length() == 1 && mem.get_obj_at(0).get_string("data") == "aabb" && mem.get_obj_at(0).get_bool("ok"), "read-back blob");
    check(!r.has("mem_log"), "no mem_log unless asked");
    check(g_job == "", "job slot released");
}

// --- emulator memory-log helpers ----------------------------------------------------------------

void emu_ptr_size_widths()
{
    check(emu_ptr_size("mov eax, dword ptr [rcx]") == 4, "dword");
    check(emu_ptr_size("mov ax, word ptr [rcx]") == 2, "word (not matched by dword)");
    check(emu_ptr_size("movzx eax, byte ptr [rcx]") == 1, "byte");
    check(emu_ptr_size("movaps xmm0, xmmword ptr [rcx]") == 16, "xmmword");
    check(emu_ptr_size("vmovups ymm0, ymmword ptr [rcx]") == 32, "ymmword");
    check(emu_ptr_size("fld tbyte ptr [rcx]") == 10, "tbyte");
    check(emu_ptr_size("push qword ptr [rcx]") == 8, "qword");
    check(emu_ptr_size("call [rax]") == 8, "default 8");
}

void emu_addr_reg_values()
{
    uint64 v;
    g_mock_uc_regs[int(x86_reg::rbx)] = 0xabc;
    check(emu_addr_reg(1, 0, 0x5000, v) && v == 0, "no register -> 0");
    check(emu_addr_reg(1, mock_zreg("rip"), 0x5000, v) && v == 0x5000, "rip -> next instruction");
    check(emu_addr_reg(1, mock_zreg("rbx"), 0x5000, v) && v == 0xabc, "rbx via uc::reg_read64");
    check(!emu_addr_reg(1, mock_zreg("eax"), 0x5000, v), "32-bit register unsupported");
}

disasm_operand mem_op(int action, const string &in base, int64 disp, const string &in seg = "")
{
    disasm_operand op;
    op.type = int(op_type::mem);
    op.action = action;
    op.mem_base = base == "" ? 0 : mock_zreg(base);
    op.mem_index = 0;
    op.mem_scale = 1;
    op.mem_disp = disp;
    op.mem_segment = seg == "" ? 0 : mock_zreg(seg);
    return op;
}

void mock_insn(uint64 address, uint8 len, const string &in text, disasm_operand op)
{
    disasm_insn i;
    i.runtime_address = address;
    i.length = len;
    i.text = text;
    i.ops.insertLast(op);
    i.operand_count = 1;
    i.operand_count_visible = 1;
    g_mock_insns.insertLast(i);
}

void emulate_mem_log()
{
    // 0x1000: mov dword ptr [rax+0x10], ecx  (writes 4 bytes at 0x3010)
    // 0x1003: mov rdx, qword ptr gs:[0x60]   (reads 8 bytes at gs_base + 0x60)
    // 0x100c: lea rsi, [rax+8]               (no memory access)
    mock_insn(0x1000, 3, "mov dword ptr [rax+0x10], ecx", mem_op(int(op_action::write), "rax", 0x10));
    mock_insn(0x1003, 9, "mov rdx, qword ptr gs:[0x60]", mem_op(int(op_action::read), "", 0x60, "gs"));
    mock_insn(0x100c, 4, "lea rsi, [rax+8]", mem_op(int(op_action::read), "rax", 8));
    MockStep s1; s1.address = 0x1000; s1.size = 3; s1.write_addr = 0x3010; s1.write_data = { 0x78, 0x56, 0x34, 0x12 };
    MockStep s2; s2.address = 0x1003; s2.size = 9;
    MockStep s3; s3.address = 0x100c; s3.size = 4;
    g_mock_uc_steps = { s1, s2, s3 };
    g_mock_uc_regs[int(x86_reg::gs_base)] = 0x3000;

    json_obj@ r = expect_ok('{"type":"emulate","id":6,"start":"0x1000","end":"0x2000","code":"' + "90909090909090909090909090909090" + '",'
                            '"regs":{"rax":"0x3000"},"write":[{"address":"0x3000","data":"' + "11" + '"}],"mem_log":true,"trace":true}', "emulate_result");
    if (r is null) return;
    check(r.get_int("instructions") == 3, "hook counted 3 instructions");
    check(r.get_obj("trace").length() == 3 && r.get_obj("trace").get_string_at(1) == "0x1003", "trace");
    json_obj@ ml = r.get_obj("mem_log");
    check(ml !is null && ml.length() == 2, "two memory accesses (lea skipped)");
    if (ml is null || ml.length() < 2) return;
    json_obj@ w = ml.get_obj_at(0);
    check(w.get_string("rip") == "0x1000" && w.get_string("address") == "0x3010" && w.get_int("size") == 4, "write operand decoded");
    check(w.get_string("access") == "w" && w.get_string("before") == "00000000" && w.get_string("after") == "78563412", "write before/after");
    json_obj@ rd = ml.get_obj_at(1);
    check(rd.get_string("address") == "0x3060" && rd.get_int("size") == 8 && rd.get_string("access") == "r" && !rd.has("after"), "gs read uses gs_base");
    check(!r.get_bool("mem_log_truncated"), "not truncated");
}

void emulate_mem_log_limit()
{
    mock_insn(0x1000, 3, "mov dword ptr [rax], ecx", mem_op(int(op_action::write), "rax", 0));
    MockStep s; s.address = 0x1000; s.size = 3;
    g_mock_uc_steps = { s, s, s };
    json_obj@ r = expect_ok('{"type":"emulate","id":7,"start":"0x1000","end":"0x2000","code":"909090","regs":{"rax":"0x1000"},"mem_log":true,"mem_log_limit":2}', "emulate_result");
    if (r is null) return;
    check(r.get_obj("mem_log").length() == 2 && r.get_bool("mem_log_truncated"), "capped at mem_log_limit");
}

}
