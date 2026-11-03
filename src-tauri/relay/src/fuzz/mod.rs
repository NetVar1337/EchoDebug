//! Property / fuzz tests for everything in the relay that parses target memory or file bytes.
//! Here: the symbolic lifter's decoder (target code bytes, addresses anywhere in the 64-bit
//! space), the link_map / auxv walker and the Itanium RTTI readers (hostile target memory), the
//! Itanium type-name demangler, the instance / xref scanners, PDB files, `.pd_` cabinets and the
//! page hash. `files.rs`: the stack unwinder (PE .pdata / UNWIND_INFO, ELF .eh_frame CFI), the
//! time-travel trace file decoder and the PDB type database.
//!
//! Properties: no panic (an overflow in debug builds is one), and every call inside a time
//! budget. `FUZZ_CASES` sets the cases per property (default 64, quick enough for every
//! `cargo test`), `FUZZ_BUDGET_MS` the budget (default 2000 ms: these run unoptimised); a long
//! run is `FUZZ_CASES=100000 cargo test -p echo-debug-relay fuzz`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use proptest::prelude::*;
use serde_json::{json, Map, Value};

use crate::lift::{devirt, lift_block, lift_trace, Pages};

mod files;
use crate::local::{MapLine, MemIo};

fn cases() -> u32 {
    std::env::var("FUZZ_CASES").ok().and_then(|v| v.parse().ok()).filter(|&n| n > 0).unwrap_or(64)
}

fn config() -> ProptestConfig {
    ProptestConfig { cases: cases(), failure_persistence: None, ..ProptestConfig::default() }
}

/// Runs `f` and fails when it is over the time budget (twice: a slow first run can be a page-in).
fn timed<T>(what: &str, mut f: impl FnMut() -> T) -> T {
    let budget = Duration::from_millis(std::env::var("FUZZ_BUDGET_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000));
    let t0 = Instant::now();
    let r = f();
    if t0.elapsed() <= budget {
        return r;
    }
    let t1 = Instant::now();
    let r = f();
    assert!(t1.elapsed() <= budget, "{what} took {:?} (budget {budget:?})", t1.elapsed());
    r
}

fn obj(v: Value) -> Map<String, Value> {
    match v {
        Value::Object(m) => m,
        _ => unreachable!(),
    }
}

/// Addresses that break address arithmetic: page and space boundaries.
fn address() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(u64::MAX),
        Just(u64::MAX - 7),
        Just(u64::MAX - 15),
        Just(0xffff_ffff_ffff_f000),
        Just(0x7fff_ffff_ffff),
        Just(0x1000),
        (0u64..0x10_0000).prop_map(|a| 0x40_0000 + a),
        any::<u64>(),
    ]
}

// ---- hostile target memory ----------------------------------------------------------------------

/// Target memory where every address is mapped and reads a repeating pattern of attacker-chosen
/// qwords (pointers that point anywhere, including the last page of the address space).
#[derive(Debug)]
struct Hostile {
    words: Vec<u64>,
    maps: Vec<MapLine>,
}

impl MemIo for Hostile {
    fn read_at(&self, addr: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        for (i, b) in buf.iter_mut().enumerate() {
            let a = addr.wrapping_add(i as u64);
            *b = self.words[((a / 8) % self.words.len() as u64) as usize].to_le_bytes()[(a % 8) as usize];
        }
        Ok(buf.len())
    }
    fn write_at(&self, _: u64, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn maps(&self) -> std::io::Result<Vec<MapLine>> {
        Ok(self.maps.clone())
    }
    fn alive(&self) -> bool {
        true
    }
}

fn word() -> impl Strategy<Value = u64> {
    prop_oneof![address(), Just(0x6d_6e_6f_70_31_4e_5a_5f), Just(0x0045_3352_6176_3349), Just(1), Just(32), Just(21)]
}

fn hostile() -> impl Strategy<Value = Hostile> {
    (prop::collection::vec(word(), 1..16), prop::collection::vec((address(), 0u64..0x2_0000, any::<bool>(), any::<bool>()), 0..4)).prop_map(|(words, maps)| Hostile {
        words,
        maps: maps.into_iter().map(|(start, len, w, x)| MapLine { start, end: start.saturating_add(len), writable: w, executable: x, path: "/lib/x.so".into() }).collect(),
    })
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn link_map_walk_survives_hostile_memory(mem in hostile(), phdr in address(), phnum in 0u64..80) {
        let auxv: HashMap<u64, u64> = [(3, phdr), (5, phnum), (9, 0x401000)].into_iter().collect();
        timed("walk_link_map", || crate::local_ext::walk_link_map(&mem, &auxv));
    }

    #[test]
    fn itanium_rtti_survives_hostile_memory(mem in hostile(), at in address()) {
        timed("rtti_resolve", || crate::local_ext::itanium_resolve(&mem, &obj(json!({ "address": format!("0x{at:x}") }))));
        timed("rtti_name", || crate::local_more::rtti_name(&mem, &obj(json!({ "address": format!("0x{at:x}"), "object": true }))));
        timed("rtti_resolve_batch", || crate::local_ext::itanium_resolve_batch(&mem, &obj(json!({ "addresses": [format!("0x{at:x}"), "0xfffffffffffffff8", "0x0"] }))));
    }

    #[test]
    fn scanners_survive_hostile_memory(mem in hostile(), target in address()) {
        timed("xref_scan", || crate::local_more::xref_scan(&mem, &obj(json!({ "target": format!("0x{target:x}"), "max": 64 }))));
        timed("find_instances", || crate::local_more::find_instances(&mem, &obj(json!({ "vtable": format!("0x{target:x}"), "max": 64 }))));
    }

    #[test]
    fn demangler_survives_any_type_name(s in "[0-9NEISKPRLJvbcijmtSaoxyzVe_]{0,64}", n in "[0-9]{1,24}", toks in prop::collection::vec(prop::sample::select(vec!["N", "E", "I", "L", "J", "P", "K", "R", "V", "St", "Sa", "Ss", "1a", "3foo", "i", "b", "v", "9", "0", "n1"]), 0..40)) {
        let t = toks.concat();
        timed("demangle_type(tokens)", || crate::local_ext::demangle_type(&t));
        timed("demangle_type", || crate::local_ext::demangle_type(&s));
        timed("demangle_type(len)", || crate::local_ext::demangle_type(&format!("{n}abc")));
        timed("demangle_type(nested)", || crate::local_ext::demangle_type(&format!("N{s}{n}xE")));
    }

    #[test]
    fn lifter_survives_any_code(bytes in prop::collection::vec(any::<u8>(), 0..512), page in address(), off in prop_oneof![0u64..0x1000, 0xff0u64..0x1000], trace in prop::collection::vec(0u64..0x1000, 0..64)) {
        let base = page & !0xfff;
        let mut pages = HashMap::new();
        for (k, chunk) in bytes.chunks(0x1000).enumerate() {
            pages.insert(base.wrapping_add(k as u64 * 0x1000), chunk.to_vec());
        }
        let code = Pages(pages);
        let start = base.wrapping_add(off);
        let trace: Vec<u64> = trace.into_iter().map(|t| base.wrapping_add(t)).collect();
        timed("lift_block", || lift_block(&code, start, 256));
        timed("lift_trace", || lift_trace(&code, &trace, 256));
        timed("devirt", || devirt(&code, &trace, 256));
    }

    #[test]
    fn lifter_survives_expression_growth(ops in prop::collection::vec(prop::sample::select(vec![
        &[0x48u8, 0x01, 0xc0][..], // add rax, rax
        &[0x48, 0x0f, 0xaf, 0xc0], // imul rax, rax
        &[0x48, 0x31, 0xd8],       // xor rax, rbx
        &[0x48, 0x21, 0xc3],       // and rbx, rax
        &[0x48, 0xd3, 0xe0],       // shl rax, cl
        &[0x48, 0x89, 0x03],       // mov [rbx], rax
        &[0x48, 0x8b, 0x03],       // mov rax, [rbx]
        &[0x48, 0x01, 0xc3],       // add rbx, rax
        &[0x48, 0x39, 0xd8],       // cmp rax, rbx
        &[0x48, 0xc1, 0xc0, 0x0d], // rol rax, 13
        &[0x9c],                   // pushfq
    ]), 1..400)) {
        let code: Vec<u8> = ops.concat();
        let mut pages = HashMap::new();
        for (k, chunk) in code.chunks(0x1000).enumerate() {
            pages.insert(0x40_0000 + k as u64 * 0x1000, chunk.to_vec());
        }
        let p = Pages(pages);
        let mut ip = 0x40_0000u64;
        let trace: Vec<u64> = ops.iter().map(|o| { let a = ip; ip += o.len() as u64; a }).collect();
        timed("lift_block(growth)", || lift_block(&p, 0x40_0000, 4096));
        timed("lift_trace(growth)", || lift_trace(&p, &trace, 4096));
    }

    #[test]
    fn page_hash_any_bytes(b in prop::collection::vec(any::<u8>(), 0..5000)) {
        crate::local_more::page_hash(&b);
        crate::monitor::page_hash(&b);
    }
}

// ---- PDB files ----------------------------------------------------------------------------------

fn pdb_fixture() -> Vec<u8> {
    std::fs::read(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fix.pdb")).unwrap()
}

/// A damaged PDB: the fixture with bytes overwritten (MSF header, stream directory and stream
/// contents alike) by values that break sizes, counts and page numbers, or cut short.
fn damaged_pdb() -> impl Strategy<Value = Vec<u8>> {
    let len = pdb_fixture().len();
    let edit = (0..len, prop_oneof![Just(0u32), Just(1), Just(0xffff_ffff), Just(0x7fff_ffff), Just(0x8000_0000), Just(0x1000), any::<u32>()]);
    (prop::collection::vec(edit, 0..8), prop::option::of(0..len), prop::bool::weighted(0.2)).prop_map(|(edits, cut, header)| {
        let mut b = pdb_fixture();
        for (at, v) in edits {
            // most edits land in the MSF superblock / directory (first pages), the rest anywhere
            let at = if header && at > 0x2000 { at % 0x2000 } else { at };
            let at = at & !3;
            if at + 4 <= b.len() {
                b[at..at + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        if let Some(c) = cut {
            b.truncate(c);
        }
        b
    })
}

fn pdb_case(bytes: &[u8]) {
    let dir = std::env::temp_dir().join(format!("echodebug-fuzz-{}-{:?}", std::process::id(), std::thread::current().id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("case.pdb");
    std::fs::write(&path, bytes).unwrap();
    timed("pdb_identity", || crate::symbols::pdb_identity(&path).is_ok());
    timed("pdbinfo::load", || crate::pdbinfo::load(&path).map(|l| l.syms.len()).ok());
    let _ = std::fs::remove_file(&path);
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn pdb_reader_survives_damaged_files(b in damaged_pdb()) {
        pdb_case(&b);
    }

    #[test]
    fn pdb_reader_survives_random_files(b in prop::collection::vec(any::<u8>(), 0..8192)) {
        let mut f = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0".to_vec();
        f.extend_from_slice(&b);
        pdb_case(&b);
        pdb_case(&f);
    }

    #[test]
    fn cabinet_reader_survives_random_files(b in prop::collection::vec(any::<u8>(), 0..2048), head in prop::collection::vec(any::<u8>(), 0..40)) {
        // a `.pd_` from a symbol server: MSCF header fields then anything
        let mut f = b"MSCF\0\0\0\0".to_vec();
        f.extend_from_slice(&head);
        f.extend_from_slice(&b);
        timed("uncab", || crate::symbols::uncab(&f).map(|v| v.len()).ok());
        timed("parse_rsds", || crate::symbols::parse_rsds(&b).is_some());
    }
}

// ---- regressions (each failed before its fix; the input is inlined) --------------------------

#[test]
fn lifter_decodes_at_the_top_of_the_address_space() {
    // Pages::at added the byte index to the address: an overflow panic for the last 15 bytes
    let code = Pages([(0xffff_ffff_ffff_f000u64, vec![0x90u8; 0x1000])].into_iter().collect());
    let r = lift_block(&code, 0xffff_ffff_ffff_fffc, 16);
    assert!(r["instructions"].as_array().is_some_and(|a| !a.is_empty()));
    lift_trace(&code, &[u64::MAX, u64::MAX - 3], 16);
}

#[test]
fn demangler_rejects_a_length_that_overflows() {
    // a length of usize::MAX made `start + n` overflow
    assert_eq!(crate::local_ext::demangle_type("18446744073709551615x"), "18446744073709551615x");
    assert_eq!(crate::local_ext::demangle_type("N18446744073709551615xE"), "N18446744073709551615xE");
}

#[test]
fn demangler_nesting_is_bounded() {
    // a megabyte of `P` (a symbol name from a hostile ELF) recursed until the stack overflowed
    let deep = format!("{}i", "P".repeat(1 << 20));
    assert_eq!(crate::local_ext::demangle_type(&deep), deep);
    let deep = format!("{}iE", "1aI".repeat(100_000));
    assert_eq!(crate::local_ext::demangle_type(&deep), deep);
    assert_eq!(crate::local_ext::demangle_type("PKi"), "int const*");
    // a nested name cut short inside a template literal stepped past the end, then sliced there
    for s in ["1aILN1b", "1aILi", "1aIJN1b", "St1aIL", "N1aI"] {
        assert_eq!(crate::local_ext::demangle_type(s), s);
    }
}

#[test]
fn link_map_and_type_info_pointers_at_the_top_of_memory() {
    // every qword is u64::MAX - 7: `lm + 8`, `ti + 8`, `dynamic + i * 16` overflowed
    let mem = Hostile { words: vec![u64::MAX - 7], maps: vec![] };
    let auxv: HashMap<u64, u64> = [(3, u64::MAX - 7), (5, 4)].into_iter().collect();
    crate::local_ext::walk_link_map(&mem, &auxv);
    crate::local_ext::itanium_resolve(&mem, &obj(json!({ "address": "0x1000" })));
}

#[test]
fn damaged_pdb_is_an_error_not_a_panic() {
    // single u32 edits of the fixture made the pdb crate index past a buffer (also in release):
    // 0xffffffff at 0x6008 (a module stream size), 0x1000 at 0xb10c (a name offset)
    for (at, v) in [(0x6008usize, 0xffff_ffffu32), (0xb10c, 0x1000), (0xb018, 0xffff_ffff)] {
        let mut b = pdb_fixture();
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
        let path = std::env::temp_dir().join(format!("echodebug-damaged-{at:x}-{}.pdb", std::process::id()));
        std::fs::write(&path, &b).unwrap();
        let loaded = crate::pdbinfo::load(&path).map(|_| ());
        let ident = crate::symbols::pdb_identity(&path).map(|_| ());
        let _ = std::fs::remove_file(&path);
        assert!(loaded.is_err() || ident.is_err(), "0x{at:x}");
    }
}
