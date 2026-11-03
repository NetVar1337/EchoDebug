//! Property tests for the unwinder (PE .pdata / UNWIND_INFO, ELF .eh_frame CFI and the
//! fallbacks, all over hostile target memory), the time-travel trace file decoder and the PDB
//! type database.

use proptest::prelude::*;

use super::{address, config, damaged_pdb, timed};
use crate::pdbinfo::{Member, Ty, TypeDb};
use crate::unwind::{Flat, ModuleInfo, Regions, Regs, Unwinder};

// ---- seeds ----------------------------------------------------------------------------------

/// The clang/lld fixture with .pdata and UNWIND_INFO, laid out like the loader maps it.
fn seh_image() -> Vec<u8> {
    let file: &[u8] = include_bytes!("../../../../src/lib/analysis/fixtures/fix-seh.exe");
    let rd32 = |o: usize| u32::from_le_bytes(file[o..o + 4].try_into().unwrap()) as usize;
    let rd16 = |o: usize| u16::from_le_bytes(file[o..o + 2].try_into().unwrap()) as usize;
    let nt = rd32(0x3c);
    let (nsec, opt) = (rd16(nt + 6), rd16(nt + 20));
    let mut img = vec![0u8; rd32(nt + 24 + 56)];
    let hdr = rd32(nt + 24 + 60);
    img[..hdr].copy_from_slice(&file[..hdr]);
    for i in 0..nsec {
        let s = nt + 24 + opt + i * 40;
        let (va, raw_size, raw) = (rd32(s + 12), rd32(s + 16), rd32(s + 20));
        let n = raw_size.min(file.len().saturating_sub(raw)).min(img.len() - va);
        img[va..va + n].copy_from_slice(&file[raw..raw + n]);
    }
    img
}

fn uleb_enc(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// An ELF64 image: PT_LOAD + PT_GNU_EH_FRAME -> .eh_frame_hdr (with or without the search
/// table) -> a `zR` CIE and one FDE for [0x1000, 0x1100), both running the given CFA programs.
fn cfi_image(cie_insns: &[u8], fde_insns: &[u8], with_table: bool) -> Vec<u8> {
    let mut img = vec![0u8; 0x3000];
    img[0..4].copy_from_slice(b"\x7fELF");
    img[4] = 2;
    img[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    img[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    img[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes());
    img[0x40..0x44].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD at 0
    img[0x78..0x7c].copy_from_slice(&0x6474_e550u32.to_le_bytes()); // PT_GNU_EH_FRAME
    img[0x78 + 16..0x78 + 24].copy_from_slice(&0x800u64.to_le_bytes());
    let mut cie = vec![0, 0, 0, 0, 1, b'z', b'R', 0];
    uleb_enc(1, &mut cie);
    cie.extend_from_slice(&[0x78, 16, 1, 0x1b]); // data align -8, RA 16, aug data: pcrel|sdata4
    cie.extend_from_slice(cie_insns);
    let mut eh = Vec::new();
    eh.extend_from_slice(&(cie.len() as u32).to_le_bytes());
    eh.extend_from_slice(&cie);
    let fde_at = eh.len();
    let mut f = Vec::new();
    f.extend_from_slice(&((fde_at + 4) as u32).to_le_bytes());
    let field = 0x900 + fde_at + 8;
    f.extend_from_slice(&((0x1000 - field as i64) as i32).to_le_bytes());
    f.extend_from_slice(&0x100u32.to_le_bytes());
    f.push(0);
    f.extend_from_slice(fde_insns);
    eh.extend_from_slice(&(f.len() as u32).to_le_bytes());
    eh.extend_from_slice(&f);
    eh.extend_from_slice(&[0, 0, 0, 0]);
    img[0x900..0x900 + eh.len()].copy_from_slice(&eh);
    let mut h = vec![1, 0x1b, if with_table { 0x03 } else { 0xff }, 0x3b];
    h.extend_from_slice(&(0x900i32 - 0x804).to_le_bytes());
    if with_table {
        h.extend_from_slice(&1u32.to_le_bytes());
        h.extend_from_slice(&(0x1000i32 - 0x800).to_le_bytes());
        h.extend_from_slice(&((0x900 + fde_at) as i32 - 0x800).to_le_bytes());
    }
    img[0x800..0x800 + h.len()].copy_from_slice(&h);
    img
}

/// u32 writes at offsets below `hot` (headers, directories) most of the time, anywhere otherwise.
fn mutate(mut img: Vec<u8>, edits: &[(usize, u32, bool)], hot: usize) -> Vec<u8> {
    for &(at, v, anywhere) in edits {
        let at = if anywhere { at % img.len() } else { at % hot.min(img.len()) } & !1;
        if at + 4 <= img.len() {
            img[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    img
}

fn edit() -> impl Strategy<Value = (usize, u32, bool)> {
    (any::<usize>(), prop_oneof![Just(0u32), Just(1), Just(0xffff_ffff), Just(0x7fff_ffff), Just(0x8000_0000), Just(0xffff_fff0), any::<u32>()], prop::bool::weighted(0.3))
}

/// A stack of hostile words: return addresses into the module and pointers anywhere.
fn stack_words(base: u64) -> impl Strategy<Value = Vec<u64>> {
    prop::collection::vec(prop_oneof![address(), (0u64..0x6000).prop_map(move |o| base.wrapping_add(o))], 0..64)
}

fn walk_case(img: Vec<u8>, base: u64, stack_at: u64, stack: &[u64], rip: u64, rbp: u64) {
    let size = img.len() as u64;
    let st: Vec<u8> = stack.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mem = Regions(vec![(base, img), (stack_at, st)]);
    let mut un = Unwinder::new(&mem, vec![ModuleInfo { name: "m".into(), base, size }]);
    un.max_scan = 256;
    timed("Unwinder::walk", || un.walk(&Regs::new(rip, stack_at, rbp), 64).len());
    timed("read_pdata", || crate::unwind::read_pdata(&mem, base).map(|v| v.len()));
    timed("pe_exports", || crate::unwind::pe_exports(&mem, base).len());
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn pe_unwinder_survives_damaged_images(edits in prop::collection::vec(edit(), 0..10), base in prop_oneof![Just(0x1_4000_0000u64), Just(0xffff_ffff_fff0_0000), Just(0)],
                                           stack in stack_words(0x1_4000_0000), rip_off in 0u64..0x3000,
                                           stack_at in prop_oneof![Just(0x7000_0000u64), Just(u64::MAX - 0x100), address()], rbp in address()) {
        let img = mutate(seh_image(), &edits, 0x400);
        walk_case(img, base, stack_at, &stack, base.wrapping_add(rip_off), rbp);
    }

    #[test]
    fn pe_unwind_info_survives_random_xdata(xdata in prop::collection::vec(any::<u8>(), 0..64), stack in stack_words(0x1_4000_0000), prolog in 0u64..0x40, rbp in address()) {
        // every RUNTIME_FUNCTION of the fixture points at the same random UNWIND_INFO
        let mut img = seh_image();
        let at = img.len() - 0x100;
        img[at..at + xdata.len()].copy_from_slice(&xdata);
        let flat = Flat { base: 0, data: &img };
        let (Some(pdata), Some((rva, _))) = (crate::unwind::read_pdata(&flat, 0), crate::unwind::pe_directory(&flat, 0, 3)) else { panic!("fixture") };
        for i in 0..pdata.len() {
            let o = rva as usize + i * 12 + 8;
            img[o..o + 4].copy_from_slice(&(at as u32).to_le_bytes());
        }
        let rip = 0x1_4000_0000 + pdata[0].begin as u64 + prolog;
        walk_case(img, 0x1_4000_0000, 0x7000_0000, &stack, rip, rbp);
    }

    #[test]
    fn cfi_unwinder_survives_random_programs(cie in prop::collection::vec(any::<u8>(), 0..48), fde in prop::collection::vec(any::<u8>(), 0..96), table in any::<bool>(),
                                             edits in prop::collection::vec(edit(), 0..4), stack in stack_words(0x5555_0000_0000), pc in 0x1000u64..0x1100,
                                             base in prop_oneof![Just(0x5555_0000_0000u64), Just(0xffff_ffff_ffff_0000)], rbp in address()) {
        let img = mutate(cfi_image(&cie, &fde, table), &edits, 0xa00);
        walk_case(img, base, 0x7fff_0000_0000, &stack, base.wrapping_add(pc), rbp);
    }
}

// ---- time-travel trace files (.edt) ---------------------------------------------------------

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, x| (h ^ *x as u64).wrapping_mul(0x100_0000_01b3))
}

/// `body` with a valid checksum appended: the checksum is no defence against a crafted file.
fn sealed(mut body: Vec<u8>) -> Vec<u8> {
    let s = fnv(&body);
    body.extend_from_slice(&s.to_le_bytes());
    body
}

fn sample_trace() -> Vec<u8> {
    use crate::trace::{Builder, Meta, RawAccess, NREG};
    let meta = Meta { name: "fuzz".into(), source: "test".into(), created_ms: 1, pid: Some(1), tid: Some(1), stop_reason: "end".into(), truncated: false };
    let mut regs = [0u64; NREG];
    regs[16] = 0x40_1000;
    let mut b = Builder::new(meta, regs, 4);
    for i in 0..12u64 {
        let mut after = regs;
        after[0] = i * 3;
        after[16] = 0x40_1000 + i * 4;
        let acc = [RawAccess { addr: 0x7000 + i * 8, write: i % 2 == 0, old: vec![i as u8; 8], new: vec![!(i as u8); 8] }];
        b.step(0x40_1000 + i * 4, &[0x48, 0x89, 0x07, 0x90], &after, &acc);
        regs = after;
    }
    b.finish().encode()
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn trace_decoder_survives_damaged_files(edits in prop::collection::vec((any::<usize>(), any::<u8>()), 0..12), cut in prop::option::of(any::<usize>()),
                                            varint in prop::collection::vec(any::<u8>(), 0..12), splice_at in any::<usize>()) {
        let enc = sample_trace();
        let mut body = enc[..enc.len() - 8].to_vec();
        for (at, v) in edits {
            let at = at % body.len();
            body[at] = v;
        }
        if let Some(c) = cut {
            body.truncate(c % (body.len() + 1));
        }
        // a hostile varint (a huge count or length) spliced in anywhere
        let at = splice_at % (body.len() + 1);
        body.splice(at..at, varint);
        let file = sealed(body);
        timed("Trace::decode", || crate::trace::Trace::decode(&file).map(|t| t.len()).ok());
        timed("Trace::peek_meta", || crate::trace::Trace::peek_meta(&file).ok());
    }

    #[test]
    fn trace_decoder_survives_random_files(b in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut body = b"EDTRACE1".to_vec();
        body.extend_from_slice(&b);
        let file = sealed(body);
        timed("Trace::decode(random)", || crate::trace::Trace::decode(&file).is_ok());
        timed("b64_decode", || crate::trace::b64_decode(&String::from_utf8_lossy(&b)).is_ok());
    }

    #[test]
    fn pdb_type_reader_survives_damaged_files(b in damaged_pdb()) {
        let dir = std::env::temp_dir().join(format!("echodebug-fuzz-pdbinfo-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("case.pdb");
        std::fs::write(&path, &b).unwrap();
        timed("pdbinfo::load", || crate::pdbinfo::load(&path).map(|l| l.types.types.len()).ok());
        let _ = std::fs::remove_file(&path);
    }
}

// ---- PDB type graphs ------------------------------------------------------------------------

const FIRST: u32 = 0x1000;

/// A type index: a primitive, one of the `n` records, or out of range.
fn tidx(n: u32) -> impl Strategy<Value = u32> {
    prop_oneof![Just(0x74u32), Just(0x603), Just(0), (0..n).prop_map(|i| FIRST + i), Just(u32::MAX)]
}

fn ty(n: u32) -> impl Strategy<Value = Ty> {
    let t = || tidx(n);
    prop_oneof![
        (t(), any::<bool>()).prop_map(|(to, r)| Ty::Ptr { to, size: 8, reference: r, konst: false }),
        t().prop_map(|to| Ty::Mod { to, konst: true, vol: false }),
        (t(), any::<u32>()).prop_map(|(elem, size)| Ty::Array { elem, size, dims: vec![] }),
        t().prop_map(|to| Ty::Bitfield { to, len: 3, pos: 1 }),
        (prop::option::of(t()), any::<bool>(), any::<u64>()).prop_map(|(fields, forward, size)| Ty::Udt { kind: "struct", name: "S".into(), unique: None, size, fields, forward }),
        (t(), t()).prop_map(|(underlying, fields)| Ty::Enum { name: "E".into(), unique: None, underlying, fields, forward: false }),
        (prop::option::of(t()), t()).prop_map(|(ret, args)| Ty::Proc { ret, args, cc: 0, class: None }),
        prop::collection::vec(t(), 0..24).prop_map(Ty::Args),
        (prop::collection::vec((t(), any::<u64>()), 0..24), prop::option::of(t())).prop_map(|(m, cont)| Ty::Fields {
            members: m.into_iter().map(|(ty, offset)| Member::Data { name: "f".into(), ty, offset }).collect(),
            cont,
        }),
    ]
}

fn type_db() -> impl Strategy<Value = TypeDb> {
    (1u32..12).prop_flat_map(|n| prop::collection::vec(ty(n), n as usize)).prop_map(|types| {
        let mut db = TypeDb { first: FIRST, types, ..Default::default() };
        db.index();
        db
    })
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn pdb_type_queries_survive_hostile_graphs(db in type_db()) {
        for i in 0..db.types.len() as u32 + 1 {
            let idx = FIRST + i;
            timed("TypeDb::name", || db.name(idx).len());
            timed("TypeDb::desc", || db.desc(idx).len());
            timed("TypeDb::size", || db.size(idx));
            timed("TypeDb::layout", || db.layout_with_nested(idx, 8).is_some());
        }
        timed("TypeDb::list", || db.list("", 1000).0);
    }
}

// ---- regressions (each failed before its fix; the input is inlined) ---------------------------

/// An encoded trace without steps whose zero register file ends the body as
/// `[code count 0, keyframe count 1, 20 x 0]`; `tail` replaces those 22 bytes.
fn empty_trace_with_tail(tail: &[u8]) -> Vec<u8> {
    use crate::trace::{Builder, Meta, NREG};
    let meta = Meta { name: String::new(), source: String::new(), created_ms: 0, pid: None, tid: None, stop_reason: String::new(), truncated: false };
    let enc = Builder::new(meta, [0u64; NREG], 4).finish().encode();
    let mut body = enc[..enc.len() - 8].to_vec();
    assert_eq!(&body[body.len() - 22..], &[&[0u8, 1][..], &[0u8; 20][..]].concat()[..]);
    body.truncate(body.len() - 22);
    body.extend_from_slice(tail);
    sealed(body)
}

#[test]
fn trace_decode_rejects_huge_counts_and_lengths() {
    // keyframe count 2^63: Vec::with_capacity panicked with a capacity overflow (release too)
    let f = empty_trace_with_tail(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]);
    assert!(crate::trace::Trace::decode(&f).is_err());
    // two code entries whose pc deltas overflow: `pc += delta` panicked
    let mut tail = vec![2, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 1, 0x90, 2, 1, 0x90, 1];
    tail.extend_from_slice(&[0u8; 20]);
    let _ = crate::trace::Trace::decode(&empty_trace_with_tail(&tail));
    // a meta length of 2^64-1: `i + n` overflowed before the bounds check
    let mut body = b"EDTRACE1".to_vec();
    body.extend_from_slice(&[1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
    assert!(crate::trace::Trace::decode(&sealed(body)).is_err());
}

#[test]
fn frame_pointer_fallback_at_the_top_of_memory() {
    // rbp = 2^64 - 8 with rsp just below it: `rbp + 8` overflowed in the frame-pointer step
    let top = u64::MAX - 7;
    let mem = Regions(vec![(top - 0x100, vec![0u8; 0x100])]);
    let mut un = Unwinder::new(&mem, vec![ModuleInfo { name: "m".into(), base: 0x1000, size: 0x1000 }]);
    un.walk(&Regs::new(0x1800, top - 0x100, top), 8);
}

#[test]
fn cfa_offsets_that_overflow_when_factored() {
    // DW_CFA_offset_extended_sf r16, 2^62 with data alignment -8: `off * data_align` overflowed
    let fde = [0x11, 16, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xc0, 0x00];
    walk_case(cfi_image(&[0x0c, 7, 8], &fde, true), 0x5555_0000_0000, 0x7fff_0000_0000, &[0x5555_0000_1000], 0x5555_0000_1010, 0);
    // DW_CFA_offset r16 with a ULEB of 2^63
    let fde = [0x90, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
    walk_case(cfi_image(&[0x0c, 7, 8], &fde, false), 0x5555_0000_0000, 0x7fff_0000_0000, &[], 0x5555_0000_1010, 0);
}

#[test]
fn pdb_type_names_do_not_explode() {
    // a function type whose 24 arguments are all a pointer to that same function: spelling it
    // visited 24^24 records (the depth limit alone does not bound fan-out)
    let mut db = TypeDb { first: FIRST, ..Default::default() };
    db.types = vec![
        Ty::Ptr { to: FIRST + 1, size: 8, reference: false, konst: false },
        Ty::Proc { ret: Some(FIRST), args: FIRST + 2, cc: 0, class: None },
        Ty::Args(vec![FIRST; 24]),
        Ty::Fields { members: (0..64).map(|i| Member::Data { name: format!("f{i}"), ty: FIRST, offset: i * 8 }).collect(), cont: Some(FIRST + 3) },
        Ty::Udt { kind: "struct", name: "S".into(), unique: None, size: 8, fields: Some(FIRST + 3), forward: false },
    ];
    db.index();
    let t = std::time::Instant::now();
    assert!(db.name(FIRST).contains('…'));
    // a field list continued by itself was listed 4096 times
    assert_eq!(db.layout(FIRST + 4).unwrap()["fields"].as_array().unwrap().len(), 64);
    assert!(t.elapsed() < std::time::Duration::from_secs(2), "{:?}", t.elapsed());
}
