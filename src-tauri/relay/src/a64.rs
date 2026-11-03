//! AArch64 (arm64) disassembly for Linux arm64 and Windows-on-ARM modules, pure Rust via
//! `yaxpeax-arm`.
//!
//! Lines have the same shape as the x86-64 decoder's (address, length, bytes, text). PC-relative
//! operands (branches, `adr`, `adrp`, literal loads) are printed as absolute addresses so the
//! CFG builder and the views read targets the same way they do for x86. `adrp` + `add` /
//! `adrp` + `ldr`/`str` pairs are tracked within a run and the materialised address is appended as
//! `  ; 0x...` on the second instruction, like the x86 decoder annotates RIP-relative operands.

use yaxpeax_arch::{Decoder as _, U8Reader};
use yaxpeax_arm::armv8::a64::{ARMv8, Opcode, Operand};

/// One decoded instruction.
#[derive(Clone, Debug, PartialEq)]
pub struct Line {
    pub address: u64,
    pub word: u32,
    pub text: String,
}

/// Decodes the instruction word at `pc`. `None` for an undecodable word (data in code, or an
/// extension the decoder does not know).
pub fn decode_word(word: u32, pc: u64) -> Option<String> {
    let bytes = word.to_le_bytes();
    let mut reader = U8Reader::new(&bytes[..]);
    let insn = <ARMv8 as yaxpeax_arch::Arch>::Decoder::default().decode(&mut reader).ok()?;
    let text = insn.to_string();
    let Some(off) = insn.operands.iter().find_map(|o| match o {
        Operand::PCOffset(off) => Some(*off),
        _ => None,
    }) else {
        return Some(text);
    };
    let base = if insn.opcode == Opcode::ADRP { pc & !0xfff } else { pc };
    let target = base.wrapping_add(off as u64);
    // the decoder prints the offset as `$+0x10` / `$-0x10`: replace it with the target
    Some(match text.find("$+").or_else(|| text.find("$-")) {
        Some(i) => {
            let end = text[i..].find([',', ' ']).map_or(text.len(), |e| i + e);
            format!("{}0x{target:x}{}", &text[..i], &text[end..])
        }
        None => text,
    })
}

/// Decodes one instruction from `code` (at least 4 bytes) at `pc`: (length, text). Undecodable
/// words come back as `.inst 0x...` so a listing continues past data in code.
pub fn disasm_one(code: &[u8], pc: u64) -> Option<(usize, String)> {
    let w = code.get(..4)?;
    let word = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
    Some((4, decode_word(word, pc).unwrap_or_else(|| format!(".inst 0x{word:08x}"))))
}

/// `adrp` → (Rd, page target).
pub fn adrp(word: u32, pc: u64) -> Option<(usize, u64)> {
    if word & 0x9f00_0000 != 0x9000_0000 {
        return None;
    }
    let imm = (((word >> 5) & 0x7ffff) << 2) | ((word >> 29) & 3);
    let off = (((imm as i64) << 43) >> 43) << 12;
    Some(((word & 0x1f) as usize, (pc & !0xfff).wrapping_add(off as u64)))
}

/// `add Xd, Xn, #imm{, lsl #12}` (64-bit, no flags) → (Rd, Rn, imm).
pub fn add_imm(word: u32) -> Option<(usize, usize, u64)> {
    // sf=1 op=0 S=0 100010; bit 22 is the shift
    if word & 0xff80_0000 != 0x9100_0000 {
        return None;
    }
    let imm = ((word >> 10) & 0xfff) as u64;
    let shift = if word & (1 << 22) != 0 { 12 } else { 0 };
    Some(((word & 0x1f) as usize, ((word >> 5) & 0x1f) as usize, imm << shift))
}

/// Load/store register (unsigned immediate), GPR and SIMD&FP: → (Rt, Rn, byte offset, is_load).
pub fn ldst_uimm(word: u32) -> Option<(usize, usize, u64, bool)> {
    if word & 0x3b00_0000 != 0x3900_0000 {
        return None;
    }
    let size = word >> 30;
    let simd = word & (1 << 26) != 0;
    let opc = (word >> 22) & 3;
    // SIMD&FP size 00 with opc 1x is the 128-bit q form
    let scale = if simd && size == 0 && opc & 2 != 0 { 4 } else { size };
    let imm = (((word >> 10) & 0xfff) as u64) << scale;
    Some(((word & 0x1f) as usize, ((word >> 5) & 0x1f) as usize, imm, opc != 0))
}

/// Disassembles `code` placed at `addr`, 4 bytes per instruction, tracking `adrp` pages so
/// `adrp`+`add` and `adrp`+`ldr`/`str` get their resolved address annotated. A trailing partial
/// word is not decoded.
pub fn disasm(code: &[u8], addr: u64) -> Vec<Line> {
    let mut out = Vec::with_capacity(code.len() / 4);
    let mut pages: [Option<u64>; 32] = [None; 32];
    for (i, w) in code.as_chunks::<4>().0.iter().enumerate() {
        let pc = addr.wrapping_add(i as u64 * 4);
        let word = u32::from_le_bytes(*w);
        let mut text = decode_word(word, pc).unwrap_or_else(|| format!(".inst 0x{word:08x}"));
        let rd = (word & 0x1f) as usize;
        if let Some((d, page)) = adrp(word, pc) {
            pages[d] = Some(page);
        } else if let Some((d, n, imm)) = add_imm(word) {
            if let Some(p) = pages[n] {
                text.push_str(&format!("  ; 0x{:x}", p.wrapping_add(imm)));
            }
            pages[d] = None;
        } else if let Some((t, n, imm, load)) = ldst_uimm(word) {
            if let Some(p) = pages[n] {
                text.push_str(&format!("  ; 0x{:x}", p.wrapping_add(imm)));
            }
            if load {
                pages[t] = None;
            }
        } else if is_flow(word) {
            pages = [None; 32];
        } else if !is_store_or_cmp(word) {
            // anything else may write Rd: forget it (a heuristic; keeps false pairs out)
            pages[rd] = None;
        }
        out.push(Line { address: pc, word, text });
    }
    out
}

/// Branches, calls and returns (they end the tracking window).
fn is_flow(word: u32) -> bool {
    word & 0x7c00_0000 == 0x1400_0000 // b / bl
        || word & 0xff00_0010 == 0x5400_0000 // b.cond
        || word & 0x7e00_0000 == 0x3400_0000 // cbz / cbnz
        || word & 0x7e00_0000 == 0x3600_0000 // tbz / tbnz
        || word & 0xfe00_0000 == 0xd600_0000 // br / blr / ret (+ pointer-auth forms)
}

/// Instructions that do not write the register in bits 0-4: stores and flag-only compares.
fn is_store_or_cmp(word: u32) -> bool {
    let ldst = word & 0x0a00_0000 == 0x0800_0000;
    let load = word & (1 << 22) != 0;
    // cmp/cmn/tst write xzr (Rd = 31)
    (ldst && !load) || word & 0x1f == 0x1f
}

/// True for the instructions a function-sized listing stops at (ret, brk, udf, undecodable).
pub fn ends_function(text: &str) -> bool {
    let mn = text.split_whitespace().next().unwrap_or("");
    matches!(mn, "ret" | "retaa" | "retab" | "brk" | "udf" | ".inst" | "eret")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dis(word: u32, pc: u64) -> String {
        decode_word(word, pc).unwrap()
    }

    #[test]
    fn decodes_known_encodings() {
        // from the fix-a64.elf fixture (llvm-objdump ground truth)
        assert_eq!(dis(0xd65f03c0, 0x210170), "ret");
        assert_eq!(dis(0xa9be7bfd, 0x210198), "stp x29, x30, [sp, #-0x20]!");
        assert_eq!(dis(0x528000a1, 0x2101a4), "mov w1, #0x5");
        assert_eq!(dis(0xf940ee80, 0x2101a8), "ldr x0, [x20, #0x1d8]");
        assert_eq!(dis(0x97ffffee, 0x2101b0), "bl 0x210168");
        assert_eq!(dis(0x90000094, 0x2101a0), "adrp x20, 0x220000");
        assert_eq!(dis(0x10f7fce0, 0x2101bc), "adr x0, 0x200158");
        assert_eq!(dis(0xb40000a9, 0x210180), "cbz x9, 0x210194");
        assert_eq!(dis(0x54ffff63, 0x210190), "b.lo 0x21017c");
        assert_eq!(dis(0xd503201f, 0), "nop");
        // tbz w1, #3, +8 / br x16 / blr x8 / b -4
        assert_eq!(dis(0x36180041, 0x1000), "tbz w1, #0x3, 0x1008");
        assert_eq!(dis(0xd61f0200, 0x1000), "br x16");
        assert_eq!(dis(0xd63f0100, 0x1000), "blr x8");
        assert_eq!(dis(0x17ffffff, 0x1000), "b 0xffc");
        // ldr x1, literal +0x10
        assert_eq!(dis(0x58000081, 0x2000), "ldr x1, 0x2010");
    }

    #[test]
    fn undecodable_words_continue_the_listing() {
        let (len, text) = disasm_one(&[0, 0, 0, 0], 0x1000).unwrap();
        assert_eq!(len, 4);
        assert!(text.starts_with("udf") || text.starts_with(".inst"), "{text}");
        assert!(disasm_one(&[1, 2, 3], 0).is_none());
    }

    #[test]
    fn adrp_pairs_are_annotated() {
        // from fix-a64.exe: adrp x0, 0x140002000 ; add x0, x0, #0x0 ; bl ...
        let code: Vec<u8> = [0xb000_0000u32, 0x9100_0000, 0x97ff_ffee].iter().flat_map(|w| w.to_le_bytes()).collect();
        let l = disasm(&code, 0x1_4000_104c);
        assert_eq!(l[0].text, "adrp x0, 0x140002000");
        assert_eq!(l[1].text, "add x0, x0, #0x0  ; 0x140002000");
        // adrp x20, page ; mov w1, #5 ; ldr x0, [x20, #0x1d8] (ELF fixture: g_counter)
        let code: Vec<u8> = [0x9000_0094u32, 0x5280_00a1, 0xf940_ee80].iter().flat_map(|w| w.to_le_bytes()).collect();
        let l = disasm(&code, 0x2101a0);
        assert_eq!(l[2].text, "ldr x0, [x20, #0x1d8]  ; 0x2201d8");
        // a clobbered register is forgotten: adrp x0 ; mov x0, x1 ; add x0, x0, #8
        let code: Vec<u8> = [0x9000_0000u32, 0xaa01_03e0, 0x9100_2000].iter().flat_map(|w| w.to_le_bytes()).collect();
        assert!(!disasm(&code, 0x1000)[2].text.contains(';'));
    }

    #[test]
    fn helpers_decode_fields() {
        assert_eq!(adrp(0x9000_0094, 0x2101a0), Some((20, 0x220000)));
        assert_eq!(add_imm(0x9100_0508), Some((8, 8, 1)));
        assert_eq!(add_imm(0x9140_0400), Some((0, 0, 0x1000)));
        assert_eq!(ldst_uimm(0xf940_ee80), Some((0, 20, 0x1d8, true)));
        assert_eq!(ldst_uimm(0xf900_ee80), Some((0, 20, 0x1d8, false)));
        assert_eq!(ldst_uimm(0x3940_0109), Some((9, 8, 0, true)));
        assert!(ends_function("ret"));
        assert!(!ends_function("bl 0x1000"));
    }
}
