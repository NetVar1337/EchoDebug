//! Target architecture: detection from PE / ELF headers and the `arch` request parameter.
//!
//! x86-64 stays the default everywhere; `arm64` selects the AArch64 decoder (`a64.rs`) and the
//! AArch64 Unicorn emulator. Names on the wire: `"x86_64"`, `"x86"`, `"arm64"`.

/// PE `IMAGE_FILE_HEADER.Machine` values we know.
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
/// ARM64EC objects. Linked ARM64EC images carry `AMD64` in the header (x64-compatible), with the
/// arm64 code described by the load config's CHPE metadata.
pub const IMAGE_FILE_MACHINE_ARM64EC: u16 = 0xa641;
/// ARM64X objects. Linked ARM64X (hybrid) images carry `ARM64` in the header.
pub const IMAGE_FILE_MACHINE_ARM64X: u16 = 0xa64e;
/// ELF `e_machine` values we know.
pub const EM_386: u16 = 3;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Arch {
    #[default]
    X86_64,
    X86,
    Arm64,
}

impl Arch {
    pub fn as_str(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::X86 => "x86",
            Arch::Arm64 => "arm64",
        }
    }

    /// The `arch` request parameter; accepts the usual aliases.
    pub fn parse(s: &str) -> Option<Arch> {
        match s.trim().to_ascii_lowercase().as_str() {
            "x86_64" | "x86-64" | "x64" | "amd64" => Some(Arch::X86_64),
            "x86" | "i386" | "i686" => Some(Arch::X86),
            "arm64" | "aarch64" | "a64" | "arm64ec" | "arm64x" => Some(Arch::Arm64),
            _ => None,
        }
    }

    pub fn from_pe_machine(machine: u16) -> Option<Arch> {
        match machine {
            IMAGE_FILE_MACHINE_AMD64 => Some(Arch::X86_64),
            IMAGE_FILE_MACHINE_I386 => Some(Arch::X86),
            IMAGE_FILE_MACHINE_ARM64 | IMAGE_FILE_MACHINE_ARM64EC | IMAGE_FILE_MACHINE_ARM64X => Some(Arch::Arm64),
            _ => None,
        }
    }

    pub fn from_elf_machine(e_machine: u16) -> Option<Arch> {
        match e_machine {
            EM_X86_64 => Some(Arch::X86_64),
            EM_386 => Some(Arch::X86),
            EM_AARCH64 => Some(Arch::Arm64),
            _ => None,
        }
    }

    /// The architecture of the relay's own host (the local backend's targets normally match it).
    pub fn host() -> Arch {
        if cfg!(target_arch = "aarch64") {
            Arch::Arm64
        } else {
            Arch::X86_64
        }
    }
}

/// Detects the architecture from the start of a PE or ELF image (file or mapped, both work: only
/// the headers are read). `None` for anything else or a truncated header.
pub fn detect(head: &[u8]) -> Option<Arch> {
    let u16le = |o: usize| head.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32le = |o: usize| head.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if head.starts_with(b"\x7fELF") {
        // EI_DATA 2 = big endian
        let m = if head.get(5) == Some(&2) { head.get(18..20).map(|b| u16::from_be_bytes([b[0], b[1]])) } else { u16le(18) };
        return m.and_then(Arch::from_elf_machine);
    }
    if head.starts_with(b"MZ") {
        let nt = u32le(0x3c)? as usize;
        if u32le(nt)? != 0x4550 {
            return None;
        }
        return Arch::from_pe_machine(u16le(nt + 4)?);
    }
    None
}

/// The `arch` parameter of a request, if present and known.
pub fn from_req(req: &serde_json::Map<String, serde_json::Value>) -> Option<Arch> {
    req.get("arch").and_then(|v| v.as_str()).and_then(Arch::parse)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ELF_A64: &[u8] = include_bytes!("../../../src/lib/analysis/fixtures/fix-a64.elf");
    const PE_A64: &[u8] = include_bytes!("../../../src/lib/analysis/fixtures/fix-a64.exe");
    const PE_X64: &[u8] = include_bytes!("../../../src/lib/analysis/fixtures/fix.exe");

    #[test]
    fn detects_fixtures() {
        assert_eq!(detect(ELF_A64), Some(Arch::Arm64));
        assert_eq!(detect(PE_A64), Some(Arch::Arm64));
        assert_eq!(detect(PE_X64), Some(Arch::X86_64));
        assert_eq!(detect(b"\x7fELF"), None);
        assert_eq!(detect(b"garbage"), None);
    }

    #[test]
    fn detects_synthetic_headers() {
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        assert_eq!(detect(&elf), Some(Arch::X86_64));
        elf[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        assert_eq!(detect(&elf), Some(Arch::Arm64));
        let mut pe = vec![0u8; 0x100];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        for (m, a) in [(0xaa64u16, Arch::Arm64), (0xa641, Arch::Arm64), (0xa64e, Arch::Arm64), (0x8664, Arch::X86_64), (0x14c, Arch::X86)] {
            pe[0x84..0x86].copy_from_slice(&m.to_le_bytes());
            assert_eq!(detect(&pe), Some(a), "machine {m:#x}");
        }
        pe[0x84..0x86].copy_from_slice(&0x1c4u16.to_le_bytes()); // ARMNT: not supported
        assert_eq!(detect(&pe), None);
    }

    #[test]
    fn parses_names() {
        assert_eq!(Arch::parse("AArch64"), Some(Arch::Arm64));
        assert_eq!(Arch::parse("x64"), Some(Arch::X86_64));
        assert_eq!(Arch::parse("mips"), None);
        assert_eq!(Arch::Arm64.as_str(), "arm64");
    }
}
