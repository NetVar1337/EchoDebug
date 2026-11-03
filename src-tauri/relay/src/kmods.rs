//! `kernel_modules`: the loaded kernel drivers of this machine (name, path, base, size), for the
//! Dump view's driver dumps. User-mode only, no driver:
//!
//! * Windows: `NtQuerySystemInformation(SystemModuleInformation)`. Since Windows 11 24H2 the
//!   kernel only reports image bases to callers holding SeDebugPrivilege, so the relay enables it
//!   first (it has it when EchoDebug runs elevated); without it every base reads 0 and the reply
//!   says so.
//! * Linux: `/proc/modules` (addresses read as 0 unless root with `kptr_restrict` allowing it).
//!
//! The dump itself reads the image through the attached backend like any other memory, so it
//! works only where the backend can read kernel addresses: Echo's documented API does not promise
//! that (its reads go through the attached process's address space), the local /proc backend
//! cannot.

use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KMod {
    pub name: String,
    pub path: String,
    pub base: u64,
    pub size: u64,
}

impl KMod {
    fn to_json(&self) -> Value {
        let mut v = json!({ "name": self.name, "path": self.path, "base": format!("0x{:x}", self.base), "size": self.size });
        if cfg!(windows) {
            let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
            let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
            if let Some(f) = dos_path(&self.path, &root, &drive) {
                v["file"] = json!(f);
            }
        }
        v
    }
}

/// The file behind a kernel image path as the kernel reports it: `\SystemRoot\...` (the Windows
/// directory), `\??\C:\...` (a DOS path), `\Windows\...` or `\System32\...` (on the system
/// drive), or already `C:\...`. `None` for anything else (device paths, Linux).
pub fn dos_path(nt: &str, system_root: &str, system_drive: &str) -> Option<String> {
    let lower = nt.to_ascii_lowercase();
    let root = system_root.trim_end_matches('\\');
    if let Some(rest) = lower.strip_prefix("\\systemroot\\") {
        return Some(format!("{root}\\{}", &nt[nt.len() - rest.len()..]));
    }
    if let Some(rest) = nt.strip_prefix("\\??\\").or_else(|| nt.strip_prefix("\\DosDevices\\")) {
        return Some(rest.to_owned());
    }
    if lower.starts_with("\\windows\\") {
        return Some(format!("{}{nt}", system_drive.trim_end_matches('\\')));
    }
    if let Some(rest) = lower.strip_prefix("\\system32\\") {
        return Some(format!("{root}\\System32\\{}", &nt[nt.len() - rest.len()..]));
    }
    let b = nt.as_bytes();
    (b.len() > 2 && b[1] == b':' && b[0].is_ascii_alphabetic()).then(|| nt.to_owned())
}

/// RTL_PROCESS_MODULES as NtQuerySystemInformation(SystemModuleInformation) fills it on x64:
/// ULONG NumberOfModules (padded to 8), then 296-byte RTL_PROCESS_MODULE_INFORMATION entries
/// (Section, MappedBase, ImageBase, ImageSize, Flags, four USHORTs ending in OffsetToFileName,
/// FullPathName[256]).
pub fn parse_rtl_modules(buf: &[u8]) -> Vec<KMod> {
    const ENTRY: usize = 296;
    if buf.len() < 8 {
        return Vec::new();
    }
    let n = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let mut out = Vec::new();
    for i in 0..n.min((buf.len() - 8) / ENTRY) {
        let e = &buf[8 + i * ENTRY..8 + (i + 1) * ENTRY];
        let base = u64::from_le_bytes(e[16..24].try_into().unwrap_or_default());
        let size = u32::from_le_bytes(e[24..28].try_into().unwrap_or_default()) as u64;
        let name_off = u16::from_le_bytes([e[38], e[39]]) as usize;
        let full = &e[40..296];
        let end = full.iter().position(|c| *c == 0).unwrap_or(full.len());
        let path = String::from_utf8_lossy(&full[..end]).into_owned();
        let name = path.get(name_off.min(path.len())..).unwrap_or(&path).to_owned();
        out.push(KMod { name: if name.is_empty() { path.rsplit('\\').next().unwrap_or(&path).to_owned() } else { name }, path, base, size });
    }
    out
}

/// `/proc/modules`: `name size refcount deps state address`.
pub fn parse_proc_modules(text: &str) -> Vec<KMod> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let size = f.get(1)?.parse().ok()?;
            let base = f.get(5).and_then(|a| u64::from_str_radix(a.trim_start_matches("0x"), 16).ok()).unwrap_or(0);
            Some(KMod { name: format!("{}.ko", f[0]), path: String::new(), base, size })
        })
        .collect()
}

pub fn handle() -> Value {
    match list() {
        Ok((mods, source, note)) => {
            let hidden = !mods.is_empty() && mods.iter().all(|m| m.base == 0);
            let mut v = json!({ "type": "kernel_modules_result", "success": true, "source": source, "count": mods.len(), "modules": mods.iter().map(KMod::to_json).collect::<Vec<_>>() });
            if let Some(n) = note {
                v["note"] = json!(n);
            } else if hidden {
                v["note"] = json!("the kernel hides the image bases from this process: run EchoDebug elevated (Windows) or as root (Linux) to see them");
            }
            v
        }
        Err(e) => json!({ "type": "error", "code": 3003, "message": "kernel_modules failed", "detail": e }),
    }
}

#[cfg(target_os = "linux")]
fn list() -> Result<(Vec<KMod>, &'static str, Option<String>), String> {
    let t = std::fs::read_to_string("/proc/modules").map_err(|e| format!("/proc/modules: {e}"))?;
    Ok((parse_proc_modules(&t), "/proc/modules", Some("the local /proc backend cannot read kernel memory; listing only".into())))
}

#[cfg(windows)]
fn list() -> Result<(Vec<KMod>, &'static str, Option<String>), String> {
    use std::ffi::c_void;
    #[link(name = "ntdll")]
    extern "system" {
        fn NtQuerySystemInformation(class: u32, info: *mut c_void, len: u32, ret: *mut u32) -> i32;
    }
    enable_debug_privilege();
    let mut len: u32 = 1 << 16;
    for _ in 0..6 {
        let mut buf = vec![0u8; len as usize];
        let mut need: u32 = 0;
        // SAFETY: the buffer is `len` bytes; the call writes at most that and reports the size it needs.
        let st = unsafe { NtQuerySystemInformation(11, buf.as_mut_ptr().cast(), len, &mut need) };
        if st == 0 {
            return Ok((parse_rtl_modules(&buf), "NtQuerySystemInformation", None));
        }
        // STATUS_INFO_LENGTH_MISMATCH
        if st as u32 != 0xC000_0004 {
            return Err(format!("NtQuerySystemInformation(SystemModuleInformation) failed: 0x{:08x}", st as u32));
        }
        len = need.max(len * 2) + 0x1000;
    }
    Err("NtQuerySystemInformation kept asking for a larger buffer".into())
}

/// SeDebugPrivilege, so 24H2+ reports driver bases (needs an elevated EchoDebug; harmless otherwise).
#[cfg(windows)]
fn enable_debug_privilege() {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LUID};
    use windows_sys::Win32::Security::{AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let name: Vec<u16> = "SeDebugPrivilege".encode_utf16().chain(std::iter::once(0)).collect();
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: plain Win32 calls on this process's own token; every out-pointer is a local.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
            return;
        }
        let mut luid = LUID { LowPart: 0, HighPart: 0 };
        if LookupPrivilegeValueW(std::ptr::null(), name.as_ptr(), &mut luid) != 0 {
            let tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }] };
            AdjustTokenPrivileges(token, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut());
        }
        CloseHandle(token);
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn list() -> Result<(Vec<KMod>, &'static str, Option<String>), String> {
    Err("kernel module listing is implemented for Windows and Linux".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtl_process_modules() {
        let mut buf = vec![0u8; 8 + 2 * 296];
        buf[0] = 2;
        for (i, (path, base, size)) in [("\\SystemRoot\\system32\\ntoskrnl.exe", 0xfffff800_12000000u64, 0x1046000u32), ("\\SystemRoot\\System32\\drivers\\ACPI.sys", 0xfffff800_1c000000, 0xd8000)].into_iter().enumerate() {
            let e = 8 + i * 296;
            buf[e + 16..e + 24].copy_from_slice(&base.to_le_bytes());
            buf[e + 24..e + 28].copy_from_slice(&size.to_le_bytes());
            let off = path.rfind('\\').unwrap() as u16 + 1;
            buf[e + 38..e + 40].copy_from_slice(&off.to_le_bytes());
            buf[e + 40..e + 40 + path.len()].copy_from_slice(path.as_bytes());
        }
        let m = parse_rtl_modules(&buf);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0], KMod { name: "ntoskrnl.exe".into(), path: "\\SystemRoot\\system32\\ntoskrnl.exe".into(), base: 0xfffff800_12000000, size: 0x1046000 });
        assert_eq!(m[1].name, "ACPI.sys");
        // a count larger than the buffer is clamped
        buf[0] = 9;
        assert_eq!(parse_rtl_modules(&buf).len(), 2);
        assert!(parse_rtl_modules(&[1, 0]).is_empty());
    }

    #[test]
    fn kernel_paths_to_files() {
        let f = |p: &str| dos_path(p, "C:\\Windows", "C:");
        assert_eq!(f("\\SystemRoot\\System32\\drivers\\ACPI.sys").as_deref(), Some("C:\\Windows\\System32\\drivers\\ACPI.sys"));
        assert_eq!(f("\\systemroot\\system32\\ntoskrnl.exe").as_deref(), Some("C:\\Windows\\system32\\ntoskrnl.exe"));
        assert_eq!(f("\\??\\D:\\Tools\\my.sys").as_deref(), Some("D:\\Tools\\my.sys"));
        assert_eq!(f("\\Windows\\System32\\drivers\\x.sys").as_deref(), Some("C:\\Windows\\System32\\drivers\\x.sys"));
        assert_eq!(f("\\System32\\drivers\\y.sys").as_deref(), Some("C:\\Windows\\System32\\drivers\\y.sys"));
        assert_eq!(f("C:\\x.sys").as_deref(), Some("C:\\x.sys"));
        assert_eq!(f("\\Device\\HarddiskVolume3\\x.sys"), None);
        assert_eq!(dos_path("\\SystemRoot\\a.sys", "C:\\WINDOWS\\", "C:").as_deref(), Some("C:\\WINDOWS\\a.sys"));
    }

    #[test]
    fn proc_modules() {
        let m = parse_proc_modules("nf_tables 315392 0 - Live 0xffffffffc0a00000\nvirtio_net 69632 0 - Live 0x0000000000000000 (E)\nbroken\n");
        assert_eq!(m, vec![
            KMod { name: "nf_tables.ko".into(), path: String::new(), base: 0xffffffffc0a00000, size: 315392 },
            KMod { name: "virtio_net.ko".into(), path: String::new(), base: 0, size: 69632 },
        ]);
    }
}
