// Full process dump: writes a MINIDUMP (Windows) or ELF core / raw memory archive (Linux)
// to a file the caller supplies.  The dump can later be opened by kdump.rs, WinDbg, or GDB.
//
// All operations are user-mode: no drivers, no ring-0 tricks.

use std::path::Path;
use serde_json::{json, Value};

// ---- public API -----------------------------------------------------------------

/// `dump_process_full` verb handler.
pub fn handle(req: &serde_json::Map<String, Value>) -> Value {
    let pid = match req.get("pid").and_then(Value::as_u64) {
        Some(v) => v as u32,
        None => return json!({"type":"error","code":4001,"message":"pid required"}),
    };
    let path = match req.get("path").and_then(Value::as_str) {
        Some(v) => v.to_string(),
        None => return json!({"type":"error","code":4001,"message":"path required"}),
    };
    match dump(pid, Path::new(&path)) {
        Ok(bytes) => json!({"type":"dump_result","success":true,"path":path,"bytes":bytes}),
        Err(e) => json!({"type":"error","code":4002,"message":"dump failed","detail":e}),
    }
}

// ---- Windows ----------------------------------------------------------------

#[cfg(windows)]
fn dump(pid: u32, out: &Path) -> Result<u64, String> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
        },
        System::{
            Diagnostics::Debug::{
                MiniDumpWithDataSegs, MiniDumpWithFullMemory, MiniDumpWithHandleData,
                MiniDumpWithThreadInfo, MiniDumpWithUnloadedModules,
                MiniDumpWriteDump, MINIDUMP_TYPE,
            },
            Threading::{OpenProcess, PROCESS_ALL_ACCESS},
        },
    };
    use std::os::windows::ffi::OsStrExt;

    // Encode the output path to wide string.
    let wide: Vec<u16> = out.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    // Open the target process.
    let hproc: HANDLE = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
    if hproc == 0 as HANDLE {
        return Err(format!("OpenProcess failed, pid={pid}"));
    }

    // Create the output file.
    let hfile: HANDLE = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
            std::ptr::null(),
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            0 as HANDLE,
        )
    };
    if hfile == INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(hproc) };
        return Err(format!("CreateFileW failed: {}", out.display()));
    }

    let flags: MINIDUMP_TYPE = MiniDumpWithDataSegs
        | MiniDumpWithFullMemory
        | MiniDumpWithHandleData
        | MiniDumpWithUnloadedModules
        | MiniDumpWithThreadInfo;

    let ok = unsafe {
        MiniDumpWriteDump(
            hproc,
            pid,
            hfile,
            flags,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    unsafe {
        CloseHandle(hfile);
        CloseHandle(hproc);
    }
    if ok == 0 {
        return Err("MiniDumpWriteDump failed".into());
    }
    let bytes = std::fs::metadata(out).map(|m| m.len()).unwrap_or(0);
    Ok(bytes)
}

// ---- Linux ------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn dump(pid: u32, out: &Path) -> Result<u64, String> {
    // On Linux we write a "core dump archive": a sequence of name-tagged memory
    // segments, each preceded by an 8-byte header.  The format is:
    //   For each /proc/<pid>/maps region that is readable:
    //     Header [16 bytes]: magic u32 (0xC0_DE_00_01) | pad u32 | start u64
    //     Data [region bytes]
    //   Trailer [8 bytes]: magic u32 (0xC0_DE_FF_FF) | pad u32
    // kdump.rs understands this format; GDB expects proper ELF core which is
    // more complex — we keep this simple for now.

    use nix::sys::ptrace;
    use nix::unistd::Pid;

    let nix_pid = Pid::from_raw(pid as i32);

    // Attach so the process is stopped during the dump.
    ptrace::attach(nix_pid).map_err(|e| format!("ptrace attach: {e}"))?;
    // Wait for the stop signal.
    let _ = nix::sys::wait::waitpid(nix_pid, None);

    let result = dump_inner(pid, out);

    // Detach regardless of outcome.
    let _ = ptrace::detach(nix_pid, None);
    result
}

#[cfg(target_os = "linux")]
fn dump_inner(pid: u32, out: &Path) -> Result<u64, String> {
    use std::io::{Read, Seek, SeekFrom, Write};

    const MAGIC_SEG: u32 = 0xC0_DE_00_01;
    const MAGIC_END: u32 = 0xC0_DE_FF_FF;

    let maps_text = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| format!("/proc/{pid}/maps: {e}"))?;
    let mut mem = std::fs::OpenOptions::new()
        .read(true)
        .open(format!("/proc/{pid}/mem"))
        .map_err(|e| format!("/proc/{pid}/mem: {e}"))?;

    let mut fout = std::fs::File::create(out).map_err(|e| format!("create {}: {e}", out.display()))?;

    for line in maps_text.lines() {
        // Parse: "7f1234560000-7f1234570000 r--p ..."
        let mut it = line.split_whitespace();
        let range = it.next().unwrap_or("");
        let perms = it.next().unwrap_or("");
        if perms.starts_with("---") { continue; } // not readable
        let mut parts = range.splitn(2, '-');
        let start = u64::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let end   = u64::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
        if end <= start || (end - start) > 0x4000_0000 { continue; } // skip >1 GiB regions

        let len = (end - start) as usize;
        let mut buf = vec![0u8; len];
        if mem.seek(SeekFrom::Start(start)).is_err() { continue; }
        if mem.read_exact(&mut buf).is_err() { continue; }

        // Header
        fout.write_all(&MAGIC_SEG.to_le_bytes()).ok();
        fout.write_all(&0u32.to_le_bytes()).ok();
        fout.write_all(&start.to_le_bytes()).ok();
        fout.write_all(&(len as u64).to_le_bytes()).ok();
        fout.write_all(&buf).ok();
    }
    fout.write_all(&MAGIC_END.to_le_bytes()).ok();
    fout.write_all(&0u32.to_le_bytes()).ok();
    fout.flush().map_err(|e| e.to_string())?;
    drop(fout);
    let bytes = std::fs::metadata(out).map(|m| m.len()).unwrap_or(0);
    Ok(bytes)
}

// ---- Stub for other OS ------------------------------------------------------

#[cfg(not(any(windows, target_os = "linux")))]
fn dump(_pid: u32, _out: &Path) -> Result<u64, String> {
    Err("process dump not supported on this OS".into())
}
