// Kernel and process dump file parser.
//
// Supports:
//   • Windows MINIDUMP (.dmp) – user-mode and kernel minidumps created by WinDbg,
//     ProcDump, Task Manager, or `MiniDumpWriteDump`.
//   • Windows kernel crash dump (complete / kernel / small) – the `DUMP`/`DU64` format
//     produced by a system bugcheck or by NotMyFault / LiveKD.
//   • EchoDebug raw dump – the `0xC0DE0001`-tagged segment archive written by procdump.rs.
//
// All parsing is offline and purely user-mode.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------
// Public verb handlers
// ---------------------------------------------------------------------------

/// `kdump_open` – parse a dump file, return its module list.
pub fn handle_open(req: &Map<String, Value>) -> Value {
    let path = match req.get("path").and_then(Value::as_str) {
        Some(p) => p.to_string(),
        None => return json!({"type":"error","code":4010,"message":"path required"}),
    };
    match open_dump(Path::new(&path)) {
        Ok(info) => {
            let mods: Vec<Value> = info.modules.iter().map(|m| json!({
                "name": m.name,
                "base": m.base,
                "size": m.size,
                "timestamp": m.timestamp,
            })).collect();
            json!({
                "type": "kdump_info",
                "success": true,
                "format": info.format,
                "arch": info.arch,
                "os_version": info.os_version,
                "bug_check": info.bug_check,
                "modules": mods,
                "path": path,
            })
        }
        Err(e) => json!({"type":"error","code":4011,"message":"kdump_open failed","detail":e}),
    }
}

/// `kdump_extract` – extract a module's PE image from the dump to a file on disk.
pub fn handle_extract(req: &Map<String, Value>) -> Value {
    let dump_path = match req.get("path").and_then(Value::as_str) {
        Some(p) => p,
        None => return json!({"type":"error","code":4010,"message":"path required"}),
    };
    let base = match req.get("base").and_then(Value::as_u64) {
        Some(b) => b,
        None => return json!({"type":"error","code":4010,"message":"base required"}),
    };
    let out = match req.get("out").and_then(Value::as_str) {
        Some(o) => o.to_string(),
        None => return json!({"type":"error","code":4010,"message":"out required"}),
    };
    match extract_module(Path::new(dump_path), base, Path::new(&out)) {
        Ok(bytes) => json!({"type":"kdump_extract_result","success":true,"path":out,"bytes":bytes}),
        Err(e) => json!({"type":"error","code":4012,"message":"kdump_extract failed","detail":e}),
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

struct ModuleEntry {
    name: String,
    base: u64,
    size: u32,
    timestamp: u32,
}

struct DumpInfo {
    format: &'static str,
    arch: &'static str,
    os_version: String,
    bug_check: Option<u32>,
    modules: Vec<ModuleEntry>,
    /// VA → file offset map for read_va helper
    segments: Vec<Segment>,
}

struct Segment {
    va: u64,
    size: u64,
    file_offset: u64,
}

impl DumpInfo {
    fn read_va(&self, f: &mut File, va: u64, buf: &mut [u8]) -> io::Result<()> {
        for seg in &self.segments {
            if va >= seg.va && va + buf.len() as u64 <= seg.va + seg.size {
                let off = seg.file_offset + (va - seg.va);
                f.seek(SeekFrom::Start(off))?;
                f.read_exact(buf)?;
                return Ok(());
            }
        }
        Err(io::Error::new(io::ErrorKind::NotFound, format!("VA 0x{va:x} not in dump")))
    }
}

// ---------------------------------------------------------------------------
// MINIDUMP format
// ---------------------------------------------------------------------------

const MDMP_SIG: u32 = 0x504d_444d; // "PMDM" LE
const STREAM_MODULE_LIST: u32 = 4;
const STREAM_MEMORY64_LIST: u32 = 9;
const STREAM_MEMORY_LIST: u32 = 5;
const STREAM_SYSTEM_INFO: u32 = 7;

fn parse_u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap_or([0; 4]))
}
fn parse_u64_le(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap_or([0; 8]))
}

fn read_minidump_string(f: &mut File, rva: u32) -> String {
    if rva == 0 { return String::new(); }
    let _ = f.seek(SeekFrom::Start(rva as u64));
    let mut len_buf = [0u8; 4];
    if f.read_exact(&mut len_buf).is_err() { return String::new(); }
    let byte_len = u32::from_le_bytes(len_buf) as usize;
    if byte_len == 0 || byte_len > 1024 { return String::new(); }
    let mut utf16 = vec![0u8; byte_len];
    if f.read_exact(&mut utf16).is_err() { return String::new(); }
    let words: Vec<u16> = utf16.chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&words).to_owned()
}

fn try_minidump(f: &mut File, header: &[u8]) -> Option<DumpInfo> {
    if parse_u32_le(header, 0) != MDMP_SIG { return None; }
    let num_streams = parse_u32_le(header, 8);
    let stream_dir_rva = parse_u32_le(header, 12);

    // Read stream directory
    let dir_size = num_streams as usize * 12;
    let mut dir = vec![0u8; dir_size];
    f.seek(SeekFrom::Start(stream_dir_rva as u64)).ok()?;
    f.read_exact(&mut dir).ok()?;

    // Collect stream locations
    let mut stream_locs: HashMap<u32, (u32, u32)> = HashMap::new(); // type -> (rva, size)
    for i in 0..num_streams as usize {
        let off = i * 12;
        let stype = parse_u32_le(&dir, off);
        let size  = parse_u32_le(&dir, off + 4);
        let rva   = parse_u32_le(&dir, off + 8);
        stream_locs.insert(stype, (rva, size));
    }

    // System info → arch + version
    let (arch, os_version) = if let Some(&(rva, _)) = stream_locs.get(&STREAM_SYSTEM_INFO) {
        let mut si = vec![0u8; 48];
        let _ = f.seek(SeekFrom::Start(rva as u64)).and_then(|_| f.read_exact(&mut si));
        let proc_arch = parse_u32_le(&si, 0) as u16; // PROCESSOR_ARCHITECTURE
        let arch_str: &'static str = match proc_arch {
            9  => "x86-64",
            12 => "arm64",
            0  => "x86",
            _  => "unknown",
        };
        let major = parse_u32_le(&si, 4);
        let minor = parse_u32_le(&si, 8);
        (arch_str, format!("{major}.{minor}"))
    } else {
        ("unknown", String::new())
    };

    // Module list
    let mut modules = Vec::new();
    if let Some(&(rva, _)) = stream_locs.get(&STREAM_MODULE_LIST) {
        let mut count_buf = [0u8; 4];
        let _ = f.seek(SeekFrom::Start(rva as u64)).and_then(|_| f.read_exact(&mut count_buf));
        let count = u32::from_le_bytes(count_buf) as usize;
        for i in 0..count {
            let mod_rva = rva + 4 + (i as u32) * 108;
            let mut mb = [0u8; 108];
            if f.seek(SeekFrom::Start(mod_rva as u64)).is_err() { break; }
            if f.read_exact(&mut mb).is_err() { break; }
            let base      = parse_u64_le(&mb,  0);
            let size      = parse_u32_le(&mb,  8);
            let timestamp = parse_u32_le(&mb, 12);
            let name_rva  = parse_u32_le(&mb, 16);
            let name = read_minidump_string(f, name_rva);
            let short = name.rsplit(&['\\', '/'][..]).next().unwrap_or(&name).to_string();
            modules.push(ModuleEntry { name: short, base, size, timestamp });
        }
    }

    // Memory64 segments
    let mut segments = Vec::new();
    if let Some(&(rva, _)) = stream_locs.get(&STREAM_MEMORY64_LIST) {
        let mut hdr = [0u8; 16];
        let _ = f.seek(SeekFrom::Start(rva as u64)).and_then(|_| f.read_exact(&mut hdr));
        let count    = parse_u64_le(&hdr, 0);
        let base_rva = parse_u64_le(&hdr, 8);
        let mut cur_rva = base_rva;
        for i in 0..count {
            let desc_off = rva as u64 + 16 + i * 16;
            let mut desc = [0u8; 16];
            if f.seek(SeekFrom::Start(desc_off)).is_err() { break; }
            if f.read_exact(&mut desc).is_err() { break; }
            let va   = parse_u64_le(&desc, 0);
            let size = parse_u64_le(&desc, 8);
            segments.push(Segment { va, size, file_offset: cur_rva });
            cur_rva = cur_rva.saturating_add(size);
        }
    } else if let Some(&(rva, _)) = stream_locs.get(&STREAM_MEMORY_LIST) {
        let mut count_buf = [0u8; 4];
        let _ = f.seek(SeekFrom::Start(rva as u64)).and_then(|_| f.read_exact(&mut count_buf));
        let count = u32::from_le_bytes(count_buf) as usize;
        for i in 0..count {
            let desc_off = rva as u64 + 4 + (i as u64) * 12;
            let mut desc = [0u8; 12];
            if f.seek(SeekFrom::Start(desc_off)).is_err() { break; }
            if f.read_exact(&mut desc).is_err() { break; }
            let va          = u64::from(parse_u32_le(&desc, 0));
            let data_size   = parse_u32_le(&desc, 4);
            let data_rva    = parse_u32_le(&desc, 8);
            segments.push(Segment { va, size: data_size as u64, file_offset: data_rva as u64 });
        }
    }

    Some(DumpInfo {
        format: "minidump",
        arch,
        os_version,
        bug_check: None,
        modules,
        segments,
    })
}

// ---------------------------------------------------------------------------
// Windows crash dump format
// ---------------------------------------------------------------------------

const DUMP_MAGIC: &[u8; 4] = b"DUMP";
const DUMP64_VALID: &[u8; 4] = b"DU64";
const DUMP32_VALID: &[u8; 4] = b"DUMP";

fn try_win_crash_dump(f: &mut File, header: &[u8]) -> Option<DumpInfo> {
    if header.len() < 4096 { return None; }
    if &header[0..4] != DUMP_MAGIC { return None; }
    let is64 = &header[4..8] == DUMP64_VALID;
    if !is64 && &header[4..8] != DUMP32_VALID { return None; }

    // The dump header is 0x2000 bytes (one page on x86/x64).
    // Fields at well-known offsets (64-bit layout):
    //   0x08: MajorVersion
    //   0x0C: MinorVersion
    //   0x18: DirectoryTableBase
    //   0x28: PfnDataBase
    //   0x30: PsLoadedModuleList (VA of the kernel's _LIST_ENTRY)
    //   0x38: PsActiveProcessHead
    //   0x3C: MachineImageType
    //   0x40: NumberProcessors
    //   0x44: BugCheckCode
    //   0x48–0x68: BugCheckParameters[4]
    //   0xFA0: DumpType (1=Full, 2=Kernel, 3=Small)
    //   (physical pages follow the header at file offset 0x2000)

    let machine_type = parse_u32_le(header, 0x3c);
    let arch: &'static str = match machine_type {
        0x8664 => "x86-64",
        0x014c => "x86",
        0xAA64 => "arm64",
        _ => "unknown",
    };
    let major = parse_u32_le(header, 0x08);
    let minor = parse_u32_le(header, 0x0C);
    let bug_check = parse_u32_le(header, 0x44);
    let dump_type = parse_u32_le(header, 0xFA0);

    let format: &'static str = match dump_type {
        1 => "win-crash-full",
        2 => "win-crash-kernel",
        3 => "win-crash-small",
        _ => "win-crash",
    };

    // The loaded-module list VA in the header lets us walk the kernel's PsLoadedModuleList,
    // but doing so requires translating VAs via the page directory in the dump, which is
    // complex to do correctly across all Windows versions.
    //
    // For small/kernel dumps we scan the physical pages for PE signatures (MZ + PE) and
    // record every driver base that looks like a loaded image.  For complete dumps this
    // recovers nearly all drivers reliably.

    let modules = scan_for_pe_images(f, 0x2000);
    let segments = build_physical_segments(f, 0x2000);

    Some(DumpInfo {
        format,
        arch,
        os_version: format!("{major}.{minor}"),
        bug_check: Some(bug_check),
        modules,
        segments,
    })
}

/// Scan the dump file starting at `data_offset`, looking for PE headers.
fn scan_for_pe_images(f: &mut File, data_offset: u64) -> Vec<ModuleEntry> {
    let Ok(meta) = f.metadata() else { return vec![] };
    let file_size = meta.len();
    if file_size <= data_offset { return vec![]; }

    let scan_size = (file_size - data_offset).min(256 * 1024 * 1024); // scan up to 256 MiB
    let mut buf = vec![0u8; scan_size as usize];
    let _ = f.seek(SeekFrom::Start(data_offset));
    let read = f.read(&mut buf).unwrap_or(0);
    buf.truncate(read);

    let mut modules = Vec::new();
    let mut i = 0;
    while i + 0x40 < buf.len() {
        if buf[i] == b'M' && buf[i + 1] == b'Z' {
            // Check for PE signature at e_lfanew
            let e_lfanew = parse_u32_le(&buf, i + 0x3c) as usize;
            if e_lfanew > 0 && i + e_lfanew + 4 < buf.len()
                && buf[i + e_lfanew] == b'P' && buf[i + e_lfanew + 1] == b'E'
                && buf[i + e_lfanew + 2] == 0 && buf[i + e_lfanew + 3] == 0
            {
                // Try to read export directory to get module name.
                let name = pe_export_name(&buf[i..]);
                // Virtual base: in physical dumps pages are at predictable offsets;
                // we record file offset as a placeholder base.
                let file_va = data_offset + i as u64;
                let image_size = pe_image_size(&buf[i..]).unwrap_or(0x1000);
                modules.push(ModuleEntry {
                    name,
                    base: file_va, // "base" = file offset for extraction
                    size: image_size,
                    timestamp: 0,
                });
                i += image_size.max(0x1000) as usize;
                continue;
            }
        }
        i += 0x1000; // PE images are page-aligned
    }
    modules
}

fn pe_export_name(pe: &[u8]) -> String {
    if pe.len() < 0x40 { return String::new(); }
    let e_lfanew = parse_u32_le(pe, 0x3c) as usize;
    if e_lfanew + 0x78 + 8 >= pe.len() { return String::new(); }
    let is64 = {
        let machine = u16::from_le_bytes([pe[e_lfanew + 4], pe[e_lfanew + 5]]);
        machine == 0x8664 || machine == 0xaa64
    };
    let opt_off = e_lfanew + 24;
    let export_dir_rva = if is64 {
        if opt_off + 0x70 + 8 >= pe.len() { return String::new(); }
        parse_u32_le(pe, opt_off + 0x70)
    } else {
        if opt_off + 0x60 + 8 >= pe.len() { return String::new(); }
        parse_u32_le(pe, opt_off + 0x60)
    };
    if export_dir_rva == 0 || export_dir_rva as usize + 40 >= pe.len() { return String::new(); }
    let name_rva = parse_u32_le(pe, export_dir_rva as usize + 12) as usize;
    if name_rva == 0 || name_rva >= pe.len() { return String::new(); }
    let end = pe[name_rva..].iter().position(|&b| b == 0).unwrap_or(64).min(64);
    let s = std::str::from_utf8(&pe[name_rva..name_rva + end]).unwrap_or("");
    s.rsplit(&['\\', '/'][..]).next().unwrap_or(s).to_string()
}

fn pe_image_size(pe: &[u8]) -> Option<u32> {
    if pe.len() < 0x40 { return None; }
    let e_lfanew = parse_u32_le(pe, 0x3c) as usize;
    if e_lfanew + 24 + 60 >= pe.len() { return None; }
    let sz_off = e_lfanew + 24 + 56; // SizeOfImage is at opt+56 in both PE32 and PE32+
    if sz_off + 4 >= pe.len() { return None; }
    Some(parse_u32_le(pe, sz_off).max(0x1000))
}

fn build_physical_segments(f: &mut File, data_offset: u64) -> Vec<Segment> {
    let Ok(meta) = f.metadata() else { return vec![] };
    let total = meta.len();
    if total <= data_offset { return vec![]; }
    // Physical dumps: pages are at file_offset = data_offset + (pfn * 0x1000).
    // We expose the raw file range as a single segment with va=0.
    vec![Segment { va: 0, size: total - data_offset, file_offset: data_offset }]
}

// ---------------------------------------------------------------------------
// EchoDebug raw dump (from procdump.rs Linux path)
// ---------------------------------------------------------------------------

const ECHO_MAGIC_SEG: u32 = 0xC0_DE_00_01;
const ECHO_MAGIC_END: u32 = 0xC0_DE_FF_FF;

fn try_echo_raw_dump(f: &mut File, header: &[u8]) -> Option<DumpInfo> {
    if header.len() < 8 { return None; }
    if parse_u32_le(header, 0) != ECHO_MAGIC_SEG { return None; }

    let mut segments = Vec::new();
    let _ = f.seek(SeekFrom::Start(0));
    loop {
        let mut hdr = [0u8; 16];
        if f.read_exact(&mut hdr).is_err() { break; }
        let magic = parse_u32_le(&hdr, 0);
        if magic == ECHO_MAGIC_END { break; }
        if magic != ECHO_MAGIC_SEG { break; }
        let va   = parse_u64_le(&hdr, 8);
        let size = parse_u64_le(&hdr, 8); // (reread at correct offset)
        // Actually: header layout: magic(4) + pad(4) + start(8) + len(8) = 24 bytes
        // Reread with correct offsets (16 bytes already read, need 8 more for len)
        let mut len_buf = [0u8; 8];
        if f.read_exact(&mut len_buf).is_err() { break; }
        let _ = size; // shadowed
        let seg_len = u64::from_le_bytes(len_buf);
        let file_offset = f.stream_position().unwrap_or(0);
        segments.push(Segment { va, size: seg_len, file_offset });
        let _ = f.seek(SeekFrom::Current(seg_len as i64));
    }

    let modules = Vec::new(); // raw dumps don't carry a module list
    Some(DumpInfo {
        format: "echo-raw",
        arch: "x86-64",
        os_version: String::new(),
        bug_check: None,
        modules,
        segments,
    })
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

fn open_dump(path: &Path) -> Result<DumpInfo, String> {
    let mut f = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    let mut header = vec![0u8; 4096.min(f.metadata().map(|m| m.len()).unwrap_or(4096) as usize)];
    f.read(&mut header).map_err(|e| e.to_string())?;

    if let Some(d) = try_minidump(&mut f, &header) { return Ok(d); }
    if let Some(d) = try_win_crash_dump(&mut f, &header) { return Ok(d); }
    if let Some(d) = try_echo_raw_dump(&mut f, &header) { return Ok(d); }
    Err("unrecognised dump format (expected MINIDUMP, Windows crash dump, or EchoDebug raw dump)".into())
}

// ---------------------------------------------------------------------------
// Module extraction
// ---------------------------------------------------------------------------

fn extract_module(dump_path: &Path, base: u64, out: &Path) -> Result<u64, String> {
    let mut f = File::open(dump_path).map_err(|e| e.to_string())?;
    let mut header = vec![0u8; 4096.min(f.metadata().map(|m| m.len()).unwrap_or(4096) as usize)];
    f.read(&mut header).map_err(|e| e.to_string())?;

    let info = if let Some(d) = try_minidump(&mut f, &header) { d }
    else if let Some(d) = try_win_crash_dump(&mut f, &header) { d }
    else if let Some(d) = try_echo_raw_dump(&mut f, &header) { d }
    else { return Err("unrecognised dump format".into()); };

    // Read the PE header at `base` to find image size.
    let mut mz = [0u8; 0x40];
    info.read_va(&mut f, base, &mut mz).map_err(|e| e.to_string())?;
    if mz[0] != b'M' || mz[1] != b'Z' {
        return Err(format!("no MZ signature at 0x{base:x}"));
    }
    let e_lfanew = parse_u32_le(&mz, 0x3c) as u64;
    let mut pe_hdr = [0u8; 4];
    info.read_va(&mut f, base + e_lfanew, &mut pe_hdr).map_err(|e| e.to_string())?;
    if &pe_hdr != b"PE\0\0" {
        return Err(format!("no PE signature at 0x{base:x}+0x{e_lfanew:x}"));
    }
    // machine
    let mut mach_buf = [0u8; 2];
    info.read_va(&mut f, base + e_lfanew + 4, &mut mach_buf).map_err(|e| e.to_string())?;
    let _machine = u16::from_le_bytes(mach_buf);
    let opt_off = base + e_lfanew + 24;
    let sz_off = opt_off + 56; // SizeOfImage is at opt+56 in both PE32 and PE32+
    let mut sz_buf = [0u8; 4];
    info.read_va(&mut f, sz_off, &mut sz_buf).map_err(|e| e.to_string())?;
    let image_size = u32::from_le_bytes(sz_buf) as u64;
    if image_size == 0 || image_size > 256 * 1024 * 1024 {
        return Err(format!("unexpected SizeOfImage: 0x{image_size:x}"));
    }

    // Copy image bytes page by page (unreadable pages filled with zeros).
    let mut out_buf = vec![0u8; image_size as usize];
    let mut off = 0u64;
    while off < image_size {
        let page = 0x1000.min(image_size - off);
        let dst = &mut out_buf[off as usize..(off + page) as usize];
        let _ = info.read_va(&mut f, base + off, dst); // ignore errors (page may not be present)
        off += page;
    }

    std::fs::write(out, &out_buf).map_err(|e| e.to_string())?;
    Ok(image_size)
}
