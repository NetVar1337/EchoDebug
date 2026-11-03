# PE / ELF test fixtures

Built from `fix.c` with LLVM (no MSVC, no CRT), so they can be rebuilt anywhere:

```sh
llvm-dlltool -m i386:x86-64 -d k32.def -l k32.lib
clang --target=x86_64-pc-windows-msvc -O1 -c fix.c -o fix.obj -fno-stack-protector
lld-link /nologo /entry:mainCRTStartup /subsystem:console /nodefaultlib /debug \
  /pdb:fix.pdb /pdbaltpath:fix.pdb /dynamicbase /out:fix.exe fix.obj k32.lib
```

`fix.exe`: two kernel32 imports, a TLS callback, base relocations, a CodeView (RSDS) entry for
`fix.pdb` (GUID `E5F4837E-BE62-2C4A-4C4C-44205044422E`, age 1). Ground truth from `pefile`:
imphash `855fe313bcb171bd90823be6a896a99c`, 7 relocations, TLS callback at `0x140001000`.

`fix-signed.exe`: `fix.exe` padded to 8 bytes plus a certificate table holding a CMS SignedData
over an `SpcIndirectDataContent` with the file's Authenticode SHA-256
(`6b995689d9e5ef37dd42531159e1a41b7bd53b3a12d9d12ea5c858fa24510991`), signed with a throwaway
self-signed certificate (`CN=EchoDebug Test Signer, O=EchoDebug Tests, C=NO`, serial
`48D24D75EFEA085185CC135C51837E7EF561E3FF`) via `openssl cms -sign -econtent_type 1.3.6.1.4.1.311.2.1.4`.
The private key was discarded.

`fix-seh.exe`: `fix-seh.c` with `__try/__except/__finally` (three scopes in `guarded`), its language
handler `__C_specific_handler` imported from `ntdll.dll` through an lld import thunk, a frame
register (rbp) and a tail-call epilog. Used by the SEH listing (TypeScript) and the x64 unwinder
(Rust) tests; `llvm-objdump --unwind-info fix-seh.exe` shows the ground truth.

```sh
llvm-dlltool -m i386:x86-64 -d k32.def -l k32.lib
llvm-dlltool -m i386:x86-64 -d ntdll.def -l ntdll.lib
clang --target=x86_64-pc-windows-msvc -O1 -c fix-seh.c -o fix-seh.obj -fno-stack-protector
lld-link /nologo /entry:mainCRTStartup /subsystem:console /nodefaultlib /dynamicbase \
  /out:fix-seh.exe fix-seh.obj k32.lib ntdll.lib
```

## AArch64 fixtures

`fix-a64.elf` and `fix-a64.exe` are built from `fix-a64.c` (and, for the PE, `fix-a64-seh.s`, a
function that names an exception handler so its unwind data cannot be packed):

```sh
clang --target=aarch64-linux-gnu -O1 -ffreestanding -fno-stack-protector -nostdlib -fuse-ld=lld \
  -Wl,-e,entry -Wl,--build-id=none -static -o fix-a64.elf fix-a64.c
clang --target=aarch64-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector -funwind-tables -c fix-a64.c -o fix-a64.obj
clang --target=aarch64-pc-windows-msvc -c fix-a64-seh.s -o fix-a64-seh.obj
lld-link /nologo /machine:arm64 /entry:with_handler /subsystem:console /nodefaultlib /dynamicbase \
  /out:fix-a64.exe fix-a64.obj fix-a64-seh.obj
```

Ground truth from `llvm-objdump -d` / `llvm-readobj --unwind`: the ELF has `add_scaled` at
`0x210168` (12 bytes), `walk` at `0x210174` (0x24), `entry` at `0x210198` (0x40), `adr x0, g_msg`
(`0x200158`) and `adrp x20` + `ldr`/`str [x20, #0x1d8]` for `g_counter` (`0x2201d8`). The PE has
`.pdata` entries for `entry` (RVA `0x1030`, packed, 60 bytes) and `with_handler` (`0x106c`, `.xdata`,
20 bytes), `adrp x0` + `add x0, x0, #0` at `0x104c` for `g_msg` (`.rdata`, RVA `0x2000`) and
`adrp x20` + `ldr w0, [x20]` at `0x1038` for `g_counter` (`.data`, RVA `0x3000`).
