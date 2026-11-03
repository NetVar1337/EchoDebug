# PE test fixtures

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
