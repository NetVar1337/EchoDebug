#!/bin/sh
# Rebuilds types.exe + types.pdb with LLVM only (no MSVC, no CRT, no Microsoft files).
set -e
cd "$(dirname "$0")"
clang --target=x86_64-pc-windows-msvc -O1 -g -gcodeview -fno-stack-protector -c types.c -o types.obj
lld-link /nologo /entry:mainCRTStartup /subsystem:console /nodefaultlib /debug \
  /pdb:types.pdb /pdbaltpath:types.pdb /out:types.exe types.obj
rm -f types.obj
