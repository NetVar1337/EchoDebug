// Function prototypes for the decompiler: how many arguments a callee takes,
// their names and types, and whether it returns a value. Providers are
// consulted in registration order; the built-in table knows a few common C
// runtime and Win32 functions by name. A symbol (PDB) loader can register
// its own provider with registerPrototypeProvider.

export type ProtoType = "void" | "int" | "uint" | "int64" | "uint64" | "char" | "bool" | "float" | "double" | "ptr" | "str" | "wstr" | string;
export type Prototype = {
  name?: string;
  returns?: ProtoType;
  args?: { name?: string; type?: ProtoType }[];
  variadic?: boolean;
  /** the callee never returns (exit, abort, ...) */
  noreturn?: boolean;
};

/** Looks up a prototype by the callee's address (0x hex) and, when known, its name. */
export type PrototypeProvider = (address: string | null, name: string | null) => Prototype | null | undefined;

const providers: { id: string; p: PrototypeProvider }[] = [];

/** Adds (or replaces, by id) a provider. Returns a function that removes it. */
export function registerPrototypeProvider(id: string, p: PrototypeProvider): () => void {
  const i = providers.findIndex((x) => x.id === id);
  if (i >= 0) providers[i] = { id, p };
  else providers.push({ id, p });
  return () => {
    const j = providers.findIndex((x) => x.id === id && x.p === p);
    if (j >= 0) providers.splice(j, 1);
  };
}

const a = (...names: string[]) => names.map((n) => {
  const [type, name] = n.split(" ");
  return { type, name };
});

/** A small table of well-known functions (matched without import decoration). */
export const kKnownPrototypes: Record<string, Prototype> = {
  memcpy: { returns: "ptr", args: a("ptr dst", "ptr src", "uint64 n") },
  memmove: { returns: "ptr", args: a("ptr dst", "ptr src", "uint64 n") },
  memset: { returns: "ptr", args: a("ptr dst", "int c", "uint64 n") },
  memcmp: { returns: "int", args: a("ptr a", "ptr b", "uint64 n") },
  strlen: { returns: "uint64", args: a("str s") },
  wcslen: { returns: "uint64", args: a("wstr s") },
  strcmp: { returns: "int", args: a("str a", "str b") },
  strncmp: { returns: "int", args: a("str a", "str b", "uint64 n") },
  strcpy: { returns: "str", args: a("str dst", "str src") },
  strcat: { returns: "str", args: a("str dst", "str src") },
  strchr: { returns: "str", args: a("str s", "int c") },
  strstr: { returns: "str", args: a("str s", "str sub") },
  malloc: { returns: "ptr", args: a("uint64 size") },
  calloc: { returns: "ptr", args: a("uint64 n", "uint64 size") },
  realloc: { returns: "ptr", args: a("ptr p", "uint64 size") },
  free: { returns: "void", args: a("ptr p") },
  puts: { returns: "int", args: a("str s") },
  printf: { returns: "int", args: a("str fmt"), variadic: true },
  sprintf: { returns: "int", args: a("str buf", "str fmt"), variadic: true },
  snprintf: { returns: "int", args: a("str buf", "uint64 n", "str fmt"), variadic: true },
  fprintf: { returns: "int", args: a("ptr f", "str fmt"), variadic: true },
  exit: { returns: "void", args: a("int code"), noreturn: true },
  _exit: { returns: "void", args: a("int code"), noreturn: true },
  abort: { returns: "void", args: [], noreturn: true },
  __stack_chk_fail: { returns: "void", args: [], noreturn: true },
  __security_check_cookie: { returns: "void", args: a("uint64 cookie") },
  ExitProcess: { returns: "void", args: a("uint code"), noreturn: true },
  GetLastError: { returns: "uint", args: [] },
  SetLastError: { returns: "void", args: a("uint code") },
  GetModuleHandleA: { returns: "ptr", args: a("str name") },
  GetModuleHandleW: { returns: "ptr", args: a("wstr name") },
  GetProcAddress: { returns: "ptr", args: a("ptr module", "str name") },
  LoadLibraryA: { returns: "ptr", args: a("str name") },
  LoadLibraryW: { returns: "ptr", args: a("wstr name") },
  CloseHandle: { returns: "int", args: a("ptr handle") },
  CreateFileA: { returns: "ptr", args: a("str name", "uint access", "uint share", "ptr security", "uint disposition", "uint flags", "ptr tmpl") },
  CreateFileW: { returns: "ptr", args: a("wstr name", "uint access", "uint share", "ptr security", "uint disposition", "uint flags", "ptr tmpl") },
  ReadFile: { returns: "int", args: a("ptr file", "ptr buf", "uint size", "ptr read", "ptr overlapped") },
  WriteFile: { returns: "int", args: a("ptr file", "ptr buf", "uint size", "ptr written", "ptr overlapped") },
  VirtualAlloc: { returns: "ptr", args: a("ptr address", "uint64 size", "uint type", "uint protect") },
  VirtualFree: { returns: "int", args: a("ptr address", "uint64 size", "uint type") },
  VirtualProtect: { returns: "int", args: a("ptr address", "uint64 size", "uint protect", "ptr old") },
  Sleep: { returns: "void", args: a("uint ms") },
  GetTickCount: { returns: "uint", args: [] },
  GetTickCount64: { returns: "uint64", args: [] },
  QueryPerformanceCounter: { returns: "int", args: a("ptr count") },
  GetCurrentProcess: { returns: "ptr", args: [] },
  GetCurrentThreadId: { returns: "uint", args: [] },
  IsDebuggerPresent: { returns: "int", args: [] },
  MessageBoxA: { returns: "int", args: a("ptr hwnd", "str text", "str caption", "uint type") },
  MessageBoxW: { returns: "int", args: a("ptr hwnd", "wstr text", "wstr caption", "uint type") },
  HeapAlloc: { returns: "ptr", args: a("ptr heap", "uint flags", "uint64 size") },
  HeapFree: { returns: "int", args: a("ptr heap", "uint flags", "ptr p") },
  GetProcessHeap: { returns: "ptr", args: [] },
  EnterCriticalSection: { returns: "void", args: a("ptr cs") },
  LeaveCriticalSection: { returns: "void", args: a("ptr cs") },
};

/** Strips import decoration: `__imp_CreateFileW`, `kernel32!CreateFileW`, `_memcpy`, `memcpy@plt`. */
export function bareName(name: string): string {
  return name.replace(/^.*!/, "").replace(/^__imp_/, "").replace(/@plt$|@@.*$|@\d+$/, "").replace(/^_(?=[a-z])/, "");
}

/** The first provider's answer, else the built-in table by name. */
export function lookupPrototype(address: string | null, name: string | null): Prototype | null {
  for (const { p } of providers) {
    const r = p(address, name);
    if (r) return r;
  }
  if (name) {
    const k = kKnownPrototypes[name] ?? kKnownPrototypes[bareName(name)];
    if (k) return k;
  }
  return null;
}

/** C spelling of a prototype type. */
export function cType(t: ProtoType | undefined): string {
  switch (t) {
    case undefined:
      return "__int64";
    case "int":
      return "int";
    case "uint":
      return "unsigned int";
    case "int64":
      return "__int64";
    case "uint64":
      return "unsigned __int64";
    case "char":
      return "char";
    case "bool":
      return "bool";
    case "float":
      return "float";
    case "double":
      return "double";
    case "ptr":
      return "void *";
    case "str":
      return "char *";
    case "wstr":
      return "wchar_t *";
    case "void":
      return "void";
    default:
      return t;
  }
}
