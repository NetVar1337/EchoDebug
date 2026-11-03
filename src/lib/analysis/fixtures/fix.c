typedef unsigned long DWORD; typedef void* PVOID;
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) void __stdcall Sleep(DWORD);
static void __stdcall on_tls(PVOID h, DWORD reason, PVOID r) { (void)h; (void)reason; (void)r; }
/* TLS directory by hand (no CRT) */
#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) void (__stdcall *tls_cb[])(PVOID, DWORD, PVOID) = { on_tls, 0 };
int _tls_index = 0;
char _tls_start[8], _tls_end[8];
typedef struct { unsigned long long s, e, idx, cb; DWORD zf, ch; } TLSDIR;
const TLSDIR _tls_used = { (unsigned long long)&_tls_start, (unsigned long long)&_tls_end, (unsigned long long)&_tls_index, (unsigned long long)tls_cb, 0, 0 };
static const char *names[] = { "echodebug", "fixture" };
__declspec(noinline) int helper(int x) { return x * 7 + (int)names[x & 1][0]; }
int mainCRTStartup(void) { DWORD t = GetTickCount(); Sleep(1); return helper((int)t); }
