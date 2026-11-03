typedef unsigned long DWORD;
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) void __stdcall Sleep(DWORD);
__declspec(noinline) int filter(int code) { return code == 5 ? 1 : 0; }
__declspec(noinline) int guarded(int x) {
  int r = 0;
  __try { r = (int)GetTickCount() + x; } __except (filter(r)) { r = -1; }
  __try { Sleep((DWORD)r); } __finally { r += 2; }
  __try { r ^= (int)GetTickCount(); } __except (1) { r = -3; }
  return r;
}
int mainCRTStartup(void) { return guarded((int)GetTickCount()); }
