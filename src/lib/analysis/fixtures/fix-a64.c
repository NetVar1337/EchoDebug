// Tiny AArch64 fixture (no libc): a global, a call, a loop and a conditional branch.
// Built for Linux (ELF) and Windows-on-ARM (PE), see README.md.
volatile long g_counter = 7;
const char g_msg[] = "echodebug-arm64";

__attribute__((noinline)) long add_scaled(long a, long b) { return a + b * 3; }

__attribute__((noinline)) long walk(const char *s) {
  long n = 0;
  while (*s) {
    n += *s++;
    if (n > 1000) break;
  }
  return n;
}

__attribute__((noinline)) long entry(void) {
  long r = add_scaled(g_counter, 5);
  r += walk(g_msg);
  g_counter = r;
  return r;
}
