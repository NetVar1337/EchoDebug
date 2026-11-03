// The process the end-to-end test attaches to: a counter, a switch, an XOR string routine, a tiny VM.
#include <stdio.h>
#include <unistd.h>
volatile int counter = 100;
volatile int mode = 0;
char buf[64];
volatile int sink;
__attribute__((noinline)) int classify(int x) {
  switch (x & 7) {
    case 0: return x * 3;
    case 1: return x + 11;
    case 2: return x - 5;
    case 3: return x ^ 0x5a;
    // no libc call here: glibc's AVX2 strlen is not emulated by Unicorn, and the batch-decrypt
    // step emulates through classify whenever counter & 7 == 4
    case 4: return buf[0] + 4;
    case 5: return x << 2;
    case 6: return x >> 1;
    default: return -1;
  }
}
__attribute__((noinline)) void dec(char *out, const unsigned char *in, int n) {
  for (int i = 0; i < n; i++) out[i] = in[i] ^ 0x5a;
  out[n] = 0;
}
/* a tiny stack VM, the shape protectors use: a dispatcher loop over a handler table */
unsigned char vm_code[] = {1, 5, 1, 3, 2, 1, 7, 4, 1, 0x55, 5, 6, 3, 0}; /* ((5+3)*7 ^ 0x55) dup sub halt */
__attribute__((noinline)) long vm_run(const unsigned char *pc) {
  long st[16];
  int sp = 0;
  for (;;) {
    switch (*pc++) {
      case 0: return st[sp - 1];
      case 1: st[sp++] = *pc++; break;
      case 2: sp--; st[sp - 1] += st[sp]; break;
      case 3: sp--; st[sp - 1] -= st[sp]; break;
      case 4: sp--; st[sp - 1] *= st[sp]; break;
      case 5: sp--; st[sp - 1] ^= st[sp]; break;
      case 6: st[sp] = st[sp - 1]; sp++; break;
      default: return -1;
    }
  }
}
static const unsigned char s0[] = {59, 42, 51, 116, 63, 34, 59, 55, 42, 54, 63, 116, 57, 53, 55}; /* api.example.com */
static const unsigned char s1[] = {62, 63, 57, 40, 35, 42, 46, 63, 62, 122, 53, 49}; /* decrypted ok */
int main(void) {
  const char *greet = "hello from the EchoDebug UI test";
  for (;;) {
    counter += classify(counter) > 50 ? 1 : 2;
    dec(buf, s0, 15); sink += buf[0];
    dec(buf, s1, 12); sink += buf[0];
    sink += (int)vm_run(vm_code);
    if (mode == 0x539) puts(greet);
    usleep(20000);
  }
}
