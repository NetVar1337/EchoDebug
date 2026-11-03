/* PDB type/line fixture: no CRT, no imports. Rebuild with build.sh. */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

enum Color { COLOR_RED = 1, COLOR_GREEN = 2, COLOR_BLUE = 4 };

struct Vec3 { float x, y, z; };

struct Flags {
  u32 visible : 1;
  u32 kind : 3;
  u32 team : 4;
  u32 rest : 24;
};

union Value { int i; float f; u8 bytes[4]; };

typedef int (*Callback)(int value, void *user);

struct Entity {
  struct Entity *next;
  struct Vec3 pos;
  struct Vec3 path[4];
  struct Flags flags;
  union Value value;
  enum Color color;
  u8 pad;
  u64 id;
  char name[16];
  Callback on_hit;
  const char *label;
};

int _fltused = 0; /* no CRT: the compiler references it once floats appear */
struct Entity g_entities[2];
volatile int g_counter;

__declspec(noinline) int entity_score(struct Entity *e, int bonus) {
  int s = e->flags.kind * 10 + bonus;
  if (e->color == COLOR_BLUE)
    s += (int)e->pos.x;
  return s;
}

static int hit(int value, void *user) { (void)user; return value + 1; }

__declspec(noinline) void entity_init(struct Entity *e, u64 id) {
  e->id = id;
  e->on_hit = hit;
  e->flags.kind = 3;
  e->color = COLOR_BLUE;
}

int mainCRTStartup(void) {
  entity_init(&g_entities[0], 7);
  g_entities[0].next = &g_entities[1];
  g_counter = entity_score(&g_entities[0], 2);
  return g_counter + g_entities[0].on_hit(1, 0);
}
