#include <stdint.h>
#include <stdio.h>

typedef void* (*factory2_t)(int64_t);
typedef void* (*factory3_t)(uint64_t);
typedef void* (*read64_t)(uint64_t);
typedef void* (*get_flag_t)(uint64_t);
// players are forced to store returned pointers into globals we can detect:
factory2_t g_fp1 = 0;
factory3_t g_fp2 = 0;
read64_t g_fp3 = 0;
uint64_t g_rv = 0;
uint64_t g_tbs = 0;
void **g_tb = 0;

// helper typedefs
typedef uint64_t (*u64_4_t)(uint64_t,uint64_t,uint64_t,uint64_t);

void *swap_me(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
  return NULL;
}

int check(char *flag) {
  // stage1: loop of 42 iterations, calling some_func iteration
  for(int i = 0; i < 42; ++i) {
    if(i == 41) {
      // The pass is expected to inject a call to secrets_stage1_factory at i==41
      g_fp1 = swap_me(1,2,3,4);
    }
  }

  if(!g_fp1) return 1; // not necessary check

  // stage2: loop with 0x1337 iterations, with impossible-if inside
  for(int64_t i = 0; i < 0x1337; ++i) {
    if(i == -1) { // impossible inside this loop
      g_fp2 = (g_fp1)(-1);
    }
  }

  if(!g_fp2) return 2; // not necessary check

  // stage3: truncation loop
  for (uint64_t i = 0xffffffff; i < 0x1ffffffff; ++i) {
    if(i == 0xfeedfacfU) { // impossible for our values
      if(i < -1)  {
        g_fp3 = (g_fp2)(i);
      }
    }
  }

  if(!g_fp3) return 3; // not necessary check

  // stage4: use g_fp3 (assume it was a pointer to secrets_read64_at)
  g_rv = (uint64_t)(g_fp3)(0); // supposed to return g_random_value
  g_tbs = (uint64_t)(g_fp3)(8); // supposed to return g_tbs size
  g_tb = (g_fp3)(16); // pointer to jump table 

  if (g_rv == 0 || g_tbs != 3 ||  g_tb == 0) return 4; // needed because optimization fuck the IR
  
  // Stage5: compute index and call through table (driver may bypass bounds)
  for(uint64_t i = 0; i < g_tbs + 1; i++) {
    if(i == 3) {
      ((get_flag_t)g_tb[i])(g_rv);
      // also works:
      // get_flag_t f = (get_flag_t) g_tb[i];
      // f(g_rv); // call get_flag(rv) — should print flag if rv matches
    }
  }

  return 11; 
}
