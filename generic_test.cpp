#include "SACache.h"
#include "GenericCache.h"
#include "CacheMemory.h"
#include "time.h"
#include "caeser.h"
#include "RP_PLRU.h"

int main() 
{
  CacheConfig config = {4, 3, 4, 6};
  RP_PLRU policy(config);
  Cache *sa_cache = new SACache(config, policy);
  unsigned P = 1;
  RMapper R(config, P, 0);
  Cache *g_cache = new GenericCache(config, policy, R, P);
  Cache *c_cache = new caeser(config,SC_V1);

  size_t t = clock();
  for (int i = 0; i < 1024*1024*16; i++)
  {
    uint64_t addr = 64*(rand() % 2048);
    AccessResult r_a = sa_cache->access({addr, 0, false, false});
    AccessResult r_g = g_cache->access({addr, 0, false, false});
    AccessResult r_c = c_cache->access({addr,0,false,false});

    if ((r_a.hit != r_g.hit) && (r_a.hit != r_c.hit))
      printf("wrong miss\n");
    // if (r_a.evicted && (r_a.evicted_addr != r_c.evicted_addr))
      // printf("different evicted addr\n");
  }
  t = clock() - t;

  printf("Clock ticks passed: %ld\n", t);

  delete sa_cache;
  delete g_cache;
  delete c_cache;

  return 0;
}