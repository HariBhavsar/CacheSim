#ifndef CAESER_S
#define CAESER_S

#include "Cache.h"

typedef enum {SC_V1, SC_V2} SCVersion;

class caeser : public Cache
{
  public:
    caeser(CacheConfig config, SCVersion version);
    caeser(CacheConfig config, SCVersion version, float noise);
    void clearCache();
    CLState isCached(size_t addr, size_t secret);
    AccessResult access(Access mem_access);
    void resetUsage(int slice);
    void flush(Access mem_access);

    CacheSet getScatterSet(uint64_t secret, size_t phys_addr);
    AccessResult extAccess(size_t addr, bool write, size_t secret, bool quiet, size_t *test_set, uint32_t test_set_size, bool *test_hit, bool no_noise = false);

    ~caeser();

    // could be void, only here because scv2_test needs this
    CacheSet getScatterSetV2(uint64_t secret, size_t phys_addr);
    CacheSet getScatterSetV1(uint64_t secret, size_t phys_addr);
  
  private:
    bool isValid (int setNum, bool hint);
    void randomAccess();
    SCVersion version_;
    bool noisy_;
    int noise_;
    uint64_t *currKeys; // currKeys[i] = key for ith skew under current epoch
    uint64_t *nextKeys; // nextKeys[i] = key for ith skew undex next epoch
    bool *epochBit; // epochBit[i] tells us whether ith cache line was mapped under current epoch or next epoch, for sets with number > setPtr
    int *skewBits; // tells us the skew number that was used to map this address
    int numSkews; // number of skews 
    int setPtr; // points to the last set that was remapped
    int accessCtr; // keeps track of number of accesses, remap a set once every 1000*numWays accesses
    unsigned sets;
    CacheSet scatter_set_;
    void remap();
};
#endif // SCATTER_CACHE_H