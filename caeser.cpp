#include <cstdlib>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "caeser.h"
#include "sha-256.h"

#define DEBUG_SET 0

/*

NOTE : THIS IS SLIGHTLY DIFFERENT THAN THE STANDARD IMPLEMENTATION OF CAESER-S
       THE SKEWS IN THIS IMPLEMENTATION ARE MIRAGE-LIKE

Assuming n skews
-> 2*n keys : k1-kn are currKeys, kn+1-k2n are next keys
-> function f(address,key)->set
-> On memory access to address a, calculate all 2*n possible sets from f(a,1),f(a,2),...,f(a,2*n)
-> Valid sets are those f(a,i) s.t. i >= n+1 (i.e. new keys) OR f(a,i) > setPtr 
-> setPtr points at the largest set that hasn't been remapped
-> Check all ways in all these valid sets
-> If hit, good 
-> If miss, choose f(a,i) such that number of unused/invalid ways in f(a,i) >= those in f(a,j) for all valid sets f(a,j)
-> In that set, insert a

Each cache line will need log_(numSkews) + 1 extra bits:
log_(numSkews) to keep track of which skew landed our function here
1 extra bit to keep track of whether it was a currKey or a nextKey (call it epoch bit)
Epoch bit = 1 if nextKey and 0 otherwise

Every say 1000*numWays accesses, we remap a set
On a remap:
-> Increment setPtr :) (modulo numSets ofc)
-> For all ways in setPtr
-> If epoch bit == 1 : change epoch bit to 0 
-> Else : Compute f^{-1}(a,i) using skew bits to obtain i then compute f(a,j) for all j >= n+1, and place a in set having most invalid ways, call it s
-> While placing a there are two cases
-> Case 1 : s <= setPtr => Here when u place a, you will place it with epoch bit 0
-> Case 2 : s > setPtr => Place it with epoch bit 1
-> If setPtr == numSets - 1:
-> currKeys = nextKeys (for all i, dont be lazy :))
-> Obtain a new set of nextKeys

*/

uint64_t encrypt (uint64_t address, uint64_t key) {
    return address ^ key; // hopefully we will have better stuff
}
uint64_t decrypt (uint64_t encryptedAddr, uint64_t key) {
    return encryptedAddr ^ key; // hopefully we will have better stuff
}

caeser::caeser(CacheConfig config, SCVersion version)
{
  version_ = version;
  line_size_bits_ = config.line_size_bits;
  line_size_ = 1 << line_size_bits_;
  line_bits_ = config.line_bits;
  lines_ = 1 << config.line_bits;
  size_ = config.slices * lines_ * line_size_;
  way_bits_ = config.way_bits;
  ways_ = 1 << config.way_bits;
  sets = lines_/ways_;
  slices_ = config.slices;
  name_ = "caeser-s";
  policy_name_ = "random";

  if (sets % 2 != 0) {
    printf("Wtf\n");
    exit(0);
  }
  
  numSkews = 2; // lol change pls
  currKeys = (uint64_t*)malloc(2*sizeof(uint64_t));
  nextKeys = (uint64_t*)malloc(2*sizeof(uint64_t));
  epochBit = (bool*)malloc(lines_*sizeof(bool));
  skewBits = (int*)malloc(lines_*sizeof(int)); // honestly we could make it a bool
  memory_ = (CacheLine *)malloc(slices_*lines_*sizeof(CacheLine));
  clearCache();

  srand(rand());
  
/*
  printf("\n-------------------------------------\n");
  printf("caeser PARAMETERS:\n");
  printf("size: %2.2fMB, lines: %u, ways: %u, slices: %u, linesize: %lu\n", (float)size_ / 1024 / 1024, lines_, ways_, slices_, line_size_);
  printf("-------------------------------------\n\n");
*/

}

caeser::caeser(CacheConfig config, SCVersion version, float noise) : caeser(config, version) 
{
  noisy_ = true;
  noise_ = noise*RAND_MAX;
}

void caeser::clearCache()
{
  memset(memory_, 0, slices_*lines_*sizeof(CacheLine));
  memset(occupied_lines_, 0, sizeof(occupied_lines_));
  memset(cache_misses_, 0, sizeof(cache_misses_));
  memset(cache_hits_, 0, sizeof(cache_hits_));
  memset(epochBit,0,sizeof(epochBit));
  memset(skewBits,0,sizeof(skewBits));
  setPtr = -1; // lol this is the only time this should be like this
  accessCtr = 0;
  for (int i=0; i<numSkews; i++) {
    nextKeys[i] = rand();
  }
}

void getNewKeys (uint64_t* currKeys, uint64_t* nextKeys, int numKeys) {
    for (int i=0; i<numKeys; i++) {
        currKeys[i] = nextKeys[i];
        nextKeys[i] = rand();
    }
}
bool caeser::isValid(int setNum, bool hint) { // hint is true if set generated using next keys, false otherwise
  if (setNum > setPtr) {return true;}
  else {
    return hint;
  }
}
CLState caeser::isCached(size_t addr, size_t secret)
{
  CLState cl_state = MISS;
  size_t slice = getSlice(addr);
  getScatterSet(secret, addr);

  size_t aligned_addr = (addr >> line_size_bits_) << line_size_bits_;
  for (uint32_t i = 0; i < 2*numSkews; ++i)
  {
    int setNum = scatter_set_.index[i];
    if (!isValid(setNum,(i >= numSkews))) {continue;}
    for (int way = 0; way < ways_; way ++) {
      if (aligned_addr == memory_[slice*lines_ + setNum*ways_ + way].addr && memory_[slice*lines_ + setNum*ways_ + way].valid == 1)
      {
        cl_state = HIT;
        break;
      }
    }
  }
  return cl_state;
}

void caeser::randomAccess()
{
  static uint64_t i = 0;
  extAccess((i++)*64, false, 324646576, true, 0, 0, 0, true);
}

AccessResult caeser::access(Access mem_access)
{
  return extAccess(mem_access.addr, mem_access.write, mem_access.secret, true, 0, 0, 0, false);
}

void caeser::resetUsage(int slice)
{
  for (uint32_t i = 0; i < slices_*lines_; i++)
    memory_[i].used = 0;
  for (unsigned i = 0; i < slices_; i++)
    occupied_lines_[i] = 0;
}

void caeser::flush(Access mem_access)
{
  size_t slice = getSlice(mem_access.addr);

  size_t aligned_addr = (mem_access.addr >> line_size_bits_) << line_size_bits_;
  getScatterSet(mem_access.secret, aligned_addr);

  for (int i=0; i<2*numSkews; i++) {

    if (!isValid(scatter_set_.index[i],(i >= numSkews))) {continue;}
    else {
      for (int j=0; j<ways_; j++) {
        if (memory_[scatter_set_.index[i]*ways_ + j].addr = aligned_addr && memory_[scatter_set_.index[i]*ways_ + j].valid == 1) {
          memory_[scatter_set_.index[i]*ways_ + j].valid = 0;
          return;
        }
      }
    }

  }

}

CacheSet caeser::getScatterSetV1(uint64_t secret, size_t phys_addr)
{
  uint8_t hash[32];

  int offset = 0;

  while (1)
  {

    uint64_t hash_input[2];
    hash_input[0] = (phys_addr & ~(line_size_ - 1));
    hash_input[1] = secret;

    calc_sha_256(hash, hash_input, 16);
    
    unsigned way;
    for (way = 0; way < ways_; way++)
    {
      
      int byte_offset = way*(line_bits_ - way_bits_) / 8;
      int bit_offset = way*(line_bits_ - way_bits_) % 8;
      scatter_set_.index[way] = (*((uint32_t *)(hash + byte_offset)) >> bit_offset) & ((lines_ - 1) >> way_bits_);

      /* can't have duplicates when the cache is segmented into [way] blocks
      //check for duplicates
      int i;
      for (i = 0; i < way; i++)
        if (set.index[way] == set.index[i])
          break;
      if (i != way)
        break;*/
    }
    if (way == ways_)
      break;
    offset++;
  }

  return scatter_set_;
}

CacheSet caeser::getScatterSetV2(uint64_t secret, size_t phys_addr)
{
  uint8_t hash[32];

  const uint64_t index_mask = (1 << (line_bits_ - way_bits_ + line_size_bits_)) - 1;
  uint64_t index = (phys_addr & index_mask) >> line_size_bits_;

  uint64_t hash_input[3];
  hash_input[0] = secret;
  hash_input[1] = phys_addr >> (line_bits_ - way_bits_ + line_size_bits_);

  calc_sha_256(hash, &hash_input, 16);

  unsigned way;
  for (way = 0; way < ways_; way++)
  {
    
    int byte_offset = way*(line_bits_ - way_bits_) / 8;
    int bit_offset = way*(line_bits_ - way_bits_) % 8;
    uint32_t way_hash = (*((uint32_t *)(hash + byte_offset)) >> bit_offset) & ((lines_ - 1) >> way_bits_);

    scatter_set_.index[way] = (index ^ way_hash) & ((1 << (line_bits_ - way_bits_)) - 1);

  }
  
  /*unsigned way;
  for (way = 0; way < ways_; way++)
  {
    hash_input[2] = way;
    calc_sha_256(hash, &hash_input, 24);
    //printf("%p\n", ((uint32_t *)hash)[0]);
    set.index[way] = (index ^ ((uint32_t *)hash)[0]) & ((1 << (line_bits_ - way_bits_)) - 1);
  }*/

  return scatter_set_;
}

CacheSet caeser::getScatterSet(uint64_t secret, size_t phys_addr)
{
  phys_addr = (phys_addr >> line_bits_) << line_bits_;
  for (int i=0; i<numSkews; i++) {
    scatter_set_.index[i] = (encrypt(phys_addr,currKeys[i]))%sets;
  }
  for (int i=0; i<numSkews; i++) {
    scatter_set_.index[i] = (encrypt(phys_addr,nextKeys[i]))%sets;
  }
  return scatter_set_;
}

void caeser::remap() {
  setPtr++;
  setPtr = setPtr%sets;
  if (setPtr == 0) {
    getNewKeys(currKeys,nextKeys,numSkews);
    // getScatterSet(0,addr);
  }
  int slice = 0;
  /*
-> For all ways in setPtr
-> If epoch bit == 1 : change epoch bit to 0 
-> Else : Compute f^{-1}(a,i) using skew bits to obtain i then compute f(a,j) for all j >= n+1, and place a in set having most invalid ways, call it s
-> While placing a there are two cases
-> Case 1 : s <= setPtr => Here when u place a, you will place it with epoch bit 0
-> Case 2 : s > setPtr => Place it with epoch bit 1
-> If setPtr == numSets - 1:
-> currKeys = nextKeys (for all i, dont be lazy :))
-> Obtain a new set of nextKeys
*/

  for (int way = 0; way < ways_; way++) {
    if (memory_[slice*lines_ + setPtr*ways_ + way].valid != 1) {continue;} // nothing to do for invalid blocks :P
    if (epochBit[slice*lines_ + setPtr*ways_ + way]) {
      epochBit[slice*lines_ + setPtr*ways_ + way] = 0; // this was brought here via a future key so it can stay
    }
    else {
      uint64_t address = memory_[slice*lines_ + setPtr*ways_ + way].addr;
      address = decrypt(address,currKeys[skewBits[slice*lines_ + setPtr*ways_ + way]]);
      getScatterSet(0,address);
      int bestSet = -1;
      int bestCount = -1;
      for (int i=0; i<2*numSkews; i++) {
        if (!isValid(scatter_set_.index[i],(i >= numSkews))) {
          continue;
        }
        int emptyCount = 0;
        for (int j=0; j<ways_; j++) {
          emptyCount += (memory_[slice*lines_ + scatter_set_.index[i]*ways_ + j].valid == 0);
        }
        if (bestCount < emptyCount) {
          emptyCount = bestCount;
          bestSet = i;
        }
      }
      // best set now is the best set to place it in :)
      bool needToReplace = true;
      for (int i=0; i<ways_; i++) {
        if (memory_[slice*lines_ + scatter_set_.index[bestSet]*ways_ + i].valid == 0) {
          // place it here
          memory_[slice*lines_ + scatter_set_.index[bestSet]*ways_ + i].valid = 1;
          memory_[slice*lines_ + scatter_set_.index[bestSet]*ways_ + i].addr = memory_[slice*lines_ + setPtr*ways_ + way].addr;
          memory_[slice*lines_ + scatter_set_.index[bestSet]*ways_ + i].time = memory_[slice*lines_ + setPtr*ways_ + way].time;
          memory_[slice*lines_ + scatter_set_.index[bestSet]*ways_ + i].used = memory_[slice*lines_ + setPtr*ways_ + way].used;
          memory_[slice*lines_ + setPtr*ways_ + way].valid = 0; // now this is no longer valid
          if (bestSet >= numSkews) {
            if (scatter_set_.index[bestSet] <= setPtr) {
              epochBit[scatter_set_.index[bestSet]*ways_ + i] = 0;
            }
            else {
              epochBit[scatter_set_.index[bestSet]*ways_ + i] = 1;
            }
          }
          else {
            epochBit[scatter_set_.index[bestSet]*ways_ + i] = 0;
          }
          needToReplace = false;
          break;
        }
      }
      if (!needToReplace) {
        continue;
      }
      // we need to replace some random element
      int wayToReplace = rand()%ways_;
      memory_[slice*lines_ + scatter_set_.index[bestSet]*ways_ + wayToReplace].valid = 1;
      memory_[slice*lines_ + scatter_set_.index[bestSet]*ways_ + wayToReplace].addr = memory_[slice*lines_ + setPtr*ways_ + way].addr;
      memory_[slice*lines_ + scatter_set_.index[bestSet]*ways_ + wayToReplace].time = memory_[slice*lines_ + setPtr*ways_ + way].time;
      memory_[slice*lines_ + scatter_set_.index[bestSet]*ways_ + wayToReplace].used = memory_[slice*lines_ + setPtr*ways_ + way].used;
      memory_[slice*lines_ + setPtr*ways_ + way].valid = 0; // now this is no longer valid  
    }

  }

}

AccessResult caeser::extAccess(size_t addr, bool write, size_t secret, bool quiet, size_t* test_set, uint32_t test_set_size, bool* test_hit, bool no_noise)
{
  if (noisy_ && !no_noise && rand() < noise_)
    randomAccess();

  accessCtr++;
  accessCtr = accessCtr%1000;
  if (accessCtr == 1) {
    remap();    
  }

  // getScatterSet(secret, addr);

  AccessResult cl_state = {MISS, false, 0};
  unsigned slice = getSlice(addr);
  if (slice >= slices_) exit(-1);


  size_t aligned_addr = (addr >> line_size_bits_) << line_size_bits_;
  
  getScatterSet(secret,aligned_addr); // because this is what we will be storing

/*

Assuming n skews
-> 2*n keys : k1-kn are currKeys, kn+1-k2n are next keys
-> function f(address,key)->set
-> On memory access to address a, calculate all 2*n possible sets from f(a,1),f(a,2),...,f(a,2*n)
-> Valid sets are those f(a,i) s.t. i >= n+1 (i.e. new keys) OR f(a,i) > setPtr 
-> setPtr points at the largest set that hasn't been remapped
-> Check all ways in all these valid sets
-> If hit, good 
-> If miss, choose f(a,i) such that number of unused/invalid ways in f(a,i) >= those in f(a,j) for all valid sets f(a,j)
-> In that set, insert a

Each cache line will need log_(numSkews) + 1 extra bits:
log_(numSkews) to keep track of which skew landed our function here
1 extra bit to keep track of whether it was a currKey or a nextKey (call it epoch bit)
Epoch bit = 1 if nextKey and 0 otherwise

*/

  int bestSet = -1;
  int maxInv = -1;
  bool hit = false;
  for (int i=0; i<2*numSkews; i++) {

    if (!isValid(scatter_set_.index[i],(i >= numSkews))) {continue;}

    int set = scatter_set_.index[i];
    int setInv = 0;
    for (int j=0; j<ways_; j++) {
      if (aligned_addr == memory_[set*ways_ + j].addr && memory_[set*ways_ + j].valid == 1) {
        cl_state.hit = HIT;
        hit = true;
        cache_hits_[slice]++;
        break;
      }
      else if (memory_[set*ways_ + j].valid == 0) {
        setInv ++;
      }
    }
    if (hit) {
      break;
    }
    if (maxInv < setInv) {
      maxInv = setInv;
      bestSet = i;
    }

  }

  if (hit) {
    return cl_state;
  }

  if (!hit) {
    cache_misses_[slice]++;
  }

  bool needEvict = true;
  for (int way = 0; way < ways_; way++) {
    if (memory_[scatter_set_.index[bestSet]*ways_ + way].valid == 0) {
      needEvict = false;
      memory_[scatter_set_.index[bestSet]*ways_ + way].addr = aligned_addr;
      memory_[scatter_set_.index[bestSet]*ways_ + way].valid = 1;
      memory_[scatter_set_.index[bestSet]*ways_ + way].used = 0;
      memory_[scatter_set_.index[bestSet]*ways_ + way].time = 0;
      epochBit[scatter_set_.index[bestSet]*ways_ + way] = ((bestSet >= numSkews) && (scatter_set_.index[bestSet] > setPtr));
      if (bestSet < numSkews) {
        skewBits[scatter_set_.index[bestSet]*ways_ + way] = bestSet;
      }
      else {
        skewBits[scatter_set_.index[bestSet]*ways_ + way] = bestSet - numSkews;
      }
    }
  }
  if (needEvict) {
    int way = rand()%ways_;
    cl_state.evicted = true;
    cl_state.evicted_addr = memory_[scatter_set_.index[bestSet]*ways_ + way].addr;
    memory_[scatter_set_.index[bestSet]*ways_ + way].addr = aligned_addr;
    memory_[scatter_set_.index[bestSet]*ways_ + way].valid = 1;
    memory_[scatter_set_.index[bestSet]*ways_ + way].used = 0;
    memory_[scatter_set_.index[bestSet]*ways_ + way].time = 0;
    epochBit[scatter_set_.index[bestSet]*ways_ + way] = ((bestSet >= numSkews) && (scatter_set_.index[bestSet] > setPtr));
    if (bestSet < numSkews) {
      skewBits[scatter_set_.index[bestSet]*ways_ + way] = bestSet;
    }
    else {
      skewBits[scatter_set_.index[bestSet]*ways_ + way] = bestSet - numSkews;
    }
  }

  //check if an address of a test set is being overwritten
  if (test_set_size != 0)
  {
    *test_hit = false;
    for (unsigned i = 0; i < test_set_size; i++)
    {
      size_t aligned_test_addr = (test_set[i] >> line_bits_) << line_bits_;
      if (cl_state.evicted_addr == aligned_test_addr)
      {
        *test_hit = true;
        break;
      }
    }
  }


#if DEBUG_SET
  printf("set: ");
  for (unsigned i = 0; i < ways_; i++)
    printf("%u, ", scatter_set_.index[i]);
  printf("\n");
#endif

  if (!quiet)
  {
    // printf("%s %s %18p (slc=%u, set=%5u, way=%2u)\n", write ? "write" : " read", cl_state.hit == HIT ? "hit " : "miss", (void*)addr, slice, scatter_set_.index[way], way);

    printf("set: ");
    for (unsigned i = 0; i < ways_; i++)
      printf("%u, ", scatter_set_.index[i]);
    printf("\n");
  }

  return cl_state;
}

caeser::~caeser()
{
  //printf("caeser destroyed\n");
  free(memory_);
}
