#include "tinycrypt/sha2.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_SIZE 65536
uint8_t to_hash[MAX_SIZE];
uint8_t sha256[32];
uint32_t n = MAX_SIZE;

int
main (int argc, const char **argv)
{
#ifndef TCT_LITTLE_ENDIAN
  // Deal with a bug in BINSEC where globals are mapped as little-endian even
  // when simulating big-endian architectures
  n = ((n >> 24) & 0x000000FF) | ((n >> 8) & 0x0000FF00)
      | ((n << 8) & 0x00FF0000) | ((n << 24) & 0xFF000000);
#endif
  tct_sha256 (to_hash, (uint64_t)n, sha256);
  exit (sha256[0]);
}
