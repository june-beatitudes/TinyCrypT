#include "tinycrypt/sha2.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_SIZE 65536
uint8_t to_hash[MAX_SIZE];
uint8_t sha256[32];
size_t n = MAX_SIZE;

int
main (int argc, const char **argv)
{
  tct_sha256 (to_hash, n, sha256);
  exit (sha256[0]);
}
