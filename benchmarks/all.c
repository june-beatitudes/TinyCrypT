#include "tinycrypt/chacha20_poly1305.h"
#include "tinycrypt/sha2.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define SHA256_ITERS (1024 * 64)
#define SHA512_ITERS (1024 * 64)
#define CHACHA20_ITERS (1024 * 64)

static inline void
timespec_diff (const struct timespec *a, const struct timespec *b,
               struct timespec *result)
{
  result->tv_sec = a->tv_sec - b->tv_sec;
  result->tv_nsec = a->tv_nsec - b->tv_nsec;
  // Handle underflow: borrow 1 second if nanoseconds are negative
  if (result->tv_nsec < 0)
    {
      --result->tv_sec;
      result->tv_nsec += 1000000000L;
    }
}

int
main (int argc, const char **argv)
{
  uint8_t buf[16 * 1024];
  for (size_t i = 0; i < sizeof (buf); ++i)
    {
      buf[i] = i & 0xff;
    }

  uint8_t sha256[32];
  struct timespec a;
  clock_gettime (CLOCK_REALTIME, &a);
  for (size_t i = 0; i < SHA256_ITERS; ++i)
    {
      tct_sha256 (buf, sizeof (buf), sha256);
    }
  struct timespec b;
  clock_gettime (CLOCK_REALTIME, &b);
  struct timespec diff;
  timespec_diff (&b, &a, &diff);
  printf ("Took %lld.%09ld seconds to compute %u 16KiB SHA-256 hashes\n",
          diff.tv_sec, diff.tv_nsec, SHA256_ITERS);

  uint8_t sha512[64];
  clock_gettime (CLOCK_REALTIME, &a);
  for (size_t i = 0; i < SHA512_ITERS; ++i)
    {
      tct_sha512 (buf, sizeof (buf), sha512);
    }
  clock_gettime (CLOCK_REALTIME, &b);
  timespec_diff (&b, &a, &diff);
  printf ("Took %lld.%09ld seconds to compute %u 16KiB SHA-512 hashes\n",
          diff.tv_sec, diff.tv_nsec, SHA512_ITERS);

  const uint8_t CC20_KEY[32]
      = { 0xb3, 0x36, 0x31, 0x73, 0x8e, 0xc0, 0x70, 0xe3, 0x5d, 0x77, 0xd6,
          0x65, 0xc8, 0xe8, 0xc2, 0x97, 0xc0, 0x77, 0x29, 0x3c, 0xfa, 0xa3,
          0x55, 0xfe, 0xb6, 0xa5, 0xf5, 0x17, 0xfd, 0x8f, 0xaf, 0xc6 };
  uint8_t nonce[8];

  clock_gettime (CLOCK_REALTIME, &a);
  for (uint64_t i = 0; i < CHACHA20_ITERS; ++i)
    {
      nonce[0] = i & 0xff;
      nonce[1] = (i >> 8) & 0xff;
      nonce[2] = (i >> 16) & 0xff;
      nonce[3] = (i >> 24) & 0xff;
      nonce[4] = (i >> 32) & 0xff;
      nonce[5] = (i >> 40) & 0xff;
      nonce[6] = (i >> 48) & 0xff;
      nonce[7] = (i >> 56) & 0xff;
      tct_chacha20_encrypt_or_decrypt (CC20_KEY, i, nonce, buf, sizeof (buf),
                                       buf);
      tct_chacha20_encrypt_or_decrypt (CC20_KEY, i, nonce, buf, sizeof (buf),
                                       buf);
    }
  clock_gettime (CLOCK_REALTIME, &b);
  timespec_diff (&b, &a, &diff);
  printf (
      "Took %lld.%09ld seconds to compute %u 16KiB ChaCha20 round-trips\n",
      diff.tv_sec, diff.tv_nsec, CHACHA20_ITERS);

  return 0;
}
