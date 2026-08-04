#include "tinycrypt/chacha20_poly1305.h"
#include "tinycrypt/ed25519.h"
#include "tinycrypt/sha2.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define SHA256_ITERS (64 * 1024)
#define SHA512_ITERS (64 * 1024)
#define CHACHA20_ITERS (64 * 1024)
#define EDDSA_ITERS (64)

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
  uint8_t buf[1024 * 16];
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
          (long long)diff.tv_sec, (long)diff.tv_nsec,
          (unsigned int)SHA256_ITERS);

  uint8_t sha512[64];
  clock_gettime (CLOCK_REALTIME, &a);
  for (size_t i = 0; i < SHA512_ITERS; ++i)
    {
      tct_sha512 (buf, sizeof (buf), sha512);
    }
  clock_gettime (CLOCK_REALTIME, &b);
  timespec_diff (&b, &a, &diff);
  printf ("Took %lld.%09ld seconds to compute %u 16KiB SHA-512 hashes\n",
          (long long)diff.tv_sec, (long)diff.tv_nsec,
          (unsigned int)SHA512_ITERS);

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
  printf ("Took %lld.%09ld seconds to compute %u 16KiB ChaCha20 round-trips\n",
          (long long)diff.tv_sec, (long)diff.tv_nsec,
          (unsigned int)CHACHA20_ITERS);

  clock_gettime (CLOCK_REALTIME, &a);
  uint8_t signature[64];
  uint8_t working_buf[sizeof (buf) + 64];
  static const uint8_t ED25519_PRIVKEY[]
      = { 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a,
          0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32,
          0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60 };
  static const uint8_t ED25519_PUBKEY[]
      = { 0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe,
          0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6,
          0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a };
  for (uint64_t i = 0; i < EDDSA_ITERS; ++i)
    {
      tct_ed25519_sign (buf, sizeof (buf), ED25519_PRIVKEY, ED25519_PUBKEY,
                        working_buf, signature);
    }
  clock_gettime (CLOCK_REALTIME, &b);
  timespec_diff (&b, &a, &diff);
  printf ("Took %lld.%09ld seconds to compute %u 16KiB Ed25519 signatures\n",
          (long long)diff.tv_sec, (long)diff.tv_nsec,
          (unsigned int)EDDSA_ITERS);

  return 0;
}
