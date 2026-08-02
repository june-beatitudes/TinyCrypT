#ifdef TCT_SIMD
#error You're building the wrong version of ChaCha20! SIMD architectures should use chacha20-simd.c.
#endif

#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/chacha20_poly1305.h"

static uint32_t
rotl_32 (uint32_t x, int c)
{
  return (x << c) | (x >> (32 - c));
}

static uint32_t
from_le32 (const uint8_t *x)
{
  uint32_t u = x[3];
  u = (u << 8) | x[2];
  u = (u << 8) | x[1];
  return (u << 8) | x[0];
}

static void
to_le32 (uint32_t u, uint8_t *x)
{
  for (unsigned int i = 0; i < 4; ++i)
    {
      x[i] = u & 0xFF;
      u >>= 8;
    }
}

#define CC20_QR(state, a, b, c, d)                                            \
  do                                                                          \
    {                                                                         \
      state[a] += state[b];                                                   \
      state[d] ^= state[a];                                                   \
      state[d] = rotl_32 (state[d], 16);                                      \
      state[c] += state[d];                                                   \
      state[b] ^= state[c];                                                   \
      state[b] = rotl_32 (state[b], 12);                                      \
      state[a] += state[b];                                                   \
      state[d] ^= state[a];                                                   \
      state[d] = rotl_32 (state[d], 8);                                       \
      state[c] += state[d];                                                   \
      state[b] ^= state[c];                                                   \
      state[b] = rotl_32 (state[b], 7);                                       \
    }                                                                         \
  while (false);

static void
cc20_block (const uint8_t *key, const uint32_t counter, const uint8_t *nonce,
            uint8_t *state_out)
{
  uint32_t initial_state[16]
      = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
  for (uint32_t i = 0; i < 8; ++i)
    {
      initial_state[i + 4] = from_le32 (key + i * 4);
    }
  initial_state[12] = counter;
  for (uint32_t i = 0; i < 3; ++i)
    {
      initial_state[i + 13] = from_le32 (nonce + i * 4);
    }
  uint32_t state[16];
  for (uint32_t i = 0; i < 16; ++i)
    {
      state[i] = initial_state[i];
    }
  for (uint32_t i = 0; i < 10; ++i)
    {
      CC20_QR (state, 0, 4, 8, 12);
      CC20_QR (state, 1, 5, 9, 13);
      CC20_QR (state, 2, 6, 10, 14);
      CC20_QR (state, 3, 7, 11, 15);
      CC20_QR (state, 0, 5, 10, 15);
      CC20_QR (state, 1, 6, 11, 12);
      CC20_QR (state, 2, 7, 8, 13);
      CC20_QR (state, 3, 4, 9, 14);
    }

  for (uint32_t i = 0; i < 16; ++i)
    {
      state[i] += initial_state[i];
    }
  for (unsigned int i = 0; i < 16; ++i)
    {
      to_le32 (state[i], state_out + 4 * i);
    }
}

void
tct_chacha20_encrypt_or_decrypt (const uint8_t *key, const uint32_t counter,
                                 const uint8_t *nonce,
                                 const uint8_t *plaintext,
                                 const uint64_t plaintext_len,
                                 uint8_t *encrypted_out)
{
  uint8_t key_stream[64];
  for (uint64_t i = 0; i < plaintext_len / 64; ++i)
    {
      cc20_block (key, counter + (uint32_t)i, nonce, key_stream);
      for (uint32_t j = 0; j < 64; ++j)
        {
          encrypted_out[i * 64 + j] = plaintext[i * 64 + j] ^ key_stream[j];
        }
    }
  if ((plaintext_len % 64) != 0)
    {
      uint64_t i = plaintext_len / 64;
      cc20_block (key, counter + (uint32_t)i, nonce, key_stream);
      for (uint32_t j = 0; j < plaintext_len % 64; ++j)
        {
          encrypted_out[i * 64 + j] = plaintext[i * 64 + j] ^ key_stream[j];
        }
    }
}
