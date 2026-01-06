#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/chacha20_poly1305.h"

typedef uint32_t dwpacked __attribute__ ((vector_size (16)));

static dwpacked
rotl_32 (dwpacked x, int c)
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
cc20_block (const uint8_t *key, const uint16_t counter, const uint8_t *nonce,
            uint8_t *state_out)
{
  dwpacked initial_state[4]
      = { { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 } };
  initial_state[1] = (dwpacked){ from_le32 (key), from_le32 (key + 4),
                                 from_le32 (key + 8), from_le32 (key + 12) };
  initial_state[2] = (dwpacked){ from_le32 (key + 16), from_le32 (key + 20),
                                 from_le32 (key + 24), from_le32 (key + 28) };
  initial_state[3] = (dwpacked){ counter & 0xff, (counter >> 8) & 0xff,
                                 from_le32 (nonce), from_le32 (nonce + 4) };
  dwpacked state[4];
  for (uint32_t i = 0; i < 4; ++i)
    {
      state[i] = initial_state[i];
    }
  for (uint32_t i = 0; i < 10; ++i)
    {
      CC20_QR (state, 0, 1, 2, 3);
      state[1] = __builtin_shufflevector (state[1], state[1], 1, 2, 3, 0);
      state[2] = __builtin_shufflevector (state[2], state[2], 2, 3, 0, 1);
      state[3] = __builtin_shufflevector (state[3], state[3], 3, 0, 1, 2);
      CC20_QR (state, 0, 1, 2, 3);
      state[1] = __builtin_shufflevector (state[1], state[1], 3, 0, 1, 2);
      state[2] = __builtin_shufflevector (state[2], state[2], 2, 3, 0, 1);
      state[3] = __builtin_shufflevector (state[3], state[3], 1, 2, 3, 0);
    }

  for (uint32_t i = 0; i < 4; ++i)
    {
      state[i] += initial_state[i];
    }
  for (unsigned int i = 0; i < 16; ++i)
    {
      to_le32 (state[i / 4][i % 4], state_out + 4 * i);
    }
}

static void
cc20_encrypt (const uint8_t *key, const uint32_t counter, const uint8_t *nonce,
              const uint8_t *plaintext, const uint32_t plaintext_len,
              uint8_t *encrypted_out)
{
  uint8_t key_stream[64];
  for (uint32_t i = 0; i < plaintext_len / 64; ++i)
    {
      cc20_block (key, counter + i, nonce, key_stream);
      for (uint32_t j = 0; j < 64; ++j)
        {
          encrypted_out[i * 64 + j] = plaintext[i * 64 + j] ^ key_stream[j];
        }
    }
  if ((plaintext_len % 64) != 0)
    {
      uint32_t i = plaintext_len / 64;
      cc20_block (key, counter + i, nonce, key_stream);
      for (uint32_t j = 0; j < plaintext_len % 64; ++j)
        {
          encrypted_out[i * 64 + j] = plaintext[i * 64 + j] ^ key_stream[j];
        }
    }
}

static void
to_le64 (uint64_t u, uint8_t *x)
{
  for (unsigned int i = 0; i < 8; ++i)
    {
      x[i] = u & 0xff;
      u >>= 8;
    }
}

static uint64_t
from_le64 (const uint8_t *x)
{
  uint64_t u = 0;
  for (unsigned int i = 0; i < 8; ++i)
    {
      u <<= 8;
      u |= x[7 - i];
    }
  return u;
}

static void
poly1305_clamp (uint8_t *r)
{
  r[3] &= 15;
  r[7] &= 15;
  r[11] &= 15;
  r[15] &= 15;
  r[4] &= 252;
  r[8] &= 252;
  r[12] &= 252;
}

static void
add256 (uint64_t *h, const uint64_t *c)
{
  __uint128_t accumulator = 0;
  for (unsigned int i = 0; i < 4; ++i)
    {
      accumulator += (__uint128_t)h[i] + (__uint128_t)c[i];
      h[i] = accumulator & 0xffffffffffffffff;
      accumulator >>= 64;
    }
}

static void
sub320 (uint64_t *h, const uint64_t *c)
{
  __uint128_t acc = 0;
  for (unsigned int i = 0; i < 5; ++i)
    {
      acc += (__uint128_t)(0xffffffffffffffff - h[i]) + (__uint128_t)c[i];
      h[i] = 0xffffffffffffffff - (acc & 0xffffffffffffffff);
      acc >>= 64;
    }
}

static void
mult192 (const uint64_t *a, const uint64_t *b, uint64_t *out)
{
  uint64_t a_int[3], b_int[3];
  __uint128_t intermediate[6] = {
    0, 0, 0, 0, 0, 0,
  };
  for (unsigned int i = 0; i < 3; ++i)
    {
      a_int[i] = a[i];
      b_int[i] = b[i];
      out[i] = 0x0;
      out[3 + i] = 0x0;
    }
  for (unsigned int i = 0; i < 3; ++i)
    {
      for (unsigned int j = 0; j < 3; ++j)
        {
          intermediate[i + j] += (__uint128_t)a_int[i] * (__uint128_t)b_int[j];
          intermediate[i + j + 1] += intermediate[i + j] >> 64;
          intermediate[i + j] &= 0xffffffffffffffff;
        }
    }
  for (unsigned int k = 0; k < 5; ++k)
    {
      intermediate[k + 1] += intermediate[k] >> 64;
      out[k] = intermediate[k] & 0xffffffffffffffff;
    }
  out[5] = intermediate[5] & 0xffffffffffffffff;
}

static void
shr320_by_130 (const uint64_t *in, uint64_t *out)
{
  out[0] = (in[2] >> 2) | (in[3] << 62);
  out[1] = (in[3] >> 2) | (in[4] << 62);
  out[2] = in[4] >> 2;
}

static bool
greater320 (const uint64_t *a, const uint64_t *b)
{
  uint64_t a_int[5] = { a[0], a[1], a[2], a[3], a[4] };
  sub320 (a_int, b);
  return !(a_int[4] & (1ULL << 63));
}

static void
modp320 (uint64_t *in, uint64_t *out)
{
  const uint64_t P[5]
      = { 0xfffffffffffffffb, 0xffffffffffffffff, 0x3, 0x0, 0x0 };
  const uint64_t ZERO[5] = { 0x0, 0x0, 0x0, 0x0, 0x0 };
  uint64_t approx_quotient[3];
  uint64_t approx_dividend[6];
  uint64_t accumulator[5];
  for (unsigned int i = 0; i < 5; ++i)
    {
      accumulator[i] = in[i];
    }
  for (unsigned int i = 0; i < 2; ++i)
    {
      shr320_by_130 (accumulator, approx_quotient);
      mult192 (P, approx_quotient, approx_dividend);
      sub320 (accumulator, approx_dividend);
    }
  const uint64_t *dummy = greater320 (accumulator, P) ? P : ZERO;
  sub320 (accumulator, dummy);
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = accumulator[i];
    }
}

static void
poly1305_mac_rolling (const uint8_t *msg, const uint8_t *key,
                      const uint8_t blocklen, uint64_t *a)
{
  uint8_t r[32];
  for (unsigned int i = 0; i < 32; ++i)
    {
      r[i] = 0;
    }
  for (unsigned int i = 0; i < 16; ++i)
    {
      r[i] = key[i];
    }

  poly1305_clamp (r);
  uint8_t n[32];
  for (unsigned int i = blocklen; i < 32; ++i)
    {
      n[i] = 0x0;
    }
  for (unsigned int i = 0; i < 16 && i < blocklen; ++i)
    {
      n[i] = msg[i];
    }
  n[blocklen] = 0x1;
  uint64_t n_chunked[4];
  uint64_t r_chunked[4];
  for (unsigned int i = 0; i < 4; ++i)
    {
      n_chunked[i] = from_le64 (n + 8 * i);
      r_chunked[i] = from_le64 (r + 8 * i);
    }
  add256 (a, n_chunked);
  uint64_t intermediate[6];
  mult192 (r_chunked, a, intermediate);
  modp320 (intermediate, a);
}

static void
poly1305_mac_init (uint64_t *a)
{
  for (unsigned int i = 0; i < 4; ++i)
    {
      a[i] = 0x0;
    }
}

static void
poly1305_mac_finish (uint64_t *a, const uint8_t *key)
{
  uint64_t s[4];
  for (unsigned int i = 2; i < 4; ++i)
    {
      s[i] = 0;
    }
  for (unsigned int i = 0; i < 2; ++i)
    {
      s[i] = from_le64 (key + 16 + 8 * i);
    }
  add256 (a, s);
}

bool
tct_aead_chacha20_poly1305_decrypt_and_verify (
    const uint8_t *aad, const uint64_t aad_len, const uint8_t *key,
    const uint8_t *nonce, const uint8_t *frame, const uint64_t ciphertext_len,
    uint8_t *plaintext_out)
{
  uint8_t otk[64];
  cc20_block (key, 0, nonce, otk);
  uint64_t mac_chunked[4];
  poly1305_mac_init (mac_chunked);
  uint8_t buf[16];
  uint64_t total_len = 16 + aad_len + ciphertext_len;
  uint8_t aad_len_le[8], ciphertext_len_le[8];
  to_le64 (aad_len, aad_len_le);
  to_le64 (ciphertext_len, ciphertext_len_le);
  for (unsigned int i = 0; i < total_len; ++i)
    {
      if (i < aad_len)
        {
          buf[i % 16] = aad[i];
        }
      else if (i < aad_len + 8)
        {
          buf[i % 16] = aad_len_le[i - aad_len];
        }
      else if (i < aad_len + 8 + ciphertext_len)
        {
          buf[i % 16] = frame[i - aad_len - 8];
        }
      else if (i < aad_len + 16 + ciphertext_len)
        {
          buf[i % 16] = ciphertext_len_le[i - aad_len - 16 - ciphertext_len];
        }
      if (i % 16 == 15)
        {
          poly1305_mac_rolling (buf, otk, 16, mac_chunked);
        }
    }
  if (total_len % 16 != 0)
    {
      poly1305_mac_rolling (buf, otk, total_len % 16, mac_chunked);
    }
  poly1305_mac_finish (mac_chunked, otk);
  if (((from_le64 (frame + ciphertext_len) ^ mac_chunked[0])
       | (from_le64 (frame + ciphertext_len + 8) ^ mac_chunked[1]))
      != 0)
    {
      return false;
    }
  cc20_encrypt (key, 1, nonce, frame, ciphertext_len, plaintext_out);
  return true;
}

void
tct_aead_chacha20_poly1305_encrypt (const uint8_t *aad, const uint64_t aad_len,
                                    const uint8_t *key, const uint8_t *nonce,
                                    const uint8_t *plaintext,
                                    const uint64_t plaintext_len,
                                    uint8_t *cipher_out, uint8_t *mac_out)
{
  uint8_t otk[64];
  cc20_block (key, 0, nonce, otk);
  cc20_encrypt (key, 1, nonce, plaintext, plaintext_len, cipher_out);
  uint64_t mac_chunked[4];
  poly1305_mac_init (mac_chunked);
  uint8_t buf[16];
  uint64_t total_len = 16 + aad_len + plaintext_len;
  uint8_t aad_len_le[8], plaintext_len_le[8];
  to_le64 (aad_len, aad_len_le);
  to_le64 (plaintext_len, plaintext_len_le);
  for (unsigned int i = 0; i < total_len; ++i)
    {
      if (i < aad_len)
        {
          buf[i % 16] = aad[i];
        }
      else if (i < aad_len + 8)
        {
          buf[i % 16] = aad_len_le[i - aad_len];
        }
      else if (i < aad_len + 8 + plaintext_len)
        {
          buf[i % 16] = cipher_out[i - aad_len - 8];
        }
      else if (i < aad_len + 16 + plaintext_len)
        {
          buf[i % 16] = plaintext_len_le[i - aad_len - 16 - plaintext_len];
        }
      if (i % 16 == 15)
        {
          poly1305_mac_rolling (buf, otk, 16, mac_chunked);
        }
    }
  if (total_len % 16 != 0)
    {
      poly1305_mac_rolling (buf, otk, total_len % 16, mac_chunked);
    }
  poly1305_mac_finish (mac_chunked, otk);
  for (unsigned int i = 0; i < 2; ++i)
    {
      to_le64 (mac_chunked[i], mac_out + 8 * i);
    }
}