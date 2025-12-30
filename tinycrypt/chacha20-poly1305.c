#include "tnt/crypto/chacha20-poly1305.h"
#include <stdbool.h>
#include <stdint.h>

static uint32_t
rotl_32 (uint32_t x, int c)
{
  return (x << c) | ((x & 0xffffffff) >> (32 - c));
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
      x[i] = u & 0xFF;
      u >>= 8;
    }
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
add256 (uint8_t *h, const uint8_t *c)
{
  uint16_t accumulator = 0;
  for (unsigned int i = 0; i < 32; ++i)
    {
      accumulator += h[i] + c[i];
      h[i] = accumulator & 0xFF;
      accumulator >>= 8;
    }
}

static void
sub264 (uint8_t *h, const uint8_t *c)
{
  uint16_t acc = 0;
  for (unsigned int i = 0; i < 33; ++i)
    {
      acc += (255 - h[i]) + c[i];
      h[i] = 255 - (acc & 0xFF);
      acc >>= 8;
    }
}

static void
add_shifted (uint8_t *h, const uint64_t c, unsigned int shift)
{
  uint8_t digits[8];
  to_le64 (c, digits);
  uint16_t accumulator = 0;
  unsigned int i;
  for (i = shift; i <= shift + 8 && i < 33; ++i)
    {
      accumulator += digits[i - shift] + h[i];
      h[i] = accumulator & 0xFF;
      accumulator >>= 8;
    }
  while (i < 33)
    {
      accumulator += h[i];
      h[i] = accumulator & 0xFF;
      accumulator >>= 8;
      ++i;
    }
}

static void
mult256 (const uint8_t *a, const uint8_t *b, uint8_t *out)
{
  // Literal long multiplication
  for (unsigned int i = 0; i < 33; ++i)
    {
      out[i] = 0x0;
    }
  uint32_t a_digits[8];
  uint32_t b_digits[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      a_digits[i] = from_le32 (a + i * 4);
      b_digits[i] = from_le32 (b + i * 4);
    }
  for (unsigned int i = 0; i < 8; ++i)
    {
      for (unsigned int j = 0; j < 8; ++j)
        {
          uint64_t prod = (uint64_t)a_digits[i] * (uint64_t)b_digits[j];
          add_shifted (out, prod, i * 4 + j * 4);
        }
    }
}

static void
shr264_by_130 (const uint8_t *in, uint8_t *out)
{
  for (unsigned int i = 0; i < 16; ++i)
    {
      out[31 - i] = 0x0;
    }
  for (unsigned int i = 0; i < 16; ++i)
    {
      out[i] = (in[i + 16] >> 2) | (in[i + 17] << 6);
    }
  out[16] = in[32] >> 2;
}

static bool
iszero256 (const uint8_t *a)
{
  for (unsigned int i = 0; i < 32; ++i)
    {
      if (a[i] != 0x0)
        {
          return false;
        }
    }
  return true;
}

static bool
greater264 (const uint8_t *a, const uint8_t *b)
{
  for (unsigned int i = 0; i < 33; ++i)
    {
      if (a[32 - i] < b[32 - i])
        {
          return false;
        }
      else if (a[32 - i] > b[32 - i])
        {
          return true;
        }
    }
  return false;
}

static void
modp_264 (uint8_t *in, uint8_t *out)
{
  const uint8_t P[33] = {
    0xFB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0x0,  0x0,  0x0,  0x0,  0x0,
    0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
  };
  uint8_t approx_quotient[32];
  uint8_t approx_dividend[33];
  uint8_t accumulator[33];
  for (unsigned int i = 0; i < 33; ++i)
    {
      accumulator[i] = in[i];
    }
  while (true)
    {
      shr264_by_130 (accumulator, approx_quotient);
      if (iszero256 (approx_quotient))
        {
          while (!greater264 (P, accumulator))
            {
              sub264 (accumulator, P);
            }
          for (unsigned int i = 0; i < 32; ++i)
            {
              out[i] = accumulator[i];
            }
          return;
        }
      mult256 (P, approx_quotient, approx_dividend);
      sub264 (accumulator, approx_dividend);
      if (greater264 (P, accumulator))
        {
          for (unsigned int i = 0; i < 32; ++i)
            {
              out[i] = accumulator[i];
            }
          return;
        }
    }
}

static void
poly1305_mac_rolling (const uint8_t *msg, const uint8_t *key, uint8_t *a)
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
  for (unsigned int i = 0; i < 32; ++i)
    {
      n[i] = 0x0;
    }
  for (unsigned int i = 0; i < 16; ++i)
    {
      n[i] = msg[i];
    }
  n[16] = 0x1;
  add256 (a, n);
  uint8_t intermediate[33];
  mult256 (r, a, intermediate);
  modp_264 (intermediate, a);
}

static void
poly1305_mac_init (uint8_t *a)
{
  for (unsigned int i = 0; i < 32; ++i)
    {
      a[i] = 0x0;
    }
}

static void
poly1305_mac_finish (uint8_t *a, const uint8_t *key)
{
  uint8_t s[32];
  for (unsigned int i = 0; i < 32; ++i)
    {
      s[i] = 0;
    }
  for (unsigned int i = 0; i < 16; ++i)
    {
      s[i] = key[16 + i];
    }
  add256 (a, s);
}

static void
poly1305_keygen (const uint8_t *key, const uint8_t *nonce, uint8_t *out)
{
  cc20_block (key, 0, nonce, out);
}

void
tnt_aead_chacha20_poly1305 (const uint8_t *aad, const uint64_t aad_len,
                            const uint8_t *key, const uint8_t *nonce,
                            const uint8_t *plaintext,
                            const uint64_t plaintext_len, uint8_t *cipher_out,
                            uint8_t *mac_out)
{
  uint8_t otk[32];
  poly1305_keygen (key, nonce, otk);
  cc20_encrypt (key, 1, nonce, plaintext, plaintext_len, cipher_out);
  poly1305_mac_init (mac_out);
  uint8_t buf[16];
  for (uint64_t i = 0; i < aad_len / 16; ++i)
    {
      for (unsigned int j = 0; j < 16; ++j)
        {
          buf[j] = aad[i * 16 + j];
        }
      poly1305_mac_rolling (buf, otk, mac_out);
    }
  for (unsigned int i = 0; i < aad_len % 16; ++i)
    {
      buf[i] = aad[(aad_len / 16) * 16 + i];
    }
  for (unsigned int i = aad_len % 16; i < 16; ++i)
    {
      buf[i] = 0x0;
    }
  if (aad_len % 16 != 0)
    {
      poly1305_mac_rolling (buf, otk, mac_out);
    }
  for (uint64_t i = 0; i < plaintext_len / 16; ++i)
    {
      for (unsigned int j = 0; j < 16; ++j)
        {
          buf[j] = cipher_out[i * 16 + j];
        }
      poly1305_mac_rolling (buf, otk, mac_out);
    }
  for (unsigned int i = 0; i < plaintext_len % 16; ++i)
    {
      buf[i] = cipher_out[(plaintext_len / 16) * 16 + i];
    }
  for (unsigned int i = plaintext_len % 16; i < 16; ++i)
    {
      buf[i] = 0x0;
    }
  if (plaintext_len % 16 != 0)
    {
      poly1305_mac_rolling (buf, otk, mac_out);
    }
  to_le64 (aad_len, buf);
  to_le64 (plaintext_len, buf + 8);
  poly1305_mac_rolling (buf, otk, mac_out);
  poly1305_mac_finish (mac_out, otk);
}