#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/chacha20_poly1305.h"

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

/* Fold the bits above 130 into the low 130 via 2^130 = 5 (mod 2^130-5). */
static void
fold5 (uint64_t *acc)
{
  uint64_t hi[3];
  shr320_by_130 (acc, hi);
  uint64_t lo0 = acc[0], lo1 = acc[1], lo2 = acc[2] & 0x3;
  __uint128_t c = 0;
  uint64_t m[4];
  for (unsigned int i = 0; i < 3; ++i)
    {
      __uint128_t t = (__uint128_t)hi[i] * 5 + c;
      m[i] = (uint64_t)t;
      c = t >> 64;
    }
  m[3] = (uint64_t)c;
  __uint128_t s = (__uint128_t)m[0] + lo0;
  acc[0] = (uint64_t)s;
  c = s >> 64;
  s = (__uint128_t)m[1] + lo1 + c;
  acc[1] = (uint64_t)s;
  c = s >> 64;
  s = (__uint128_t)m[2] + lo2 + c;
  acc[2] = (uint64_t)s;
  c = s >> 64;
  s = (__uint128_t)m[3] + c;
  acc[3] = (uint64_t)s;
  acc[4] = (uint64_t)(s >> 64);
}

static void
modp320 (uint64_t *in, uint64_t *out)
{
  uint64_t acc[5] = { in[0], in[1], in[2], in[3], in[4] };
  fold5 (acc);
  fold5 (acc); /* value now < 2^130 + 80 */
  /* constant-time freeze: if value + 5 carries past bit 130, subtract p */
  __uint128_t c = 5;
  __uint128_t s = (__uint128_t)acc[0] + c;
  uint64_t t0 = (uint64_t)s;
  c = s >> 64;
  s = (__uint128_t)acc[1] + c;
  uint64_t t1 = (uint64_t)s;
  c = s >> 64;
  s = (__uint128_t)acc[2] + c;
  uint64_t t2 = (uint64_t)s;
  uint64_t mask = (uint64_t)0 - ((t2 >> 2) & 1);
  out[0] = (t0 & mask) | (acc[0] & ~mask);
  out[1] = (t1 & mask) | (acc[1] & ~mask);
  out[2] = ((t2 & 0x3) & mask) | (acc[2] & ~mask);
  out[3] = 0;
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
  const uint8_t ZERO[64]
      = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
          0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
          0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
          0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
          0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
  tct_chacha20_encrypt_or_decrypt (key, 0, nonce, ZERO, sizeof (ZERO), otk);
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
          buf[i % 16] = ciphertext_len_le[i - aad_len - 8 - ciphertext_len];
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
  tct_chacha20_encrypt_or_decrypt (key, 1, nonce, frame, ciphertext_len,
                                   plaintext_out);
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
  const uint8_t ZERO[64]
      = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
          0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
          0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
          0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
          0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
  tct_chacha20_encrypt_or_decrypt (key, 0, nonce, ZERO, sizeof (ZERO), otk);
  tct_chacha20_encrypt_or_decrypt (key, 1, nonce, plaintext, plaintext_len,
                                   cipher_out);
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
          buf[i % 16] = plaintext_len_le[i - aad_len - 8 - plaintext_len];
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
