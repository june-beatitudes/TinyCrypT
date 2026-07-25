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
to_le32 (uint32_t u, uint8_t *x)
{
  for (unsigned int i = 0; i < 4; ++i)
    {
      x[i] = u & 0xff;
      u >>= 8;
    }
}

static uint32_t
from_le32 (const uint8_t *x)
{
  uint32_t u = 0;
  for (unsigned int i = 0; i < 4; ++i)
    {
      u <<= 8;
      u |= x[3 - i];
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
add256 (uint32_t *h, const uint32_t *c)
{
  uint64_t accumulator = 0;
  for (unsigned int i = 0; i < 8; ++i)
    {
      accumulator += (uint64_t)h[i] + (uint64_t)c[i];
      h[i] = accumulator & 0xffffffff;
      accumulator >>= 32;
    }
}

static void
sub160 (uint32_t *h, const uint32_t *c)
{
  uint64_t accumulator = 0;
  for (unsigned int i = 0; i < 5; ++i)
    {
      accumulator += (uint64_t)(0xffffffff - h[i]) + (uint64_t)c[i];
      h[i] = 0xffffffff - (accumulator & 0xffffffff);
      accumulator >>= 32;
    }
}

static void
mult160 (const uint32_t *a, const uint32_t *b, uint32_t *out)
{
  uint32_t a_int[5], b_int[5];
  uint64_t intermediate[10] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  for (unsigned int i = 0; i < 5; ++i)
    {
      a_int[i] = a[i];
      b_int[i] = b[i];
      out[i] = 0x0;
      out[5 + i] = 0x0;
    }
  for (unsigned int i = 0; i < 5; ++i)
    {
      for (unsigned int j = 0; j < 5; ++j)
        {
          intermediate[i + j] += (uint64_t)a_int[i] * (uint64_t)b_int[j];
          intermediate[i + j + 1] += intermediate[i + j] >> 32;
          intermediate[i + j] &= 0xffffffff;
        }
    }
  for (unsigned int k = 0; k < 9; ++k)
    {
      intermediate[k + 1] += intermediate[k] >> 32;
      out[k] = intermediate[k] & 0xffffffff;
    }
  out[9] = intermediate[9] & 0xffffffff;
}

static void
shr320_by_130 (const uint32_t *in, uint32_t *out)
{
  out[0] = (in[4] >> 2) | (in[5] << 30);
  out[1] = (in[5] >> 2) | (in[6] << 30);
  out[2] = (in[6] >> 2) | (in[7] << 30);
  out[3] = (in[7] >> 2) | (in[8] << 30);
  out[4] = (in[8] >> 2) | (in[9] << 30);
  out[5] = in[9] >> 2;
}

/* Fold the bits above 130 into the low 130 via 2^130 = 5 (mod 2^130-5). */
static void
fold5 (uint32_t *acc)
{
  uint32_t hi[6];
  uint32_t lo[10];
  shr320_by_130 (acc, hi);
  lo[0] = acc[0];
  lo[1] = acc[1];
  lo[2] = acc[2];
  lo[3] = acc[3];
  lo[4] = acc[4] & 0x3;
  lo[5] = 0x0;
  lo[6] = 0x0;
  lo[7] = 0x0;
  lo[8] = 0x0;
  lo[9] = 0x0;
  uint64_t c = 0;
  uint32_t m[10];
  for (unsigned int i = 0; i < 6; ++i)
    {
      uint64_t t = (uint64_t)hi[i] * 5 + c;
      m[i] = (uint32_t)t;
      c = t >> 32;
    }
  m[6] = (uint32_t)c;
  m[7] = m[8] = m[9] = 0x0;
  c = 0;
  for (unsigned int i = 0; i < 10; ++i)
    {
      uint64_t t = (uint64_t)m[i] + (uint64_t)lo[i] + c;
      acc[i] = (uint32_t)t;
      c = t >> 32;
    }
}

static void
modp320 (uint32_t *in, uint32_t *out)
{
  uint32_t acc[10] = { in[0], in[1], in[2], in[3], in[4],
                       in[5], in[6], in[7], in[8], in[9] };
  fold5 (acc);
  fold5 (acc);
  const uint32_t P[5]
      = { 0xfffffffb, 0xffffffff, 0xffffffff, 0xffffffff, 0x00000003 };
  uint32_t buf[5];
  for (unsigned int i = 0; i < 5; ++i)
    {
      buf[i] = acc[i];
    }
  sub160 (buf, P);
  uint32_t *res = (buf[4] >> 31) ? acc : buf;
  for (unsigned int i = 0; i < 5; ++i)
    {
      out[i] = res[i];
    }
}

static void
poly1305_mac_rolling (const uint8_t *msg, const uint8_t *key,
                      const uint8_t blocklen, uint32_t *a)
{
  uint8_t r[32];
  for (unsigned int i = 16; i < 32; ++i)
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
  uint32_t n_chunked[8];
  uint32_t r_chunked[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      n_chunked[i] = from_le32 (n + 4 * i);
      r_chunked[i] = from_le32 (r + 4 * i);
    }
  add256 (a, n_chunked);
  uint32_t intermediate[10];
  mult160 (r_chunked, a, intermediate);
  modp320 (intermediate, a);
  for (unsigned int i = 5; i < 8; ++i)
    {
      a[i] = 0x0;
    }
}

static void
poly1305_mac_init (uint32_t *a)
{
  for (unsigned int i = 0; i < 8; ++i)
    {
      a[i] = 0x0;
    }
}

static void
poly1305_mac_finish (uint32_t *a, const uint8_t *key)
{
  uint32_t s[8];
  for (unsigned int i = 4; i < 8; ++i)
    {
      s[i] = 0;
    }
  for (unsigned int i = 0; i < 4; ++i)
    {
      s[i] = from_le32 (key + 16 + 4 * i);
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
  uint32_t mac_chunked[8];
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
  uint32_t acc = 0x0;
  for (unsigned int i = 0; i < 4; ++i)
    {
      acc |= from_le32 (frame + ciphertext_len + i * 4) ^ mac_chunked[i];
    }
  if (acc != 0x0)
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
  uint32_t mac_chunked[8];
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
  for (unsigned int i = 0; i < 4; ++i)
    {
      to_le32 (mac_chunked[i], mac_out + 4 * i);
    }
}
