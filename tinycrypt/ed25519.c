#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "tinycrypt/sha2.h"
#include "tinycrypt/ed25519.h"

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
add_shifted (uint8_t *h, const uint64_t c, const unsigned int shift)
{
  uint8_t digits[8];
  to_le64 (c, digits);
  uint16_t accumulator = 0;
  unsigned int i;
  for (i = shift; i <= shift + 8 && i < 64; ++i)
    {
      accumulator += digits[i - shift] + h[i];
      h[i] = accumulator & 0xFF;
      accumulator >>= 8;
    }
  while (i < 64)
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
  for (unsigned int i = 0; i < 64; ++i)
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
mult264 (const uint8_t *a, const uint8_t *b, uint8_t *out)
{
  for (unsigned int i = 0; i < 64; ++i)
    {
      out[i] = 0x0;
    }
  uint32_t a_digits[9];
  uint32_t b_digits[9];
  for (unsigned int i = 0; i < 8; ++i)
    {
      a_digits[i] = from_le32 (a + i * 4);
      b_digits[i] = from_le32 (b + i * 4);
    }
  a_digits[8] = a[32];
  b_digits[8] = b[32];
  for (unsigned int i = 0; i < 9; ++i)
    {
      for (unsigned int j = 0; j < 9; ++j)
        {
          uint64_t prod = (uint64_t)a_digits[i] * (uint64_t)b_digits[j];
          add_shifted (out, prod, i * 4 + j * 4);
        }
    }
}

static void
shr512_by_255 (const uint8_t *in, uint8_t *out)
{
  for (unsigned int i = 0; i < 32; ++i)
    {
      out[i] = (in[i + 31] >> 7) | (in[i + 32] << 1);
    }
  out[32] = in[63] >> 7;
}

static bool
iszero264 (const uint8_t *a)
{
  uint8_t dummy = 0x0;
  for (unsigned int i = 0; i < 33; ++i)
    {
      dummy |= a[i];
    }
  return !dummy;
}

static bool
iszero256 (const uint8_t *a)
{
  uint8_t dummy = 0x0;
  for (unsigned int i = 0; i < 32; ++i)
    {
      dummy |= a[i];
    }
  return !dummy;
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

#include <stdio.h>

static bool
greater264 (const uint8_t *a, const uint8_t *b)
{
  uint8_t buf[33];
  for (unsigned int i = 0; i < 33; ++i)
    {
      buf[i] = a[i];
    }
  sub264 (buf, b);

  return !(buf[32] & (1 << 7));
}

static void
add512 (uint8_t *h, const uint8_t *c)
{
  uint16_t acc = 0;
  for (unsigned int i = 0; i < 64; ++i)
    {
      acc += h[i] + c[i];
      h[i] = acc & 0xFF;
      acc >>= 8;
    }
}

static void
sub512 (uint8_t *h, const uint8_t *c)
{
  int16_t acc = 0;
  for (unsigned int i = 0; i < 64; ++i)
    {
      acc += (int16_t)h[i] - (int16_t)c[i];
      if (acc < 0)
        {
          h[i] = acc + 256;
          acc = -1;
        }
      else
        {
          h[i] = acc % 256;
          acc /= 256;
        }
    }
}

static bool
greater512 (const uint8_t *a, const uint8_t *b)
{
  uint8_t buf[64];
  for (unsigned int i = 0; i < 64; ++i)
    {
      buf[i] = a[i];
    }
  sub512 (buf, b);

  return !(buf[63] & (1 << 7));
}

static void
modp512 (const uint8_t *in, uint8_t *out)
{
  const uint8_t P[64] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  uint8_t approx_quotient[33];
  uint8_t approx_dividend[64];
  uint8_t accumulator[64];
  for (unsigned int i = 0; i < 64; ++i)
    {
      accumulator[i] = in[i];
    }
  // Handle negatives properly
  add512 (accumulator, P);
  for (unsigned int i = 0; i < 2; ++i)
    {
      shr512_by_255 (accumulator, approx_quotient);
      mult264 (P, approx_quotient, approx_dividend);
      sub512 (accumulator, approx_dividend);
    }
  uint8_t dummy_buf[64];
  uint8_t dummy_val = (greater264 (accumulator, P)) ? 0x1 : 0x0;
  for (unsigned int i = 0; i < 64; ++i)
    {
      dummy_buf[i] = P[i] * dummy_val;
    }
  sub512 (accumulator, dummy_buf);
  for (unsigned int i = 0; i < 32; ++i)
    {
      out[i] = accumulator[i];
    }
}

static void
mult256_modp (const uint8_t *a, const uint8_t *b, uint8_t *out)
{
  uint8_t intermediate[64];
  mult256 (a, b, intermediate);
  modp512 (intermediate, out);
}

static void
sub256_modp (const uint8_t *a, const uint8_t *b, uint8_t *out)
{
  uint8_t intermediates[2][64];
  for (unsigned int i = 0; i < 32; ++i)
    {
      intermediates[0][i] = a[i];
      intermediates[1][i] = b[i];
    }
  for (unsigned int i = 32; i < 64; ++i)
    {
      intermediates[0][i] = 0x0;
      intermediates[1][i] = 0x0;
    }
  sub512 (intermediates[0], intermediates[1]);
  modp512 (intermediates[0], out);
}

static void
add256_modp (const uint8_t *a, const uint8_t *b, uint8_t *out)
{
  uint8_t intermediates[2][64];
  for (unsigned int i = 0; i < 32; ++i)
    {
      intermediates[0][i] = a[i];
      intermediates[1][i] = b[i];
    }
  for (unsigned int i = 32; i < 64; ++i)
    {
      intermediates[0][i] = 0x0;
      intermediates[1][i] = 0x0;
    }
  add512 (intermediates[0], intermediates[1]);
  modp512 (intermediates[0], out);
}

static void
inv256_modp (const uint8_t *x, uint8_t *out)
{
  uint8_t buf[64];
  uint8_t *i0 = buf;
  uint8_t *i1 = buf + 32;
  for (unsigned int i = 0; i < 32; ++i)
    {
      i0[i] = x[i];
    }
  for (unsigned int i = 0; i < 254; ++i)
    {
      mult256_modp (i0, i0, i1);
      uint8_t *t1 = i1;
      i1 = i0;
      i0 = t1;
      if (i != 251 && i != 249)
        {
          mult256_modp (i0, x, i1);
          uint8_t *t0 = i1;
          i1 = i0;
          i0 = t0;
        }
    }
  for (unsigned int i = 0; i < 32; ++i)
    {
      out[i] = i0[i];
    }
}

static void
swap256 (unsigned int do_swap, uint8_t *a, uint8_t *b)
{
  for (unsigned int i = 0; i < 32; ++i)
    {
      uint8_t dummy = (a[i] ^ b[i]) & ((do_swap) ? 0xFF : 0x0);
      a[i] = a[i] ^ dummy;
      b[i] = b[i] ^ dummy;
    }
}

static void
pow256_2523_modp (const uint8_t *in, uint8_t *out)
{
  uint8_t buf[64];
  uint8_t *i0 = buf;
  uint8_t *i1 = buf + 32;
  for (unsigned int i = 0; i < 32; ++i)
    {
      i0[i] = in[i];
    }
  for (int i = 250; i >= 0; --i)
    {
      mult256_modp (i0, i0, i0);
      if (i != 1)
        {
          mult256_modp (i0, in, i0);
        }
    }
  for (unsigned int i = 0; i < 32; ++i)
    {
      out[i] = i0[i];
    }
}

static bool
decode256 (const uint8_t *point, uint8_t *x, uint8_t *y)
{
  bool x0 = (point[31] & 0x80) != 0;
  for (unsigned int i = 0; i < 32; ++i)
    {
      y[i] = point[i];
    }
  y[31] &= 0x7F;
  const uint8_t D[32] = {
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41,
    0x41, 0x4d, 0x0a, 0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40,
    0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
  };
  const uint8_t ONE[32] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint8_t v[32];
  uint8_t u[32];
  uint8_t i0[32], i1[32];
  mult256_modp (y, y, u);
  mult256_modp (y, y, v);
  sub256_modp (u, ONE, u);
  mult256_modp (v, D, v);
  add256_modp (v, ONE, v);
  mult256_modp (u, v, i0);
  mult256_modp (i0, v, i0);
  mult256_modp (i0, v, i1);
  mult256_modp (i0, v, i0);
  mult256_modp (i1, v, i1);
  mult256_modp (i1, v, i1);
  mult256_modp (i1, v, i1);
  mult256_modp (i1, v, i1);
  pow256_2523_modp (i1, x);
  mult256_modp (x, i0, x);

  mult256_modp (x, x, i0);
  mult256_modp (i0, v, i0);
  sub256_modp (i0, u, i0);
  const uint8_t *mask;
  const uint8_t KMULT[32] = {
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f,
    0xad, 0x06, 0x18, 0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00,
    0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
  };
  const uint8_t P[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  };

  if (iszero256 (i0))
    {
      mask = ONE;
    }
  else
    {
      mask = KMULT;
    }
  mult256_modp (x, mask, x);
  mult256_modp (x, x, i0);
  mult256_modp (i0, v, i0);
  sub256_modp (i0, u, i0);
  if (!iszero256 (i0))
    {
      return false;
    }
  else if (iszero256 (x) && x0 != 0)
    {
      return false;
    }
  if ((x[0] & 1) != x0)
    {
      sub256_modp (P, x, x);
    }
  return true;
}

static void
addpoints (const uint8_t *x1, const uint8_t *y1, const uint8_t *z1,
           const uint8_t *t1, const uint8_t *x2, const uint8_t *y2,
           const uint8_t *z2, const uint8_t *t2, uint8_t *x3, uint8_t *y3,
           uint8_t *z3, uint8_t *t3)
{
  const uint8_t TWO[32] = {
    0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  const uint8_t D[32] = {
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41,
    0x41, 0x4d, 0x0a, 0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40,
    0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
  };
  uint8_t intermediates[8][32];
  sub256_modp (y1, x1, intermediates[0]);
  sub256_modp (y2, x2, intermediates[1]);
  mult256_modp (intermediates[0], intermediates[1], intermediates[0]);
  add256_modp (y1, x1, intermediates[1]);
  add256_modp (y2, x2, intermediates[2]);
  mult256_modp (intermediates[1], intermediates[2], intermediates[1]);
  mult256_modp (t1, t2, intermediates[2]);
  mult256_modp (intermediates[2], TWO, intermediates[2]);
  mult256_modp (intermediates[2], D, intermediates[2]);
  mult256_modp (z1, z2, intermediates[7]);
  mult256_modp (intermediates[7], TWO, intermediates[7]);
  sub256_modp (intermediates[1], intermediates[0], intermediates[3]);
  sub256_modp (intermediates[7], intermediates[2], intermediates[4]);
  add256_modp (intermediates[7], intermediates[2], intermediates[5]);
  add256_modp (intermediates[1], intermediates[0], intermediates[6]);
  mult256_modp (intermediates[3], intermediates[4], x3);
  mult256_modp (intermediates[5], intermediates[6], y3);
  mult256_modp (intermediates[4], intermediates[5], z3);
  mult256_modp (intermediates[3], intermediates[6], t3);
}

static bool
points_eq (const uint8_t *x1, const uint8_t *y1, const uint8_t *z1,
           const uint8_t *t1, const uint8_t *x2, const uint8_t *y2,
           const uint8_t *z2, const uint8_t *t2)
{
  uint8_t i0[32], i1[32];
  mult256_modp (x1, z2, i0);
  mult256_modp (x2, z1, i1);
  sub256_modp (i0, i1, i0);
  if (!iszero256 (i0))
    {
      return false;
    }
  mult256_modp (y1, z2, i0);
  mult256_modp (y2, z1, i1);
  sub256_modp (i0, i1, i0);
  if (!iszero256 (i0))
    {
      return false;
    }
  return true;
}

static void
scalarmult (const uint8_t *k, const uint8_t *x_in, const uint8_t *y_in,
            uint8_t *x_out, uint8_t *y_out, uint8_t *z_out, uint8_t *t_out)
{
  uint8_t x1[32], y1[32], t1[32];
  for (unsigned int i = 0; i < 32; ++i)
    {
      x1[i] = x_in[i];
      y1[i] = y_in[i];
    }
  mult256_modp (x1, y1, t1);
  uint8_t z1[32] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint8_t z2[32] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint8_t x2[32] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint8_t y2[32] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint8_t t2[32] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  for (int i = 255; i >= 0; --i)
    {
      unsigned int swap = (k[i / 8] >> (i % 8)) & 1;
      swap256 (swap, x1, x2);
      swap256 (swap, y1, y2);
      swap256 (swap, z1, z2);
      swap256 (swap, t1, t2);

      addpoints (x1, y1, z1, t1, x2, y2, z2, t2, x1, y1, z1, t1);
      addpoints (x2, y2, z2, t2, x2, y2, z2, t2, x2, y2, z2, t2);

      swap256 (swap, x1, x2);
      swap256 (swap, y1, y2);
      swap256 (swap, z1, z2);
      swap256 (swap, t1, t2);
    }
  for (unsigned int i = 0; i < 32; ++i)
    {
      x_out[i] = x2[i];
      y_out[i] = y2[i];
      z_out[i] = z2[i];
      t_out[i] = t2[i];
    }
}

static void
shr512_by_254 (const uint8_t *in, uint8_t *out)
{
  for (unsigned int i = 0; i < 32; ++i)
    {
      out[i] = (in[i + 31] >> 6) | (in[i + 32] << 2);
    }
  out[32] = in[63] >> 6;
}

static void
shl512 (const uint8_t *in, const uint64_t shift, uint8_t *out)
{
  for (uint64_t i = 0; i < 64; ++i)
    {
      out[i] = 0x0;
    }
  uint64_t shift_amt = shift % 8;
  for (uint64_t i = 0; i < 64 - shift / 8; ++i)
    {
      out[i + shift / 8] = in[i] << shift_amt;
      if (i > 0)
        {
          out[i + shift / 8] |= in[i - 1] >> (8 - shift_amt);
        }
    }
}

static void
modl512 (const uint8_t *x, uint8_t *out)
{
  uint8_t L[64] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x0,
    0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
    0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
    0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,
  };
  uint8_t LMULT[64];
  uint8_t ZERO[64] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint8_t i0[64], i1[64], i2[33];
  for (unsigned int i = 0; i < 64; ++i)
    {
      i0[i] = x[i];
    }
  for (int i = 259; i >= 0; --i)
    {
      shl512 (L, i, LMULT);
      uint8_t *dummy = greater512 (i0, LMULT) ? LMULT : ZERO;
      sub512 (i0, dummy);
      dummy = greater512 (i0, LMULT) ? LMULT : ZERO;
      sub512 (i0, dummy);
    }

  for (unsigned int i = 0; i < 32; ++i)
    {
      out[i] = i0[i];
    }
}

void
tct_ed25519_keygen (const uint8_t *privkey, uint8_t *pubkey)
{
  uint8_t digest[64];
  tct_sha512 (privkey, 32, digest);
  digest[0] &= 0b11111000;
  digest[31] &= 0b01111111;
  digest[31] |= 0b01000000;
  const uint8_t BX[32] = {
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25,
    0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2,
    0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
  };
  const uint8_t BY[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  };
  uint8_t z[32];
  uint8_t t[32];
  uint8_t x[32];
  scalarmult (digest, BX, BY, x, pubkey, z, t);
  inv256_modp (z, z);
  mult256_modp (x, z, x);
  mult256_modp (pubkey, z, pubkey);
  pubkey[31] &= 0b01111111;
  pubkey[31] |= x[0] << 7;
}

void
tct_ed25519_sign (const uint8_t *msg, const uint64_t msg_len,
                  const uint8_t *privkey, const uint8_t *pubkey,
                  uint8_t *working_buf, uint8_t *signature)
{
  const uint8_t BX[32] = {
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25,
    0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2,
    0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
  };
  const uint8_t BY[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  };
  uint8_t digest[64];
  uint8_t s[64];
  tct_sha512 (privkey, 32, digest);
  digest[0] &= 0b11111000;
  digest[31] &= 0b01111111;
  digest[31] |= 0b01000000;
  for (unsigned int i = 0; i < 32; ++i)
    {
      working_buf[i] = digest[32 + i];
      s[i] = digest[i];
    }
  for (uint64_t i = 32; i < msg_len + 32; ++i)
    {
      working_buf[i] = msg[i - 32];
    }
  tct_sha512 (working_buf, msg_len + 32, digest);
  uint8_t r[32];
  modl512 (digest, r);
  uint8_t rBx[32];
  uint8_t rBy[32];
  uint8_t rBz[32];
  uint8_t rBt[32];
  scalarmult (r, BX, BY, rBx, rBy, rBz, rBt);
  inv256_modp (rBz, rBz);
  mult256_modp (rBz, rBx, rBx);
  mult256_modp (rBz, rBy, signature);
  signature[31] &= 0b01111111;
  signature[31] |= (rBx[0] & 1) << 7;
  for (unsigned int i = 0; i < 32; ++i)
    {
      working_buf[i] = signature[i];
      working_buf[32 + i] = pubkey[i];
    }
  for (uint64_t i = 64; i < msg_len + 64; ++i)
    {
      working_buf[i] = msg[i - 64];
    }
  tct_sha512 (working_buf, msg_len + 64, digest);
  uint8_t k[32];
  modl512 (digest, k);
  mult256 (k, s, working_buf);
  uint8_t big_r[64];
  for (unsigned int i = 0; i < 32; ++i)
    {
      big_r[i] = r[i];
      big_r[32 + i] = 0x0;
    }
  add512 (working_buf, big_r);
  modl512 (working_buf, working_buf);
  for (unsigned int i = 0; i < 32; ++i)
    {
      signature[32 + i] = working_buf[i];
    }
}

bool
tct_ed25519_verify (const uint8_t *pubkey, const uint8_t *msg,
                    const uint64_t msg_len, uint8_t *working_buf,
                    const uint8_t *signature)
{
  const uint8_t BX[32] = {
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25,
    0x95, 0x60, 0xc7, 0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2,
    0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
  };
  const uint8_t BY[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  };
  uint8_t Ax[32];
  uint8_t Ay[32];
  if (!decode256 (pubkey, Ax, Ay))
    {
      return false;
    }
  uint8_t Rx[32];
  uint8_t Ry[32];
  uint8_t Rz[32] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint8_t Rt[32];
  if (!decode256 (signature, Rx, Ry))
    {
      return false;
    }
  mult256_modp (Rx, Ry, Rt);
  uint8_t h[64];
  for (uint64_t i = 0; i < 64 + msg_len; ++i)
    {
      if (i < 32)
        {
          working_buf[i] = signature[i];
        }
      else if (i < 64)
        {
          working_buf[i] = pubkey[i - 32];
        }
      else
        {
          working_buf[i] = msg[i - 64];
        }
    }
  tct_sha512 (working_buf, 64 + msg_len, h);
  modl512 (h, h);
  uint8_t sBx[32];
  uint8_t sBy[32];
  uint8_t sBz[32];
  uint8_t sBt[32];
  uint8_t hAx[32];
  uint8_t hAy[32];
  uint8_t hAz[32];
  uint8_t hAt[32];
  scalarmult (signature + 32, BX, BY, sBx, sBy, sBz, sBt);
  scalarmult (h, Ax, Ay, hAx, hAy, hAz, hAt);
  addpoints (Rx, Ry, Rz, Rt, hAx, hAy, hAz, hAt, hAx, hAy, hAz, hAt);
  return points_eq (sBx, sBy, sBz, sBt, hAx, hAy, hAz, hAt);
}