#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/ed25519.h"
#include "tinycrypt/sha2.h"

static uint32_t
from_le32 (const uint8_t *x)
{
  uint32_t u = x[3];
  u = (u << 8) | x[2];
  u = (u << 8) | x[1];
  return (u << 8) | x[0];
}

static void
to_le32 (const uint32_t x, uint8_t *out)
{
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = (x >> (8 * i)) & 0xff;
    }
}

static void
add_shifted (uint32_t *h, const uint64_t c, const unsigned int shift)
{
  uint32_t digits[2];
  digits[0] = c & 0xffffffff;
  digits[1] = (c >> 32) & 0xffffffff;
  uint64_t accumulator = 0;
  unsigned int i;
  for (i = shift; i < shift + 2 && i < 16; ++i)
    {
      accumulator += (uint64_t)digits[i - shift] + (uint64_t)h[i];
      h[i] = accumulator & 0xffffffff;
      accumulator >>= 32;
    }
  while (i < 16)
    {
      accumulator += (uint64_t)h[i];
      h[i] = accumulator & 0xffffffff;
      accumulator >>= 32;
      ++i;
    }
}

static void
mult256 (const uint32_t *a, const uint32_t *b, uint32_t *out)
{
  // Literal long multiplication
  for (unsigned int i = 0; i < 16; ++i)
    {
      out[i] = 0x0;
    }
  for (unsigned int i = 0; i < 8; ++i)
    {
      for (unsigned int j = 0; j < 8; ++j)
        {
          uint64_t prod = (uint64_t)a[i] * (uint64_t)b[j];
          add_shifted (out, prod, i + j);
        }
    }
}

static bool
iszero256 (const uint32_t *a)
{
  uint32_t dummy = 0x0;
  for (unsigned int i = 0; i < 8; ++i)
    {
      dummy |= a[i];
    }
  return !dummy;
}

static void
sub288 (uint32_t *h, const uint32_t *c)
{
  uint64_t acc = 0;
  for (unsigned int i = 0; i < 9; ++i)
    {
      acc += (uint64_t)(0xffffffff - h[i]) + (uint64_t)c[i];
      h[i] = 0xffffffff - (acc & 0xffffffff);
      acc >>= 32;
    }
}

static bool
greater288 (const uint32_t *a, const uint32_t *b)
{
  uint32_t buf[9];
  for (unsigned int i = 0; i < 9; ++i)
    {
      buf[i] = a[i];
    }
  sub288 (buf, b);

  return !(buf[8] & (1 << 31));
}

static void
sub256 (uint32_t *h, const uint32_t *c)
{
  uint64_t acc = 0;
  for (unsigned int i = 0; i < 8; ++i)
    {
      acc += (uint64_t)(0xffffffff - h[i]) + (uint64_t)c[i];
      h[i] = 0xffffffff - (acc & 0xffffffff);
      acc >>= 32;
    }
}

static bool
greater256 (const uint32_t *a, const uint32_t *b)
{
  uint32_t buf[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      buf[i] = a[i];
    }
  sub256 (buf, b);

  return !(buf[7] & (1 << 31));
}

static void
add512 (uint32_t *h, const uint32_t *c)
{
  uint64_t acc = 0;
  for (unsigned int i = 0; i < 16; ++i)
    {
      acc += (uint64_t)h[i] + (uint64_t)c[i];
      h[i] = acc & 0xffffffff;
      acc >>= 32;
    }
}

static void
sub512 (uint32_t *h, const uint32_t *c)
{
  uint64_t acc = 0;
  for (unsigned int i = 0; i < 16; ++i)
    {
      acc += (uint64_t)(0xffffffff - h[i]) + (uint64_t)c[i];
      h[i] = 0xffffffff - (acc & 0xffffffff);
      acc >>= 32;
    }
}

static void
sub534 (uint32_t *h, const uint32_t *c)
{
  uint64_t acc = 0;
  for (unsigned int i = 0; i < 17; ++i)
    {
      acc += (uint64_t)(0xffffffff - h[i]) + (uint64_t)c[i];
      h[i] = 0xffffffff - (acc & 0xffffffff);
      acc >>= 32;
    }
}

static bool
greater512_unsigned (const uint32_t *a, const uint32_t *b)
{
  uint32_t a_int[17], b_int[17];
  for (unsigned int i = 0; i < 16; ++i)
    {
      a_int[i] = a[i];
      b_int[i] = b[i];
    }
  a_int[16] = 0x0;
  b_int[16] = 0x0;
  sub534 (a_int, b_int);

  return !(a_int[16] & (1 << 31));
}

static void
modp512 (const uint32_t *in, uint32_t *out)
{
  uint32_t P[16] = {
    0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0x7fffffff, 0x0,        0x0,        0x0,        0x0,
    0x0,        0x0,        0x0,        0x0,
  };
  uint32_t P2[16] = {
    0xffffffda, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0x0,        0x0,        0x0,        0x0,
    0x0,        0x0,        0x0,        0x0,
  };
  uint32_t ZERO[16] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t approx_dividend[16];
  uint32_t accumulator[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      accumulator[i] = in[i];
    }
  // Handle negatives properly
  add512 (accumulator, P);
  for (unsigned int i = 0; i < 2; ++i)
    {
      mult256 (P2, accumulator + 8, approx_dividend);
      sub512 (accumulator, approx_dividend);
    }
  uint32_t *dummy = (greater288 (accumulator, P2)) ? P2 : ZERO;
  sub512 (accumulator, dummy);
  dummy = greater256 (accumulator, P) ? P : ZERO;
  sub256 (accumulator, dummy);
  for (unsigned int i = 0; i < 8; ++i)
    {
      out[i] = accumulator[i];
    }
}

static void
modp512_postsub (const uint32_t *in, uint32_t *out)
{
  uint32_t P[16] = {
    0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0x7fffffff, 0x0,        0x0,        0x0,        0x0,
    0x0,        0x0,        0x0,        0x0,
  };
  uint32_t ZERO[16] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t *dummy = (in[15] & (1 << 31)) ? P : ZERO;
  uint32_t i0[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      i0[i] = in[i];
    }
  add512 (i0, dummy);
  for (unsigned int i = 0; i < 8; ++i)
    {
      out[i] = i0[i];
    }
}

static void
modp512_postadd (const uint32_t *in, uint32_t *out)
{
  uint32_t P[16] = {
    0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0x7fffffff, 0x0,        0x0,        0x0,        0x0,
    0x0,        0x0,        0x0,        0x0,
  };
  uint32_t ZERO[16] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t *dummy = greater288 (in, P) ? P : ZERO;
  uint32_t i0[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      i0[i] = in[i];
    }
  sub512 (i0, dummy);
  for (unsigned int i = 0; i < 8; ++i)
    {
      out[i] = i0[i];
    }
}

static void
mult256_modp (const uint32_t *a, const uint32_t *b, uint32_t *out)
{
  uint32_t intermediate[16];
  mult256 (a, b, intermediate);
  modp512 (intermediate, out);
}

static void
sub256_modp (const uint32_t *a, const uint32_t *b, uint32_t *out)
{
  uint32_t intermediates[2][16];
  for (unsigned int i = 0; i < 8; ++i)
    {
      intermediates[0][i] = a[i];
      intermediates[1][i] = b[i];
    }
  for (unsigned int i = 8; i < 16; ++i)
    {
      intermediates[0][i] = 0x0;
      intermediates[1][i] = 0x0;
    }
  sub512 (intermediates[0], intermediates[1]);
  modp512_postsub (intermediates[0], out);
}

static void
add256_modp (const uint32_t *a, const uint32_t *b, uint32_t *out)
{
  uint32_t intermediates[2][16];
  for (unsigned int i = 0; i < 8; ++i)
    {
      intermediates[0][i] = a[i];
      intermediates[1][i] = b[i];
    }
  for (unsigned int i = 8; i < 16; ++i)
    {
      intermediates[0][i] = 0x0;
      intermediates[1][i] = 0x0;
    }
  add512 (intermediates[0], intermediates[1]);
  modp512_postadd (intermediates[0], out);
}

static void
to_montgomery (const uint32_t *in, uint32_t *out)
{
  uint32_t buf[16];
  for (unsigned int i = 0; i < 8; ++i)
    {
      buf[8 + i] = in[i];
      buf[i] = 0x0;
    }
  modp512 (buf, out);
}

static void
from_montgomery (const uint32_t *in, uint32_t *out)
{
  const uint32_t RECIPROCAL[8] = {
    0x9435e50a, 0x435e50d7, 0x35e50d79, 0x5e50d794,
    0xe50d7943, 0x50d79435, 0x0d79435e, 0x179435e5,
  };
  mult256_modp (RECIPROCAL, in, out);
}

static void
montgomery_multiply (const uint32_t *a, const uint32_t *b, uint32_t *out)
{
  uint32_t P[8] = {
    0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff,
  };
  uint32_t FACTOR[8] = {
    0x286bca1b, 0x86bca1af, 0x6bca1af2, 0xbca1af28,
    0xca1af286, 0xa1af286b, 0x1af286bc, 0x2f286bca,
  };
  uint32_t ZERO[8] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t prod[16];
  mult256 (a, b, prod);
  uint32_t i0[16], i1[16];
  mult256 (prod, FACTOR, i0);
  mult256 (i0, P, i1);
  add512 (i1, prod);
  uint32_t *dummy = greater256 (i1 + 8, P) ? P : ZERO;
  sub256 (i1 + 8, dummy);
  for (unsigned int i = 0; i < 8; ++i)
    {
      out[i] = i1[i + 8];
    }
}

static void
inv256_modp (const uint32_t *x, uint32_t *out)
{
  uint32_t i0[8];
  uint32_t x_red[8];
  to_montgomery (x, i0);
  for (unsigned int i = 0; i < 8; ++i)
    {
      x_red[i] = i0[i];
    }
  for (unsigned int i = 0; i < 254; ++i)
    {
      montgomery_multiply (i0, i0, i0);
      if (i != 251 && i != 249)
        {
          montgomery_multiply (i0, x_red, i0);
        }
    }
  from_montgomery (i0, out);
}

static void
pow256_2523_modp (const uint32_t *in, uint32_t *out)
{
  uint32_t i0[8];
  to_montgomery (in, i0);
  uint32_t in_red[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      in_red[i] = i0[i];
    }
  for (int i = 250; i >= 0; --i)
    {
      montgomery_multiply (i0, i0, i0);
      if (i != 1)
        {
          montgomery_multiply (i0, in_red, i0);
        }
    }
  from_montgomery (i0, out);
}

static bool
decode256 (const uint8_t *point, uint32_t *x, uint32_t *y)
{
  bool x0 = (point[31] & 0x80) != 0;
  for (unsigned int i = 0; i < 8; ++i)
    {
      y[i] = from_le32 (point + 4 * i);
    }
  y[7] &= 0x7fffffff;
  const uint32_t D[8] = {
    0x135978a3, 0x75eb4dca, 0x4141d8ab, 0x00700a4d,
    0x7779e898, 0x8cc74079, 0x2b6ffe73, 0x52036cee,
  };
  const uint32_t ONE[8] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t v[8];
  uint32_t u[8];
  uint32_t i0[8], i1[8];
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
  const uint32_t *mask;
  const uint32_t KMULT[8] = {
    0x4a0ea0b0, 0xc4ee1b27, 0xad2fe478, 0x2f431806,
    0x3dfbd7a7, 0x2b4d0099, 0x4fc1df0b, 0x2b832480,
  };
  uint32_t P[8] = {
    0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff,
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
addpoints (const uint32_t *x1, const uint32_t *y1, const uint32_t *z1,
           const uint32_t *t1, const uint32_t *x2, const uint32_t *y2,
           const uint32_t *z2, const uint32_t *t2, uint32_t *x3, uint32_t *y3,
           uint32_t *z3, uint32_t *t3)
{
  const uint32_t TWO[8] = {
    0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  const uint32_t D[8] = {
    0x135978a3, 0x75eb4dca, 0x4141d8ab, 0x00700a4d,
    0x7779e898, 0x8cc74079, 0x2b6ffe73, 0x52036cee,
  };
  uint32_t intermediates[8][8];
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
points_eq (const uint32_t *x1, const uint32_t *y1, const uint32_t *z1,
           const uint32_t *t1, const uint32_t *x2, const uint32_t *y2,
           const uint32_t *z2, const uint32_t *t2)
{
  uint32_t i0[8], i1[8];
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
scalarmult (const uint32_t *k, const uint32_t *x_in, const uint32_t *y_in,
            uint32_t *x_out, uint32_t *y_out, uint32_t *z_out, uint32_t *t_out)
{
  uint32_t t_in[8];
  mult256_modp (x_in, y_in, t_in);
  uint32_t z_in[8] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t z2[8] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t x2[8] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t y2[8] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t t2[8] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t lut[16][4][8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      lut[0][0][i] = 0x0;
      lut[0][1][i] = 0x0;
      lut[0][2][i] = 0x0;
      lut[0][3][i] = 0x0;
    }
  lut[0][1][0] = 0x1;
  lut[0][2][0] = 0x1;
  for (unsigned int i = 1; i < 16; ++i)
    {
      addpoints (lut[i - 1][0], lut[i - 1][1], lut[i - 1][2], lut[i - 1][3],
                 x_in, y_in, z_in, t_in, lut[i][0], lut[i][1], lut[i][2],
                 lut[i][3]);
    }
  for (int i = 63; i >= 0; --i)
    {
      addpoints (x2, y2, z2, t2, x2, y2, z2, t2, x2, y2, z2, t2);
      addpoints (x2, y2, z2, t2, x2, y2, z2, t2, x2, y2, z2, t2);
      addpoints (x2, y2, z2, t2, x2, y2, z2, t2, x2, y2, z2, t2);
      addpoints (x2, y2, z2, t2, x2, y2, z2, t2, x2, y2, z2, t2);
      uint8_t ind = (k[i / 8] >> (4 * (i % 8))) & 0xf;
      addpoints (lut[ind][0], lut[ind][1], lut[ind][2], lut[ind][3], x2, y2,
                 z2, t2, x2, y2, z2, t2);
    }
  for (unsigned int i = 0; i < 8; ++i)
    {
      x_out[i] = x2[i];
      y_out[i] = y2[i];
      z_out[i] = z2[i];
      t_out[i] = t2[i];
    }
}

static void
shl512 (const uint32_t *in, const uint64_t shift, uint32_t *out)
{
  for (uint64_t i = 0; i < 16; ++i)
    {
      out[i] = 0x0;
    }
  uint64_t shift_amt = shift % 32;
  for (uint64_t i = 0; i < 16 - shift / 32; ++i)
    {
      out[i + shift / 32] = in[i] << shift_amt;
      if (i > 0 && shift_amt != 0)
        {
          out[i + shift / 32] |= in[i - 1] >> (32 - shift_amt);
        }
    }
}

static void
modl512 (const uint32_t *x, uint32_t *out)
{
  uint32_t L[16] = {
    0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0x00000000, 0x00000000,
    0x00000000, 0x10000000, 0x0,        0x0,        0x0,        0x0,
    0x0,        0x0,        0x0,        0x0,
  };
  uint32_t LMULT[16];
  uint32_t ZERO[16] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t i0[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      i0[i] = x[i];
    }
  for (int i = 259; i >= 0; --i)
    {
      shl512 (L, i, LMULT);
      uint32_t *dummy = greater512_unsigned (i0, LMULT) ? LMULT : ZERO;
      sub512 (i0, dummy);
      dummy = greater512_unsigned (i0, LMULT) ? LMULT : ZERO;
      sub512 (i0, dummy);
    }

  for (unsigned int i = 0; i < 8; ++i)
    {
      out[i] = i0[i];
    }
}

static void
xB_lowmem (const uint32_t *k, uint32_t *x, uint32_t *y, uint32_t *z,
           uint32_t *t)
{
  const uint32_t BX[8] = {
    0x8f25d51a, 0xc9562d60, 0x9525a7b2, 0x692cc760,
    0xfdd6dc5c, 0xc0a4e231, 0xcd6e53fe, 0x216936d3,
  };
  const uint32_t BY[8] = {
    0x66666658, 0x66666666, 0x66666666, 0x66666666,
    0x66666666, 0x66666666, 0x66666666, 0x66666666,
  };
  scalarmult (k, BX, BY, x, y, z, t);
}

void
tct_ed25519_pctable_gen (uint32_t *out)
{
  uint32_t a[16], b[16];
  for (unsigned int i = 0; i < 8; ++i)
    {
      a[i] = 0x0;
      a[8 + i] = 0x0;
    }
  a[0] = b[0] = 0x1;
  uint32_t t[8], z[8];
  for (unsigned int i = 0; i < 64; ++i)
    {
      modl512 (a, a);
      modl512 (a, b);
      if (iszero256 (a) && iszero256 (a + 8))
        {
          a[0] = b[0] = 0x1;
        }
      for (unsigned int j = 8; j < 16; ++j)
        {
          a[j] = b[j] = 0x0;
        }
      for (unsigned int j = 0; j < 15; ++j)
        {
          // We don't need `t` where we're going
          uint32_t *x_out = &(out[15 * 8 * 2 * i + 8 * 2 * j]);
          uint32_t *y_out = &(out[15 * 8 * 2 * i + 8 * 2 * j + 8]);
          xB_lowmem (a, x_out, y_out, z, t);
          uint32_t z_inv[8];
          inv256_modp (z, z_inv);
          mult256_modp (x_out, z_inv, x_out);
          mult256_modp (y_out, z_inv, y_out);
          add512 (a, b);
        }
    }
}

#ifndef TCT_LOWMEM

#include "tinycrypt/portable/ed25519_precompute.h"

static void
xB (const uint32_t *k, uint32_t *x, uint32_t *y, uint32_t *z, uint32_t *t)
{
  uint32_t ONE[8] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  for (unsigned int i = 0; i < 8; ++i)
    {
      x[i] = y[i] = z[i] = t[i] = 0x0;
    }
  y[0] = 1;
  z[0] = 1;
  for (unsigned int i = 0; i < 64; ++i)
    {
      uint32_t ri = (k[i / 8] >> (4 * (i % 8))) & 0xf;
      uint32_t t0[8];
      if (ri != 0)
        {
          mult256_modp (
              &PRECOMPUTE_TABLE[i * 15 * 8 * 2 + (ri - 1) * 8 * 2],
              &PRECOMPUTE_TABLE[i * 15 * 8 * 2 + (ri - 1) * 8 * 2 + 8], t0);
          addpoints (x, y, z, t,
                     &PRECOMPUTE_TABLE[i * 15 * 8 * 2 + (ri - 1) * 8 * 2],
                     &PRECOMPUTE_TABLE[i * 15 * 8 * 2 + (ri - 1) * 8 * 2 + 8],
                     ONE, t0, x, y, z, t);
        }
    }
}

#else

static void
xB (const uint32_t *k, uint32_t *x, uint32_t *y, uint32_t *z, uint32_t *t)
{
  xB_lowmem (k, x, y, z, t);
}

#endif

void
tct_ed25519_keygen (const uint8_t *privkey, uint8_t *pubkey)
{
  uint8_t digest[64];
  tct_sha512 (privkey, 32, digest);
  digest[0] &= 0b11111000;
  digest[31] &= 0b01111111;
  digest[31] |= 0b01000000;
  uint32_t k[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      k[i] = from_le32 (digest + 4 * i);
    }
  uint32_t y[8];
  uint32_t z[8];
  uint32_t t[8];
  uint32_t x[8];
  xB (k, x, y, z, t);
  inv256_modp (z, z);
  mult256_modp (x, z, x);
  mult256_modp (y, z, y);
  for (unsigned int i = 0; i < 8; ++i)
    {
      to_le32 (y[i], pubkey + 4 * i);
    }
  pubkey[31] &= 0b01111111;
  pubkey[31] |= x[0] << 7;
}

void
tct_ed25519_sign (const uint8_t *msg, const uint64_t msg_len,
                  const uint8_t *privkey, const uint8_t *pubkey,
                  uint8_t *working_buf, uint8_t *signature)
{
  uint8_t digest[64];
  uint32_t s[8];
  tct_sha512 (privkey, 32, digest);
  digest[0] &= 0b11111000;
  digest[31] &= 0b01111111;
  digest[31] |= 0b01000000;
  for (unsigned int i = 0; i < 32; ++i)
    {
      working_buf[i] = digest[32 + i];
    }
  for (unsigned int i = 0; i < 8; ++i)
    {
      s[i] = from_le32 (digest + i * 4);
    }
  for (uint64_t i = 32; i < msg_len + 32; ++i)
    {
      working_buf[i] = msg[i - 32];
    }
  tct_sha512 (working_buf, msg_len + 32, digest);
  uint32_t r[8];
  uint32_t chunked[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      chunked[i] = from_le32 (digest + i * 4);
    }
  modl512 (chunked, r);
  uint32_t rBx[8];
  uint32_t rBy[8];
  uint32_t rBz[8];
  uint32_t rBt[8];
  xB (r, rBx, rBy, rBz, rBt);
  inv256_modp (rBz, rBz);
  mult256_modp (rBz, rBx, rBx);
  mult256_modp (rBz, rBy, chunked);
  for (unsigned int i = 0; i < 8; ++i)
    {
      to_le32 (chunked[i], signature + 4 * i);
    }
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
  uint32_t k[8];
  for (unsigned int i = 0; i < 16; ++i)
    {
      chunked[i] = from_le32 (digest + 4 * i);
    }
  modl512 (chunked, k);
  mult256 (k, s, chunked);
  uint32_t big_r[16];
  for (unsigned int i = 0; i < 8; ++i)
    {
      big_r[i] = r[i];
      big_r[8 + i] = 0x0;
    }
  add512 (chunked, big_r);
  modl512 (chunked, chunked);
  for (unsigned int i = 0; i < 8; ++i)
    {
      to_le32 (chunked[i], 32 + signature + 4 * i);
    }
}

bool
tct_ed25519_verify (const uint8_t *pubkey, const uint8_t *msg,
                    const uint64_t msg_len, uint8_t *working_buf,
                    const uint8_t *signature)
{
  uint32_t Ax[8];
  uint32_t Ay[8];
  if (!decode256 (pubkey, Ax, Ay))
    {
      return false;
    }
  uint32_t Rx[8];
  uint32_t Ry[8];
  uint32_t Rz[8] = {
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint32_t Rt[8];
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
  uint32_t chunked[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      chunked[i] = from_le32 (h + i * 4);
    }
  modl512 (chunked, chunked);
  uint32_t sBx[8];
  uint32_t sBy[8];
  uint32_t sBz[8];
  uint32_t sBt[8];
  uint32_t hAx[8];
  uint32_t hAy[8];
  uint32_t hAz[8];
  uint32_t hAt[8];
  uint32_t sigk[16];
  for (unsigned int i = 0; i < 8; ++i)
    {
      sigk[i] = from_le32 (signature + 32 + 4 * i);
      sigk[8 + i] = 0x0;
    }
  modl512 (sigk, sigk);
  xB (sigk, sBx, sBy, sBz, sBt);
  scalarmult (chunked, Ax, Ay, hAx, hAy, hAz, hAt);
  addpoints (Rx, Ry, Rz, Rt, hAx, hAy, hAz, hAt, hAx, hAy, hAz, hAt);
  return points_eq (sBx, sBy, sBz, sBt, hAx, hAy, hAz, hAt);
}