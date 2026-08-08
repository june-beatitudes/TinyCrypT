#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/ed25519.h"
#include "tinycrypt/sha2.h"

static uint32_t
from_le32 (const uint8_t *x)
{
  uint32_t u = 0;
  for (int i = 3; i >= 0; --i)
    {
      u <<= 8;
      u |= x[i];
    }
  return u;
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
mult256 (const uint32_t *a, const uint32_t *b, uint32_t *out)
{
  uint32_t a_int[8], b_int[8];
  uint64_t intermediate[16]
      = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  for (unsigned int i = 0; i < 8; ++i)
    {
      a_int[i] = a[i];
      b_int[i] = b[i];
      out[i] = 0x0;
      out[8 + i] = 0x0;
    }
  for (unsigned int i = 0; i < 8; ++i)
    {
      for (unsigned int j = 0; j < 8; ++j)
        {
          intermediate[i + j] += (uint64_t)a_int[i] * (uint64_t)b_int[j];
          if (i + j < 15)
            {
              intermediate[i + j + 1] += intermediate[i + j] >> 32;
            }
          intermediate[i + j] &= 0xffffffff;
        }
    }
  for (unsigned int k = 0; k < 15; ++k)
    {
      intermediate[k + 1] += intermediate[k] >> 32;
      out[k] = intermediate[k] & 0xffffffff;
    }
  out[15] = intermediate[15] & 0xffffffff;
}

static void
square256 (const uint32_t *in, uint32_t *out)
{
  mult256 (in, in, out);
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
sub320 (uint32_t *h, const uint32_t *c)
{
  uint64_t acc = 0;
  for (unsigned int i = 0; i < 10; ++i)
    {
      acc += (uint64_t)(0xffffffff - h[i]) + (uint64_t)c[i];
      h[i] = 0xffffffff - (acc & 0xffffffff);
      acc >>= 32;
    }
}

static bool
greater320 (const uint32_t *a, const uint32_t *b)
{
  uint32_t buf[10];
  for (unsigned int i = 0; i < 10; ++i)
    {
      buf[i] = a[i];
    }
  sub320 (buf, b);

  return !(buf[9] >> 31);
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
fold38 (uint32_t *acc)
{
  uint32_t r[9];
  uint64_t carry = 0;
  for (unsigned int i = 0; i < 8; ++i)
    {
      uint64_t t = (uint64_t)acc[8 + i] * 38 + carry;
      r[i] = (uint32_t)t;
      carry = t >> 32;
    }
  r[8] = (uint32_t)carry;
  carry = 0;
  for (unsigned int i = 0; i < 8; ++i)
    {
      uint64_t s = (uint64_t)r[i] + acc[i] + carry;
      acc[i] = (uint32_t)s;
      carry = s >> 32;
    }
  acc[8] = (uint32_t)(r[8] + carry);
  acc[9] = acc[10] = acc[11] = acc[12] = acc[13] = acc[14] = acc[15] = 0;
}

static void
modp512 (const uint32_t *in, uint32_t *out)
{
  const uint32_t P[16] = { 0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff,
                           0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff,
                           0x0,        0x0,        0x0,        0x0,
                           0x0,        0x0,        0x0,        0x0 };
  const uint32_t P2[16] = { 0xffffffda, 0xffffffff, 0xffffffff, 0xffffffff,
                            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
                            0x0,        0x0,        0x0,        0x0,
                            0x0,        0x0,        0x0,        0x0 };

  uint32_t accumulator[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      accumulator[i] = in[i];
    }
  // Handle negatives properly
  add512 (accumulator, P);
  fold38 (accumulator);
  fold38 (accumulator);
  uint32_t mask = greater320 (accumulator, P2) * 0xffffffff;
  uint32_t dummy[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      dummy[i] = P2[i] & mask;
    }
  sub512 (accumulator, dummy);
  mask = greater256 (accumulator, P) * 0xffffffff;
  for (unsigned int i = 0; i < 16; ++i)
    {
      dummy[i] = P[i] & mask;
    }
  sub512 (accumulator, dummy);
  for (unsigned int i = 0; i < 8; ++i)
    {
      out[i] = accumulator[i];
    }
}

static void
modp512_postsub (const uint32_t *in, uint32_t *out)
{
  const uint32_t P[16] = { 0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff,
                           0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff,
                           0x0,        0x0,        0x0,        0x0,
                           0x0,        0x0,        0x0,        0x0 };
  uint32_t mask = ((in[15] & (1 << 31)) >> 31) * 0xffffffff;
  uint32_t i0[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      i0[i] = in[i];
    }
  uint32_t dummy[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      dummy[i] = P[i] & mask;
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
  const uint32_t P[16] = { 0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff,
                           0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff,
                           0x0,        0x0,        0x0,        0x0,
                           0x0,        0x0,        0x0,        0x0 };
  uint32_t mask = greater320 (in, P) * 0xffffffff;
  uint32_t i0[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      i0[i] = in[i];
    }
  uint32_t dummy[16];
  for (unsigned int i = 0; i < 16; ++i)
    {
      dummy[i] = P[i] & mask;
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
square256_modp (const uint32_t *in, uint32_t *out)
{
  uint32_t intermediate[16];
  square256 (in, intermediate);
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
inv256_modp (const uint32_t *in, uint32_t *out)
{
  uint32_t i0[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      i0[i] = in[i];
    }
  for (unsigned int i = 0; i < 254; ++i)
    {
      square256_modp (i0, i0);
      if (i != 251 && i != 249)
        {
          mult256_modp (i0, in, i0);
        }
    }
  for (unsigned int i = 0; i < 8; ++i)
    {
      out[i] = i0[i];
    }
}

static void
pow256_2523_modp (const uint32_t *in, uint32_t *out)
{
  for (unsigned int i = 0; i < 8; ++i)
    {
      out[i] = in[i];
    }
  for (int i = 250; i >= 0; --i)
    {
      square256_modp (out, out);
      if (i != 1)
        {
          mult256_modp (out, in, out);
        }
    }
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
  const uint32_t D[8] = { 0x135978a3, 0x75eb4dca, 0x4141d8ab, 0x00700a4d,
                          0x7779e898, 0x8cc74079, 0x2b6ffe73, 0x52036cee };
  const uint32_t ONE[8] = { 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
  uint32_t v[8];
  uint32_t u[8];
  uint32_t i0[8], i1[8];
  square256_modp (y, u);
  for (unsigned int i = 0; i < 8; ++i)
    {
      v[i] = u[i];
    }
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

  square256_modp (x, i0);
  mult256_modp (i0, v, i0);
  sub256_modp (i0, u, i0);
  const uint32_t mask = 0xffffffff * (!iszero256 (i0));
  const uint32_t KMULT_MINUS1[8]
      = { 0x4a0ea0af, 0xc4ee1b27, 0xad2fe478, 0x2f431806,
          0x3dfbd7a7, 0x2b4d0099, 0x4fc1df0b, 0x2b832480 };
  const uint32_t P[8] = { 0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff,
                          0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff };

  uint32_t dummy[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      dummy[i] = KMULT_MINUS1[i] & mask;
    }
  add256_modp (dummy, ONE, dummy);
  mult256_modp (x, dummy, x);
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

static void
doublepoint (const uint32_t *x1, const uint32_t *y1, const uint32_t *z1,
             const uint32_t *t1, uint32_t *x3, uint32_t *y3, uint32_t *z3,
             uint32_t *t3)
{
  uint32_t intermediates[7][8];
  mult256_modp (x1, x1, intermediates[0]);
  mult256_modp (y1, y1, intermediates[1]);
  mult256_modp (z1, z1, intermediates[2]);
  add256_modp (intermediates[2], intermediates[2], intermediates[2]);
  add256_modp (intermediates[0], intermediates[1], intermediates[3]);
  add256_modp (x1, y1, intermediates[4]);
  square256_modp (intermediates[4], intermediates[4]);
  sub256_modp (intermediates[3], intermediates[4], intermediates[4]);
  sub256_modp (intermediates[0], intermediates[1], intermediates[5]);
  add256_modp (intermediates[2], intermediates[5], intermediates[6]);
  mult256_modp (intermediates[4], intermediates[6], x3);
  mult256_modp (intermediates[3], intermediates[5], y3);
  mult256_modp (intermediates[3], intermediates[4], t3);
  mult256_modp (intermediates[5], intermediates[6], z3);
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
  uint32_t z_in[8] = { 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
  uint32_t z2[8] = { 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
  uint32_t x2[8] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
  uint32_t y2[8] = { 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
  uint32_t t2[8] = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
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
      doublepoint (x2, y2, z2, t2, x2, y2, z2, t2);
      doublepoint (x2, y2, z2, t2, x2, y2, z2, t2);
      doublepoint (x2, y2, z2, t2, x2, y2, z2, t2);
      doublepoint (x2, y2, z2, t2, x2, y2, z2, t2);
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

static uint64_t
load_3 (const uint8_t *in)
{
  return (uint64_t)in[0] | ((uint64_t)in[1] << 8) | ((uint64_t)in[2] << 16);
}

static uint64_t
load_4 (const uint8_t *in)
{
  return (uint64_t)in[0] | ((uint64_t)in[1] << 8) | ((uint64_t)in[2] << 16)
         | ((uint64_t)in[3] << 24);
}

static void
sc_reduce (unsigned char *s)
{
  int64_t s0 = 2097151 & load_3 (s);
  int64_t s1 = 2097151 & (load_4 (s + 2) >> 5);
  int64_t s2 = 2097151 & (load_3 (s + 5) >> 2);
  int64_t s3 = 2097151 & (load_4 (s + 7) >> 7);
  int64_t s4 = 2097151 & (load_4 (s + 10) >> 4);
  int64_t s5 = 2097151 & (load_3 (s + 13) >> 1);
  int64_t s6 = 2097151 & (load_4 (s + 15) >> 6);
  int64_t s7 = 2097151 & (load_3 (s + 18) >> 3);
  int64_t s8 = 2097151 & load_3 (s + 21);
  int64_t s9 = 2097151 & (load_4 (s + 23) >> 5);
  int64_t s10 = 2097151 & (load_3 (s + 26) >> 2);
  int64_t s11 = 2097151 & (load_4 (s + 28) >> 7);
  int64_t s12 = 2097151 & (load_4 (s + 31) >> 4);
  int64_t s13 = 2097151 & (load_3 (s + 34) >> 1);
  int64_t s14 = 2097151 & (load_4 (s + 36) >> 6);
  int64_t s15 = 2097151 & (load_3 (s + 39) >> 3);
  int64_t s16 = 2097151 & load_3 (s + 42);
  int64_t s17 = 2097151 & (load_4 (s + 44) >> 5);
  int64_t s18 = 2097151 & (load_3 (s + 47) >> 2);
  int64_t s19 = 2097151 & (load_4 (s + 49) >> 7);
  int64_t s20 = 2097151 & (load_4 (s + 52) >> 4);
  int64_t s21 = 2097151 & (load_3 (s + 55) >> 1);
  int64_t s22 = 2097151 & (load_4 (s + 57) >> 6);
  int64_t s23 = (load_4 (s + 60) >> 3);
  int64_t carry0, carry1, carry2, carry3, carry4, carry5, carry6, carry7,
      carry8, carry9, carry10, carry11, carry12, carry13, carry14, carry15,
      carry16;

  s11 += s23 * 666643;
  s12 += s23 * 470296;
  s13 += s23 * 654183;
  s14 -= s23 * 997805;
  s15 += s23 * 136657;
  s16 -= s23 * 683901;
  s23 = 0;
  s10 += s22 * 666643;
  s11 += s22 * 470296;
  s12 += s22 * 654183;
  s13 -= s22 * 997805;
  s14 += s22 * 136657;
  s15 -= s22 * 683901;
  s22 = 0;
  s9 += s21 * 666643;
  s10 += s21 * 470296;
  s11 += s21 * 654183;
  s12 -= s21 * 997805;
  s13 += s21 * 136657;
  s14 -= s21 * 683901;
  s21 = 0;
  s8 += s20 * 666643;
  s9 += s20 * 470296;
  s10 += s20 * 654183;
  s11 -= s20 * 997805;
  s12 += s20 * 136657;
  s13 -= s20 * 683901;
  s20 = 0;
  s7 += s19 * 666643;
  s8 += s19 * 470296;
  s9 += s19 * 654183;
  s10 -= s19 * 997805;
  s11 += s19 * 136657;
  s12 -= s19 * 683901;
  s19 = 0;
  s6 += s18 * 666643;
  s7 += s18 * 470296;
  s8 += s18 * 654183;
  s9 -= s18 * 997805;
  s10 += s18 * 136657;
  s11 -= s18 * 683901;
  s18 = 0;

  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;
  carry12 = (s12 + (1 << 20)) >> 21;
  s13 += carry12;
  s12 -= carry12 << 21;
  carry14 = (s14 + (1 << 20)) >> 21;
  s15 += carry14;
  s14 -= carry14 << 21;
  carry16 = (s16 + (1 << 20)) >> 21;
  s17 += carry16;
  s16 -= carry16 << 21;
  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 << 21;
  carry13 = (s13 + (1 << 20)) >> 21;
  s14 += carry13;
  s13 -= carry13 << 21;
  carry15 = (s15 + (1 << 20)) >> 21;
  s16 += carry15;
  s15 -= carry15 << 21;

  s5 += s17 * 666643;
  s6 += s17 * 470296;
  s7 += s17 * 654183;
  s8 -= s17 * 997805;
  s9 += s17 * 136657;
  s10 -= s17 * 683901;
  s17 = 0;
  s4 += s16 * 666643;
  s5 += s16 * 470296;
  s6 += s16 * 654183;
  s7 -= s16 * 997805;
  s8 += s16 * 136657;
  s9 -= s16 * 683901;
  s16 = 0;
  s3 += s15 * 666643;
  s4 += s15 * 470296;
  s5 += s15 * 654183;
  s6 -= s15 * 997805;
  s7 += s15 * 136657;
  s8 -= s15 * 683901;
  s15 = 0;
  s2 += s14 * 666643;
  s3 += s14 * 470296;
  s4 += s14 * 654183;
  s5 -= s14 * 997805;
  s6 += s14 * 136657;
  s7 -= s14 * 683901;
  s14 = 0;
  s1 += s13 * 666643;
  s2 += s13 * 470296;
  s3 += s13 * 654183;
  s4 -= s13 * 997805;
  s5 += s13 * 136657;
  s6 -= s13 * 683901;
  s13 = 0;
  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = (s0 + (1 << 20)) >> 21;
  s1 += carry0;
  s0 -= carry0 << 21;
  carry2 = (s2 + (1 << 20)) >> 21;
  s3 += carry2;
  s2 -= carry2 << 21;
  carry4 = (s4 + (1 << 20)) >> 21;
  s5 += carry4;
  s4 -= carry4 << 21;
  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;
  carry1 = (s1 + (1 << 20)) >> 21;
  s2 += carry1;
  s1 -= carry1 << 21;
  carry3 = (s3 + (1 << 20)) >> 21;
  s4 += carry3;
  s3 -= carry3 << 21;
  carry5 = (s5 + (1 << 20)) >> 21;
  s6 += carry5;
  s5 -= carry5 << 21;
  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 << 21;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21;
  s1 += carry0;
  s0 -= carry0 << 21;
  carry1 = s1 >> 21;
  s2 += carry1;
  s1 -= carry1 << 21;
  carry2 = s2 >> 21;
  s3 += carry2;
  s2 -= carry2 << 21;
  carry3 = s3 >> 21;
  s4 += carry3;
  s3 -= carry3 << 21;
  carry4 = s4 >> 21;
  s5 += carry4;
  s4 -= carry4 << 21;
  carry5 = s5 >> 21;
  s6 += carry5;
  s5 -= carry5 << 21;
  carry6 = s6 >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry7 = s7 >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry8 = s8 >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry9 = s9 >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry10 = s10 >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;
  carry11 = s11 >> 21;
  s12 += carry11;
  s11 -= carry11 << 21;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21;
  s1 += carry0;
  s0 -= carry0 << 21;
  carry1 = s1 >> 21;
  s2 += carry1;
  s1 -= carry1 << 21;
  carry2 = s2 >> 21;
  s3 += carry2;
  s2 -= carry2 << 21;
  carry3 = s3 >> 21;
  s4 += carry3;
  s3 -= carry3 << 21;
  carry4 = s4 >> 21;
  s5 += carry4;
  s4 -= carry4 << 21;
  carry5 = s5 >> 21;
  s6 += carry5;
  s5 -= carry5 << 21;
  carry6 = s6 >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry7 = s7 >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry8 = s8 >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry9 = s9 >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry10 = s10 >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;

  s[0] = s0 >> 0;
  s[1] = s0 >> 8;
  s[2] = (s0 >> 16) | (s1 << 5);
  s[3] = s1 >> 3;
  s[4] = s1 >> 11;
  s[5] = (s1 >> 19) | (s2 << 2);
  s[6] = s2 >> 6;
  s[7] = (s2 >> 14) | (s3 << 7);
  s[8] = s3 >> 1;
  s[9] = s3 >> 9;
  s[10] = (s3 >> 17) | (s4 << 4);
  s[11] = s4 >> 4;
  s[12] = s4 >> 12;
  s[13] = (s4 >> 20) | (s5 << 1);
  s[14] = s5 >> 7;
  s[15] = (s5 >> 15) | (s6 << 6);
  s[16] = s6 >> 2;
  s[17] = s6 >> 10;
  s[18] = (s6 >> 18) | (s7 << 3);
  s[19] = s7 >> 5;
  s[20] = s7 >> 13;
  s[21] = s8 >> 0;
  s[22] = s8 >> 8;
  s[23] = (s8 >> 16) | (s9 << 5);
  s[24] = s9 >> 3;
  s[25] = s9 >> 11;
  s[26] = (s9 >> 19) | (s10 << 2);
  s[27] = s10 >> 6;
  s[28] = (s10 >> 14) | (s11 << 7);
  s[29] = s11 >> 1;
  s[30] = s11 >> 9;
  s[31] = s11 >> 17;
}

static void
modl512 (const uint32_t *x, uint32_t *out)
{
  uint8_t s[64];
  for (unsigned int i = 0; i < 16; ++i)
    {
      to_le32 (x[i], s + 4 * i);
    }
  sc_reduce (s);
  for (unsigned int i = 0; i < 8; ++i)
    {
      out[i] = from_le32 (s + 4 * i);
    }
}

static void
xB_lowmem (const uint32_t *k, uint32_t *x, uint32_t *y, uint32_t *z,
           uint32_t *t)
{
  const uint32_t BX[8] = { 0x8f25d51a, 0xc9562d60, 0x9525a7b2, 0x692cc760,
                           0xfdd6dc5c, 0xc0a4e231, 0xcd6e53fe, 0x216936d3 };
  const uint32_t BY[8] = { 0x66666658, 0x66666666, 0x66666666, 0x66666666,
                           0x66666666, 0x66666666, 0x66666666, 0x66666666 };
  scalarmult (k, BX, BY, x, y, z, t);
}

static void
xB (const uint32_t *k, uint32_t *x, uint32_t *y, uint32_t *z, uint32_t *t)
{
  xB_lowmem (k, x, y, z, t);
}

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
  uint32_t grantaire[16];
  for (unsigned int i = 0; i < 8; ++i)
    {
      grantaire[i] = r[i];
      grantaire[8 + i] = 0x0;
    }
  add512 (chunked, grantaire);
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
  uint32_t Rz[8] = { 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
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
  const uint32_t L[8] = { 0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de,
                          0x00000000, 0x00000000, 0x00000000, 0x10000000 };
  xB (sigk, sBx, sBy, sBz, sBt);
  scalarmult (chunked, Ax, Ay, hAx, hAy, hAz, hAt);
  addpoints (Rx, Ry, Rz, Rt, hAx, hAy, hAz, hAt, hAx, hAy, hAz, hAt);
  bool s_in_range = greater256(L, sigk);
  bool correct_sig = points_eq (sBx, sBy, sBz, sBt, hAx, hAy, hAz, hAt);
  return s_in_range && correct_sig;
}
