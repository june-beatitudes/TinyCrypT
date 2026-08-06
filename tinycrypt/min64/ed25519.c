#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/ed25519.h"
#include "tinycrypt/sha2.h"

static uint64_t
from_le64 (const uint8_t *x)
{
  uint64_t u = 0;
  for (int i = 7; i >= 0; --i)
    {
      u <<= 8;
      u |= x[i];
    }
  return u;
}

static void
to_le64 (const uint64_t x, uint8_t *out)
{
  for (unsigned int i = 0; i < 8; ++i)
    {
      out[i] = (x >> (8 * i)) & 0xff;
    }
}

static void
mult256 (const uint64_t *a, const uint64_t *b, uint64_t *out)
{
  uint64_t a_int[4], b_int[4];
  __uint128_t intermediate[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
  for (unsigned int i = 0; i < 4; ++i)
    {
      a_int[i] = a[i];
      b_int[i] = b[i];
      out[i] = 0x0;
      out[4 + i] = 0x0;
    }
  for (unsigned int i = 0; i < 4; ++i)
    {
      for (unsigned int j = 0; j < 4; ++j)
        {
          intermediate[i + j] += (__uint128_t)a_int[i] * (__uint128_t)b_int[j];
          if (i + j < 7)
            {
              intermediate[i + j + 1] += intermediate[i + j] >> 64;
            }
          intermediate[i + j] &= 0xffffffffffffffff;
        }
    }
  for (unsigned int k = 0; k < 7; ++k)
    {
      intermediate[k + 1] += intermediate[k] >> 64;
      out[k] = intermediate[k] & 0xffffffffffffffff;
    }
  out[7] = intermediate[7] & 0xffffffffffffffff;
}

static void
square256 (const uint64_t *in, uint64_t *out)
{
  uint64_t a_int[4];
  __uint128_t intermediate[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
  for (unsigned int i = 0; i < 4; ++i)
    {
      a_int[i] = in[i];
      out[i] = 0x0;
      out[4 + i] = 0x0;
    }
  for (unsigned int i = 0; i < 4; ++i)
    {
      intermediate[2 * i] += (__uint128_t)a_int[i] * (__uint128_t)a_int[i];
      intermediate[2 * i + 1] += intermediate[2 * i] >> 64;
      intermediate[2 * i] &= 0xffffffffffffffff;
      for (unsigned int j = i + 1; j < 4; ++j)
        {
          __uint128_t prod = (__uint128_t)a_int[i] * (__uint128_t)a_int[j];
          intermediate[i + j] += prod;
          if (i + j < 7)
            {
              intermediate[i + j + 1] += intermediate[i + j] >> 64;
            }
          intermediate[i + j] &= 0xffffffffffffffff;
          intermediate[i + j] += prod;
          if (i + j < 7)
            {
              intermediate[i + j + 1] += intermediate[i + j] >> 64;
            }
          intermediate[i + j] &= 0xffffffffffffffff;
        }
    }
  for (unsigned int k = 0; k < 7; ++k)
    {
      intermediate[k + 1] += intermediate[k] >> 64;
      out[k] = intermediate[k] & 0xffffffffffffffff;
    }
  out[7] = intermediate[7] & 0xffffffffffffffff;
}

static bool
iszero256 (const uint64_t *a)
{
  uint64_t dummy = 0x0;
  for (unsigned int i = 0; i < 4; ++i)
    {
      dummy |= a[i];
    }
  return !dummy;
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

static bool
greater320 (const uint64_t *a, const uint64_t *b)
{
  uint64_t buf[5];
  for (unsigned int i = 0; i < 5; ++i)
    {
      buf[i] = a[i];
    }
  sub320 (buf, b);

  return !(buf[4] >> 63);
}

static void
sub256 (uint64_t *h, const uint64_t *c)
{
  __uint128_t acc = 0;
  for (unsigned int i = 0; i < 4; ++i)
    {
      acc += (__uint128_t)(0xffffffffffffffff - h[i]) + (__uint128_t)c[i];
      h[i] = 0xffffffffffffffff - (acc & 0xffffffffffffffff);
      acc >>= 64;
    }
}

static bool
greater256 (const uint64_t *a, const uint64_t *b)
{
  uint64_t buf[4];
  for (unsigned int i = 0; i < 4; ++i)
    {
      buf[i] = a[i];
    }
  sub256 (buf, b);

  return !(buf[3] >> 63);
}

static void
add512 (uint64_t *h, const uint64_t *c)
{
  __uint128_t acc = 0;
  for (unsigned int i = 0; i < 8; ++i)
    {
      acc += (__uint128_t)h[i] + (__uint128_t)c[i];
      h[i] = acc & 0xffffffffffffffff;
      acc >>= 64;
    }
}

static void
sub512 (uint64_t *h, const uint64_t *c)
{
  __uint128_t acc = 0;
  for (unsigned int i = 0; i < 8; ++i)
    {
      acc += (__uint128_t)(0xffffffffffffffff - h[i]) + (__uint128_t)c[i];
      h[i] = 0xffffffffffffffff - (acc & 0xffffffffffffffff);
      acc >>= 64;
    }
}

static void
fold38 (uint64_t *acc)
{
  uint64_t r[5];
  __uint128_t carry = 0;
  for (unsigned int i = 0; i < 4; ++i)
    {
      __uint128_t t = (__uint128_t)acc[4 + i] * 38 + carry;
      r[i] = (uint64_t)t;
      carry = t >> 64;
    }
  r[4] = (uint64_t)carry;
  __uint128_t c2 = 0;
  for (unsigned int i = 0; i < 4; ++i)
    {
      __uint128_t s = (__uint128_t)r[i] + acc[i] + c2;
      acc[i] = (uint64_t)s;
      c2 = s >> 64;
    }
  acc[4] = (uint64_t)(r[4] + c2);
  acc[5] = acc[6] = acc[7] = 0;
}

static void
modp512 (const uint64_t *in, uint64_t *out)
{
  uint64_t P[8] = {
    0xffffffffffffffed,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
    0x0,
    0x0,
    0x0,
    0x0,
  };
  uint64_t P2[8] = {
    0xffffffffffffffda,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x0,
    0x0,
    0x0,
    0x0,
  };
  uint64_t ZERO[8] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint64_t accumulator[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      accumulator[i] = in[i];
    }
  // Handle negatives properly
  add512 (accumulator, P);
  fold38 (accumulator);
  fold38 (accumulator);
  uint64_t *dummy = greater320 (accumulator, P2) ? P2 : ZERO;
  sub512 (accumulator, dummy);
  dummy = greater256 (accumulator, P) ? P : ZERO;
  sub256 (accumulator, dummy);
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = accumulator[i];
    }
}

static void
modp512_postsub (const uint64_t *in, uint64_t *out)
{
  uint64_t P[8] = {
    0xffffffffffffffed,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
    0x0,
    0x0,
    0x0,
    0x0,
  };
  uint64_t ZERO[8] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint64_t *dummy = (in[7] & (1ULL << 63)) ? P : ZERO;
  uint64_t i0[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      i0[i] = in[i];
    }
  add512 (i0, dummy);
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = i0[i];
    }
}

static void
modp512_postadd (const uint64_t *in, uint64_t *out)
{
  uint64_t P[8] = {
    0xffffffffffffffed,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
    0x0,
    0x0,
    0x0,
    0x0,
  };
  uint64_t ZERO[8] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint64_t *dummy = greater320 (in, P) ? P : ZERO;
  uint64_t i0[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      i0[i] = in[i];
    }
  sub512 (i0, dummy);
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = i0[i];
    }
}

static void
mult256_modp (const uint64_t *a, const uint64_t *b, uint64_t *out)
{
  uint64_t intermediate[8];
  mult256 (a, b, intermediate);
  modp512 (intermediate, out);
}

static void
square256_modp (const uint64_t *in, uint64_t *out)
{
  uint64_t intermediate[8];
  square256 (in, intermediate);
  modp512 (intermediate, out);
}

static void
sub256_modp (const uint64_t *a, const uint64_t *b, uint64_t *out)
{
  uint64_t intermediates[2][8];
  for (unsigned int i = 0; i < 4; ++i)
    {
      intermediates[0][i] = a[i];
      intermediates[1][i] = b[i];
    }
  for (unsigned int i = 4; i < 8; ++i)
    {
      intermediates[0][i] = 0x0;
      intermediates[1][i] = 0x0;
    }
  sub512 (intermediates[0], intermediates[1]);
  modp512_postsub (intermediates[0], out);
}

static void
add256_modp (const uint64_t *a, const uint64_t *b, uint64_t *out)
{
  uint64_t intermediates[2][8];
  for (unsigned int i = 0; i < 4; ++i)
    {
      intermediates[0][i] = a[i];
      intermediates[1][i] = b[i];
    }
  for (unsigned int i = 4; i < 8; ++i)
    {
      intermediates[0][i] = 0x0;
      intermediates[1][i] = 0x0;
    }
  add512 (intermediates[0], intermediates[1]);
  modp512_postadd (intermediates[0], out);
}

static void
inv256_modp (const uint64_t *in, uint64_t *out)
{
  uint64_t i0[4];
  for (unsigned int i = 0; i < 4; ++i)
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
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = i0[i];
    }
}

static void
pow256_2523_modp (const uint64_t *in, uint64_t *out)
{
  for (unsigned int i = 0; i < 4; ++i)
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
decode256 (const uint8_t *point, uint64_t *x, uint64_t *y)
{
  bool x0 = (point[31] & 0x80) != 0;
  for (unsigned int i = 0; i < 4; ++i)
    {
      y[i] = from_le64 (point + 8 * i);
    }
  y[3] &= 0x7fffffffffffffff;
  const uint64_t D[4] = {
    0x75eb4dca135978a3,
    0x00700a4d4141d8ab,
    0x8cc740797779e898,
    0x52036cee2b6ffe73,
  };
  const uint64_t ONE[4] = {
    0x1,
    0x0,
    0x0,
    0x0,
  };
  uint64_t v[4];
  uint64_t u[4];
  uint64_t i0[4], i1[4];
  square256_modp (y, u);
  for (unsigned int i = 0; i < 4; ++i)
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
  const uint64_t *mask;
  const uint64_t KMULT[4] = {
    0xc4ee1b274a0ea0b0,
    0x2f431806ad2fe478,
    0x2b4d00993dfbd7a7,
    0x2b8324804fc1df0b,
  };
  uint64_t P[4] = {
    0xffffffffffffffed,
    0xffffffffffffffff,
    0xffffffffffffffff,
    0x7fffffffffffffff,
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
addpoints (const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
           const uint64_t *t1, const uint64_t *x2, const uint64_t *y2,
           const uint64_t *z2, const uint64_t *t2, uint64_t *x3, uint64_t *y3,
           uint64_t *z3, uint64_t *t3)
{
  const uint64_t TWO[4] = {
    0x2,
    0x0,
    0x0,
    0x0,
  };
  const uint64_t D2[4] = { 0xebd69b9426b2f146, 0x00e0149a8283b156,
                           0x198e80f2eef3d130, 0xa406d9dc56dffce7 };
  uint64_t intermediates[8][4];
  sub256_modp (y1, x1, intermediates[0]);
  sub256_modp (y2, x2, intermediates[1]);
  mult256_modp (intermediates[0], intermediates[1], intermediates[0]);
  add256_modp (y1, x1, intermediates[1]);
  add256_modp (y2, x2, intermediates[2]);
  mult256_modp (intermediates[1], intermediates[2], intermediates[1]);
  mult256_modp (t1, t2, intermediates[2]);
  mult256_modp (intermediates[2], D2, intermediates[2]);
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
doublepoint (const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
             const uint64_t *t1, uint64_t *x3, uint64_t *y3, uint64_t *z3,
             uint64_t *t3)
{
  uint64_t intermediates[7][4];
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
points_eq (const uint64_t *x1, const uint64_t *y1, const uint64_t *z1,
           const uint64_t *t1, const uint64_t *x2, const uint64_t *y2,
           const uint64_t *z2, const uint64_t *t2)
{
  uint64_t i0[4], i1[4];
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
scalarmult (const uint64_t *k, const uint64_t *x_in, const uint64_t *y_in,
            uint64_t *x_out, uint64_t *y_out, uint64_t *z_out, uint64_t *t_out)
{
  uint64_t t_in[4];
  mult256_modp (x_in, y_in, t_in);
  uint64_t z_in[4] = {
    0x1,
    0x0,
    0x0,
    0x0,
  };
  uint64_t z2[4] = {
    0x1,
    0x0,
    0x0,
    0x0,
  };
  uint64_t x2[4] = {
    0x0,
    0x0,
    0x0,
    0x0,
  };
  uint64_t y2[4] = {
    0x1,
    0x0,
    0x0,
    0x0,
  };
  uint64_t t2[4] = {
    0x0,
    0x0,
    0x0,
    0x0,
  };
  uint64_t lut[16][4][4];
  for (unsigned int i = 0; i < 4; ++i)
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
      uint8_t ind = (k[i / 16] >> (4 * (i % 16))) & 0xf;
      addpoints (lut[ind][0], lut[ind][1], lut[ind][2], lut[ind][3], x2, y2,
                 z2, t2, x2, y2, z2, t2);
    }
  for (unsigned int i = 0; i < 4; ++i)
    {
      x_out[i] = x2[i];
      y_out[i] = y2[i];
      z_out[i] = z2[i];
      t_out[i] = t2[i];
    }
}

static uint64_t
load_3 (const unsigned char *in)
{
  return (uint64_t)in[0] | ((uint64_t)in[1] << 8) | ((uint64_t)in[2] << 16);
}
static uint64_t
load_4 (const unsigned char *in)
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
modl512 (const uint64_t *x, uint64_t *out)
{
  unsigned char s[64];
  for (unsigned int i = 0; i < 8; ++i)
    for (unsigned int b = 0; b < 8; ++b)
      s[i * 8 + b] = (x[i] >> (8 * b)) & 0xff;
  sc_reduce (s);
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = 0;
      for (unsigned int b = 0; b < 8; ++b)
        out[i] |= (uint64_t)s[i * 8 + b] << (8 * b);
    }
}

static void
xB_lowmem (const uint64_t *k, uint64_t *x, uint64_t *y, uint64_t *z,
           uint64_t *t)
{
  const uint64_t BX[4] = {
    0xc9562d608f25d51a,
    0x692cc7609525a7b2,
    0xc0a4e231fdd6dc5c,
    0x216936d3cd6e53fe,
  };
  const uint64_t BY[4] = {
    0x6666666666666658,
    0x6666666666666666,
    0x6666666666666666,
    0x6666666666666666,
  };
  scalarmult (k, BX, BY, x, y, z, t);
}

void
tct_ed25519_pctable_gen_64bit (uint64_t *out)
{
  const uint64_t D2[4] = { 0xebd69b9426b2f146, 0x00e0149a8283b156,
                           0x198e80f2eef3d130, 0xa406d9dc56dffce7 };
  uint64_t a[8], b[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      a[i] = 0x0;
    }
  a[0] = 0x1;
  uint64_t t[4], z[4];
  for (unsigned int i = 0; i < 64; ++i)
    {
      modl512 (a, a);
      modl512 (a, b);
      if (iszero256 (b) && iszero256 (b + 4))
        {
          b[0] = 0x1;
        }
      for (unsigned int j = 4; j < 8; ++j)
        {
          a[j] = b[j] = 0x0;
        }
      for (unsigned int j = 1; j < 16; ++j)
        {
          // We don't need `t` where we're going
          uint64_t *u_out = &(out[15 * 4 * 3 * i + 4 * 3 * (j - 1)]);
          uint64_t *v_out = &(out[15 * 4 * 3 * i + 4 * 3 * (j - 1) + 4]);
          uint64_t *w_out = &(out[15 * 4 * 3 * i + 4 * 3 * (j - 1) + 8]);
          uint64_t x[4], y[4];
          xB_lowmem (a, x, y, z, t);
          uint64_t z_inv[4];
          inv256_modp (z, z_inv);
          mult256_modp (x, z_inv, x);
          mult256_modp (y, z_inv, y);
          sub256_modp (y, x, u_out);
          u_out[0] ^= 1;
          add256_modp (y, x, v_out);
          v_out[0] ^= 1;
          mult256_modp (y, x, w_out);
          mult256_modp (w_out, D2, w_out);
          add512 (a, b);
        }
    }
}

static void
addpoints_precompute (const uint64_t *x1, const uint64_t *y1,
                      const uint64_t *z1, const uint64_t *t1,
                      const uint64_t *u2, const uint64_t *v2,
                      const uint64_t *w2, uint64_t *x3, uint64_t *y3,
                      uint64_t *z3, uint64_t *t3)
{
  uint64_t intermediates[8][4];
  sub256_modp (y1, x1, intermediates[0]);
  mult256_modp (intermediates[0], u2, intermediates[0]);
  add256_modp (y1, x1, intermediates[1]);
  mult256_modp (intermediates[1], v2, intermediates[1]);
  mult256_modp (t1, w2, intermediates[2]);
  add256_modp (z1, z1, intermediates[7]);
  sub256_modp (intermediates[1], intermediates[0], intermediates[3]);
  sub256_modp (intermediates[7], intermediates[2], intermediates[4]);
  add256_modp (intermediates[7], intermediates[2], intermediates[5]);
  add256_modp (intermediates[1], intermediates[0], intermediates[6]);
  mult256_modp (intermediates[3], intermediates[4], x3);
  mult256_modp (intermediates[5], intermediates[6], y3);
  mult256_modp (intermediates[4], intermediates[5], z3);
  mult256_modp (intermediates[3], intermediates[6], t3);
}

#ifndef TCT_LOWMEM

#include "tinycrypt/min64/ed25519_precompute.h"

static void
xB (const uint64_t *k, uint64_t *x, uint64_t *y, uint64_t *z, uint64_t *t)
{
  for (unsigned int i = 0; i < 4; ++i)
    {
      x[i] = y[i] = z[i] = t[i] = 0x0;
    }
  y[0] = 1;
  z[0] = 1;
  for (unsigned int i = 0; i < 64; ++i)
    {
      uint64_t ri = (k[i / 16] >> (4 * (i % 16))) & 0xf;
      uint64_t u[4] = { 0x1, 0x0, 0x0, 0x0 };
      uint64_t v[4] = { 0x1, 0x0, 0x0, 0x0 };
      uint64_t w[4] = { 0x0, 0x0, 0x0, 0x0 };
      for (unsigned int j = 1; j < 16; ++j)
        {
          uint64_t mask = 0xffffffffffffffff * (!(j ^ ri));
          for (unsigned int h = 0; h < 4; ++h)
            {
              u[h] ^= mask
                      & PRECOMPUTE_TABLE[i * 15 * 4 * 3 + (j - 1) * 4 * 3 + h];
              v[h] ^= mask
                      & PRECOMPUTE_TABLE[i * 15 * 4 * 3 + (j - 1) * 4 * 3 + 4
                                         + h];
              w[h] ^= mask
                      & PRECOMPUTE_TABLE[i * 15 * 4 * 3 + (j - 1) * 4 * 3 + 8
                                         + h];
            }
        }
      addpoints_precompute (x, y, z, t, u, v, w, x, y, z, t);
    }
}

#else

static void
xB (const uint64_t *k, uint64_t *x, uint64_t *y, uint64_t *z, uint64_t *t)
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
  uint64_t k[4];
  for (unsigned int i = 0; i < 4; ++i)
    {
      k[i] = from_le64 (digest + 8 * i);
    }
  uint64_t y[4];
  uint64_t z[4];
  uint64_t t[4];
  uint64_t x[4];
  xB (k, x, y, z, t);
  inv256_modp (z, z);
  mult256_modp (x, z, x);
  mult256_modp (y, z, y);
  for (unsigned int i = 0; i < 4; ++i)
    {
      to_le64 (y[i], pubkey + 8 * i);
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
  uint64_t s[4];
  tct_sha512 (privkey, 32, digest);
  digest[0] &= 0b11111000;
  digest[31] &= 0b01111111;
  digest[31] |= 0b01000000;
  for (unsigned int i = 0; i < 32; ++i)
    {
      working_buf[i] = digest[32 + i];
    }
  for (unsigned int i = 0; i < 4; ++i)
    {
      s[i] = from_le64 (digest + i * 8);
    }
  for (uint64_t i = 32; i < msg_len + 32; ++i)
    {
      working_buf[i] = msg[i - 32];
    }
  tct_sha512 (working_buf, msg_len + 32, digest);
  uint64_t r[4];
  uint64_t chunked[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      chunked[i] = from_le64 (digest + i * 8);
    }
  modl512 (chunked, r);
  uint64_t rBx[4];
  uint64_t rBy[4];
  uint64_t rBz[4];
  uint64_t rBt[4];
  xB (r, rBx, rBy, rBz, rBt);
  inv256_modp (rBz, rBz);
  mult256_modp (rBz, rBx, rBx);
  mult256_modp (rBz, rBy, chunked);
  for (unsigned int i = 0; i < 4; ++i)
    {
      to_le64 (chunked[i], signature + 8 * i);
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
  uint64_t k[4];
  for (unsigned int i = 0; i < 8; ++i)
    {
      chunked[i] = from_le64 (digest + 8 * i);
    }
  modl512 (chunked, k);
  mult256 (k, s, chunked);
  uint64_t big_r[8];
  for (unsigned int i = 0; i < 4; ++i)
    {
      big_r[i] = r[i];
      big_r[4 + i] = 0x0;
    }
  add512 (chunked, big_r);
  modl512 (chunked, chunked);
  for (unsigned int i = 0; i < 4; ++i)
    {
      to_le64 (chunked[i], 32 + signature + 8 * i);
    }
}

bool
tct_ed25519_verify (const uint8_t *pubkey, const uint8_t *msg,
                    const uint64_t msg_len, uint8_t *working_buf,
                    const uint8_t *signature)
{
  uint64_t Ax[4];
  uint64_t Ay[4];
  if (!decode256 (pubkey, Ax, Ay))
    {
      return false;
    }
  uint64_t Rx[4];
  uint64_t Ry[4];
  uint64_t Rz[4] = {
    0x1,
    0x0,
    0x0,
    0x0,
  };
  uint64_t Rt[4];
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
  uint64_t chunked[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      chunked[i] = from_le64 (h + i * 8);
    }
  modl512 (chunked, chunked);
  uint64_t sBx[4];
  uint64_t sBy[4];
  uint64_t sBz[4];
  uint64_t sBt[4];
  uint64_t hAx[4];
  uint64_t hAy[4];
  uint64_t hAz[4];
  uint64_t hAt[4];
  uint64_t sigk[8];
  for (unsigned int i = 0; i < 4; ++i)
    {
      sigk[i] = from_le64 (signature + 32 + 8 * i);
      sigk[4 + i] = 0x0;
    }
  uint64_t L[4] = { 0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0x0000000000000000,
                    0x1000000000000000 };
  xB (sigk, sBx, sBy, sBz, sBt);
  scalarmult (chunked, Ax, Ay, hAx, hAy, hAz, hAt);
  addpoints (Rx, Ry, Rz, Rt, hAx, hAy, hAz, hAt, hAx, hAy, hAz, hAt);
  return points_eq (sBx, sBy, sBz, sBt, hAx, hAy, hAz, hAt)
         * greater256 (L, sigk);
}
