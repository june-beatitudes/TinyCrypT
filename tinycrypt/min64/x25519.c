#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/x25519.h"

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
to_le64 (uint64_t u, uint8_t *x)
{
  for (unsigned int i = 0; i < 8; ++i)
    {
      x[i] = u & 0xFF;
      u >>= 8;
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
          intermediate[i + j + 1] += intermediate[i + j] >> 64;
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
          intermediate[i + j + 1] += intermediate[i + j] >> 64;
          intermediate[i + j] &= 0xffffffffffffffff;
          intermediate[i + j] += prod;
          intermediate[i + j + 1] += intermediate[i + j] >> 64;
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

/* Fold the top 256 bits into the low 256 via 2^256 = 38 (mod 2^255-19).
   Replaces a general 256x256 multiply by 2p with a multiply by the small
   constant 38, leaving value = lo + 38*hi in acc[0..4]. */
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
  uint64_t accumulator[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      accumulator[i] = in[i];
    }
  // Handle negatives properly
  add512 (accumulator, P);
  fold38 (accumulator);
  fold38 (accumulator);
  uint64_t dummy[8];
  uint64_t mask = greater320 (accumulator, P2) * 0xffffffffffffffff;
  for (unsigned int i = 0; i < 8; ++i)
    {
      dummy[i] = P2[i] & mask;
    }
  sub512 (accumulator, dummy);
  mask = greater256 (accumulator, P) * 0xffffffffffffffff;
  for (unsigned int i = 0; i < 8; ++i)
    {
      dummy[i] = P[i] & mask;
    }
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
  uint64_t dummy[8];
  uint64_t mask = ((in[7] & (1ULL << 63)) >> 63) * 0xffffffffffffffff;
  for (unsigned int i = 0; i < 8; ++i)
    {
      dummy[i] = P[i] & mask;
    }
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
  uint64_t dummy[8];
  uint64_t mask = greater320 (in, P) * 0xffffffffffffffff;
  for (unsigned int i = 0; i < 8; ++i)
    {
      dummy[i] = P[i] & mask;
    }
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
mult256_modp (const uint64_t *a, const uint64_t *b, uint64_t *out)
{
  uint64_t intermediate[8];
  mult256 (a, b, intermediate);
  modp512 (intermediate, out);
}

static void
inv256_modp (const uint64_t *x, uint64_t *out)
{
  uint64_t i0[4], i1[4];
  for (unsigned int i = 0; i < 4; ++i)
    {
      i1[i] = i0[i] = out[i];
    }
  for (unsigned int i = 0; i < 254; ++i)
    {
      square256_modp (i0, i0);
      if (i != 251 && i != 249)
        {
          mult256_modp (i0, i1, i0);
        }
    }
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = i0[i];
    }
}

static void
swap256 (unsigned int do_swap, uint64_t *a, uint64_t *b)
{
  for (unsigned int i = 0; i < 4; ++i)
    {
      uint64_t dummy = (a[i] ^ b[i]) & (do_swap * 0xffffffffffffffff);
      a[i] = a[i] ^ dummy;
      b[i] = b[i] ^ dummy;
    }
}

void
tct_x25519 (const uint8_t *key, const uint8_t *u, uint8_t *out)
{
  uint64_t k_int[4], u_int[8];
  for (unsigned int i = 0; i < 4; ++i)
    {
      k_int[i] = from_le64 (key + i * 8);
      u_int[i] = from_le64 (u + i * 8);
      u_int[4 + i] = 0x0;
    }
  u_int[3] &= 0x7fffffffffffffff;
  k_int[0] &= 0xfffffffffffffff8;
  k_int[3] &= 0x7fffffffffffffff;
  k_int[3] |= 0x4000000000000000;
  modp512_postadd (u_int, u_int);
  uint64_t A24[4] = { 0x1db41, 0, 0, 0 };
  uint64_t x2[4], z2[4], x3[4], z3[4];
  unsigned int swap = 0;
  for (unsigned int i = 0; i < 4; ++i)
    {
      x2[i] = 0x0;
      z2[i] = 0x0;
      x3[i] = u_int[i];
      z3[i] = 0x0;
    }
  x2[0] = 0x1;
  z3[0] = 0x1;
  for (int i = 254; i >= 0; --i)
    {
      swap = (k_int[i / 64] >> (i % 64)) & 1;
      swap256 (swap, x2, x3);
      swap256 (swap, z2, z3);

      uint64_t e[4], f[4];
      add256_modp (x2, z2, e);
      sub256_modp (x2, z2, x2);
      add256_modp (x3, z3, z2);
      sub256_modp (x3, z3, x3);
      square256_modp (e, z3);
      square256_modp (x2, f);
      mult256_modp (x2, z2, x2);
      mult256_modp (x3, e, z2);
      add256_modp (x2, z2, e);
      sub256_modp (x2, z2, x2);
      square256_modp (x2, x3);
      sub256_modp (z3, f, z2);
      mult256_modp (z2, A24, x2);
      add256_modp (x2, z3, x2);
      mult256_modp (z2, x2, z2);
      mult256_modp (z3, f, x2);
      mult256_modp (x3, u_int, z3);
      square256_modp (e, x3);

      swap256 (swap, x2, x3);
      swap256 (swap, z2, z3);
    }

  inv256_modp (z2, z2);
  mult256_modp (x2, z2, x2);
  for (unsigned int i = 0; i < 4; ++i)
    {
      to_le64 (x2[i], out + i * 8);
    }
}
