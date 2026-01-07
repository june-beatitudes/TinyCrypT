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
  uint64_t approx_dividend[8];
  uint64_t accumulator[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      accumulator[i] = in[i];
    }
  // Handle negatives properly
  add512 (accumulator, P);
  for (unsigned int i = 0; i < 2; ++i)
    {
      mult256 (P2, accumulator + 4, approx_dividend);
      sub512 (accumulator, approx_dividend);
    }
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
to_montgomery (const uint64_t *in, uint64_t *out)
{
  uint64_t buf[8];
  for (unsigned int i = 0; i < 4; ++i)
    {
      buf[4 + i] = in[i];
      buf[i] = 0x0;
    }
  modp512 (buf, out);
}

static void
from_montgomery (const uint64_t *in, uint64_t *out)
{
  const uint64_t RECIPROCAL[4] = { 0x435e50d79435e50a, 0x5e50d79435e50d79,
                                   0x50d79435e50d7943, 0x179435e50d79435e };
  mult256_modp (RECIPROCAL, in, out);
}

static void
montgomery_multiply (const uint64_t *a, const uint64_t *b, uint64_t *out)
{
  uint64_t P[4] = { 0xffffffffffffffed, 0xffffffffffffffff, 0xffffffffffffffff,
                    0x7fffffffffffffff };
  uint64_t FACTOR[4] = { 0x86bca1af286bca1b, 0xbca1af286bca1af2,
                         0xa1af286bca1af286, 0x2f286bca1af286bc };
  uint64_t ZERO[4] = { 0x0, 0x0, 0x0, 0x0 };
  uint64_t prod[8];
  mult256 (a, b, prod);
  uint64_t i0[8], i1[8];
  mult256 (prod, FACTOR, i0);
  mult256 (i0, P, i1);
  add512 (i1, prod);
  uint64_t *dummy = greater256 (i1 + 4, P) ? P : ZERO;
  sub256 (i1 + 4, dummy);
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = i1[i + 4];
    }
}

static void
montgomery_square (const uint64_t *in, uint64_t *out)
{
  uint64_t P[4] = { 0xffffffffffffffed, 0xffffffffffffffff, 0xffffffffffffffff,
                    0x7fffffffffffffff };
  uint64_t FACTOR[4] = { 0x86bca1af286bca1b, 0xbca1af286bca1af2,
                         0xa1af286bca1af286, 0x2f286bca1af286bc };
  uint64_t ZERO[4] = { 0x0, 0x0, 0x0, 0x0 };
  uint64_t prod[8];
  square256 (in, prod);
  uint64_t i0[8], i1[8];
  mult256 (prod, FACTOR, i0);
  mult256 (i0, P, i1);
  add512 (i1, prod);
  uint64_t *dummy = greater256 (i1 + 4, P) ? P : ZERO;
  sub256 (i1 + 4, dummy);
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = i1[i + 4];
    }
}

static void
inv256_modp (const uint64_t *x, uint64_t *out)
{
  uint64_t i0[4], i1[4];
  to_montgomery (x, i0);
  for (unsigned int i = 0; i < 4; ++i)
    {
      i1[i] = i0[i];
    }
  for (unsigned int i = 0; i < 254; ++i)
    {
      montgomery_square (i0, i0);
      if (i != 251 && i != 249)
        {
          montgomery_multiply (i0, i1, i0);
        }
    }
  from_montgomery (i0, out);
}

static void
swap256 (unsigned int do_swap, uint64_t *a, uint64_t *b)
{
  for (unsigned int i = 0; i < 4; ++i)
    {
      uint64_t dummy = (a[i] ^ b[i]) & ((do_swap) ? 0xffffffffffffffff : 0x0);
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
  k_int[0] &= 0xfffffffffffffff8;
  k_int[3] &= 0x7fffffffffffffff;
  k_int[3] |= 0x4000000000000000;
  modp512_postadd (u_int, u_int);
  uint64_t A24[4] = { 0x000000000001db41, 0x00, 0x00, 0x00 };
  uint64_t buf[16];
  uint64_t *x2 = buf;
  uint64_t *z2 = buf + 4;
  uint64_t *x3 = buf + 8;
  uint64_t *z3 = buf + 12;
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
