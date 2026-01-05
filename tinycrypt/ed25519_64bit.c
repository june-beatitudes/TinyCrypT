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
add_shifted (uint64_t *h, const __uint128_t c, const unsigned int shift)
{
  uint64_t digits[2];
  digits[0] = c & 0xffffffffffffffff;
  digits[1] = (c >> 64) & 0xffffffffffffffff;
  __uint128_t accumulator = 0;
  unsigned int i;
  for (i = shift; i < shift + 2 && i < 8; ++i)
    {
      accumulator += (__uint128_t)digits[i - shift] + (__uint128_t)h[i];
      h[i] = accumulator & 0xffffffffffffffff;
      accumulator >>= 64;
    }
  while (i < 8)
    {
      accumulator += (__uint128_t)h[i];
      h[i] = accumulator & 0xffffffffffffffff;
      accumulator >>= 64;
      ++i;
    }
}

static void
mult256 (const uint64_t *a, const uint64_t *b, uint64_t *out)
{
  uint64_t a_int[4], b_int[4];
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
          __uint128_t prod = (__uint128_t)a_int[i] * (__uint128_t)b_int[j];
          add_shifted (out, prod, i + j);
        }
    }
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
sub566 (uint64_t *h, const uint64_t *c)
{
  __uint128_t acc = 0;
  for (unsigned int i = 0; i < 9; ++i)
    {
      acc += (__uint128_t)(0xffffffffffffffff - h[i]) + (__uint128_t)c[i];
      h[i] = 0xffffffffffffffff - (acc & 0xffffffffffffffff);
      acc >>= 64;
    }
}

static bool
greater512_unsigned (const uint64_t *a, const uint64_t *b)
{
  uint64_t a_int[9], b_int[9];
  for (unsigned int i = 0; i < 8; ++i)
    {
      a_int[i] = a[i];
      b_int[i] = b[i];
    }
  a_int[8] = 0x0;
  b_int[8] = 0x0;
  sub566 (a_int, b_int);

  return !(a_int[8] & (1ULL << 63));
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
mult256_modp (const uint64_t *a, const uint64_t *b, uint64_t *out)
{
  uint64_t intermediate[8];
  mult256 (a, b, intermediate);
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
      mult256_modp (i0, i0, i0);
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
      mult256_modp (out, out, out);
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
  const uint64_t D[4] = {
    0x75eb4dca135978a3,
    0x00700a4d4141d8ab,
    0x8cc740797779e898,
    0x52036cee2b6ffe73,
  };
  uint64_t intermediates[8][4];
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
      addpoints (x2, y2, z2, t2, x2, y2, z2, t2, x2, y2, z2, t2);
      addpoints (x2, y2, z2, t2, x2, y2, z2, t2, x2, y2, z2, t2);
      addpoints (x2, y2, z2, t2, x2, y2, z2, t2, x2, y2, z2, t2);
      addpoints (x2, y2, z2, t2, x2, y2, z2, t2, x2, y2, z2, t2);
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

static void
shl512 (const uint64_t *in, const uint64_t shift, uint64_t *out)
{
  for (uint64_t i = 0; i < 8; ++i)
    {
      out[i] = 0x0;
    }
  uint64_t shift_amt = shift % 64;
  for (uint64_t i = 0; i < 8 - shift / 64; ++i)
    {
      out[i + shift / 64] = in[i] << shift_amt;
      if (i > 0 && shift_amt != 0)
        {
          out[i + shift / 64] |= in[i - 1] >> (64 - shift_amt);
        }
    }
}

static void
modl512 (const uint64_t *x, uint64_t *out)
{
  uint64_t L[8] = {
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
    0x0,
    0x0,
    0x0,
    0x0,
  };
  uint64_t LMULT[8];
  uint64_t ZERO[8] = {
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  uint64_t i0[8];
  for (unsigned int i = 0; i < 8; ++i)
    {
      i0[i] = x[i];
    }
  for (int i = 259; i >= 0; --i)
    {
      shl512 (L, i, LMULT);
      uint64_t *dummy = greater512_unsigned (i0, LMULT) ? LMULT : ZERO;
      sub512 (i0, dummy);
      dummy = greater512_unsigned (i0, LMULT) ? LMULT : ZERO;
      sub512 (i0, dummy);
    }

  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = i0[i];
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
      if (iszero256 (a) && iszero256 (a + 4))
        {
          a[0] = b[0] = 0x1;
        }
      for (unsigned int j = 4; j < 8; ++j)
        {
          a[j] = b[j] = 0x0;
        }
      for (unsigned int j = 0; j < 15; ++j)
        {
          // We don't need `t` where we're going
          uint64_t *x_out = &(out[15 * 4 * 2 * i + 4 * 2 * j]);
          uint64_t *y_out = &(out[15 * 4 * 2 * i + 4 * 2 * j + 4]);
          xB_lowmem (a, x_out, y_out, z, t);
          uint64_t z_inv[4];
          inv256_modp (z, z_inv);
          mult256_modp (x_out, z_inv, x_out);
          mult256_modp (y_out, z_inv, y_out);
          add512 (a, b);
        }
    }
}

#ifndef TCT_LOWMEM

#include "tinycrypt/ed25519_precompute_64bit.h"

static void
xB (const uint64_t *k, uint64_t *x, uint64_t *y, uint64_t *z, uint64_t *t)
{
  uint64_t ONE[4] = {
    0x1,
    0x0,
    0x0,
    0x0,
  };
  for (unsigned int i = 0; i < 4; ++i)
    {
      x[i] = y[i] = z[i] = t[i] = 0x0;
    }
  y[0] = 1;
  z[0] = 1;
  for (unsigned int i = 0; i < 64; ++i)
    {
      uint64_t ri = (k[i / 16] >> (4 * (i % 16))) & 0xf;
      uint64_t t0[4];
      if (ri != 0)
        {
          mult256_modp (
              &PRECOMPUTE_TABLE[i * 15 * 4 * 2 + (ri - 1) * 4 * 2],
              &PRECOMPUTE_TABLE[i * 15 * 4 * 2 + (ri - 1) * 4 * 2 + 4], t0);
          addpoints (x, y, z, t,
                     &PRECOMPUTE_TABLE[i * 15 * 4 * 2 + (ri - 1) * 4 * 2],
                     &PRECOMPUTE_TABLE[i * 15 * 4 * 2 + (ri - 1) * 4 * 2 + 4],
                     ONE, t0, x, y, z, t);
        }
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
  modl512 (sigk, sigk);
  xB (sigk, sBx, sBy, sBz, sBt);
  scalarmult (chunked, Ax, Ay, hAx, hAy, hAz, hAt);
  addpoints (Rx, Ry, Rz, Rt, hAx, hAy, hAz, hAt, hAx, hAy, hAz, hAt);
  return points_eq (sBx, sBy, sBz, sBt, hAx, hAy, hAz, hAt);
}