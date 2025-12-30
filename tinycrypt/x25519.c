#include <stdbool.h>
#include <stdint.h>

#include <stdio.h>

static void
print256 (const uint8_t *x)
{
  for (unsigned int i = 0; i < 32; ++i)
    {
      printf ("%02x", x[i]);
    }
  printf ("\n");
}

static void
print512 (const uint8_t *x)
{
  for (unsigned int i = 0; i < 64; ++i)
    {
      printf ("%02x", x[63 - i]);
    }
  printf ("\n");
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
  for (unsigned int i = 0; i < 33; ++i)
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
  uint16_t acc = 0;
  for (unsigned int i = 0; i < 64; ++i)
    {
      acc += (255 - h[i]) + c[i];
      h[i] = 255 - (acc & 0xFF);
      acc >>= 8;
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
modp_512 (const uint8_t *in, uint8_t *out)
{
  const uint8_t P[33] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00,
  };
  uint8_t approx_quotient[33];
  uint8_t approx_dividend[64];
  uint8_t accumulator[64];
  for (unsigned int i = 0; i < 64; ++i)
    {
      accumulator[i] = in[i];
    }
  while (true)
    {
      shr512_by_255 (accumulator, approx_quotient);
      if (iszero264 (approx_quotient))
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
      mult264 (P, approx_quotient, approx_dividend);
      sub512 (accumulator, approx_dividend);
    }
}

static void
mult256_modp (const uint8_t *a, const uint8_t *b, uint8_t *out)
{
  uint8_t intermediate[64];
  mult256 (a, b, intermediate);
  modp_512 (intermediate, out);
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
  modp_512 (intermediates[0], out);
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
  modp_512 (intermediates[0], out);
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
x25519 (const uint8_t *key, const uint8_t *u, uint8_t *out)
{
  uint8_t k_int[32];
  for (unsigned int i = 0; i < 32; ++i)
    {
      if (i == 0)
        {
          k_int[i] = key[i] & 248;
        }
      else if (i == 31)
        {
          k_int[i] = (key[i] & 127) | 64;
        }
      else
        {
          k_int[i] = key[i];
        }
    }
  uint8_t A24[32] = {
    0x41, 0xdb, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  print256(A24);
  uint8_t buf[32 * 4];
  uint8_t *x2 = buf;
  uint8_t *z2 = buf + 32;
  uint8_t *x3 = buf + 64;
  uint8_t *z3 = buf + 96;
  unsigned int swap = 0;
  for (unsigned int i = 0; i < 32; ++i)
    {
      x2[i] = 0x0;
      z2[i] = 0x0;
      x3[i] = u[i];
      z3[i] = 0x0;
    }
  x2[0] = 0x1;
  z3[0] = 0x1;
  for (int i = 254; i >= 0; --i)
    {
      swap = (k_int[i / 8] >> (i % 8)) & 1;
      swap256 (swap, x2, x3);
      swap256 (swap, z2, z3);

      uint8_t e[32], f[32];

      add256_modp (x2, z2, e);
      sub256_modp (x2, z2, x2);
      add256_modp (x3, z3, z2);
      sub256_modp (x3, z3, x3);
      mult256_modp (e, e, z3);
      mult256_modp (x2, x2, f);
      mult256_modp (x2, z2, x2);
      mult256_modp (x3, e, z2);
      add256_modp (x2, z2, e);
      sub256_modp (x2, z2, x2);
      mult256_modp (x2, x2, x3);
      sub256_modp (z3, f, z2);
      mult256_modp (z2, A24, x2);
      add256_modp (x2, z3, x2);
      mult256_modp (z2, x2, z2);
      mult256_modp (z3, f, x2);
      mult256_modp (x3, u, z3);
      mult256_modp (e, e, x3);

      swap256 (swap, x2, x3);
      swap256 (swap, z2, z3);
    }
  uint8_t intermediate[32];
  inv256_modp (z2, intermediate);
  mult256_modp (x2, intermediate, out);
}

int
main (int argc, const char **argv)
{
  uint8_t k[32] = {
    0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  print256 (k);
  uint8_t u[32] = {
    0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
  };
  print256 (u);
  uint8_t out[32];
  x25519 (k, u, out);
  print256 (out);
  return 0;
}