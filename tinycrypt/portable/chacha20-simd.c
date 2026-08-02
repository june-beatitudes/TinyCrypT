#ifndef TCT_SIMD
#error "You're building the wrong version of ChaCha20! LLVM emulates SIMD poorly on non-SIMD architectures. Use chacha20-scalar.c."
#endif

#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/chacha20_poly1305.h"

typedef uint32_t dwpacked __attribute__ ((vector_size (16)));
typedef uint8_t bytes16 __attribute__ ((vector_size (16)));

#if TCT_SIMD128
static dwpacked
rotl16 (dwpacked x)
{
  bytes16 b = (bytes16)x;
  b = __builtin_shufflevector (b, b, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14,
                               15, 12, 13);
  return (dwpacked)b;
}
static dwpacked
rotl8 (dwpacked x)
{
  bytes16 b = (bytes16)x;
  b = __builtin_shufflevector (b, b, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15,
                               12, 13, 14);
  return (dwpacked)b;
}
#else
static dwpacked
rotl16 (dwpacked x)
{
  return (x << 16) | (x >> 16);
}
static dwpacked
rotl8 (dwpacked x)
{
  return (x << 8) | (x >> 24);
}
#endif

static dwpacked
rotl_n (dwpacked x, int c)
{
  return (x << c) | (x >> (32 - c));
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

#define CC20_QR(a, b, c, d)                                                   \
  do                                                                          \
    {                                                                         \
      a += b;                                                                 \
      d ^= a;                                                                 \
      d = rotl16 (d);                                                         \
      c += d;                                                                 \
      b ^= c;                                                                 \
      b = rotl_n (b, 12);                                                     \
      a += b;                                                                 \
      d ^= a;                                                                 \
      d = rotl8 (d);                                                          \
      c += d;                                                                 \
      b ^= c;                                                                 \
      b = rotl_n (b, 7);                                                      \
    }                                                                         \
  while (false)

static dwpacked
splat (uint32_t v)
{
  return (dwpacked){ v, v, v, v };
}

static dwpacked
cc20_counter_row (uint32_t counter, uint32_t n0, uint32_t n1, uint32_t n2)
{
  return (dwpacked){ counter, n0, n1, n2 };
}

/* One ChaCha20 block; keystream returned in four vectors (row layout). */
static void
chacha_core (dwpacked s0, dwpacked s1, dwpacked s2, dwpacked s3,
             dwpacked out[4])
{
  dwpacked x0 = s0, x1 = s1, x2 = s2, x3 = s3;
  for (uint32_t i = 0; i < 10; ++i)
    {
      CC20_QR (x0, x1, x2, x3);
      x1 = __builtin_shufflevector (x1, x1, 1, 2, 3, 0);
      x2 = __builtin_shufflevector (x2, x2, 2, 3, 0, 1);
      x3 = __builtin_shufflevector (x3, x3, 3, 0, 1, 2);
      CC20_QR (x0, x1, x2, x3);
      x1 = __builtin_shufflevector (x1, x1, 3, 0, 1, 2);
      x2 = __builtin_shufflevector (x2, x2, 2, 3, 0, 1);
      x3 = __builtin_shufflevector (x3, x3, 1, 2, 3, 0);
    }
  out[0] = x0 + s0;
  out[1] = x1 + s1;
  out[2] = x2 + s2;
  out[3] = x3 + s3;
}

#ifdef TCT_LITTLE_ENDIAN
static void
cc20_xor64 (const uint8_t *in, const dwpacked ks[4], uint8_t *out)
{
  for (unsigned int k = 0; k < 4; ++k)
    {
      dwpacked p;
      __builtin_memcpy (&p, in + 16 * k, 16);
      p ^= ks[k];
      __builtin_memcpy (out + 16 * k, &p, 16);
    }
}
#else
static void
cc20_xor64 (const uint8_t *in, const dwpacked ks[4], uint8_t *out)
{
  for (unsigned int k = 0; k < 4; ++k)
    {
      dwpacked p;
      __builtin_memcpy (&p, in + 16 * k, 16);
      bytes16 be = (bytes16)p;
      be = __builtin_shufflevector (be, be, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9,
                                    8, 15, 14, 13, 12);
      be ^= (bytes16)ks[k];
      be = __builtin_shufflevector (be, be, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9,
                                    8, 15, 14, 13, 12);
      __builtin_memcpy (out + 16 * k, &be, 16);
    }
}
#endif

static void
transpose4 (dwpacked *r0, dwpacked *r1, dwpacked *r2, dwpacked *r3)
{
  dwpacked a0 = __builtin_shufflevector (*r0, *r1, 0, 4, 1, 5);
  dwpacked a1 = __builtin_shufflevector (*r0, *r1, 2, 6, 3, 7);
  dwpacked a2 = __builtin_shufflevector (*r2, *r3, 0, 4, 1, 5);
  dwpacked a3 = __builtin_shufflevector (*r2, *r3, 2, 6, 3, 7);
  *r0 = __builtin_shufflevector (a0, a2, 0, 1, 4, 5);
  *r1 = __builtin_shufflevector (a0, a2, 2, 3, 6, 7);
  *r2 = __builtin_shufflevector (a1, a3, 0, 1, 4, 5);
  *r3 = __builtin_shufflevector (a1, a3, 2, 3, 6, 7);
}

static void
cc20_xor_x4 (dwpacked v[16], const uint8_t *pt, uint8_t *out)
{
  dwpacked in[16];
  for (unsigned int k = 0; k < 16; ++k)
    in[k] = v[k];
  for (unsigned int r = 0; r < 10; ++r)
    {
      CC20_QR (v[0], v[4], v[8], v[12]);
      CC20_QR (v[1], v[5], v[9], v[13]);
      CC20_QR (v[2], v[6], v[10], v[14]);
      CC20_QR (v[3], v[7], v[11], v[15]);
      CC20_QR (v[0], v[5], v[10], v[15]);
      CC20_QR (v[1], v[6], v[11], v[12]);
      CC20_QR (v[2], v[7], v[8], v[13]);
      CC20_QR (v[3], v[4], v[9], v[14]);
    }
  for (unsigned int k = 0; k < 16; ++k)
    v[k] += in[k];
  transpose4 (&v[0], &v[1], &v[2], &v[3]);
  transpose4 (&v[4], &v[5], &v[6], &v[7]);
  transpose4 (&v[8], &v[9], &v[10], &v[11]);
  transpose4 (&v[12], &v[13], &v[14], &v[15]);
  for (unsigned int j = 0; j < 4; ++j)
    {
      const dwpacked ks[4] = { v[j], v[4 + j], v[8 + j], v[12 + j] };
      cc20_xor64 (pt + 64 * j, ks, out + 64 * j);
    }
}

#ifdef TCT_SIMD256
typedef uint32_t qwpacked __attribute__ ((vector_size (32)));
typedef uint8_t bytes32 __attribute__ ((vector_size (32)));

static qwpacked
rotl16_x8 (qwpacked x)
{
  bytes32 b = (bytes32)x;
  b = __builtin_shufflevector (b, b, 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14,
                               15, 12, 13, 18, 19, 16, 17, 22, 23, 20, 21, 26,
                               27, 24, 25, 30, 31, 28, 29);
  return (qwpacked)b;
}
static qwpacked
rotl8_x8 (qwpacked x)
{
  bytes32 b = (bytes32)x;
  b = __builtin_shufflevector (b, b, 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15,
                               12, 13, 14, 19, 16, 17, 18, 23, 20, 21, 22, 27,
                               24, 25, 26, 31, 28, 29, 30);
  return (qwpacked)b;
}
static qwpacked
rotl_n_x8 (qwpacked x, int c)
{
  return (x << c) | (x >> (32 - c));
}

#define CC20_QR8(a, b, c, d)                                                  \
  do                                                                          \
    {                                                                         \
      a += b;                                                                 \
      d ^= a;                                                                 \
      d = rotl16_x8 (d);                                                      \
      c += d;                                                                 \
      b ^= c;                                                                 \
      b = rotl_n_x8 (b, 12);                                                  \
      a += b;                                                                 \
      d ^= a;                                                                 \
      d = rotl8_x8 (d);                                                       \
      c += d;                                                                 \
      b ^= c;                                                                 \
      b = rotl_n_x8 (b, 7);                                                   \
    }                                                                         \
  while (false)

#define CC20_UNPACKLO32(a, b)                                                 \
  __builtin_shufflevector (a, b, 0, 8, 1, 9, 4, 12, 5, 13)
#define CC20_UNPACKHI32(a, b)                                                 \
  __builtin_shufflevector (a, b, 2, 10, 3, 11, 6, 14, 7, 15)
#define CC20_UNPACKLO64(a, b)                                                 \
  __builtin_shufflevector (a, b, 0, 1, 8, 9, 4, 5, 12, 13)
#define CC20_UNPACKHI64(a, b)                                                 \
  __builtin_shufflevector (a, b, 2, 3, 10, 11, 6, 7, 14, 15)
#define CC20_PERM128_LO(a, b)                                                 \
  __builtin_shufflevector (a, b, 0, 1, 2, 3, 8, 9, 10, 11)
#define CC20_PERM128_HI(a, b)                                                 \
  __builtin_shufflevector (a, b, 4, 5, 6, 7, 12, 13, 14, 15)

static void
transpose8 (qwpacked r[8])
{
  qwpacked t0 = CC20_UNPACKLO32 (r[0], r[1]),
           t1 = CC20_UNPACKHI32 (r[0], r[1]);
  qwpacked t2 = CC20_UNPACKLO32 (r[2], r[3]),
           t3 = CC20_UNPACKHI32 (r[2], r[3]);
  qwpacked t4 = CC20_UNPACKLO32 (r[4], r[5]),
           t5 = CC20_UNPACKHI32 (r[4], r[5]);
  qwpacked t6 = CC20_UNPACKLO32 (r[6], r[7]),
           t7 = CC20_UNPACKHI32 (r[6], r[7]);
  qwpacked u0 = CC20_UNPACKLO64 (t0, t2), u1 = CC20_UNPACKHI64 (t0, t2);
  qwpacked u2 = CC20_UNPACKLO64 (t1, t3), u3 = CC20_UNPACKHI64 (t1, t3);
  qwpacked u4 = CC20_UNPACKLO64 (t4, t6), u5 = CC20_UNPACKHI64 (t4, t6);
  qwpacked u6 = CC20_UNPACKLO64 (t5, t7), u7 = CC20_UNPACKHI64 (t5, t7);
  r[0] = CC20_PERM128_LO (u0, u4);
  r[4] = CC20_PERM128_HI (u0, u4);
  r[1] = CC20_PERM128_LO (u1, u5);
  r[5] = CC20_PERM128_HI (u1, u5);
  r[2] = CC20_PERM128_LO (u2, u6);
  r[6] = CC20_PERM128_HI (u2, u6);
  r[3] = CC20_PERM128_LO (u3, u7);
  r[7] = CC20_PERM128_HI (u3, u7);
}

static qwpacked
splat8 (uint32_t v)
{
  return (qwpacked){ v, v, v, v, v, v, v, v };
}

/* Encrypt exactly eight blocks held in vertical layout in v[16]. */
static void
cc20_xor_x8 (qwpacked v[16], const uint8_t *pt, uint8_t *out)
{
  qwpacked in[16];
  for (unsigned int k = 0; k < 16; ++k)
    in[k] = v[k];
  for (unsigned int r = 0; r < 10; ++r)
    {
      CC20_QR8 (v[0], v[4], v[8], v[12]);
      CC20_QR8 (v[1], v[5], v[9], v[13]);
      CC20_QR8 (v[2], v[6], v[10], v[14]);
      CC20_QR8 (v[3], v[7], v[11], v[15]);
      CC20_QR8 (v[0], v[5], v[10], v[15]);
      CC20_QR8 (v[1], v[6], v[11], v[12]);
      CC20_QR8 (v[2], v[7], v[8], v[13]);
      CC20_QR8 (v[3], v[4], v[9], v[14]);
    }
  for (unsigned int k = 0; k < 16; ++k)
    v[k] += in[k];
  /* words 0..7 and 8..15 transposed independently -> lane j is block j */
  transpose8 (&v[0]);
  transpose8 (&v[8]);
  for (unsigned int j = 0; j < 8; ++j)
    {
      qwpacked p0, p1;
      __builtin_memcpy (&p0, pt + 64 * j, 32);
      __builtin_memcpy (&p1, pt + 64 * j + 32, 32);
      p0 ^= v[j];
      p1 ^= v[8 + j];
      __builtin_memcpy (out + 64 * j, &p0, 32);
      __builtin_memcpy (out + 64 * j + 32, &p1, 32);
    }
}
#endif /* TCT_SIMD256 */

void
tct_chacha20_encrypt_or_decrypt (const uint8_t *key, const uint32_t counter,
                                 const uint8_t *nonce, const uint8_t *in,
                                 const uint64_t in_len, uint8_t *out)
{
  const dwpacked s0 = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
  const dwpacked s1 = { from_le32 (key), from_le32 (key + 4),
                        from_le32 (key + 8), from_le32 (key + 12) };
  const dwpacked s2 = { from_le32 (key + 16), from_le32 (key + 20),
                        from_le32 (key + 24), from_le32 (key + 28) };
  const uint32_t n0 = from_le32 (nonce), n1 = from_le32 (nonce + 4),
                 n2 = from_le32 (nonce + 8);
  const uint64_t full = in_len / 64;
  uint64_t i = 0;

#ifdef TCT_SIMD256
  {
    const qwpacked b[12]
        = { splat8 (s0[0]), splat8 (s0[1]), splat8 (s0[2]), splat8 (s0[3]),
            splat8 (s1[0]), splat8 (s1[1]), splat8 (s1[2]), splat8 (s1[3]),
            splat8 (s2[0]), splat8 (s2[1]), splat8 (s2[2]), splat8 (s2[3]) };
    const qwpacked bn0 = splat8 (n0), bn1 = splat8 (n1), bn2 = splat8 (n2);
    for (; i + 8 <= full; i += 8)
      {
        uint32_t c[8];
        for (unsigned int j = 0; j < 8; ++j)
          {
            c[j] = counter + (uint32_t)i + j;
          }
        qwpacked lo = { c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7] };
        qwpacked v[16] = { b[0], b[1], b[2],  b[3],  b[4], b[5], b[6], b[7],
                           b[8], b[9], b[10], b[11], lo,   bn0,  bn1,  bn2 };
        cc20_xor_x8 (v, in + 64 * i, out + 64 * i);
      }
  }
#endif

  dwpacked bc[12];
  for (unsigned int j = 0; j < 4; ++j)
    {
      bc[j] = splat (s0[j]);
      bc[4 + j] = splat (s1[j]);
      bc[8 + j] = splat (s2[j]);
    }
  const dwpacked bn0 = splat (n0), bn1 = splat (n1), bn2 = splat (n2);
  for (; i + 4 <= full; i += 4)
    {
      uint32_t c0 = counter + (uint32_t)i, c1 = counter + (uint32_t)i + 1,
               c2 = counter + (uint32_t)i + 2, c3 = counter + (uint32_t)i + 3;
      dwpacked v[16] = { bc[0],
                         bc[1],
                         bc[2],
                         bc[3],
                         bc[4],
                         bc[5],
                         bc[6],
                         bc[7],
                         bc[8],
                         bc[9],
                         bc[10],
                         bc[11],
                         (dwpacked){ c0, c1, c2, c3 },
                         bn0,
                         bn1,
                         bn2 };
      cc20_xor_x4 (v, in + 64 * i, out + 64 * i);
    }

  /* Remaining whole blocks (fewer than the vector width), one at a time. */
  for (; i < full; ++i)
    {
      dwpacked s3 = cc20_counter_row (counter + (uint32_t)i, n0, n1, n2);
      dwpacked ks[4];
      chacha_core (s0, s1, s2, s3, ks);
      cc20_xor64 (in + 64 * i, ks, out + 64 * i);
    }

  /* Trailing partial block. */
  if ((in_len % 64) != 0)
    {
      dwpacked s3 = cc20_counter_row (counter + full, n0, n1, n2);
      dwpacked ks[4];
      chacha_core (s0, s1, s2, s3, ks);
      uint8_t key_stream[64];
      for (unsigned int k = 0; k < 16; ++k)
        {
          to_le32 (ks[k / 4][k % 4], key_stream + 4 * k);
        }
      for (uint32_t j = 0; j < in_len % 64; ++j)
        {
          out[64 * full + j] = in[64 * full + j] ^ key_stream[j];
        }
    }
}
