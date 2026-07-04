#include <stdbool.h>
#include <stdint.h>

#include "tinycrypt/chacha20_poly1305.h"

typedef uint32_t dwpacked __attribute__ ((vector_size (16)));
typedef uint8_t bytes16 __attribute__ ((vector_size (16)));

/* On SSSE3 / NEON the 16- and 8-bit left-rotations each lower to a single
   byte permute (pshufb / tbl). On plain SSE2 that permute is emulated poorly
   and is markedly slower than shift-or, so fall back to shift-or there. The
   12- and 7-bit rotations are always shift-or. */
#if defined(__SSSE3__) || defined(__ARM_NEON) || defined(__ARM_NEON__)
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

/* Quarter-round on whole vectors. The shape is layout agnostic, so the same
   macro drives the single-block (row) core and the vertical multi-block
   cores below. */
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

/* Counter/nonce row in the DJB / OpenSSH layout: a 64-bit block counter in
   words 12/13 (little-endian) and a 64-bit nonce in words 14/15. This matches
   standard ChaCha20 as used by chacha20-poly1305@openssh.com. */
static dwpacked
cc20_counter_row (uint64_t counter, uint32_t n0, uint32_t n1)
{
  return (dwpacked){ (uint32_t)counter, (uint32_t)(counter >> 32), n0, n1 };
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

/* Serializing single-block wrapper, used for the Poly1305 one-time key. */
static void
cc20_block (const uint8_t *key, const uint64_t counter, const uint8_t *nonce,
            uint8_t *state_out)
{
  dwpacked s0 = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
  dwpacked s1 = { from_le32 (key), from_le32 (key + 4), from_le32 (key + 8),
                  from_le32 (key + 12) };
  dwpacked s2 = { from_le32 (key + 16), from_le32 (key + 20),
                  from_le32 (key + 24), from_le32 (key + 28) };
  dwpacked s3
      = cc20_counter_row (counter, from_le32 (nonce), from_le32 (nonce + 4));
  dwpacked ks[4];
  chacha_core (s0, s1, s2, s3, ks);
  for (unsigned int i = 0; i < 16; ++i)
    to_le32 (ks[i / 4][i % 4], state_out + 4 * i);
}

/* XOR a full 64-byte block; keystream stays in registers. Assumes a
   little-endian target (x86-64 / aarch64, the platforms this file targets). */
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

/* Transpose a 4x4 word matrix held in four vectors (rows <-> columns). */
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

/* Encrypt exactly four blocks held in vertical layout (lane = block) in
   v[16]. Removes the per-round diagonalization shuffles the row core needs. */
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

#ifdef __AVX2__
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

/* AVX2 (per-128-bit-lane) building blocks for an 8x8 word transpose. */
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
  qwpacked t0 = CC20_UNPACKLO32 (r[0], r[1]), t1 = CC20_UNPACKHI32 (r[0], r[1]);
  qwpacked t2 = CC20_UNPACKLO32 (r[2], r[3]), t3 = CC20_UNPACKHI32 (r[2], r[3]);
  qwpacked t4 = CC20_UNPACKLO32 (r[4], r[5]), t5 = CC20_UNPACKHI32 (r[4], r[5]);
  qwpacked t6 = CC20_UNPACKLO32 (r[6], r[7]), t7 = CC20_UNPACKHI32 (r[6], r[7]);
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
#endif /* __AVX2__ */

static void
cc20_encrypt (const uint8_t *key, const uint64_t counter, const uint8_t *nonce,
              const uint8_t *plaintext, const uint32_t plaintext_len,
              uint8_t *encrypted_out)
{
  /* Constant/key/nonce state is invariant across blocks; build it once. */
  const dwpacked s0 = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
  const dwpacked s1 = { from_le32 (key), from_le32 (key + 4),
                        from_le32 (key + 8), from_le32 (key + 12) };
  const dwpacked s2 = { from_le32 (key + 16), from_le32 (key + 20),
                        from_le32 (key + 24), from_le32 (key + 28) };
  const uint32_t n0 = from_le32 (nonce), n1 = from_le32 (nonce + 4);
  const uint32_t full = plaintext_len / 64;
  uint32_t i = 0;

#ifdef __AVX2__
  {
    const qwpacked b[12]
        = { splat8 (s0[0]), splat8 (s0[1]), splat8 (s0[2]), splat8 (s0[3]),
            splat8 (s1[0]), splat8 (s1[1]), splat8 (s1[2]), splat8 (s1[3]),
            splat8 (s2[0]), splat8 (s2[1]), splat8 (s2[2]), splat8 (s2[3]) };
    const qwpacked bn0 = splat8 (n0), bn1 = splat8 (n1);
    for (; i + 8 <= full; i += 8)
      {
        uint64_t c[8];
        for (unsigned int j = 0; j < 8; ++j)
          c[j] = counter + i + j;
        qwpacked lo
            = { (uint32_t)c[0], (uint32_t)c[1], (uint32_t)c[2], (uint32_t)c[3],
                (uint32_t)c[4], (uint32_t)c[5], (uint32_t)c[6], (uint32_t)c[7] };
        qwpacked hi = { (uint32_t)(c[0] >> 32), (uint32_t)(c[1] >> 32),
                        (uint32_t)(c[2] >> 32), (uint32_t)(c[3] >> 32),
                        (uint32_t)(c[4] >> 32), (uint32_t)(c[5] >> 32),
                        (uint32_t)(c[6] >> 32), (uint32_t)(c[7] >> 32) };
        qwpacked v[16] = { b[0],  b[1], b[2], b[3],  b[4],  b[5], b[6], b[7],
                           b[8],  b[9], b[10], b[11], lo,   hi,   bn0, bn1 };
        cc20_xor_x8 (v, plaintext + 64 * i, encrypted_out + 64 * i);
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
  const dwpacked bn0 = splat (n0), bn1 = splat (n1);
  for (; i + 4 <= full; i += 4)
    {
      uint64_t c0 = counter + i, c1 = counter + i + 1, c2 = counter + i + 2,
               c3 = counter + i + 3;
      dwpacked v[16]
          = { bc[0], bc[1], bc[2], bc[3], bc[4], bc[5], bc[6], bc[7], bc[8],
              bc[9], bc[10], bc[11],
              (dwpacked){ (uint32_t)c0, (uint32_t)c1, (uint32_t)c2,
                          (uint32_t)c3 },
              (dwpacked){ (uint32_t)(c0 >> 32), (uint32_t)(c1 >> 32),
                          (uint32_t)(c2 >> 32), (uint32_t)(c3 >> 32) },
              bn0, bn1 };
      cc20_xor_x4 (v, plaintext + 64 * i, encrypted_out + 64 * i);
    }

  /* Remaining whole blocks (fewer than the vector width), one at a time. */
  for (; i < full; ++i)
    {
      dwpacked s3 = cc20_counter_row (counter + i, n0, n1);
      dwpacked ks[4];
      chacha_core (s0, s1, s2, s3, ks);
      cc20_xor64 (plaintext + 64 * i, ks, encrypted_out + 64 * i);
    }

  /* Trailing partial block. */
  if ((plaintext_len % 64) != 0)
    {
      dwpacked s3 = cc20_counter_row (counter + full, n0, n1);
      dwpacked ks[4];
      chacha_core (s0, s1, s2, s3, ks);
      uint8_t key_stream[64];
      for (unsigned int k = 0; k < 16; ++k)
        to_le32 (ks[k / 4][k % 4], key_stream + 4 * k);
      for (uint32_t j = 0; j < plaintext_len % 64; ++j)
        encrypted_out[64 * full + j] = plaintext[64 * full + j] ^ key_stream[j];
    }
}

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
add256 (uint64_t *h, const uint64_t *c)
{
  __uint128_t accumulator = 0;
  for (unsigned int i = 0; i < 4; ++i)
    {
      accumulator += (__uint128_t)h[i] + (__uint128_t)c[i];
      h[i] = accumulator & 0xffffffffffffffff;
      accumulator >>= 64;
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

static void
mult192 (const uint64_t *a, const uint64_t *b, uint64_t *out)
{
  uint64_t a_int[3], b_int[3];
  __uint128_t intermediate[6] = {
    0, 0, 0, 0, 0, 0,
  };
  for (unsigned int i = 0; i < 3; ++i)
    {
      a_int[i] = a[i];
      b_int[i] = b[i];
      out[i] = 0x0;
      out[3 + i] = 0x0;
    }
  for (unsigned int i = 0; i < 3; ++i)
    {
      for (unsigned int j = 0; j < 3; ++j)
        {
          intermediate[i + j] += (__uint128_t)a_int[i] * (__uint128_t)b_int[j];
          intermediate[i + j + 1] += intermediate[i + j] >> 64;
          intermediate[i + j] &= 0xffffffffffffffff;
        }
    }
  for (unsigned int k = 0; k < 5; ++k)
    {
      intermediate[k + 1] += intermediate[k] >> 64;
      out[k] = intermediate[k] & 0xffffffffffffffff;
    }
  out[5] = intermediate[5] & 0xffffffffffffffff;
}

static void
shr320_by_130 (const uint64_t *in, uint64_t *out)
{
  out[0] = (in[2] >> 2) | (in[3] << 62);
  out[1] = (in[3] >> 2) | (in[4] << 62);
  out[2] = in[4] >> 2;
}

static bool
greater320 (const uint64_t *a, const uint64_t *b)
{
  uint64_t a_int[5] = { a[0], a[1], a[2], a[3], a[4] };
  sub320 (a_int, b);
  return !(a_int[4] & (1ULL << 63));
}

static void
modp320 (uint64_t *in, uint64_t *out)
{
  const uint64_t P[5]
      = { 0xfffffffffffffffb, 0xffffffffffffffff, 0x3, 0x0, 0x0 };
  const uint64_t ZERO[5] = { 0x0, 0x0, 0x0, 0x0, 0x0 };
  uint64_t approx_quotient[3];
  uint64_t approx_dividend[6];
  uint64_t accumulator[5];
  for (unsigned int i = 0; i < 5; ++i)
    {
      accumulator[i] = in[i];
    }
  for (unsigned int i = 0; i < 2; ++i)
    {
      shr320_by_130 (accumulator, approx_quotient);
      mult192 (P, approx_quotient, approx_dividend);
      sub320 (accumulator, approx_dividend);
    }
  const uint64_t *dummy = greater320 (accumulator, P) ? P : ZERO;
  sub320 (accumulator, dummy);
  for (unsigned int i = 0; i < 4; ++i)
    {
      out[i] = accumulator[i];
    }
}

static void
poly1305_mac_rolling (const uint8_t *msg, const uint8_t *key,
                      const uint8_t blocklen, uint64_t *a)
{
  uint8_t r[32];
  for (unsigned int i = 0; i < 32; ++i)
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
  uint64_t n_chunked[4];
  uint64_t r_chunked[4];
  for (unsigned int i = 0; i < 4; ++i)
    {
      n_chunked[i] = from_le64 (n + 8 * i);
      r_chunked[i] = from_le64 (r + 8 * i);
    }
  add256 (a, n_chunked);
  uint64_t intermediate[6];
  mult192 (r_chunked, a, intermediate);
  modp320 (intermediate, a);
}

static void
poly1305_mac_init (uint64_t *a)
{
  for (unsigned int i = 0; i < 4; ++i)
    {
      a[i] = 0x0;
    }
}

static void
poly1305_mac_finish (uint64_t *a, const uint8_t *key)
{
  uint64_t s[4];
  for (unsigned int i = 2; i < 4; ++i)
    {
      s[i] = 0;
    }
  for (unsigned int i = 0; i < 2; ++i)
    {
      s[i] = from_le64 (key + 16 + 8 * i);
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
  cc20_block (key, 0, nonce, otk);
  uint64_t mac_chunked[4];
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
  if (((from_le64 (frame + ciphertext_len) ^ mac_chunked[0])
       | (from_le64 (frame + ciphertext_len + 8) ^ mac_chunked[1]))
      != 0)
    {
      return false;
    }
  cc20_encrypt (key, 1, nonce, frame, ciphertext_len, plaintext_out);
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
  cc20_block (key, 0, nonce, otk);
  cc20_encrypt (key, 1, nonce, plaintext, plaintext_len, cipher_out);
  uint64_t mac_chunked[4];
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
  for (unsigned int i = 0; i < 2; ++i)
    {
      to_le64 (mac_chunked[i], mac_out + 8 * i);
    }
}

/* ------------------------------------------------------------------ */
/* chacha20-poly1305@openssh.com                                      */
/*                                                                    */
/* Unlike the RFC 8439 AEAD above, OpenSSH's SSH transport cipher     */
/* uses two ChaCha20 keys, encrypts the 4-byte packet length          */
/* separately, and authenticates the raw ciphertext with a plain      */
/* Poly1305 (no AAD, no length framing). The 8-byte nonce is the SSH  */
/* packet sequence number. See PROTOCOL.chacha20poly1305.             */
/* ------------------------------------------------------------------ */

/* Poly1305 tag over a contiguous message (the standard construction). */
static void
poly1305_tag (const uint8_t *otk, const uint8_t *msg, uint64_t len,
              uint8_t tag[16])
{
  uint64_t acc[4];
  poly1305_mac_init (acc);
  uint64_t i = 0;
  for (; i + 16 <= len; i += 16)
    poly1305_mac_rolling (msg + i, otk, 16, acc);
  if (i < len)
    poly1305_mac_rolling (msg + i, otk, (uint8_t)(len - i), acc);
  poly1305_mac_finish (acc, otk);
  to_le64 (acc[0], tag);
  to_le64 (acc[1], tag + 8);
}

void
tct_chacha20_poly1305_openssh_seal (const uint8_t *seqnr, const uint8_t *key,
                                    const uint8_t *packet, uint32_t payload_len,
                                    uint8_t *out)
{
  const uint8_t *k_payload = key;      /* K_2 */
  const uint8_t *k_length = key + 32;  /* K_1 */
  uint8_t otk[64];
  cc20_block (k_payload, 0, seqnr, otk);                /* Poly1305 key @ ctr 0 */
  cc20_encrypt (k_length, 0, seqnr, packet, 4, out);    /* length  @ ctr 0 */
  cc20_encrypt (k_payload, 1, seqnr, packet + 4, payload_len, out + 4);
  poly1305_tag (otk, out, 4 + (uint64_t)payload_len, out + 4 + payload_len);
}

void
tct_chacha20_poly1305_openssh_decrypt_length (const uint8_t *seqnr,
                                              const uint8_t *key,
                                              const uint8_t *enc_len,
                                              uint8_t *len_out)
{
  cc20_encrypt (key + 32, 0, seqnr, enc_len, 4, len_out); /* K_1 @ ctr 0 */
}

bool
tct_chacha20_poly1305_openssh_open (const uint8_t *seqnr, const uint8_t *key,
                                    const uint8_t *frame, uint32_t payload_len,
                                    uint8_t *packet_out)
{
  const uint8_t *k_payload = key;      /* K_2 */
  const uint8_t *k_length = key + 32;  /* K_1 */
  uint8_t otk[64];
  cc20_block (k_payload, 0, seqnr, otk);
  const uint64_t ct_len = 4 + (uint64_t)payload_len;
  uint8_t tag[16];
  poly1305_tag (otk, frame, ct_len, tag);
  /* constant-time tag comparison before touching the payload */
  if (((from_le64 (frame + ct_len) ^ from_le64 (tag))
       | (from_le64 (frame + ct_len + 8) ^ from_le64 (tag + 8)))
      != 0)
    {
      return false;
    }
  cc20_encrypt (k_length, 0, seqnr, frame, 4, packet_out);
  cc20_encrypt (k_payload, 1, seqnr, frame + 4, payload_len, packet_out + 4);
  return true;
}
