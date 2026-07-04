extern "C"
{
#include "tinycrypt/chacha20_poly1305.h"
}
#include "gtest/gtest.h"
#include <cstdint>
#include <cstring>
#include <vector>

TEST (ChaCha20_Poly1305, cc20_p1305_full)
{
  const uint8_t KEY[]
      = { 0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
          0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
          0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07 };
  const uint8_t INPUT[]
      = { 0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca };
  const uint8_t NONCE[] = { 0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a };
  const uint8_t AAD[]
      = { 0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0 };
  const uint8_t EXPECTED_OUTPUT[]
      = { 0xe3, 0xe4, 0x46, 0xf7, 0xed, 0xe9, 0xa1, 0x9b, 0x62,
          0xa4, 0x67, 0x7d, 0xab, 0xf4, 0xe3, 0xd2, 0x4b, 0x87,
          0x6b, 0xb2, 0x84, 0x75, 0x38, 0x96, 0xe1, 0xd6 };
  uint8_t actual_output[sizeof (EXPECTED_OUTPUT)];
  tct_aead_chacha20_poly1305_encrypt (AAD, sizeof (AAD), KEY, NONCE, INPUT,
                                      sizeof (INPUT), actual_output,
                                      actual_output + sizeof (INPUT));
  EXPECT_EQ (memcmp (actual_output, EXPECTED_OUTPUT, sizeof (EXPECTED_OUTPUT)),
             0);
}

// Encrypt-then-decrypt round trip across a spread of message lengths. This
// exercises the multi-block keystream paths (the 8-block AVX2 and 4-block SIMD
// cores kick in at 512 and 256 bytes respectively) as well as the
// partial-block tail, none of which the single fixed vector above reaches.
TEST (ChaCha20_Poly1305, round_trip_lengths)
{
  const uint8_t KEY[32]
      = { 0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
          0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
          0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07 };
  const uint8_t NONCE[8] = { 0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a };
  const uint8_t AAD[10]
      = { 0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0 };

  // Lengths straddling block (64) and vector-width (256, 512) boundaries.
  const size_t lengths[]
      = { 0,   1,   63,  64,  65,   127,  128,  255,  256,
          257, 320, 511, 512, 513,  576,  1024, 2048, 4096 };

  for (size_t aad_len = 0; aad_len <= sizeof (AAD); aad_len += sizeof (AAD))
    {
      for (size_t len : lengths)
        {
          std::vector<uint8_t> plaintext (len), cipher (len), recovered (len);
          for (size_t i = 0; i < len; ++i)
            plaintext[i] = static_cast<uint8_t> (i * 31 + 7);

          uint8_t mac[16];
          tct_aead_chacha20_poly1305_encrypt (AAD, aad_len, KEY, NONCE,
                                              plaintext.data (), len,
                                              cipher.data (), mac);

          // ciphertext must differ from plaintext where there is data
          if (len > 0)
            {
              EXPECT_NE (memcmp (cipher.data (), plaintext.data (), len), 0)
                  << "len=" << len;
            }

          // frame = ciphertext || 16-byte tag
          std::vector<uint8_t> frame (len + 16);
          memcpy (frame.data (), cipher.data (), len);
          memcpy (frame.data () + len, mac, 16);

          bool ok = tct_aead_chacha20_poly1305_decrypt_and_verify (
              AAD, aad_len, KEY, NONCE, frame.data (), len, recovered.data ());
          EXPECT_TRUE (ok) << "verify failed: aad_len=" << aad_len
                           << " len=" << len;
          EXPECT_EQ (memcmp (recovered.data (), plaintext.data (), len), 0)
              << "aad_len=" << aad_len << " len=" << len;

          // a single flipped ciphertext bit must fail verification
          if (len > 0)
            {
              frame[0] ^= 0x01;
              EXPECT_FALSE (tct_aead_chacha20_poly1305_decrypt_and_verify (
                  AAD, aad_len, KEY, NONCE, frame.data (), len,
                  recovered.data ()))
                  << "tamper not detected: len=" << len;
            }
        }
    }
}

// ---- chacha20-poly1305@openssh.com ----

static std::vector<uint8_t>
unhex (const char *h)
{
  std::vector<uint8_t> v;
  for (size_t i = 0; h[i] && h[i + 1]; i += 2)
    {
      auto nib = [] (char c) {
        return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
      };
      v.push_back (static_cast<uint8_t> (nib (h[i]) << 4 | nib (h[i + 1])));
    }
  return v;
}

// build the packet the reference used: 2-byte LE length + 2 zero bytes, then
// payload[i] = i*11 + 1
static std::vector<uint8_t>
make_packet (uint32_t plen)
{
  std::vector<uint8_t> p (4 + plen);
  p[0] = plen & 0xff;
  p[1] = (plen >> 8) & 0xff;
  for (uint32_t i = 0; i < plen; ++i)
    p[4 + i] = static_cast<uint8_t> (i * 11 + 1);
  return p;
}

// Golden vectors from an independent reference implementation that is itself
// anchored against the canonical RFC 8439 ChaCha20 and Poly1305 test vectors.
TEST (ChaCha20_Poly1305, openssh_golden)
{
  auto key = unhex ("030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0"
                    "c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d84"
                    "8b9299a0a7aeb5bc");
  auto seq = unhex ("0000000000000005");
  struct
  {
    uint32_t plen;
    const char *out;
  } golden[] = {
    { 8, "fe5bcdbc9fdefa8cf3de24c316be2bd5af1fdef8f4730379b7fc0df0" },
    { 60,
      "ca5bcdbc9fdefa8cf3de24c3f9cfb43fdb24a92f38ad88ebf7209eef95b0a44c"
      "f0d8c30674fdaf749bfcd12bb622551bfa0a25bdf1be24d96ef9df544547c240"
      "e25732916c0370aea37d9fdb8d374605" },
  };
  for (auto &g : golden)
    {
      auto packet = make_packet (g.plen);
      auto expected = unhex (g.out);
      std::vector<uint8_t> out (4 + g.plen + 16);
      tct_chacha20_poly1305_openssh_seal (seq.data (), key.data (),
                                          packet.data (), g.plen, out.data ());
      EXPECT_EQ (out, expected) << "seal mismatch, plen=" << g.plen;
    }
}

TEST (ChaCha20_Poly1305, openssh_round_trip)
{
  auto key = unhex ("030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0"
                    "c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d84"
                    "8b9299a0a7aeb5bc");
  const uint8_t seq[8] = { 0, 0, 0, 0, 0, 0, 0, 5 };

  for (uint32_t plen : { 0u, 1u, 8u, 63u, 64u, 65u, 255u, 256u, 512u, 1000u, 4096u })
    {
      auto packet = make_packet (plen);
      std::vector<uint8_t> frame (4 + plen + 16), recovered (4 + plen);
      tct_chacha20_poly1305_openssh_seal (seq, key.data (), packet.data (),
                                          plen, frame.data ());

      // length field decrypts to the real length
      uint8_t declen[4];
      tct_chacha20_poly1305_openssh_decrypt_length (seq, key.data (),
                                                    frame.data (), declen);
      EXPECT_EQ (memcmp (declen, packet.data (), 4), 0) << "plen=" << plen;

      // open verifies and recovers the packet
      EXPECT_TRUE (tct_chacha20_poly1305_openssh_open (
          seq, key.data (), frame.data (), plen, recovered.data ()))
          << "plen=" << plen;
      EXPECT_EQ (recovered, packet) << "plen=" << plen;

      // any tampered ciphertext byte fails authentication
      frame[0] ^= 0x40;
      EXPECT_FALSE (tct_chacha20_poly1305_openssh_open (
          seq, key.data (), frame.data (), plen, recovered.data ()))
          << "tamper undetected, plen=" << plen;
    }
}