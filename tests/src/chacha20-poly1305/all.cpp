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
  const uint8_t KEY[] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
    0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
    0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
  };
  const uint8_t INPUT[]
      = "Ladies and Gentlemen of the class of '99: If I could offer you only "
        "one tip for the future, sunscreen would be it.";
  const uint8_t NONCE[] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  };
  const uint8_t AAD[] = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
                          0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
  const uint8_t EXPECTED_CIPHERTEXT[] = {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
    0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
    0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
    0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
    0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
    0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16,
  };
  const uint8_t EXPECTED_MAC[16] = {
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
    0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
  };
  uint8_t actual_ciphertext[sizeof (EXPECTED_CIPHERTEXT)];
  uint8_t actual_mac[16];
  tct_aead_chacha20_poly1305_encrypt (AAD, sizeof (AAD), KEY, NONCE, INPUT,
                                      sizeof (INPUT) - 1, actual_ciphertext,
                                      actual_mac);
  EXPECT_EQ (memcmp (actual_ciphertext, EXPECTED_CIPHERTEXT,
                     sizeof (EXPECTED_CIPHERTEXT)),
             0);
  EXPECT_EQ (memcmp (actual_mac, EXPECTED_MAC, sizeof (EXPECTED_MAC)), 0);
}

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
  const size_t lengths[] = { 0,   1,   63,  64,  65,  127, 128,  255,  256,
                             257, 320, 511, 512, 513, 576, 1024, 2048, 4096 };

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
          if (len != 0)
            {
              memcpy (frame.data (), cipher.data (), len);
            }
          memcpy (frame.data () + len, mac, 16);

          bool ok = tct_aead_chacha20_poly1305_decrypt_and_verify (
              AAD, aad_len, KEY, NONCE, frame.data (), len, recovered.data ());
          EXPECT_TRUE (ok) << "verify failed: aad_len=" << aad_len
                           << " len=" << len;
          if (len != 0)
            {
              EXPECT_EQ (memcmp (recovered.data (), plaintext.data (), len), 0)
                  << "aad_len=" << aad_len << " len=" << len;
            }

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
