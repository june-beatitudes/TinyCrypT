#ifndef TNT_CC20_P1305_H
#define TNT_CC20_P1305_H

#include <stdbool.h>
#include <stdint.h>

/// Implements the AEAD-ChaCha20-Poly1305 encryption and MAC algorithm defined
/// in RFC 8439
void tct_aead_chacha20_poly1305_encrypt (
    const uint8_t *aad, const uint64_t aad_len, const uint8_t *key,
    const uint8_t *nonce, const uint8_t *plaintext,
    const uint64_t plaintext_len, uint8_t *cipher_out, uint8_t *mac_out);

/// Decrypts and verifies an AEAD-ChaCha20-Poly1305 frame
bool tct_aead_chacha20_poly1305_decrypt_and_verify (
    const uint8_t *aad, const uint64_t aad_len, const uint8_t *key,
    const uint8_t *nonce, const uint8_t *frame, const uint64_t ciphertext_len,
    uint8_t *plaintext_out);

/// Seals an SSH packet with the chacha20-poly1305@openssh.com cipher (RFC-
/// incompatible; matches OpenSSH's PROTOCOL.chacha20poly1305).
///
/// \param seqnr       8-byte packet sequence number (the ChaCha20 nonce).
/// \param key         64-byte key: K_2 = key[0..32) encrypts the payload and
///                    derives the Poly1305 key, K_1 = key[32..64) encrypts the
///                    4-byte length field.
/// \param packet      4-byte packet length followed by \p payload_len bytes.
/// \param payload_len number of payload bytes after the length field.
/// \param out         receives 4 + \p payload_len ciphertext bytes followed by
///                    a 16-byte Poly1305 tag.
void tct_chacha20_poly1305_openssh_seal (const uint8_t *seqnr,
                                         const uint8_t *key,
                                         const uint8_t *packet,
                                         uint32_t payload_len, uint8_t *out);

/// Decrypts only the 4-byte encrypted length field (with K_1), so a reader can
/// size the packet before authenticating it.
void tct_chacha20_poly1305_openssh_decrypt_length (const uint8_t *seqnr,
                                                   const uint8_t *key,
                                                   const uint8_t *enc_len,
                                                   uint8_t *len_out);

/// Verifies the tag and opens a chacha20-poly1305@openssh.com packet.
///
/// \param frame       4-byte encrypted length, \p payload_len encrypted payload
///                    bytes, then the 16-byte tag.
/// \param payload_len payload length (obtain via
///                    tct_chacha20_poly1305_openssh_decrypt_length).
/// \param packet_out  on success receives 4 + \p payload_len plaintext bytes
///                    (length field followed by payload).
/// \return true and writes \p packet_out on success; false (writing nothing) if
///         authentication fails.
bool tct_chacha20_poly1305_openssh_open (const uint8_t *seqnr,
                                         const uint8_t *key,
                                         const uint8_t *frame,
                                         uint32_t payload_len,
                                         uint8_t *packet_out);

#endif