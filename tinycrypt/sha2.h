#ifndef TCT_SHA2_H
#define TCT_SHA2_H

#include <stdint.h>

#define TCT_SHA256_DIGEST_LEN 32
#define TCT_SHA512_DIGEST_LEN 64

/*@ requires \separated(data, hash_out);
  @ requires \valid(data + (0..data_len-1));
  @ requires \valid(hash_out + (0..31));
  @ requires data_len <= 0xffffffffffffffff - 73;
  @ terminates \true;
  @ exits \false;
  @ assigns hash_out[0..31];
 */
/// Implements the NIST SHA-256 algorithm
void tct_sha256 (const uint8_t *data, uint64_t data_len, uint8_t *hash_out);

/*@ requires \separated(data, hash_out);
  @ requires \valid(data + (0..data_len-1));
  @ requires \valid(hash_out + (0..63));
  @ requires data_len <= 0xffffffffffffffff - 145;
  @ terminates \true;
  @ exits \false;
  @ assigns hash_out[0..63];
 */
/// Implements the NIST SHA-512 algorithm
void tct_sha512 (const uint8_t *data, uint64_t data_len, uint8_t *hash_out);

#endif
