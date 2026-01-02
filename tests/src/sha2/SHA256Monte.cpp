#include <cstdint>
#include <cstring>
#include "gtest/gtest.h"
extern "C" {
#include "tinycrypt/sha2.h"
}
static uint8_t SEED[] = {0x6d,0x1e,0x72,0xad,0x03,0xdd,0xeb,0x5d,0xe8,0x91,0xe5,0x72,0xe2,0x39,0x6f,0x8d,0xa0,0x15,0xd8,0x99,0xef,0x0e,0x79,0x50,0x31,0x52,0xd6,0x01,0x0a,0x3f,0xe6,0x91,};
static uint8_t ROUND0[] = {0xe9,0x3c,0x33,0x0a,0xe5,0x44,0x77,0x38,0xc8,0xaa,0x85,0xd7,0x1a,0x6c,0x80,0xf2,0xa5,0x83,0x81,0xd0,0x58,0x72,0xd2,0x6b,0xdd,0x39,0xf1,0xfc,0xd4,0xf2,0xb7,0x88,};
static uint8_t ROUND1[] = {0x2e,0x78,0xf8,0xc8,0x77,0x2e,0xa7,0xc9,0x33,0x1d,0x41,0xed,0x3f,0x9c,0xdf,0x27,0xd8,0xf5,0x14,0xa9,0x93,0x42,0xee,0x76,0x6e,0xe3,0xb8,0xb0,0xd0,0xb1,0x21,0xc0,};
static uint8_t ROUND2[] = {0xd6,0xa2,0x3d,0xff,0x1b,0x7f,0x2e,0xdd,0xc1,0xa2,0x12,0xf8,0xa2,0x18,0x39,0x75,0x23,0xa7,0x99,0xb0,0x73,0x86,0xa3,0x06,0x92,0xfd,0x6f,0xe9,0xd2,0xbf,0x09,0x44,};
static uint8_t ROUND3[] = {0xfb,0x00,0x99,0xa9,0x64,0xfa,0xd5,0xa8,0x8c,0xf1,0x29,0x52,0xf2,0x99,0x1c,0xe2,0x56,0xa4,0xac,0x30,0x49,0xf3,0xd3,0x89,0xc3,0xb9,0xe6,0xc0,0x0e,0x58,0x5d,0xb4,};
static uint8_t ROUND4[] = {0xf9,0xeb,0xa2,0xa4,0xcf,0x62,0x63,0x82,0x6b,0xea,0xf6,0x15,0x00,0x57,0x84,0x9e,0xb9,0x75,0xa9,0x51,0x3c,0x0b,0x76,0xec,0xad,0x0f,0x1c,0x19,0xeb,0xba,0xd8,0x9b,};
static uint8_t ROUND5[] = {0x3d,0xdf,0x05,0xba,0x8d,0xfe,0xc9,0x82,0x45,0x1a,0x3e,0x9a,0x97,0x69,0x5e,0xa9,0xcd,0xb7,0x09,0x8c,0x87,0x7d,0x0c,0x2c,0xd2,0xc6,0x4e,0x58,0xa8,0x77,0x54,0xd9,};
static uint8_t ROUND6[] = {0x2c,0xc3,0xfe,0x50,0x1e,0x3b,0x2e,0x33,0xe6,0x04,0x07,0xb0,0xa2,0x70,0x25,0x73,0x5d,0xd0,0x4f,0xd7,0x62,0x3b,0xb4,0xfc,0xee,0xeb,0xae,0x5c,0xad,0x67,0xad,0x4b,};
static uint8_t ROUND7[] = {0xc5,0x34,0x80,0x2a,0x45,0x9b,0x40,0xc7,0x92,0xe1,0xfa,0x68,0xe5,0x4c,0xea,0xb6,0x9e,0x33,0x3f,0xbe,0xee,0xca,0xd6,0x5f,0xb1,0x24,0xd2,0xf3,0xcc,0x1f,0x1f,0xc1,};
static uint8_t ROUND8[] = {0x89,0x86,0xe9,0x5d,0x85,0xe6,0x48,0x22,0x28,0x7c,0x78,0xcb,0x7a,0x71,0x43,0x39,0x43,0x13,0x32,0x18,0x21,0x07,0x10,0x9d,0x57,0x82,0x77,0x76,0xc6,0xcc,0x93,0x0e,};
static uint8_t ROUND9[] = {0x72,0x36,0x14,0x01,0xc6,0x70,0xd0,0x7f,0x11,0x51,0xa9,0x5e,0x2e,0xe9,0x14,0x66,0x5c,0x2b,0xdb,0x12,0x28,0x58,0x18,0x33,0xc7,0xdc,0x53,0xb8,0x9c,0x01,0xc9,0x27,};
static uint8_t ROUND10[] = {0x12,0x4c,0x44,0x3b,0xad,0x9d,0x95,0x5e,0x08,0x4a,0x39,0x61,0xb0,0x79,0xc4,0x3c,0x59,0xb5,0xe0,0xd6,0x66,0xaf,0x38,0xf2,0xf3,0x78,0x46,0xe8,0x53,0x69,0xa6,0x18,};
static uint8_t ROUND11[] = {0x81,0x91,0x4b,0x78,0x67,0x4a,0x2a,0x62,0x04,0xee,0xf7,0x8f,0xf5,0x13,0x69,0x52,0x6b,0xf0,0xc2,0xe1,0x21,0xcd,0x36,0x4e,0xb4,0x0a,0x84,0x35,0x47,0x9d,0xda,0x14,};
static uint8_t ROUND12[] = {0x8e,0xac,0x9d,0x96,0x3b,0x44,0x02,0x1b,0x70,0xa5,0x27,0xea,0x07,0x42,0x0b,0x03,0xf5,0x1a,0x99,0x8d,0x0d,0x6c,0xb7,0x3a,0xd4,0xcb,0x7f,0xc6,0x88,0xb4,0xd1,0x74,};
static uint8_t ROUND13[] = {0x04,0x27,0x26,0x3b,0x4d,0xd3,0xeb,0xfc,0xb7,0x87,0x19,0x39,0xdb,0xac,0xa5,0xca,0x94,0xe7,0x94,0xf7,0x48,0xc0,0x29,0x20,0xc9,0x75,0x9d,0xfa,0x55,0x4e,0xa5,0x34,};
static uint8_t ROUND14[] = {0x3e,0x9d,0x75,0x4f,0x2e,0xc2,0x73,0xb0,0x05,0x6c,0x2f,0xca,0xd2,0xe8,0x91,0xaa,0xf9,0x61,0x6f,0xe7,0x40,0x05,0xd3,0x6c,0xbf,0x5c,0xcb,0xa2,0xe0,0x37,0xb5,0xb3,};
static uint8_t ROUND15[] = {0x98,0x6b,0x65,0x94,0xed,0x96,0xa8,0x19,0xe4,0x9e,0xdb,0x9f,0x65,0xdb,0x2e,0xa5,0x21,0x68,0x97,0x3d,0x7e,0x18,0xae,0x9e,0x0b,0x88,0x69,0xa8,0xb5,0xdd,0x29,0xa0,};
static uint8_t ROUND16[] = {0x11,0x75,0x78,0x12,0x6a,0x35,0x17,0x6a,0x00,0xf8,0xc0,0xcf,0x99,0x94,0x42,0xdf,0x08,0x90,0x73,0x7b,0xe1,0x88,0x0f,0x06,0xe6,0xa7,0x27,0x09,0x59,0xc1,0x14,0xc6,};
static uint8_t ROUND17[] = {0xfd,0x7f,0x55,0x74,0x78,0x8d,0x8e,0xf6,0x4b,0x83,0x33,0x3f,0xfb,0x62,0xe4,0xcd,0x33,0x11,0xe6,0x38,0xdb,0x0c,0x51,0x40,0x71,0xc1,0x9b,0x84,0xe9,0x11,0x7a,0xfe,};
static uint8_t ROUND18[] = {0x19,0xdb,0x7b,0xa6,0xe3,0x48,0x8a,0x9e,0x93,0x5a,0xf3,0x3f,0xfb,0x91,0x2d,0x60,0xc9,0xd3,0xb9,0x8a,0x0b,0xe1,0xd7,0x8e,0x0b,0x37,0x4d,0xcb,0x52,0x74,0xa7,0xfb,};
static uint8_t ROUND19[] = {0x52,0x51,0x9e,0x63,0x19,0x50,0x5d,0xf7,0xa9,0xaa,0x83,0x77,0x86,0x18,0xec,0x10,0xb7,0x8c,0x57,0x71,0xba,0xc5,0x0e,0x8d,0x3f,0x59,0xbc,0x81,0x5d,0xab,0xfb,0x1f,};
static uint8_t ROUND20[] = {0x43,0x4d,0x77,0x95,0xfc,0x75,0x10,0xaf,0x04,0xb6,0x13,0xe1,0x20,0xf7,0xf4,0x8e,0x6d,0x61,0x3e,0xc0,0x56,0xae,0x9f,0xbc,0x7c,0x86,0x9b,0x87,0xc1,0xdc,0xe6,0x3e,};
static uint8_t ROUND21[] = {0x02,0x03,0x24,0xde,0x7f,0x67,0x63,0xbe,0x57,0xbc,0x4a,0x6a,0x09,0x60,0x25,0x8e,0xa4,0x01,0xff,0xe4,0x0d,0x68,0xf8,0x54,0xe8,0x2c,0xcf,0xa9,0xe0,0x61,0x2f,0xf7,};
static uint8_t ROUND22[] = {0xb8,0x7c,0x7f,0xd0,0xec,0x4c,0xd3,0x5f,0xab,0x07,0x7b,0x64,0xd0,0x09,0x17,0xad,0x06,0xaa,0xcc,0xb0,0x95,0xbb,0xe4,0x60,0x34,0x66,0x64,0x4c,0xe6,0xcb,0xce,0x18,};
static uint8_t ROUND23[] = {0x01,0xab,0xbd,0x12,0xb2,0xb4,0x76,0xb2,0xd5,0x40,0xd0,0xc4,0x7e,0xdc,0xb5,0x62,0x63,0xea,0x65,0x8a,0x80,0x80,0xa8,0xf0,0x8d,0xbb,0x31,0x39,0x42,0x56,0x2f,0x00,};
static uint8_t ROUND24[] = {0xce,0x95,0xbb,0x2b,0xf2,0xd5,0xc9,0x14,0x02,0xe1,0x3e,0xd5,0x27,0x16,0x15,0x60,0x7f,0x39,0xe0,0x67,0x8a,0xae,0x77,0x6d,0x18,0xa7,0x83,0x51,0xb9,0x0b,0x58,0x38,};
static uint8_t ROUND25[] = {0xb8,0x1a,0xf2,0x64,0xb0,0xbb,0x48,0x5f,0x66,0x56,0xbe,0x91,0x47,0x8f,0x7b,0x96,0xc3,0x24,0xfe,0x26,0x2f,0xcc,0x36,0x6d,0x9c,0xe3,0xed,0xd4,0x4c,0xcb,0x85,0xd0,};
static uint8_t ROUND26[] = {0x9e,0x2a,0xd9,0x01,0x20,0x0c,0xa5,0x24,0xc9,0x13,0x73,0xf7,0xb5,0xed,0xa9,0xcd,0xa1,0x42,0x35,0x3e,0x76,0x38,0x62,0xe3,0x50,0x31,0x4f,0x79,0x3a,0x0b,0x70,0x0d,};
static uint8_t ROUND27[] = {0xdb,0xfa,0xbc,0x71,0x24,0x33,0x8d,0x68,0x45,0xf0,0x83,0xcb,0x1b,0xbd,0xf7,0xb4,0x06,0x02,0x74,0xd8,0xe0,0xe9,0x8d,0x08,0xbb,0x7c,0xa3,0x77,0x90,0x59,0xb4,0x5b,};
static uint8_t ROUND28[] = {0xd9,0x3c,0x2c,0xd6,0x1f,0x54,0x76,0xea,0x08,0xd8,0x5f,0x74,0x17,0x20,0xab,0x2c,0xe5,0xc4,0xe3,0x8c,0xd8,0x25,0x47,0x58,0x23,0x81,0x55,0xfd,0x68,0xea,0x77,0x23,};
static uint8_t ROUND29[] = {0x23,0x2d,0x9c,0x3b,0x58,0x3e,0x29,0x74,0x39,0xc8,0x59,0x15,0x07,0x38,0xe1,0xb1,0xd5,0x30,0x81,0x2d,0x63,0xa9,0xa2,0xc1,0xcb,0x8e,0x40,0xcb,0x50,0xa2,0xf2,0x7b,};
static uint8_t ROUND30[] = {0x8b,0x9c,0x85,0x8b,0xd1,0x35,0x13,0x8d,0x90,0x23,0xa0,0xb5,0xfc,0xf3,0xf1,0x2e,0xbb,0xc3,0xb7,0xf7,0x21,0xee,0x0b,0x44,0xbe,0x18,0x71,0x18,0x7f,0x21,0xf5,0x06,};
static uint8_t ROUND31[] = {0x05,0xce,0xdb,0xd5,0x68,0xce,0x9a,0xdc,0xf5,0x02,0x29,0x99,0xb8,0xf3,0xa2,0x89,0x95,0xa9,0x10,0xc5,0x72,0x37,0x51,0x86,0xda,0x5f,0xeb,0xd7,0x75,0xd6,0x2b,0x79,};
static uint8_t ROUND32[] = {0x24,0x28,0x2c,0xba,0x8f,0x5d,0xfc,0xe7,0xe4,0x23,0xa1,0x03,0x48,0x8a,0x9a,0x92,0x40,0x80,0xd5,0x49,0x85,0x3c,0x69,0x91,0x59,0xd2,0x78,0x16,0xdb,0xdb,0xe5,0xd9,};
static uint8_t ROUND33[] = {0xba,0x6e,0x3c,0x38,0x12,0x8f,0x93,0xf2,0x88,0xe7,0x81,0xaf,0x8a,0x13,0xe7,0xce,0x51,0x20,0xc2,0xa4,0x3a,0x6d,0x1c,0x0d,0x4e,0xdc,0x83,0x12,0x47,0x35,0x00,0x79,};
static uint8_t ROUND34[] = {0x70,0x6f,0xff,0xec,0x5b,0x69,0xf5,0xef,0x54,0x65,0xb6,0xa8,0x66,0x3c,0x30,0x21,0x43,0xaf,0x74,0x3c,0x6b,0x7c,0xd5,0xfe,0xc9,0xf3,0xfa,0x9b,0xf9,0xb2,0xe2,0x85,};
static uint8_t ROUND35[] = {0x6d,0x32,0xc5,0x5c,0x00,0x5e,0xea,0x65,0xda,0xcd,0xf0,0xe9,0x0f,0x43,0x69,0x43,0xd0,0xd0,0xac,0xec,0x3c,0x23,0x55,0xc3,0x6e,0x2d,0xf1,0xa8,0x6d,0x1a,0x11,0xa7,};
static uint8_t ROUND36[] = {0xb3,0x53,0xf4,0x25,0x29,0x3d,0xb4,0x64,0xad,0x81,0x41,0x77,0xea,0x96,0x89,0xf4,0x30,0x54,0xbc,0xdb,0xaf,0x75,0x67,0x5e,0x91,0x8b,0x78,0xa8,0x2c,0xa9,0x7a,0x50,};
static uint8_t ROUND37[] = {0xc3,0xfa,0x99,0x93,0x13,0x0b,0x3c,0x95,0xd9,0xae,0xd3,0x02,0x43,0xba,0x90,0x20,0x35,0x93,0x3d,0x18,0xad,0xf5,0xe2,0x1d,0x25,0x67,0x67,0x47,0x69,0x06,0x2e,0x81,};
static uint8_t ROUND38[] = {0x1e,0x77,0xe0,0x79,0x88,0xeb,0xd6,0x18,0x74,0x0c,0x2f,0x89,0xa7,0xbc,0xf0,0xae,0x25,0x42,0x27,0x9e,0xa8,0x89,0x5b,0x39,0xaa,0x70,0xba,0x8b,0xc3,0x7e,0xe0,0x0f,};
static uint8_t ROUND39[] = {0x06,0x39,0x27,0x89,0x2a,0x0b,0x09,0x5b,0xe7,0xd2,0x19,0x87,0xff,0x81,0x57,0xcd,0x4c,0x67,0x4c,0x1c,0xd0,0x1a,0xb9,0xf0,0x83,0x48,0x24,0xe8,0xef,0xbc,0xf9,0x38,};
static uint8_t ROUND40[] = {0xf4,0x30,0x54,0xc2,0x80,0xf0,0x53,0x71,0xcf,0xba,0xc7,0x76,0xd4,0x3d,0x60,0x01,0xf7,0x13,0x50,0xd8,0x98,0x67,0x7f,0x03,0x5a,0xa8,0xf7,0xe5,0xbd,0x7b,0x3f,0xa3,};
static uint8_t ROUND41[] = {0x24,0x27,0x93,0x4b,0x28,0xc7,0xa9,0xc2,0xb1,0x8a,0x5b,0x7e,0x99,0x63,0x51,0xaa,0x56,0x75,0x23,0x74,0x4f,0x60,0xd5,0x4d,0xc3,0x5b,0xbb,0x61,0xf5,0x6f,0x6f,0xd4,};
static uint8_t ROUND42[] = {0x36,0x33,0x97,0x6d,0x17,0x42,0x79,0x16,0x1e,0x13,0xb4,0x9e,0x58,0x66,0xc1,0x44,0xce,0x8c,0x1d,0x17,0xec,0x19,0x01,0xad,0x56,0xa0,0x2c,0x90,0x02,0x73,0xfe,0x11,};
static uint8_t ROUND43[] = {0x5f,0x97,0x88,0x66,0x0d,0x82,0xc8,0x01,0x55,0xa7,0xfe,0xa9,0x18,0x96,0xbe,0x3b,0xe2,0xeb,0x6a,0x7b,0x2c,0xe9,0x63,0xf3,0x80,0x4c,0xd0,0x9d,0xa5,0xac,0x0c,0x8f,};
static uint8_t ROUND44[] = {0x09,0x7e,0xf5,0x7d,0xe6,0xdf,0x98,0xc2,0x93,0x46,0xe6,0x7e,0x7f,0x67,0x65,0x69,0xad,0x40,0x2f,0x7a,0x1c,0x88,0xd1,0xcf,0x39,0xce,0x2d,0x44,0xfd,0x70,0x6f,0x72,};
static uint8_t ROUND45[] = {0xfe,0xdc,0xc8,0x10,0xc7,0x47,0x06,0xa2,0x7f,0xc0,0xb6,0x66,0x3a,0xb2,0xf9,0xde,0x07,0x61,0x08,0x96,0x82,0xdf,0xf1,0x27,0x9f,0xcd,0x91,0x31,0x2a,0xf1,0xb8,0xe3,};
static uint8_t ROUND46[] = {0xbd,0x5d,0x61,0xfe,0xa8,0xd2,0x30,0x89,0xf3,0xf3,0x02,0x66,0xb1,0xda,0xa6,0x36,0xa3,0x52,0xe4,0x94,0x76,0x52,0x6e,0x71,0xcc,0x07,0x35,0xcb,0xd1,0x70,0x54,0xfe,};
static uint8_t ROUND47[] = {0x5e,0xad,0x02,0x7c,0x03,0xd7,0xa5,0x5c,0x17,0xf0,0xc7,0x83,0xb6,0xd7,0x76,0x70,0xcd,0xb8,0x94,0x27,0x72,0x07,0x7d,0x09,0xdf,0xf9,0xa4,0x6e,0xcd,0x52,0x7b,0xec,};
static uint8_t ROUND48[] = {0x7a,0x06,0xee,0xea,0x07,0xca,0x9e,0xb9,0x4a,0x98,0xa5,0xe9,0xf0,0x0b,0x7e,0xfd,0x8d,0xe9,0x84,0x3b,0x6a,0xa8,0x88,0x82,0x2c,0x3d,0xcc,0xf8,0x03,0x63,0x77,0x32,};
static uint8_t ROUND49[] = {0x44,0xb6,0xa8,0x95,0x05,0x8e,0xd3,0xf3,0x1a,0x55,0x49,0x40,0x7a,0xf8,0xf7,0x88,0x63,0x1f,0x8a,0x6e,0xb8,0xc0,0xa5,0xf2,0xe1,0x5f,0xac,0xc9,0x19,0x0b,0x56,0x72,};
static uint8_t ROUND50[] = {0xf8,0xa5,0x8b,0xff,0x4b,0x54,0xaa,0xeb,0xe1,0x8f,0xc3,0xf0,0xbb,0x1d,0x24,0x97,0x4a,0x12,0x55,0x30,0x75,0x6d,0xd4,0xa0,0xf1,0x56,0x28,0xc3,0x5c,0x02,0xea,0x1c,};
static uint8_t ROUND51[] = {0x3b,0xf2,0xae,0x54,0x08,0x39,0x9a,0xba,0x59,0xf4,0x2e,0x5b,0xed,0x35,0xa0,0x0d,0x03,0x8f,0xad,0xa1,0x60,0x13,0xff,0xa5,0xda,0x9e,0x8b,0x72,0x07,0xf6,0x01,0x2c,};
static uint8_t ROUND52[] = {0x31,0xd3,0x3c,0x02,0x75,0x98,0x6b,0x06,0xf6,0xdc,0xcf,0x57,0x0d,0x10,0x64,0xc7,0xb3,0x6e,0x15,0x74,0xcc,0x43,0x71,0xd4,0xbb,0xa2,0xe5,0x53,0x21,0xd7,0x53,0x97,};
static uint8_t ROUND53[] = {0xbd,0xa5,0x9c,0xbd,0x65,0xe8,0x7a,0x57,0xdf,0x3f,0x03,0xc8,0x9e,0x4d,0x95,0x11,0xde,0x71,0xda,0x05,0xe2,0xee,0xe0,0x56,0x09,0x48,0x69,0x6b,0x37,0x61,0x5f,0x8f,};
static uint8_t ROUND54[] = {0xf4,0x31,0xcc,0x18,0x17,0x56,0x9e,0x92,0xc8,0xba,0x11,0xec,0x47,0x41,0xe6,0xdd,0x2e,0x36,0x11,0x56,0x57,0x5a,0xf7,0xb4,0x82,0x58,0x7e,0xd7,0x8e,0x9f,0xb7,0xfe,};
static uint8_t ROUND55[] = {0x1b,0x3b,0x37,0x89,0xa3,0x21,0x65,0xf7,0x25,0x16,0x7d,0xa6,0xf5,0xef,0x89,0xd9,0x5d,0xe5,0x99,0x27,0x83,0x96,0x14,0x40,0xfc,0xe6,0x7b,0x66,0xc3,0x35,0x1e,0xa6,};
static uint8_t ROUND56[] = {0xc9,0x87,0x3a,0x09,0xc0,0x79,0xca,0x7f,0x47,0x7b,0x56,0x01,0x51,0x9c,0xe5,0x18,0x96,0xc2,0xa3,0x5a,0x28,0xfe,0x05,0xfe,0x8b,0x13,0xe9,0x90,0x81,0x3c,0x66,0x34,};
static uint8_t ROUND57[] = {0xfb,0x16,0xcc,0x86,0x5d,0xdc,0xf5,0x13,0xbe,0x29,0x8c,0x7d,0x51,0x40,0x33,0xab,0x3f,0xae,0x7a,0x80,0xb2,0x85,0xd2,0xb4,0x3e,0x82,0x36,0x33,0x42,0xe4,0x98,0xf4,};
static uint8_t ROUND58[] = {0xeb,0xae,0xbc,0x26,0x1b,0x32,0x7f,0x8b,0xe2,0x40,0x26,0xe3,0x20,0x99,0xa6,0xb1,0x59,0x27,0xc5,0x4d,0xbe,0x39,0x0b,0x72,0x75,0x6f,0x3f,0x63,0x62,0xea,0x3b,0x3a,};
static uint8_t ROUND59[] = {0xae,0x5a,0x4f,0xdc,0x77,0x9d,0x80,0x8b,0xa8,0x98,0x96,0x6c,0x8c,0x14,0xa6,0xc9,0x89,0x41,0x07,0xef,0x3e,0x1d,0x68,0x0f,0x6a,0xe3,0x7e,0x95,0xcb,0x7e,0x1b,0x67,};
static uint8_t ROUND60[] = {0x5a,0x4a,0x67,0x45,0x1c,0x19,0x7b,0x03,0x8c,0x54,0x08,0x78,0xb6,0xe7,0xbc,0x6f,0xce,0x3e,0xea,0x9c,0x95,0x79,0x5d,0x61,0x13,0x59,0x70,0x3d,0x6c,0xc7,0xca,0x02,};
static uint8_t ROUND61[] = {0xef,0xb0,0x75,0xaa,0x05,0x10,0x70,0xa6,0xb2,0x30,0x3e,0x02,0x6f,0x81,0xa5,0x26,0x2a,0x6e,0x64,0xea,0xbb,0x27,0x0e,0xc5,0xe1,0x3f,0xc6,0xef,0xa3,0x52,0x9f,0x6f,};
static uint8_t ROUND62[] = {0x8f,0xf3,0xdf,0x1a,0x5c,0xd0,0x84,0x0b,0xce,0x61,0x52,0x0f,0x1e,0x56,0x45,0xce,0x27,0x2a,0x37,0xb8,0x84,0xc1,0x75,0x0c,0x69,0xa9,0x57,0x13,0x4c,0x1a,0x20,0xd2,};
static uint8_t ROUND63[] = {0x8f,0xbd,0x86,0x56,0x7c,0x20,0xdc,0x3e,0xa9,0x94,0x8d,0xd5,0xea,0x6f,0x52,0x04,0x02,0x8c,0x4b,0xa2,0x58,0xc3,0x50,0x52,0x99,0x4e,0x7c,0x86,0xde,0x2d,0x77,0x01,};
static uint8_t ROUND64[] = {0x67,0x05,0x59,0x57,0x2a,0x74,0xe9,0xaf,0x05,0x13,0xa3,0xf9,0x24,0x3b,0xfb,0xfd,0x58,0x05,0xb8,0x37,0x70,0x5f,0xae,0xdc,0x3c,0x48,0x0d,0x67,0xa9,0x2b,0xc1,0x24,};
static uint8_t ROUND65[] = {0xef,0x2a,0xd8,0x65,0x6f,0xac,0x9c,0x59,0x3d,0x30,0x1f,0xcf,0xac,0x77,0xa7,0x81,0x5d,0x50,0xb4,0x25,0x26,0xd3,0xa4,0x4e,0x15,0x73,0x31,0x6a,0x25,0xb0,0x59,0x04,};
static uint8_t ROUND66[] = {0xa3,0x48,0x4a,0x7a,0x6c,0xb5,0xc9,0x41,0xe1,0x53,0x46,0xa3,0xac,0x4e,0x09,0xe9,0x9a,0x51,0x89,0xcc,0x96,0xa8,0x71,0x04,0xd1,0x96,0xaf,0x3c,0x43,0xcf,0x99,0x5e,};
static uint8_t ROUND67[] = {0x96,0x68,0x51,0xa0,0xef,0x41,0xf8,0xd8,0xff,0x97,0x0f,0x43,0x40,0xa8,0xda,0xe8,0xee,0xc4,0xf1,0x99,0x9f,0x5f,0xd4,0xf6,0xcb,0xcf,0xa3,0x72,0xfb,0xf8,0x54,0x95,};
static uint8_t ROUND68[] = {0x8e,0x15,0x59,0xcd,0x44,0x31,0xfe,0xbf,0xa1,0x56,0x62,0xa2,0xcc,0xf2,0xca,0xc8,0x2f,0x54,0x01,0xb2,0x65,0x75,0x51,0x48,0x0b,0xb0,0xe3,0xdd,0x21,0x11,0x03,0x2c,};
static uint8_t ROUND69[] = {0x5f,0x53,0x5e,0x2e,0x73,0x51,0xcb,0x8c,0xaf,0x00,0x70,0x16,0x62,0x18,0x23,0x8a,0x84,0x3c,0x17,0x47,0x2c,0xea,0x2f,0x59,0x11,0x00,0x8b,0xe5,0xd7,0xfd,0x6b,0xa2,};
static uint8_t ROUND70[] = {0x86,0xac,0x4e,0xa1,0x5f,0x10,0xc2,0x64,0xb1,0x58,0x05,0x8f,0x5c,0x13,0xa3,0x6a,0x87,0xac,0x72,0xf8,0x40,0x07,0x1b,0xbc,0x45,0x39,0x9b,0x36,0x82,0x3a,0x57,0x09,};
static uint8_t ROUND71[] = {0x5c,0x0d,0x3f,0xe2,0x89,0xb2,0xaa,0xc7,0xd1,0xbb,0xaf,0x57,0xf4,0x15,0x4b,0x8d,0x10,0x87,0x5c,0xff,0xc9,0xd8,0xbd,0x24,0x02,0x25,0x5e,0xd1,0x61,0x5f,0x1d,0x5f,};
static uint8_t ROUND72[] = {0xd7,0xd8,0x08,0x36,0x6d,0x0c,0x8b,0x76,0xce,0x3e,0x7a,0xb8,0x0e,0xa1,0x1b,0x4e,0x2f,0x87,0x58,0xf9,0xff,0x40,0x4a,0x3a,0xaf,0xbf,0x5b,0x0c,0xc1,0x91,0xad,0xcb,};
static uint8_t ROUND73[] = {0xe0,0x76,0x85,0x36,0x85,0x6d,0x1d,0x73,0x99,0x66,0x7d,0x6f,0xd2,0xc3,0x2f,0x72,0x41,0x6e,0xee,0xa1,0xc4,0x0a,0x31,0x3e,0xe6,0xed,0xc9,0x10,0xa5,0xc3,0xb7,0x86,};
static uint8_t ROUND74[] = {0xd6,0x70,0x92,0x37,0x31,0xb3,0xe5,0x98,0xf5,0xc4,0xdb,0x4c,0x7e,0x57,0xfe,0x22,0x75,0xcc,0x6c,0x49,0xb4,0xbf,0x67,0xcb,0x91,0xd5,0x20,0x84,0x6a,0xec,0x25,0x6e,};
static uint8_t ROUND75[] = {0x2c,0xb0,0xbd,0xcc,0x30,0x5e,0xf3,0xb3,0xd6,0xb7,0x26,0x5a,0xb6,0x2b,0xee,0x55,0x5c,0x52,0x41,0x02,0x67,0x9d,0xa1,0x22,0x42,0x47,0x13,0xa9,0xa0,0x1d,0x69,0xf6,};
static uint8_t ROUND76[] = {0x5a,0xcd,0xc3,0x23,0xfe,0x06,0x7a,0x4b,0x91,0x5e,0xe5,0x21,0xac,0x8e,0xb8,0x1b,0xcf,0xf4,0xe2,0x05,0xd5,0x3e,0x4e,0x7f,0x9a,0x69,0xd4,0x36,0x03,0x5c,0xc5,0xad,};
static uint8_t ROUND77[] = {0xe6,0x34,0xc4,0x35,0x58,0xd1,0x2c,0x2a,0x87,0x10,0xf2,0xd6,0xf1,0x0a,0x86,0x41,0x1c,0xfa,0xd5,0xa0,0x14,0xe6,0xb6,0xcc,0x15,0x97,0x33,0xc8,0xcc,0xec,0xe2,0x83,};
static uint8_t ROUND78[] = {0x4a,0x05,0xf4,0xbc,0x3f,0xca,0xf5,0x0e,0x6d,0x09,0x16,0xd7,0xe7,0x02,0x4b,0x0e,0xd2,0x2e,0x9a,0x3c,0x41,0x3f,0xf4,0xbb,0xcc,0x09,0x22,0xd2,0x32,0x6d,0xcf,0x6e,};
static uint8_t ROUND79[] = {0x17,0xc9,0xd6,0x02,0x9e,0x15,0xd3,0xfd,0x84,0xe6,0x80,0x9c,0x5e,0xf8,0xa2,0x79,0xa0,0x40,0xf4,0x9a,0xda,0x91,0x60,0x1a,0x3b,0xa4,0x57,0x2c,0xef,0x7c,0x08,0xbd,};
static uint8_t ROUND80[] = {0x1f,0x21,0xe1,0x37,0xda,0x24,0x27,0x53,0x67,0x58,0x40,0x9f,0x3f,0xbf,0x58,0x42,0x58,0x9c,0x5f,0x58,0x7f,0x0b,0x9d,0x2d,0x10,0x43,0x0f,0x84,0x0f,0xaa,0xaf,0x45,};
static uint8_t ROUND81[] = {0xe3,0xd3,0x8c,0xff,0x8a,0x8d,0x7f,0xc0,0x06,0x93,0xdc,0xa5,0xe3,0x7b,0x03,0xe7,0xb1,0x0d,0xaf,0xe4,0x92,0x60,0x23,0xe2,0x6d,0x93,0x71,0x06,0xdd,0xac,0x6a,0x78,};
static uint8_t ROUND82[] = {0xcd,0x74,0x9e,0xb0,0x5c,0x67,0x03,0x8f,0xe8,0x37,0x91,0x03,0x10,0xb3,0xb4,0xcd,0xda,0x19,0x0f,0x62,0x35,0xfa,0x97,0x06,0x02,0xf8,0x65,0xbe,0xc1,0xb6,0x1a,0x1b,};
static uint8_t ROUND83[] = {0xd5,0x96,0xcc,0xdd,0xea,0x01,0xb4,0xae,0x29,0xb6,0x8b,0x0e,0x8a,0x19,0x10,0x07,0xf0,0xc8,0x9a,0x10,0x16,0xc3,0x80,0xb4,0x97,0x86,0xf2,0xd4,0xfa,0xc4,0xc4,0x3d,};
static uint8_t ROUND84[] = {0xcb,0xcc,0xb1,0xff,0x23,0xe3,0x3c,0x59,0xdc,0x4c,0x85,0x80,0x93,0xc9,0xe2,0x15,0xc3,0x75,0x9a,0xcf,0xe6,0xbc,0x84,0xff,0x75,0x94,0x0b,0x59,0xb2,0x5a,0x4e,0x40,};
static uint8_t ROUND85[] = {0x72,0x14,0xc1,0x34,0xe9,0xa9,0x63,0xd6,0xc4,0x39,0x69,0xd3,0xef,0x44,0xec,0xe8,0x25,0xdd,0x9c,0xf3,0x5b,0xda,0x5f,0xcc,0xe9,0x2a,0x6b,0x9d,0x0d,0x3f,0xd1,0xb8,};
static uint8_t ROUND86[] = {0xac,0xea,0xf5,0xb7,0x75,0x77,0x96,0x21,0x31,0x9f,0x9a,0xb5,0xd4,0xd3,0x70,0xa3,0x35,0x9c,0xd6,0x55,0x3e,0xd2,0x32,0x8c,0xdc,0x9d,0xba,0xb5,0xb6,0x88,0x40,0xfa,};
static uint8_t ROUND87[] = {0xe8,0x12,0x3a,0xcb,0x0a,0x2f,0xb6,0x29,0x78,0xd3,0x81,0x1b,0x31,0x67,0x69,0x75,0x54,0x29,0x93,0x93,0x21,0x08,0xab,0x14,0xd4,0x87,0xad,0x78,0x75,0xdd,0xef,0x72,};
static uint8_t ROUND88[] = {0x66,0x02,0x02,0xa4,0x36,0xfb,0x05,0xc3,0xd5,0x9b,0xe6,0x99,0x73,0x4e,0x77,0xc9,0x75,0x0c,0x90,0x6c,0x85,0x97,0xca,0x21,0x3d,0x06,0x48,0x53,0xec,0xf8,0xc9,0xf3,};
static uint8_t ROUND89[] = {0x47,0x52,0xb0,0xa5,0xec,0x3f,0x1f,0xb2,0x95,0xd5,0xbf,0xa9,0x8f,0xa6,0x3a,0x0b,0xa3,0x8a,0x02,0xa4,0xc1,0xe1,0xf7,0x3b,0x0c,0x4d,0x4e,0x88,0xa0,0x7e,0x03,0x17,};
static uint8_t ROUND90[] = {0x1e,0x24,0xf1,0x46,0x7c,0x36,0xb0,0x51,0xaf,0x32,0x41,0xfc,0xf8,0xc2,0xc8,0x68,0xb8,0x6d,0xcb,0x8e,0x46,0x69,0x93,0x18,0x78,0x01,0x8e,0x99,0x14,0x12,0x9b,0x42,};
static uint8_t ROUND91[] = {0xd1,0xc3,0xef,0xc9,0x9d,0x94,0x87,0xe1,0x47,0x28,0x2d,0x81,0x1a,0xb9,0x32,0xd4,0xa2,0x43,0x62,0xd0,0x9a,0xc9,0x09,0xf4,0x85,0x4e,0x78,0x38,0x87,0x06,0x88,0x91,};
static uint8_t ROUND92[] = {0x7d,0xc4,0x55,0xcf,0x6f,0x8b,0x20,0x42,0xb6,0xf0,0xf3,0x68,0xc4,0x4f,0x18,0xa0,0x80,0xe5,0xd3,0x91,0x2c,0xe3,0xcd,0xaf,0x71,0x42,0xbd,0x61,0xae,0x50,0xd0,0x2e,};
static uint8_t ROUND93[] = {0x4b,0x99,0x1c,0x15,0x78,0x90,0x84,0xeb,0x1d,0x6c,0x1d,0x7c,0xe8,0xf0,0x92,0x8d,0xf4,0xd3,0x93,0x1c,0x0c,0x22,0xc5,0x71,0xf3,0x75,0x84,0x9b,0x9a,0x6c,0x2b,0x71,};
static uint8_t ROUND94[] = {0x8b,0x78,0xf9,0x5a,0x00,0x7c,0xfb,0x0b,0xd0,0x54,0xa1,0xf5,0xd9,0x62,0xcd,0x8d,0x92,0x76,0x65,0xf7,0x9a,0x5c,0xe9,0xe0,0xfc,0x31,0x10,0x5e,0x57,0xb8,0x46,0x0b,};
static uint8_t ROUND95[] = {0xbf,0x30,0x54,0x23,0x84,0x9c,0xf7,0x73,0xfc,0x54,0x20,0x6d,0x8a,0xe3,0xc0,0x00,0xc3,0xe8,0xb3,0x59,0xcb,0xa8,0x36,0x45,0x81,0xd1,0xf9,0x1b,0x0a,0x20,0x10,0x32,};
static uint8_t ROUND96[] = {0x47,0x00,0x6a,0xf9,0x6c,0xff,0x38,0x43,0xd3,0xed,0x53,0xbd,0xed,0xb1,0x67,0x49,0x0d,0x7b,0xfe,0xfd,0x93,0xae,0x3e,0x9e,0xf4,0x73,0xcb,0x53,0xaa,0x84,0x0f,0xc0,};
static uint8_t ROUND97[] = {0xc5,0x3c,0xf5,0x02,0x61,0x62,0x02,0x1f,0xd2,0x34,0x5d,0xba,0xd7,0xc5,0x3d,0x3a,0x3d,0xf4,0x7b,0x5b,0xdf,0xf8,0xcd,0x34,0xa0,0xcc,0xfe,0xe0,0x6d,0xbb,0x73,0x28,};
static uint8_t ROUND98[] = {0x33,0x26,0x89,0x9b,0x57,0x5f,0x93,0xcd,0xaf,0xf7,0x57,0xf8,0xab,0x7c,0x39,0x96,0xa2,0xfe,0x93,0x04,0x50,0xd5,0x00,0x2d,0x45,0x75,0xf4,0xe4,0xcc,0x4b,0x43,0x60,};
static uint8_t ROUND99[] = {0x6a,0x91,0x2b,0xa4,0x18,0x83,0x91,0xa7,0x8e,0x6f,0x13,0xd8,0x8e,0xd2,0xd1,0x4e,0x13,0xaf,0xce,0x9d,0xb6,0xf7,0xdc,0xbf,0x4a,0x48,0xc2,0x4f,0x3d,0xb0,0x27,0x78,};
TEST (TinyCrypT_SHA256, monte_0)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (0 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND0, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_1)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (1 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND1, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_2)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (2 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND2, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_3)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (3 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND3, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_4)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (4 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND4, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_5)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (5 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND5, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_6)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (6 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND6, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_7)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (7 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND7, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_8)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (8 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND8, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_9)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (9 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND9, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_10)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (10 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND10, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_11)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (11 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND11, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_12)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (12 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND12, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_13)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (13 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND13, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_14)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (14 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND14, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_15)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (15 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND15, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_16)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (16 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND16, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_17)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (17 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND17, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_18)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (18 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND18, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_19)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (19 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND19, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_20)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (20 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND20, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_21)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (21 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND21, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_22)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (22 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND22, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_23)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (23 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND23, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_24)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (24 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND24, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_25)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (25 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND25, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_26)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (26 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND26, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_27)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (27 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND27, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_28)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (28 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND28, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_29)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (29 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND29, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_30)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (30 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND30, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_31)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (31 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND31, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_32)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (32 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND32, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_33)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (33 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND33, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_34)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (34 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND34, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_35)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (35 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND35, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_36)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (36 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND36, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_37)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (37 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND37, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_38)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (38 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND38, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_39)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (39 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND39, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_40)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (40 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND40, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_41)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (41 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND41, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_42)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (42 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND42, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_43)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (43 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND43, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_44)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (44 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND44, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_45)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (45 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND45, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_46)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (46 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND46, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_47)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (47 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND47, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_48)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (48 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND48, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_49)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (49 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND49, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_50)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (50 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND50, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_51)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (51 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND51, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_52)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (52 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND52, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_53)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (53 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND53, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_54)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (54 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND54, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_55)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (55 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND55, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_56)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (56 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND56, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_57)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (57 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND57, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_58)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (58 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND58, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_59)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (59 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND59, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_60)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (60 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND60, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_61)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (61 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND61, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_62)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (62 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND62, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_63)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (63 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND63, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_64)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (64 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND64, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_65)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (65 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND65, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_66)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (66 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND66, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_67)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (67 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND67, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_68)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (68 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND68, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_69)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (69 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND69, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_70)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (70 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND70, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_71)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (71 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND71, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_72)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (72 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND72, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_73)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (73 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND73, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_74)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (74 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND74, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_75)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (75 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND75, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_76)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (76 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND76, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_77)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (77 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND77, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_78)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (78 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND78, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_79)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (79 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND79, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_80)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (80 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND80, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_81)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (81 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND81, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_82)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (82 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND82, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_83)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (83 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND83, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_84)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (84 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND84, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_85)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (85 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND85, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_86)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (86 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND86, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_87)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (87 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND87, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_88)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (88 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND88, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_89)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (89 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND89, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_90)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (90 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND90, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_91)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (91 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND91, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_92)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (92 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND92, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_93)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (93 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND93, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_94)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (94 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND94, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_95)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (95 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND95, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_96)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (96 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND96, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_97)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (97 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND97, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_98)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (98 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND98, digest, 32), 0);
}
TEST (TinyCrypT_SHA256, monte_99)
{
uint8_t msg[96];
uint8_t digest[32];
uint8_t *a = msg; uint8_t *b = msg + 32; uint8_t *c = msg + 64;
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = SEED[j];
for (uint64_t i = 0; i < (99 + 1) * 1000; ++i)
{
if (i % 1000 == 0 && i != 0) {
for (uint64_t j = 0; j < 32; ++j) a[j] = b[j] = c[j] = digest[j];
}
tct_sha256(msg, sizeof(msg), digest);
for (uint64_t j = 0; j < 32; ++j) { a[j] = b[j]; b[j] = c[j]; c[j] = digest[j]; }
}
EXPECT_EQ(memcmp(ROUND99, digest, 32), 0);
}
