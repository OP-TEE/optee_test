/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef XML_CRYPTO_API_H_
#define XML_CRYPTO_API_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include "tee_client_api.h"
#include "utee_defines.h"
#include "xtest_test.h"
#include "xml_common_api.h"

#define BIT_CHANGE(a, b) ((a) ^= (1 << (b)))

#define CRYPTO_INIT(b) \
	b.buffer = NULL; \
	b.size = 0;

#define CRYPTO_MALLOC(b, size) \
	b.size = size; \
	b.buffer = malloc(size);

#define CRYPTO_FREE(b) { \
		if (b.buffer != NULL) { \
			b.size = 0; \
			free(b.buffer); \
			b.buffer = NULL; \
		} }

/*Crypto_CMD redefines*/
#define CMD_AsymmetricVerifyDigest  CMD_AsymmetricVerifyDigestNoParam
#define CMD_AsymmetricSignDigest    CMD_AsymmetricSignDigestNoParam
#define CMD_AsymmetricEncrypt       CMD_AsymmetricEncryptNoParam
#define CMD_AsymmetricDecrypt       CMD_AsymmetricDecryptNoParam

/*Missing TEE Error codes*/
#define TEE_ERROR_TOO_SHORT_BUFFER  TEE_ERROR_SHORT_BUFFER

/*Other defines*/
#define TEE_USAGE_NONE      0

#define BIG_SIZE                    1024
uint32_t DS_BIG_SIZE = 16384;

/*ALL_OBJECT_SIZES*/
#define KEY_SIZE_TOO_LARGE          4096
#define SIZE_AES_256                256
#define SIZE_DES3_192               168
#define SIZE_DES_64                 56
#define SIZE_DH_KEYPAIR_1024        1024
#define SIZE_DSA_KEYPAIR_768        768
#define SIZE_DSA_PUBLIC_KEY_768     768
#define SIZE_GENERIC_SECRET_2048    2048
#define SIZE_HMAC_MD5_256           256
#define SIZE_HMAC_SHA1_256          256
#define SIZE_HMAC_SHA224_256        256
#define SIZE_HMAC_SHA256_512        512
#define SIZE_HMAC_SHA384_512        512
#define SIZE_HMAC_SHA512_512        512
#define SIZE_RSA_KEYPAIR_2048       2048
#define SIZE_RSA_PUBLIC_KEY_2048    2048
#define SIZE_ZERO                   0
#define WRONG_SIZE                  5

/*ALL_TEE_TAG_LENGTH_FOR_AES*/
#define AES_104_bits                104
#define AES_112_bits                112
#define AES_120_bits                120
#define AES_128_bits                128
#define AES_32_bits                 32
#define AES_48_bits                 48
#define AES_64_bits                 64
#define AES_96_bits                 96

/*attribute not defined*/
#define TEE_ATTR_NONE               0

static TEEC_SharedMemory *SHARE_MEM01;
static TEEC_SharedMemory *SHARE_MEM02;
static TEEC_SharedMemory *SHARE_MEM03;
static TEEC_SharedMemory *SHARE_MEM04;
static TEEC_SharedMemory *SHARE_MEM05;
static TEEC_SharedMemory *SHARE_MEM06;
static TEEC_Session *SESSION01;
static TEEC_Session *SESSION02;
static TEEC_Context *CONTEXT01;
static TEEC_Context *CONTEXT02;
static TEE_OperationHandle *OPERATION_HANDLE_01;
static TEE_OperationHandle *OPERATION_HANDLE_02;
static TEE_OperationHandle *OPERATION_HANDLE_INVALID;
static TEE_ObjectHandle *OBJECT_HANDLE_01;
static TEE_ObjectHandle *OBJECT_HANDLE_02;
static TEE_ObjectHandle *OBJECT_HANDLE_INVALID;

/*ALL_ATTRIBUTE_VALUES*/
static const uint8_t TEE_ATTR_AES_256_VALUE01[] = {
	0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
	0x85, 0x7d, 0x77, 0x81,
	0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
	0x09, 0x14, 0xdf, 0xf4
};
static const uint8_t TEE_ATTR_DH_PRIME_VALUE01[] = {
	0xe0, 0x01, 0xe8, 0x96, 0x7d, 0xb4, 0x93, 0x53, 0xe1, 0x6f, 0x8e, 0x89,
	0x22, 0x0c, 0xce, 0xfc,
	0x5c, 0x5f, 0x12, 0xe3, 0xdf, 0xf8, 0xf1, 0xd1, 0x49, 0x90, 0x12, 0xe6,
	0xef, 0x53, 0xe3, 0x1f,
	0x02, 0xea, 0xcc, 0x5a, 0xdd, 0xf3, 0x37, 0x89, 0x35, 0xc9, 0x5b, 0x21,
	0xea, 0x3d, 0x6f, 0x1c,
	0xd7, 0xce, 0x63, 0x75, 0x52, 0xec, 0x38, 0x6c, 0x0e, 0x34, 0xf7, 0x36,
	0xad, 0x95, 0x17, 0xef,
	0xfe, 0x5e, 0x4d, 0xa7, 0xa8, 0x6a, 0xf9, 0x0e, 0x2c, 0x22, 0x8f, 0xe4,
	0xb9, 0xe6, 0xd8, 0xf8,
	0xf0, 0x2d, 0x20, 0xaf, 0x78, 0xab, 0xb6, 0x92, 0xac, 0xbc, 0x4b, 0x23,
	0xfa, 0xf2, 0xc5, 0xcc,
	0xd4, 0x9a, 0x0c, 0x9a, 0x8b, 0xcd, 0x91, 0xac, 0x0c, 0x55, 0x92, 0x01,
	0xe6, 0xc2, 0xfd, 0x1f,
	0x47, 0xc2, 0xcb, 0x2a, 0x88, 0xa8, 0x3c, 0x21, 0x0f, 0xc0, 0x54, 0xdb,
	0x29, 0x2d, 0xbc, 0x45
};
static const uint8_t TEE_ATTR_DH_BASE_VALUE01[] = {
	0x1c, 0xe0, 0xf6, 0x69, 0x26, 0x46, 0x11, 0x97, 0xef, 0x45, 0xc4, 0x65,
	0x8b, 0x83, 0xb8, 0xab,
	0x04, 0xa9, 0x22, 0x42, 0x68, 0x50, 0x4d, 0x05, 0xb8, 0x19, 0x83, 0x99,
	0xdd, 0x71, 0x37, 0x18,
	0xcc, 0x1f, 0x24, 0x5d, 0x47, 0x6c, 0xcf, 0x61, 0xa2, 0xf9, 0x34, 0x93,
	0xf4, 0x1f, 0x55, 0x52,
	0x48, 0x65, 0x57, 0xe6, 0xd4, 0xca, 0xa8, 0x00, 0xd6, 0xd0, 0xdb, 0x3c,
	0xbf, 0x5a, 0x95, 0x4b,
	0x20, 0x8a, 0x4e, 0xba, 0xf7, 0xe6, 0x49, 0xfb, 0x61, 0x24, 0xd8, 0xa2,
	0x1e, 0xf2, 0xf2, 0x2b,
	0xaa, 0xae, 0x29, 0x21, 0x10, 0x19, 0x10, 0x51, 0x46, 0x47, 0x31, 0xb6,
	0xcc, 0x3c, 0x93, 0xdc,
	0x6e, 0x80, 0xba, 0x16, 0x0b, 0x66, 0x64, 0xa5, 0x6c, 0xfa, 0x96, 0xea,
	0xf1, 0xb2, 0x83, 0x39,
	0x8e, 0xb4, 0x61, 0x64, 0xe5, 0xe9, 0x43, 0x84, 0xee, 0x02, 0x24, 0xe7,
	0x1f, 0x03, 0x7c, 0x23
};
static const uint8_t TEE_ATTR_HMAC_SHA256_512_VALUE01[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0x3e, 0x3f
};
static const uint8_t TEE_ATTR_DH_PUBLIC_VALUE_VALUE01[] = {
	0xbb, 0xe9, 0x18, 0xdd, 0x4b, 0x2b, 0x94, 0x1b, 0x10, 0x0e, 0x88, 0x35,
	0x28, 0x68, 0xfc, 0x62,
	0x04, 0x38, 0xa6, 0xdb, 0x32, 0xa6, 0x9e, 0xee, 0x6c, 0x6f, 0x45, 0x1c,
	0xa3, 0xa6, 0xd5, 0x37,
	0x77, 0x75, 0x5b, 0xc1, 0x37, 0x0a, 0xce, 0xfe, 0x2b, 0x8f, 0x13, 0xa9,
	0x14, 0x2c, 0x5b, 0x44,
	0x15, 0x78, 0x86, 0x30, 0xd6, 0x95, 0xb1, 0x92, 0x20, 0x63, 0xa3, 0xcf,
	0x9d, 0xef, 0x65, 0x61,
	0x27, 0x4d, 0x24, 0x01, 0xe7, 0xa1, 0x45, 0xf2, 0xd8, 0xb9, 0x3a, 0x45,
	0x17, 0xf4, 0x19, 0xd0,
	0x5e, 0xf8, 0xcb, 0x35, 0x59, 0x37, 0x9d, 0x04, 0x20, 0xa3, 0xbf, 0x02,
	0xad, 0xfe, 0xa8, 0x60,
	0xb2, 0xc3, 0xee, 0x85, 0x58, 0x90, 0xf3, 0xb5, 0x57, 0x2b, 0xb4, 0xef,
	0xd7, 0x8f, 0x37, 0x68,
	0x78, 0x7c, 0x71, 0x52, 0x9d, 0x5e, 0x0a, 0x61, 0x4f, 0x09, 0x89, 0x92,
	0x39, 0xf7, 0x4b, 0x01
};
static const uint8_t TEE_ATTR_DH_PRIVATE_VALUE_VALUE01[] = {
	0x53, 0x8d, 0x3d, 0x64, 0x27, 0x4a, 0x40, 0x05, 0x9b, 0x9c, 0x26, 0xe9,
	0x13, 0xe6, 0x91, 0x53,
	0x23, 0x7b, 0x55, 0x83
};
static const uint8_t TEE_ATTR_RSA_MODULUS_VALUE01[] = {
	0xf0, 0x1a, 0x95, 0xcd, 0x5f, 0x9f, 0x1c, 0xbc, 0x5c, 0x2e, 0xc8, 0x00,
	0x3b, 0xfa, 0xe0, 0xd5,
	0x72, 0xea, 0xfc, 0x9e, 0x74, 0xe1, 0x02, 0x66, 0xa8, 0x13, 0x3f, 0x0c,
	0xe6, 0x24, 0xcb, 0x1c,
	0xa5, 0xdf, 0x64, 0xfb, 0x06, 0xd7, 0x13, 0xce, 0xaa, 0x6c, 0xee, 0x16,
	0x7b, 0xf8, 0x92, 0xaf,
	0xc4, 0x5b, 0x46, 0x18, 0xc6, 0x30, 0xb6, 0x04, 0x1c, 0x3a, 0x2e, 0xd7,
	0xca, 0xb8, 0xb5, 0x00,
	0x78, 0x89, 0xa0, 0x69, 0x37, 0x84, 0x59, 0x99, 0x0c, 0x2f, 0x00, 0xe5,
	0x3b, 0xe1, 0x18, 0xe0,
	0xb9, 0x2e, 0x77, 0x1d, 0x32, 0x7e, 0x5f, 0xf4, 0x18, 0xf3, 0x9f, 0x58,
	0xc6, 0x83, 0xe2, 0x7a,
	0xcb, 0x89, 0x18, 0xc2, 0x09, 0x84, 0x7e, 0x9d, 0x96, 0xe0, 0xb9, 0x49,
	0x75, 0xef, 0xcf, 0xff,
	0xf0, 0xb6, 0x18, 0xd3, 0x7a, 0xc1, 0x6f, 0x0c, 0x55, 0x33, 0xbe, 0x9d,
	0x63, 0x06, 0xd6, 0x9f,
	0xc1, 0xa5, 0xe9, 0xbd, 0xb1, 0xb2, 0x5d, 0x5c, 0xf9, 0xab, 0xa9, 0xb5,
	0x6a, 0x4e, 0xa4, 0xfa,
	0x44, 0x32, 0xd6, 0x71, 0x2e, 0x5f, 0xa6, 0x25, 0xf8, 0x40, 0x24, 0xc4,
	0x5b, 0x61, 0x55, 0x1b,
	0xac, 0xa3, 0x0a, 0x11, 0x8e, 0x65, 0x20, 0xda, 0x2c, 0x0d, 0xdf, 0xdb,
	0x47, 0x6b, 0x61, 0x18,
	0x4d, 0xfe, 0xfd, 0x2a, 0x7e, 0x77, 0x40, 0x44, 0x43, 0xc6, 0x33, 0x6c,
	0xe5, 0x1b, 0x8d, 0x80,
	0xf9, 0x97, 0xa2, 0xe4, 0xb9, 0x34, 0x3e, 0x28, 0x94, 0x9f, 0xbd, 0xa8,
	0x2b, 0x0a, 0x4d, 0x1a,
	0xa8, 0x06, 0xe5, 0x99, 0x4e, 0xb9, 0x13, 0x45, 0xc8, 0xf6, 0x0f, 0xd0,
	0x4d, 0xbf, 0xe7, 0x8f,
	0xed, 0xca, 0x8e, 0xf8, 0x8d, 0x87, 0x5f, 0xd4, 0xb4, 0x1a, 0x2c, 0xc9,
	0xa7, 0x67, 0x7e, 0xb2,
	0x1b, 0xc1, 0xce, 0xb6, 0x83, 0x7c, 0xce, 0xb4, 0x3d, 0x85, 0xc7, 0x53,
	0x30, 0x7c, 0xfe, 0x85
};
static const uint8_t TEE_ATTR_RSA_PUBLIC_EXPONENT_VALUE01[] = {
	0x01, 0x00, 0x01
};
static const uint8_t TEE_ATTR_DSA_PRIME_VALUE01[] = {
	0xf6, 0xad, 0x20, 0x71, 0xe1, 0x5a, 0x4b, 0x9c, 0x2b, 0x7e, 0x53, 0x26,
	0xda, 0x43, 0x9d, 0xc1,
	0x47, 0x4c, 0x1a, 0xd1, 0x6f, 0x2f, 0x85, 0xe9, 0x2c, 0xea, 0x89, 0xfc,
	0xdc, 0x74, 0x66, 0x11,
	0xcf, 0x30, 0xdd, 0xc8, 0x5e, 0x33, 0xf5, 0x83, 0xc1, 0x9d, 0x10, 0xbc,
	0x1a, 0xc3, 0x93, 0x22,
	0x26, 0x24, 0x6f, 0xa7, 0xb9, 0xe0, 0xdd, 0x25, 0x77, 0xb5, 0xf4, 0x27,
	0x59, 0x4c, 0x39, 0xfa,
	0xeb, 0xfc, 0x59, 0x8a, 0x32, 0xe1, 0x74, 0xcb, 0x8a, 0x68, 0x03, 0x57,
	0xf8, 0x62, 0xf2, 0x0b,
	0x6e, 0x84, 0x32, 0xa5, 0x30, 0x65, 0x2f, 0x1c, 0x21, 0x39, 0xae, 0x1f,
	0xaf, 0x76, 0x8b, 0x83
};
static const uint8_t TEE_ATTR_DSA_SUBPRIME_VALUE01[] = {
	0x87, 0x44, 0xe4, 0xdd, 0xc6, 0xd0, 0x19, 0xa5, 0xea, 0xc2, 0xb1, 0x5a,
	0x15, 0xd7, 0xe1, 0xc7,
	0xf6, 0x63, 0x35, 0xf7
};
static const uint8_t TEE_ATTR_DSA_BASE_VALUE01[] = {
	0x9a, 0x09, 0x32, 0xb3, 0x8c, 0xb2, 0x10, 0x5b, 0x93, 0x00, 0xdc, 0xb8,
	0x66, 0xc0, 0x66, 0xd9,
	0xce, 0xc6, 0x43, 0x19, 0x2f, 0xcb, 0x28, 0x34, 0xa1, 0x23, 0x9d, 0xba,
	0x28, 0xbd, 0x09, 0xfe,
	0x01, 0x00, 0x1e, 0x04, 0x51, 0xf9, 0xd6, 0x35, 0x1f, 0x6e, 0x56, 0x4a,
	0xfb, 0xc8, 0xf8, 0xc3,
	0x9b, 0x10, 0x59, 0x86, 0x3e, 0xbd, 0x09, 0x85, 0x09, 0x0b, 0xd5, 0x5c,
	0x82, 0x8e, 0x9f, 0xc1,
	0x57, 0xac, 0x7d, 0xa3, 0xcf, 0xc2, 0x89, 0x2a, 0x0e, 0xd9, 0xb9, 0x32,
	0x39, 0x05, 0x82, 0xf2,
	0x97, 0x1e, 0x4a, 0x0c, 0x48, 0x3e, 0x06, 0x22, 0xd7, 0x31, 0x66, 0xbf,
	0x62, 0xa5, 0x9f, 0x26
};
static const uint8_t TEE_ATTR_DSA_PRIVATE_VALUE_VALUE01[] = {
	0x70, 0x4a, 0x46, 0xc6, 0x25, 0x2a, 0x95, 0xa3, 0x9b, 0x40, 0xe0, 0x43,
	0x5a, 0x69, 0x1b, 0xad,
	0xae, 0x52, 0xa5, 0xc0
};
static const uint8_t TEE_ATTR_DSA_PUBLIC_VALUE_VALUE01[] = {
	0x52, 0x9d, 0xed, 0x98, 0xa2, 0x32, 0x09, 0x85, 0xfc, 0x84, 0xb6, 0x5a,
	0x9d, 0xc8, 0xd4, 0xfe,
	0x41, 0xad, 0xa6, 0xe3, 0x59, 0x3d, 0x70, 0x4f, 0x08, 0x98, 0xc1, 0x4e,
	0xc2, 0x46, 0x34, 0xdd,
	0xf5, 0xf1, 0xdb, 0x47, 0xcc, 0x49, 0x15, 0xfc, 0xe1, 0xe2, 0x67, 0x4d,
	0x2e, 0xcd, 0x98, 0xd5,
	0x8b, 0x59, 0x8e, 0x8d, 0xdf, 0xaf, 0xf3, 0x0e, 0x88, 0x26, 0xf5, 0x0a,
	0xab, 0x40, 0x27, 0xb5,
	0xaa, 0xb8, 0x87, 0xc1, 0x9a, 0xd9, 0x6d, 0x7e, 0x57, 0xde, 0x53, 0x90,
	0xad, 0x8e, 0x55, 0x57,
	0xb4, 0x1a, 0x80, 0x19, 0xc9, 0x0d, 0x80, 0x60, 0x71, 0x79, 0xb5, 0x4e,
	0xb0, 0xad, 0x4d, 0x23
};
static const uint8_t TEE_ATTR_DES3_192_VALUE01[] = {
	0xCD, 0xFE, 0x57, 0xB6, 0xB6, 0x2F, 0xAE, 0x6B, 0x04, 0x73, 0x40, 0xF1,
	0x02, 0xD6, 0xA4, 0x8C,
	0x89, 0x5D, 0xAD, 0xF2, 0x9D, 0x62, 0xEF, 0x25
};
static const uint8_t TEE_ATTR_RSA_PRIVATE_EXPONENT_VALUE01[] = {
	0xa5, 0x0d, 0xe1, 0x84, 0xf9, 0x02, 0xec, 0x42, 0x20, 0x2c, 0x98, 0x98,
	0x70, 0xa3, 0x1a, 0x04,
	0x21, 0xa7, 0xa0, 0x59, 0x5d, 0x87, 0x80, 0x9b, 0x09, 0x57, 0x91, 0xb4,
	0x50, 0x51, 0x62, 0xbf,
	0x22, 0xd7, 0xdb, 0x17, 0x25, 0xb0, 0x9c, 0x91, 0x29, 0x5f, 0x10, 0x9c,
	0xac, 0x44, 0x48, 0xb2,
	0x43, 0x8d, 0x6b, 0x36, 0x84, 0xa7, 0xdf, 0xb8, 0x1b, 0x9f, 0x73, 0xac,
	0x2c, 0x53, 0xa5, 0x39,
	0xd9, 0xa2, 0xe2, 0x7e, 0xf2, 0x07, 0x2d, 0x80, 0xa4, 0x7b, 0x7b, 0x66,
	0x1a, 0x2f, 0xb7, 0x66,
	0x64, 0x66, 0xa8, 0xc3, 0x8d, 0x7e, 0x8a, 0x7f, 0xc6, 0xd7, 0x52, 0xe7,
	0x38, 0x30, 0x59, 0x74,
	0x88, 0x8e, 0x8a, 0x52, 0x79, 0x30, 0x77, 0xc9, 0xe5, 0x7a, 0x3e, 0x65,
	0x5d, 0x89, 0xa9, 0xb7,
	0x0b, 0xc6, 0x62, 0x72, 0x9e, 0xa4, 0x72, 0xae, 0x4b, 0xb3, 0xf2, 0x89,
	0x47, 0x15, 0xe0, 0x5b,
	0x45, 0x4d, 0x99, 0x5b, 0x13, 0x6c, 0x90, 0xbe, 0xe5, 0xb5, 0x98, 0xad,
	0x87, 0x99, 0x1a, 0x57,
	0xd4, 0x1f, 0xf1, 0x52, 0x71, 0x5b, 0x51, 0x40, 0xdc, 0x51, 0x35, 0xf6,
	0x6c, 0xae, 0xa3, 0xf9,
	0x0f, 0x3a, 0xed, 0x28, 0xfc, 0xa5, 0x60, 0x2f, 0x4b, 0x4f, 0x31, 0xac,
	0x48, 0x3e, 0x5b, 0xba,
	0xe4, 0x2b, 0x58, 0x79, 0xe6, 0xb4, 0x6b, 0x5e, 0x56, 0x0a, 0xb2, 0xdb,
	0x68, 0xed, 0x24, 0xd8,
	0x5e, 0x6f, 0x30, 0x59, 0x8d, 0x8c, 0xa3, 0x00, 0x68, 0xf5, 0x42, 0x95,
	0x1a, 0x0b, 0xa8, 0x1c,
	0xfb, 0xdf, 0x29, 0x81, 0x10, 0x32, 0x02, 0xcc, 0x51, 0xa4, 0x17, 0x14,
	0x3e, 0xef, 0x89, 0x41,
	0xde, 0xf8, 0x2d, 0x64, 0x69, 0x30, 0xe8, 0x8a, 0xad, 0x96, 0xf6, 0xf4,
	0x82, 0x83, 0x9a, 0x77,
	0xe7, 0xde, 0x12, 0x31, 0xf7, 0x15, 0xec, 0xce, 0xed, 0x83, 0x68, 0x88,
	0x84, 0xe5, 0x64, 0x81
};
static const uint8_t TEE_ATTR_DES_64_VALUE01[] = {
	0xCD, 0xFE, 0x57, 0xB6, 0xB6, 0x2F, 0xAE, 0x6B
};
static const uint8_t TEE_ATTR_HMAC_SHA1_256_VALUE01[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t TEE_ATTR_HMAC_MD5_256_VALUE01[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t TEE_ATTR_HMAC_SHA224_256_VALUE01[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f
};
static const uint8_t TEE_ATTR_HMAC_SHA384_512_VALUE01[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0x3e, 0x3f
};
static const uint8_t TEE_ATTR_HMAC_SHA512_512_VALUE01[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
	0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
	0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
	0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0x3e, 0x3f
};

/*ALL_CRYPTO_AAD_VALUES*/
static const uint8_t AAD1_VALUE[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};

/*ALL_CRYPTO_AAD_LENGTHS*/
#define AAD1_LENGTH     8
#define NULL_LENGTH     0

/*ALL_TEE_CRYPTO_INITIALISATION_VECTOR_VALUES*/
static const uint8_t NONCE2_VALUE_AES_GCM[] = {
	0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
};
static const uint8_t NONCE1_VALUE_AES_CCM[] = {
	0x00, 0x8D, 0x49, 0x3B, 0x30, 0xAE, 0x8B, 0x3C, 0x96, 0x96, 0x76, 0x6C,
	0xFA
};

/*ALL_TEE_CRYPTO_INITIALISATION_VECTOR_LENGTHS*/
#define NONCE2_LENGTH_AES_GCM       12
#define NONCE1_LENGTH_AES_CCM       13

/*ALL_CRYPTO_DATA_VALUE*/
static const uint8_t DATA_FOR_CRYPTO1[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09,
	0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
	0x03, 0x02, 0x01, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09,
	0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
	0x03, 0x02, 0x01, 0x00
};
static const uint8_t DATA_FOR_CRYPTO1_PART1[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F,
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09
};
static const uint8_t DATA_FOR_CRYPTO1_PART2[] = {
	0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
	0x03, 0x02, 0x01, 0x00,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
	0x0C, 0x0D, 0x0E, 0x0F
};
static const uint8_t DATA_FOR_CRYPTO1_PART3[] = {
	0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09,
	0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04,
	0x03, 0x02, 0x01, 0x00
};

/*ALL_CRYPTO_DATA_LENGTH*/
#define LENGTH_DATA_FOR_CRYPTO1         96
#define LENGTH_DATA_FOR_CRYPTO1_PART1   32
#define LENGTH_DATA_FOR_CRYPTO1_PART2   32
#define LENGTH_DATA_FOR_CRYPTO1_PART3   32

/*ALL_TEE_CRYPTO_INITIALISATION_VECTOR_VALUES*/
static const uint8_t IV1_VALUE_64bits_DES_DES3[] = {
	0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef
};
static const uint8_t IV2_VALUE_128bits_AES[] = {
	0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
	0x90, 0xab, 0xcd, 0xef
};
static const uint8_t IV_INVALID_LENGTH_VALUE[] = {
	0x01, 0x02, 0x03, 0x04, 0x05
};

/*ALL_TEE_CRYPTO_INITIALISATION_VECTOR_LENGTHS*/
#define IV_LENGTH_NULL                  0
#define IV_INVALID_LENGTH               5
#define IV1_LENGTH_64bits_DES_DES3      8
#define IV2_LENGTH_128bits_AES          16

static const uint8_t *TEE_ATTR_VALUE_NONE;

/*ALL_TEE_BUFFER_CASES*/
#define OUTPUT_BUFFER_NORMAL            1
#define OUTPUT_BUFFER_TOO_SHORT         2
#define OUTPUT_OTHER_BUFFER_TOO_SHORT   3

enum signature_validity {
	INVALID_SIGNATURE = 0,
	VALID_SIGNATURE
};

enum mac_validity {
	INVALID_MAC = 0,
	VALID_MAC
};

struct crypto_buffer {
	uint8_t *buffer;
	uint32_t size;
};

/*Saved in Invoke_Crypto_AllocateOperation*/
struct crypto_op {
	uint32_t algo;
	uint32_t mode;
	uint32_t obj_size;
};
struct crypto_op saved_alloc;

/*Saved in Invoke_Crypto_InitObjectWithKeys*/
struct key_val {
	TEE_ObjectHandle obh;
	uint32_t obj_type;
	uint32_t obj_size;
	struct crypto_buffer key;
};
struct key_val saved_key_vals;

/*Saved in Invoke_Crypto_SetOperationKey*/
struct obh_val {
	TEE_OperationHandle oph;
	TEE_ObjectHandle obh;
};
struct obh_val saved_obh1;

/*Saved in Invoke_Crypto_SetOperationKey2*/
struct obh_val2 {
	TEE_OperationHandle oph;
	TEE_ObjectHandle obh1;
	TEE_ObjectHandle obh2;
};
struct obh_val2 saved_obh;

/*saved by Invoke_Crypto_AEUpdateAAD*/
struct crypto_buffer saved_aad_value;

/*Saved in Invoke_Crypto_AEEncryptFinal*/
struct crypto_buffer ae_encrypt_tag;

/*Saved in Invoke_Crypto_AEUpdate_for_encryption*/
struct crypto_buffer buffer_encrypted_chunks[4];

/*Saved in Invoke_Crypto_AEUpdate_for_Decryption*/
struct crypto_buffer buffer_decrypted_chunks[4];

/*filled with data in Invoke_Crypto_AsymmetricEncrypt*/
struct crypto_buffer buffer_asym_encrypted;

/*saved by Invoke_Crypto_AEInit*/
struct crypto_buffer saved_in_nonce;

/*Saved in Invoke_Crypto_DeriveKey*/
struct obh_val saved_derive;

/*Saved in Invoke_Crypto_GenerateRandom*/
struct crypto_buffer saved_random;

/*Saved in Invoke_Crypto_DigestDoFinal*/
struct crypto_buffer saved_digest;

/*Saved in Invoke_Crypto_MACInit*/
struct crypto_buffer saved_mac_iv;

/*Saved in Invoke_Crypto_CipherInit*/
struct crypto_buffer saved_cipher_iv;

/*Saved in Invoke_Crypto_CipherUpdate*/
struct crypto_buffer saved_cipher_update;


TEEC_UUID UUID_TTA_testingInternalAPI_crypto = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x54, 0x43, 0x52, 0x59, 0x50, 0x54, 0x4F, 0x31 }
};

/* CRYPTO API HELPERS */
#define TEEC_SelectApp(a, b) /*do nothing for now*/

static void crypto_init(void)
{
	saved_obh.oph = 0;
	saved_obh.obh1 = 0;
	saved_obh.obh2 = 0;
	saved_alloc.algo = 0;
	saved_alloc.mode = 0;
	saved_alloc.obj_size = 0;
	saved_key_vals.obh = 0;
	saved_key_vals.obj_size = 0;
	saved_key_vals.obj_type = 0;
	CRYPTO_INIT(saved_key_vals.key);
	CRYPTO_INIT(saved_aad_value);
	CRYPTO_INIT(ae_encrypt_tag);
	/*4 chunks*/
	CRYPTO_INIT(buffer_encrypted_chunks[0]);
	CRYPTO_INIT(buffer_encrypted_chunks[1]);
	CRYPTO_INIT(buffer_encrypted_chunks[2]);
	CRYPTO_INIT(buffer_encrypted_chunks[3]);
	/*4 chunks*/
	CRYPTO_INIT(buffer_decrypted_chunks[0]);
	CRYPTO_INIT(buffer_decrypted_chunks[1]);
	CRYPTO_INIT(buffer_decrypted_chunks[2]);
	CRYPTO_INIT(buffer_decrypted_chunks[3]);
	CRYPTO_INIT(buffer_asym_encrypted);
	CRYPTO_INIT(saved_in_nonce);
	CRYPTO_INIT(saved_random);
	CRYPTO_INIT(saved_digest);
	CRYPTO_INIT(saved_cipher_iv);
	CRYPTO_INIT(saved_cipher_update);
}

static void crypto_reset(void)
{
	saved_obh.oph = 0;
	saved_obh.obh1 = 0;
	saved_obh.obh2 = 0;
	saved_alloc.algo = 0;
	saved_alloc.mode = 0;
	saved_alloc.obj_size = 0;
	saved_key_vals.obh = 0;
	saved_key_vals.obj_size = 0;
	saved_key_vals.obj_type = 0;
	CRYPTO_FREE(saved_key_vals.key);

	CRYPTO_FREE(saved_aad_value);
	CRYPTO_FREE(ae_encrypt_tag);
	/*4 chunks*/
	CRYPTO_FREE(buffer_encrypted_chunks[0]);
	CRYPTO_FREE(buffer_encrypted_chunks[1]);
	CRYPTO_FREE(buffer_encrypted_chunks[2]);
	CRYPTO_FREE(buffer_encrypted_chunks[3]);
	/*4 chunks*/
	CRYPTO_FREE(buffer_decrypted_chunks[0]);
	CRYPTO_FREE(buffer_decrypted_chunks[1]);
	CRYPTO_FREE(buffer_decrypted_chunks[2]);
	CRYPTO_FREE(buffer_decrypted_chunks[3]);
	CRYPTO_FREE(buffer_asym_encrypted);
	CRYPTO_FREE(saved_in_nonce);
	CRYPTO_FREE(saved_random);
	CRYPTO_FREE(saved_digest);
	CRYPTO_FREE(saved_cipher_iv);
	CRYPTO_FREE(saved_cipher_update);
}

/*Allocates TEEC_SharedMemory inside of the TEE*/
static TEEC_Result AllocateSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm, uint32_t size,
					uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	return TEEC_AllocateSharedMemory(ctx, shm);
}

/**
 * Writes 4 byte to @p *data_pp and increases
 * @p *data_pp by 4 byte. The bytes are written
 * in Big Endian Order.
 */
static void put_uint32_be(void **data_pp, uint32_t v)
{
	uint8_t *d = *(uint8_t **)data_pp;
	uint8_t *v_p = (uint8_t *)&v;

	d[3] = v_p[0];
	d[2] = v_p[1];
	d[1] = v_p[2];
	d[0] = v_p[3];
	*((uint8_t **)data_pp) += sizeof(uint32_t);
}

static TEEC_Result calculate_digest(ADBG_Case_t *c, TEEC_Session *s,
				    const void *data, const size_t data_length,
				    struct crypto_buffer *digest);

static TEEC_Result sign_digest(ADBG_Case_t *c, TEEC_Session *s,
			       const struct crypto_buffer *in_dgst,
			       struct crypto_buffer *out_dgst);

static bool verify_digest(ADBG_Case_t *c, TEEC_Session *s,
			  const struct crypto_buffer *in_sdgst);

static TEEC_Result mac_compute_final(ADBG_Case_t *c, TEEC_Session *s,
				     const void *full_data,
				     const size_t fdata_length,
				     struct crypto_buffer *mac);

static TEEC_Result cipher_do_final(ADBG_Case_t *c, TEEC_Session *s,
				   const void *full_data,
				   const size_t fdata_length,
				   struct crypto_buffer *cipher);

static void collapse_crypto_buffers(struct crypto_buffer *in_buffer,
				    struct crypto_buffer *out_buffer)
{
	int id;
	uint8_t *tmp;

	out_buffer->size = 0;

	for (id = 0; id < 4; id++)
		out_buffer->size += in_buffer[id].size;

	out_buffer->buffer = malloc(out_buffer->size);
	tmp = out_buffer->buffer;

	for (id = 0; id < 4; id++) {
		if (in_buffer[id].buffer) {
			memcpy(tmp, in_buffer[id].buffer, in_buffer[id].size);
			tmp += in_buffer[id].size;
		}
	}
}

/*Invoke Crypto Commands Implementations*/
/*CMD_AllocateOperation*/
static TEEC_Result Invoke_Crypto_AllocateOperation(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id,
	const uint32_t algo, const uint32_t mode,
	const size_t obj_size1, const size_t obj_size2,
	TEE_OperationHandle *oph)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	op.params[0].value.a = algo;
	op.params[0].value.b = mode;
	op.params[1].value.a = obj_size1 + obj_size2;
	op.params[3].value.a = (uint32_t)*oph;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_VALUE_INPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Store this information about mode and algorithm
	 * in order to do cryptographic operation later
	 */
	if (res == TEEC_SUCCESS) {
		saved_alloc.algo = algo;
		saved_alloc.mode = mode;
		saved_alloc.obj_size = obj_size1 + obj_size2;
	}

	return res;
}

/*CMD_GetOperationInfo*/
static TEEC_Result Invoke_Crypto_GetOperationInfo(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph, const uint32_t algo,
	uint32_t op_class, TEE_OperationMode op_mod,
	const size_t dgst_length, const size_t obj1_size,
	const size_t obj2_size,
	const size_t key_size, uint32_t key_usage,
	bool flag_two_keys, bool flag_key_set, bool flag_initialized)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	uint32_t mask_handle_state = 0;

	op.params[0].value.a = (uint32_t)*oph;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_VALUE_OUTPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		ADBG_EXPECT(c, op.params[0].value.a, algo);
		ADBG_EXPECT(c, op.params[0].value.b, op_class);
		ADBG_EXPECT(c, op.params[1].value.a, (uint32_t)op_mod);
		ADBG_EXPECT(c, op.params[1].value.b, dgst_length);
		ADBG_EXPECT(c, op.params[2].value.a, obj1_size + obj2_size);
		ADBG_EXPECT(c, op.params[2].value.b, key_size);
		ADBG_EXPECT(c, op.params[3].value.a, key_usage);

		if (flag_two_keys)
 			mask_handle_state |= TEE_HANDLE_FLAG_EXPECT_TWO_KEYS;

 		if (flag_key_set)
 			mask_handle_state |= TEE_HANDLE_FLAG_KEY_SET;

 		if (flag_initialized)
 			mask_handle_state |= TEE_HANDLE_FLAG_INITIALIZED;

		ADBG_EXPECT(c, op.params[3].value.b, mask_handle_state);

	}

	return res;
}

#ifdef WITH_GP_TESTS
/*CMD_GetOperationInfoMultiple*/
static TEEC_Result Invoke_Crypto_GetOperationInfoMultiple(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph, const uint32_t algo,
	uint32_t op_class, TEE_OperationMode op_mod,
	const size_t dgst_length, const size_t obj1_size,
	const size_t obj2_size,
	const size_t key_size, uint32_t key_usage, uint32_t key_exp,
	bool flag_two_keys, bool flag_key_set, bool flag_initialized)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	uint32_t *obuf;
	uint32_t obuf_size;
	uint32_t i;
	uint32_t key_num;
	uint32_t mask_handle_state = 0;

	/*
	 * ouput buffer size computation:
	 * number of key expected * nb key fields
	 * + operationState + numberOfkeys
	 * * nb of bytes
	 */
	obuf_size = ((key_exp * 2) + 2) * 4;
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, obuf_size,
			       TEEC_MEM_OUTPUT, mem01_exit)

	op.params[0].value.a = (uint32_t)*oph;

	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_VALUE_OUTPUT,
					 TEEC_VALUE_OUTPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		ADBG_EXPECT(c, op.params[0].value.a, algo);
		ADBG_EXPECT(c, op.params[0].value.b, op_class);
		ADBG_EXPECT(c, op.params[1].value.a, (uint32_t)op_mod);
		ADBG_EXPECT(c, op.params[1].value.b, dgst_length);
		ADBG_EXPECT(c, op.params[2].value.a, obj1_size + obj2_size);

 		if (flag_two_keys)
 			mask_handle_state |= TEE_HANDLE_FLAG_EXPECT_TWO_KEYS;

 		if (flag_key_set)
 			mask_handle_state |= TEE_HANDLE_FLAG_KEY_SET;

 		if (flag_initialized)
 			mask_handle_state |= TEE_HANDLE_FLAG_INITIALIZED;

		ADBG_EXPECT(c, op.params[2].value.b, mask_handle_state);

		obuf = (uint32_t *) op.params[3].memref.parent->buffer;
		obuf++;
		key_num = *obuf;

		for(i = 0; i < key_num; i++) {
			obuf++;
			ADBG_EXPECT(c, *obuf, key_size);
			obuf++;
			ADBG_EXPECT(c, *obuf, key_usage);
		}
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);

mem01_exit:
	return res;
}
#endif

/*CMD_ResetOperation*/
static TEEC_Result Invoke_Crypto_ResetOperation(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	op.params[0].value.a = (uint32_t)*oph;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	return res;
}

/*CMD_FreeAllKeysAndOperations*/
static TEEC_Result Invoke_Crypto_FreeAllKeysAndOperations(
	ADBG_Case_t *c,
	TEEC_Session *s,
	uint32_t cmd_id,
	TEE_OperationHandle *oph)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	op.params[0].value.a = (uint32_t)*oph;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	return res;
}

/*CMD_InitObjectWithKeys*/
static TEEC_Result Invoke_Crypto_InitObjectWithKeys(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, const uint32_t obj_type, const uint32_t obj_size,
	const uint32_t attributeId_1, const void *attribValue_1,
	const uint32_t attribSize_1,
	const uint32_t attributeId_2, const void *attribValue_2,
	const uint32_t attribSize_2,
	const uint32_t attributeId_3, const void *attribValue_3,
	const uint32_t attribSize_3,
	const uint32_t attributeId_4, const void *attribValue_4,
	const uint32_t attribSize_4,
	const uint32_t attributeId_5, const void *attribValue_5,
	const uint32_t attribSize_5,
	TEE_ObjectHandle *obh)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	void *tmp_buf1 = NULL;
	uint8_t *tmp_buf2 = NULL;
	int tmp_offset = 0;

	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, BIG_SIZE,
			       TEEC_MEM_INPUT, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, DS_BIG_SIZE,
			       TEEC_MEM_INPUT, mem02_exit)

	/* Serialize the data in format:
	 * SHARE_MEM01 = (uint32_t)attr_id1|(uint32_t)attr_val1_offset
	 * in SHARE_MEM02|(uint32_t)attr_val1_length
	 * Add 0 for all three if attr_idX = TEE_ATTR_NONE
	 */
	/* Serialize the data in format:
	 * SHARE_MEM02 = attr_val1|attr_val2|attr_val3|attr_val4|attr_val5.
	 * Do not add anything if attr_valX == TEE_ATTR_VALUE_NONE.
	 */

	tmp_buf1 = SHARE_MEM01->buffer;
	tmp_buf2 = (uint8_t *)SHARE_MEM02->buffer;
	put_uint32_be(&tmp_buf1, attributeId_1);

	if (TEE_ATTR_NONE != attributeId_1) {
		put_uint32_be(&tmp_buf1, tmp_offset);
		put_uint32_be(&tmp_buf1, attribSize_1);
		memcpy(tmp_buf2, attribValue_1, (size_t)attribSize_1);
		tmp_buf2 += attribSize_1;
		tmp_offset += attribSize_1;
	} else {
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
	}

	put_uint32_be(&tmp_buf1, attributeId_2);

	if (TEE_ATTR_NONE != attributeId_2) {
		put_uint32_be(&tmp_buf1, tmp_offset);
		put_uint32_be(&tmp_buf1, attribSize_2);
		memcpy(tmp_buf2, attribValue_2, (size_t)attribSize_2);
		tmp_buf2 += attribSize_2;
		tmp_offset += attribSize_2;
	} else {
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
	}

	put_uint32_be(&tmp_buf1, attributeId_3);

	if (TEE_ATTR_NONE != attributeId_3) {
		put_uint32_be(&tmp_buf1, tmp_offset);
		put_uint32_be(&tmp_buf1, attribSize_3);
		memcpy(tmp_buf2, attribValue_3, (size_t)attribSize_3);
		tmp_buf2 += attribSize_3;
		tmp_offset += attribSize_3;
	} else {
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
	}

	put_uint32_be(&tmp_buf1, attributeId_4);

	if (TEE_ATTR_NONE != attributeId_4) {
		put_uint32_be(&tmp_buf1, tmp_offset);
		put_uint32_be(&tmp_buf1, attribSize_4);
		memcpy(tmp_buf2, attribValue_4, (size_t)attribSize_4);
		tmp_buf2 += attribSize_4;
		tmp_offset += attribSize_4;
	} else {
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
	}

	put_uint32_be(&tmp_buf1, attributeId_5);

	if (TEE_ATTR_NONE != attributeId_5) {
		put_uint32_be(&tmp_buf1, tmp_offset);
		put_uint32_be(&tmp_buf1, attribSize_5);
		memcpy(tmp_buf2, attribValue_5, (size_t)attribSize_5);
		tmp_buf2 += attribSize_5;
		tmp_offset += attribSize_5;
	} else {
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
		put_uint32_be(&tmp_buf1, TEE_ATTR_NONE);
	}

	op.params[0].value.a = obj_type;
	op.params[0].value.b = obj_size;
	/* 5 attributes
	 * 12 bytes = 4 attr_id + 4 attr_offset + 4 attr_length
	 */
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01, 60)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02, tmp_offset)
	op.params[3].value.a = (uint32_t)*obh;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_VALUE_INPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Store the key values associated with ObjectHandle in
	 * order to perform cryptographic computation later
	 */
	if (res == TEEC_SUCCESS) {
		saved_key_vals.obj_type = obj_type;
		saved_key_vals.obj_size = obj_size;
		saved_key_vals.obh = *obh;

		CRYPTO_FREE(saved_key_vals.key);
		saved_key_vals.key.size = tmp_offset;
		saved_key_vals.key.buffer = malloc(tmp_offset);
		memcpy(saved_key_vals.key.buffer, SHARE_MEM02->buffer,
		       tmp_offset);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_SetOperationKey*/
static TEEC_Result Invoke_Crypto_SetOperationKey(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph, TEE_ObjectHandle *obh)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	op.params[0].value.a = (uint32_t)*oph;
	op.params[0].value.b = (uint32_t)*obh;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* store the information about which key object handle are associated
	 * with Operation Handle in order to perform cryptographic
	 * computation later
	 */
	if (res == TEEC_SUCCESS) {
		saved_obh.oph = *oph;
		saved_obh.obh1 = *obh;
		saved_obh.obh2 = TEE_HANDLE_NULL;
	}

	return res;
}

/*CMD_SetOperationKey2*/
static TEEC_Result Invoke_Crypto_SetOperationKey2(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	TEE_ObjectHandle *obh1, TEE_ObjectHandle *obh2)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	op.params[0].value.a = (uint32_t)*oph;
	op.params[0].value.b = (uint32_t)*obh1;
	op.params[1].value.a = (uint32_t)*obh2;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Store the information about which key object handles are associated
	 * with Operation Handle in order to perform cryptographic
	 * computation later
	 */
	if (res == TEEC_SUCCESS) {
		saved_obh.oph = *oph;
		saved_obh.obh1 = *obh1;
		saved_obh.obh2 = *obh2;
	}

	return res;
}

/*CMD_DeriveKey*/
static TEEC_Result Invoke_Crypto_DeriveKey(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph, TEE_ObjectHandle *obh)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	op.params[0].value.a = (uint32_t)*oph;
	op.params[0].value.b = (uint32_t)*obh;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Save the fact that the object has been derived for later
	 * cryptographic computation
	 */
	if (res == TEEC_SUCCESS) {
		saved_derive.oph = *oph;
		saved_derive.obh = *obh;
	}

	return res;
}

/*CMD_AEInit*/
static TEEC_Result Invoke_Crypto_AEInit(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *nonce_val, const size_t nonce_length,
	const size_t in_tag_len, const size_t in_aad_len,
	const size_t in_payload_len)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, nonce_length,
					TEEC_MEM_INPUT, nonce_length,
					nonce_val, mem01_exit)

	op.params[0].value.a = (uint32_t)*oph;
	op.params[0].value.b = in_tag_len;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	op.params[2].value.a = in_aad_len;
	op.params[2].value.b = in_payload_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_VALUE_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Save the $IN_nonce$ for later computation of encryptedData
	 */
	if (res == TEEC_SUCCESS) {
		saved_in_nonce.buffer = malloc(nonce_length);
		saved_in_nonce.size = nonce_length;
		memcpy(saved_in_nonce.buffer, nonce_val, nonce_length);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_AEUpdate*/
static TEEC_Result Invoke_Crypto_AEUpdate_for_encryption(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const uint32_t case_buf, const uint32_t chunk_id)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, DS_BIG_SIZE,
			       TEEC_MEM_OUTPUT, mem02_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1  */
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Store the buffer from "shm2" in
	 * "buffer_encrypted_chunks[$IN_chunkNumber$]"
	 * which will be reused for the
	 * Invoke_Crypto_TEE_AEUpdate_for_decryption function
	 */
	if (res == TEEC_SUCCESS) {
		buffer_encrypted_chunks[chunk_id].size =
			op.params[3].memref.size;
		buffer_encrypted_chunks[chunk_id].buffer = malloc(
			buffer_encrypted_chunks[chunk_id].size);
		memcpy(buffer_encrypted_chunks[chunk_id].buffer,
		       SHARE_MEM02->buffer,
		       buffer_encrypted_chunks[chunk_id].size);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}
/*CMD_AEUpdate*/

static TEEC_Result Invoke_Crypto_AEUpdate_for_decryption(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const uint32_t case_buf, const uint32_t chunk_id)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01,
					buffer_encrypted_chunks[chunk_id].size,
					TEEC_MEM_INPUT,
					buffer_encrypted_chunks[chunk_id].size,
					buffer_encrypted_chunks[chunk_id].
						buffer, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, partd_length,
			       TEEC_MEM_OUTPUT, mem02_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01, partd_length)
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Save the buffer from "SharedMem2" into
	 * "buffer_decrypted_chunks[$IN_chunkNumber$]"
	 * in order to collapse all buffers returned for
	 * AEUpdate_for_decryption,
	 * which will be used in AEDecryptFinal
	 */
	if (res == TEEC_SUCCESS) {
		buffer_decrypted_chunks[chunk_id].size =
			op.params[3].memref.size;
		buffer_decrypted_chunks[chunk_id].buffer = malloc(
			buffer_decrypted_chunks[chunk_id].size);
		memcpy(buffer_decrypted_chunks[chunk_id].buffer,
		       SHARE_MEM02->buffer,
		       buffer_decrypted_chunks[chunk_id].size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_AEUpdateAAD*/
static TEEC_Result Invoke_Crypto_AEUpdateAAD(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *aad_data, const size_t aad_length)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, aad_length,
					TEEC_MEM_INPUT, aad_length,
					aad_data, mem01_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Save the $IN_AAD_Value$ for AAD for later cryptographic computation
	 */
	if (res == TEEC_SUCCESS) {
		saved_aad_value.buffer = malloc(aad_length);
		saved_aad_value.size = aad_length;
		memcpy(saved_aad_value.buffer, aad_data, aad_length);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_AEEncryptFinal*/
static TEEC_Result Invoke_Crypto_AEEncryptFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fdata_length,
	uint32_t case_buf, uint32_t chunk_id)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_partd_size, initial_fdata_size;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, fdata_length,
			       TEEC_MEM_OUTPUT, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, partd_length,
			       TEEC_MEM_OUTPUT, mem03_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	switch (case_buf) {
	case OUTPUT_BUFFER_TOO_SHORT:
		/*if $IN_caseBuffer$ =
			OUTPUT_BUFFER_TOO_SHORT(2) then Param[3].memref.size=1*/
		SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM03,
						      SHARE_MEM03->size)
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
		break;
	case OUTPUT_OTHER_BUFFER_TOO_SHORT:
		SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM03, 1)
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
		break;
	case OUTPUT_BUFFER_NORMAL:
	default:
		SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM03,
						      SHARE_MEM03->size)
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
		break;
	}
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_partd_size = op.params[2].memref.size;
	initial_fdata_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Store the buffer from "shm2" in
		 * "buffer_encrypted_chunks[$IN_chunkNumber$]"
		 * which will be reused for
		 * the Invoke_Crypto_TEE_AEDecryptFinal function
		 */
		buffer_encrypted_chunks[chunk_id].size =
			op.params[3].memref.size;
		buffer_encrypted_chunks[chunk_id].buffer = malloc(
			buffer_encrypted_chunks[chunk_id].size);
		memcpy(buffer_encrypted_chunks[chunk_id].buffer,
		       SHARE_MEM02->buffer,
		       buffer_encrypted_chunks[chunk_id].size);

		/* Store the tag from "SharedMem3" which will be reused for the
		 * Invoke_Crypto_TEE_AEDecryptFinal function
		 */
		ae_encrypt_tag.size = op.params[2].memref.size;
		ae_encrypt_tag.buffer = malloc(ae_encrypt_tag.size);
		memcpy(ae_encrypt_tag.buffer, SHARE_MEM03->buffer,
		       ae_encrypt_tag.size);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		if (initial_partd_size == op.params[2].memref.size)
			ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_fdata_size, <,
						     op.params[3].memref.size);
		else
			ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_partd_size, <,
						     op.params[2].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_AEDecryptFinal*/
static TEEC_Result Invoke_Crypto_AEDecryptFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fdata_length,
	const uint32_t case_buf, const enum mac_validity mac_case,
	const uint32_t chunk_id)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01,
					buffer_encrypted_chunks[chunk_id].size,
					TEEC_MEM_INPUT,
					buffer_encrypted_chunks[chunk_id].size,
					buffer_encrypted_chunks[chunk_id].
						buffer, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, partd_length,
			       TEEC_MEM_OUTPUT, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ae_encrypt_tag.size,
			       TEEC_MEM_INPUT, mem03_exit)
	/* Fill "SharedMem3" with the tag previously
	 * saved in Invoke_Crypto_AEEncryptFinal
	 * (with an error (one bit changed) if $IN_caseMac$ = INVALID_MAC)
	 */
	if (ae_encrypt_tag.buffer != NULL) {
		memcpy(SHARE_MEM03->buffer, ae_encrypt_tag.buffer,
		       ae_encrypt_tag.size);

		if (mac_case == INVALID_MAC)
			BIT_CHANGE(*(uint32_t *)SHARE_MEM03->buffer, 4);
	}

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM03,
					      SHARE_MEM03->size)
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Save the buffer from "SharedMem2" to
		 * "buffer_decrypted_chunks[$IN_chunkNumber$]"
		 */
		buffer_decrypted_chunks[chunk_id].size =
			op.params[3].memref.size;
		buffer_decrypted_chunks[chunk_id].buffer = malloc(
			buffer_decrypted_chunks[chunk_id].size);
		memcpy(buffer_decrypted_chunks[chunk_id].buffer,
		       SHARE_MEM02->buffer,
		       buffer_decrypted_chunks[chunk_id].size);

		/* Compare the data in clear $IN_fullDataValue$ and with
		 * collapsed buffers from table
		 * "buffer_decrypted_chunks" and check they are equals
		 */
		struct crypto_buffer collapsed;
		CRYPTO_INIT(collapsed);
		collapse_crypto_buffers(buffer_decrypted_chunks, &collapsed);
		ADBG_EXPECT_BUFFER(c, full_data, fdata_length, collapsed.buffer,
				   collapsed.size);
		CRYPTO_FREE(collapsed);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_GenerateRandom*/
static TEEC_Result Invoke_Crypto_GenerateRandom(ADBG_Case_t *c, TEEC_Session *s,
						const uint32_t cmd_id)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, BIG_SIZE,
			       TEEC_MEM_OUTPUT, mem01_exit)

	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Check that the buffer shm1 is not empty
	 * + Check that this random value is
	 * different of a previous call of this command
	 */
	if (res == TEEC_SUCCESS) {
		if (ADBG_EXPECT_COMPARE_SIGNED(c, 0, !=,
					       op.params[3].memref.size)) {
			if (saved_random.buffer != NULL) {
				(void)ADBG_EXPECT_COMPARE_SIGNED(c, 0, !=,
								memcmp(
								SHARE_MEM01
								->
								buffer,
								saved_random
								.
								buffer,
								op.
								params[3].
								memref.
								size));
				free(saved_random.buffer);
				saved_random.size = 0;
			}

			saved_random.size = op.params[3].memref.size;
			saved_random.buffer = malloc(saved_random.size);
			memcpy(saved_random.buffer, SHARE_MEM01->buffer,
			       saved_random.size);
		}
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_DigestUpdate*/
static TEEC_Result Invoke_Crypto_DigestUpdate(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_DigestDoFinal*/
static TEEC_Result Invoke_Crypto_DigestDoFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fdata_length,
	const uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, fdata_length,
			       TEEC_MEM_OUTPUT, mem02_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Compute the hash of $IN_fullDataValue$
		 * and compare it to "shm2"
		 */
		struct crypto_buffer tmp_dgst;
		CRYPTO_INIT(tmp_dgst);
		ADBG_EXPECT_TEEC_SUCCESS(c, res =
						 calculate_digest(c, s,
								  full_data,
								  fdata_length,
								  &tmp_dgst));
		ADBG_EXPECT_BUFFER(c, tmp_dgst.buffer, tmp_dgst.size,
				   SHARE_MEM02->buffer, tmp_dgst.size);

		/* Store the Digest value which can be reused for a next call to
		 * TEE_AsymmetricSignDigest or TEE_AsymmetricVerifyDigest
		 */
		CRYPTO_FREE(saved_digest);
		saved_digest.size = op.params[3].memref.size;
		saved_digest.buffer = malloc(saved_digest.size);
		memcpy(saved_digest.buffer, SHARE_MEM02->buffer,
		       saved_digest.size);
		CRYPTO_FREE(tmp_dgst);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_AsymmetricSignDigest*/
static TEEC_Result Invoke_Crypto_AsymmetricSignDigest(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *full_data, const size_t fdata_length, uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	/* Fill SharedMem1 with the previously stored Digest
		value after TEE_DigestDoFinal */
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, fdata_length,
					TEEC_MEM_INPUT,
					saved_digest.size, saved_digest.buffer, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, 512,
			       TEEC_MEM_OUTPUT, mem02_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      saved_digest.size)
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Compute a Verify_Signature of the signature
		 * store under "SharedMem2"
		 */
		struct crypto_buffer s_dgst;
		CRYPTO_INIT(s_dgst);
		s_dgst.size = op.params[3].memref.size;
		s_dgst.buffer = malloc(s_dgst.size);
		memcpy(s_dgst.buffer, SHARE_MEM02->buffer, s_dgst.size);
		ADBG_EXPECT(c, true, verify_digest(c, s, &s_dgst));
		CRYPTO_FREE(s_dgst);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_AsymmetricVerifyDigest*/
static TEEC_Result Invoke_Crypto_AsymmetricVerifyDigest(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *full_data, const size_t fdata_length,
	const uint32_t valid_sig)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, fdata_length,
					TEEC_MEM_INPUT,
					saved_digest.size, saved_digest.buffer, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, 512,
			       TEEC_MEM_INPUT, mem02_exit)

	struct crypto_buffer signed_dgst;
	CRYPTO_INIT(signed_dgst);
	res = sign_digest(c, s, &saved_digest, &signed_dgst);

	/* Fill "SharedMem2" with the valid computed signature based on
	 * the previously stored Digest value after TEE_DigestDoFinal
	 */
	if (signed_dgst.buffer != NULL) {
		memcpy(SHARE_MEM02->buffer, signed_dgst.buffer,
		       signed_dgst.size);

		if (valid_sig != VALID_SIGNATURE) {
			/*make it invalid*/
			BIT_CHANGE(*(uint32_t *)SHARE_MEM02->buffer, 4);
		}
	}

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      saved_digest.size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
					      signed_dgst.size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_MEMREF_PARTIAL_INPUT);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	CRYPTO_FREE(signed_dgst);

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_AsymmetricEncrypt*/
static TEEC_Result Invoke_Crypto_AsymmetricEncrypt(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *full_data, const size_t fdata_length, uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	/* Fill SharedMem1 with full_data */
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, fdata_length,
					TEEC_MEM_INPUT, fdata_length,
					full_data, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, 512,
			       TEEC_MEM_OUTPUT, mem02_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Check that "SharedMem2" is not empty
		 * Store the value from "SharedMem2" to a
		 * "buffer_asym_encrypted",
		 * which will be reused in Invoke_Crypto_AsymmetricDecrypt
		 */
		if (ADBG_EXPECT_COMPARE_SIGNED(c, 0, !=,
					       op.params[3].memref.size)) {
			buffer_asym_encrypted.size = op.params[3].memref.size;
			buffer_asym_encrypted.buffer = malloc(
				buffer_asym_encrypted.size);
			memcpy(buffer_asym_encrypted.buffer,
			       SHARE_MEM02->buffer, buffer_asym_encrypted.size);
		}
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_AsymmetricDecrypt*/
static TEEC_Result Invoke_Crypto_AsymmetricDecrypt(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *full_data, const size_t fdata_length, uint32_t case_buf,
	uint32_t nopad)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;
	char *expected_res;
	size_t expected_size;

	/* Fill SharedMem1 with buffer_asym_encrypted */
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01,
					buffer_asym_encrypted.size,
					TEEC_MEM_INPUT,
					buffer_asym_encrypted.size,
					buffer_asym_encrypted.buffer, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, 512,
			       TEEC_MEM_OUTPUT, mem02_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      buffer_asym_encrypted.size)
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	expected_res = full_data;
	expected_size =  fdata_length;
	if (nopad) {
		/*
		 * According to GP 1.1, no pad encrypting TEE_ALG_RSA_NOPAD
		 * follows "PKCS #1 (RSA primitive)", as stated in
		 * ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
		 * Page 10, it is stated that RSA primitives RSAEP and RSADP
		 * outputs "an integer between 0 and n-1". Hence the
		 * leading 0s must not be taken into account when checking
		 * the reference
		 */
		while (expected_size && expected_res[0] == 0) {
			expected_size--;
			expected_res++;
		}
	}

	if (res == TEEC_SUCCESS) {
		/* Compare the clear data in
		 * $IN_fullDataValue$ with "SharedMem2"
		 * and check they are equal
		 */
		ADBG_EXPECT_BUFFER(c, expected_res, expected_size,
				   SHARE_MEM02->buffer,
				   op.params[3].memref.size);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_CopyOperation*/
static TEEC_Result Invoke_Crypto_CopyOperation(
	ADBG_Case_t *c, TEEC_Session *s, const uint32_t cmd_id,
	TEE_OperationHandle *dst_oph, TEE_OperationHandle *src_oph)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	op.params[0].value.a = (uint32_t)*dst_oph;
	op.params[0].value.b = (uint32_t)*src_oph;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	return res;
}

/*CMD_MACInit*/
static TEEC_Result Invoke_Crypto_MACInit(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *iv, const size_t iv_len)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM06, iv_len,
					TEEC_MEM_INPUT, iv_len, iv, mem06_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM06, iv_len)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* save the $IN_InitialisationVector$ for
	 * later computation of encryptedData
	 */
	if (iv_len != 0) {
		CRYPTO_FREE(saved_mac_iv);
		saved_mac_iv.size = iv_len;
		saved_mac_iv.buffer = malloc(iv_len);
		memcpy(saved_mac_iv.buffer, iv, iv_len);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM06);
mem06_exit:
	return res;
}

/*CMD_MACUpdate*/
static TEEC_Result Invoke_Crypto_MACUpdate(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_MACCompareFinal*/
static TEEC_Result Invoke_Crypto_MACCompareFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fdata_length,
	enum mac_validity mac_case)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	/* Fill SharedMem1 with part_data */
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, fdata_length,
			       TEEC_MEM_INPUT, mem02_exit)

	/* Fill SharedMem2 with valid computed MAC of full_data */
	struct crypto_buffer mac;
	CRYPTO_INIT(mac);
	res = mac_compute_final(c, s, full_data, fdata_length, &mac);

	if (mac.buffer != NULL) {
		memcpy(SHARE_MEM02->buffer, mac.buffer, mac.size);

		if (mac_case != VALID_MAC) {
			/* change one bit from the valid
				MAC to make it invalid. */
			BIT_CHANGE(*(uint32_t *)SHARE_MEM02->buffer, 4);
		}
	}

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02, mac.size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	CRYPTO_FREE(mac);

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_MACComputeFinal*/
static TEEC_Result Invoke_Crypto_MACComputeFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fdata_length, uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	/* Fill SharedMem1 with part_data */
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, fdata_length,
			       TEEC_MEM_OUTPUT, mem02_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	/* Compute the MAC of $IN_fullDataValue$ and
		compare it to "SharedMem2" */
	if (res == TEEC_SUCCESS) {
		struct crypto_buffer tmp_mac;
		CRYPTO_INIT(tmp_mac);
		ADBG_EXPECT_TEEC_SUCCESS(c, res =
						 mac_compute_final(c, s,
								   full_data,
								   fdata_length,
								   &tmp_mac));

		if (res != TEEC_SUCCESS)
			goto exit;

		ADBG_EXPECT_COMPARE_SIGNED(c, 0, ==,
					   memcmp(SHARE_MEM02->buffer,
						  tmp_mac.buffer,
						  op.params[3].memref.size));
		CRYPTO_FREE(tmp_mac);
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_CipherInit*/
static TEEC_Result Invoke_Crypto_CipherInit(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *iv, const size_t iv_len)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, iv_len,
					TEEC_MEM_INPUT, iv_len, iv, mem01_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Save the $IN_InitialisationVector$ for later
		 * computation of encryptedData
		 */
		if (iv != NULL) {
			CRYPTO_FREE(saved_cipher_iv);
			saved_cipher_iv.size = iv_len;
			saved_cipher_iv.buffer = malloc(iv_len);
			memcpy(saved_cipher_iv.buffer, iv, iv_len);
		}
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	CRYPTO_FREE(saved_cipher_update);
	return res;
}
/*CMD_CipherUpdate*/
static TEEC_Result Invoke_Crypto_CipherUpdate(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, uint32_t partd_length,
	uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, partd_length,
			       TEEC_MEM_OUTPUT, mem02_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Save the buffer returned in "SharedMem2" in order
		 * to collapse all buffers returned for CipherUpdate,
		 * which will be used in CipherDoFinal
		 */
		if (op.params[3].memref.size != 0) {
			void *tmp = realloc(saved_cipher_update.buffer,
					    saved_cipher_update.size +
					    op.params[3].memref.size);
			saved_cipher_update.buffer = tmp;
			memcpy(
				saved_cipher_update.buffer +
				saved_cipher_update.size, SHARE_MEM02->buffer,
				op.params[3].memref.size);
			saved_cipher_update.size += op.params[3].memref.size;
		}
	} else if (res == TEEC_ERROR_SHORT_BUFFER) {
		ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
					     op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_CipherDoFinal*/
static TEEC_Result Invoke_Crypto_CipherDoFinal(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph,
	const void *part_data, const size_t partd_length,
	const void *full_data, const size_t fulld_length, uint32_t case_buf)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;
	size_t initial_size;

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM01, partd_length,
					TEEC_MEM_INPUT, partd_length,
					part_data, mem01_exit)
	/* used fulld_length instead of partd_length as
		described in the Adaptation layer specification.*/
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, fulld_length,
			       TEEC_MEM_OUTPUT, mem02_exit)

	op.params[0].value.a = (uint32_t)*oph;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	/*if $IN_caseBuffer$ = OUTPUT_BUFFER_TOO_SHORT(2)
		then Param[3].memref.size=1*/
	if (case_buf == OUTPUT_BUFFER_TOO_SHORT) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02, 1)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM02,
						      SHARE_MEM02->size)
	}

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);
	initial_size = op.params[3].memref.size;

	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		/* Append the buffer returned in "SharedMem2"
		 * to the previously buffers
		 * returned for CipherUpdate => "collapsed_buffers"
		 */
		if (op.params[3].memref.size != 0) {
			void *tmp = realloc(saved_cipher_update.buffer,
					    saved_cipher_update.size +
					    op.params[3].memref.size);
			saved_cipher_update.buffer = tmp;
			memcpy(
				saved_cipher_update.buffer +
				saved_cipher_update.size, SHARE_MEM02->buffer,
				op.params[3].memref.size);
			saved_cipher_update.size += op.params[3].memref.size;
		}

		/* Compute the ciphered data of
		 * $IN_fullDataValue$ and compare it
		 * to "collapsed_buffers"
		 */
		struct crypto_buffer full_ciphered_data;
		CRYPTO_INIT(full_ciphered_data);
		ADBG_EXPECT_TEEC_SUCCESS(c, res =
						 cipher_do_final(c, s,
							full_data,
							fulld_length,
							&
							full_ciphered_data));

		if (res == TEEC_SUCCESS) {
			ADBG_EXPECT_BUFFER(c, full_ciphered_data.buffer,
					   full_ciphered_data.size,
					   saved_cipher_update.buffer,
					   saved_cipher_update.size);
		} else if (res == TEEC_ERROR_SHORT_BUFFER) {
			ADBG_EXPECT_COMPARE_UNSIGNED(c, initial_size, <,
						     op.params[3].memref.size);
		}

		CRYPTO_FREE(full_ciphered_data);
		CRYPTO_FREE(saved_cipher_update);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

/*CMD_FreeOperation*/
static TEEC_Result Invoke_Crypto_FreeOperation(
	ADBG_Case_t *c, TEEC_Session *s,
	const uint32_t cmd_id, TEE_OperationHandle *oph)
{
	TEEC_Result res;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	op.params[0].value.a = (uint32_t)*oph;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(s, cmd_id, &op, &ret_orig);

	return res;
}

static TEEC_Result calculate_digest(
	ADBG_Case_t *c, TEEC_Session *s,
	const void *data, const size_t data_length,
	struct crypto_buffer *digest)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEE_OperationHandle op1 = (TEE_OperationHandle)3;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig;

	res = Invoke_Crypto_AllocateOperation(c, s, CMD_AllocateOperation,
					      saved_alloc.algo, TEE_MODE_DIGEST,
					      saved_alloc.obj_size, 0, &op1);

	if (res != TEEC_SUCCESS)
		goto exit;

	/*CMD_DigestDoFinal*/
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM04, data_length,
					TEEC_MEM_INPUT, data_length,
					data, mem04_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM05, data_length,
			       TEEC_MEM_OUTPUT, mem05_exit)

	op.params[0].value.a = (uint32_t)op1;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
					      SHARE_MEM04->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM05,
					      SHARE_MEM05->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, CMD_DigestDoFinal, &op, &ret_orig);

	if (SHARE_MEM05->size != 0 && res == TEEC_SUCCESS) {
		digest->size = op.params[3].memref.size;
		digest->buffer = malloc(op.params[3].memref.size);
		memcpy(digest->buffer, SHARE_MEM05->buffer,
		       op.params[3].memref.size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM05);
mem05_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM04);
mem04_exit:
	Invoke_Crypto_FreeOperation(c, s, CMD_FreeOperation, &op1);
exit:
	return res;
}

static TEEC_Result sign_digest(
	ADBG_Case_t *c, TEEC_Session *s,
	const struct crypto_buffer *in_dgst, struct crypto_buffer *out_dgst)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEE_OperationHandle op1 = (TEE_OperationHandle)3;
	uint32_t ret_orig;

	res = Invoke_Crypto_AllocateOperation(c, s, CMD_AllocateOperation,
					      saved_alloc.algo, TEE_MODE_SIGN,
					      saved_alloc.obj_size, 0, &op1);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (saved_obh.obh2 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey2(c, s, CMD_SetOperationKey2,
						     &op1, &saved_obh.obh1,
						     &saved_obh.obh2);

		if (res != TEEC_SUCCESS)
			goto exit;

	} else if (saved_obh.obh1 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey(c, s, CMD_SetOperationKey,
						    &op1, &saved_obh.obh1);

		if (res != TEEC_SUCCESS)
			goto exit;

	}

	/*CMD_AsymmetricSignDigest*/
	/* Fill SharedMem1 with the previously stored
		Digest value after TEE_DigestDoFinal*/
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM04, 512,
					TEEC_MEM_INPUT,
					in_dgst->size, in_dgst->buffer, mem04_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM05, 512,
			       TEEC_MEM_OUTPUT, mem05_exit)

	op.params[0].value.a = (uint32_t)op1;
	if (in_dgst->size != 0) {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
						      in_dgst->size)
	} else {
		SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
						      SHARE_MEM04->size)
	}
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM05,
					      SHARE_MEM05->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, CMD_AsymmetricSignDigest, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		out_dgst->size = op.params[3].memref.size;
		out_dgst->buffer = malloc(out_dgst->size);
		memcpy(out_dgst->buffer, SHARE_MEM05->buffer, out_dgst->size);
	}

exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM05);
mem05_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM04);
mem04_exit:
	Invoke_Crypto_FreeOperation(c, s, CMD_FreeOperation, &op1);
	return res;
}

static bool verify_digest(
	ADBG_Case_t *c, TEEC_Session *s,
	const struct crypto_buffer *in_sdgst)
{
	TEEC_Result res;
	bool is_valid = false;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEE_OperationHandle op1 = (TEE_OperationHandle)3;
	uint32_t ret_orig;

	res = Invoke_Crypto_AllocateOperation(c, s, CMD_AllocateOperation,
					      saved_alloc.algo, TEE_MODE_VERIFY,
					      saved_alloc.obj_size, 0, &op1);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (saved_obh.obh2 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey2(c, s, CMD_SetOperationKey2,
						     &op1, &saved_obh.obh1,
						     &saved_obh.obh2);

		if (res != TEEC_SUCCESS)
			goto exit;

	} else if (saved_obh.obh1 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey(c, s, CMD_SetOperationKey,
						    &op1, &saved_obh.obh1);

		if (res != TEEC_SUCCESS)
			goto exit;

	}

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM04, 512,
					TEEC_MEM_INPUT,
					saved_digest.size, saved_digest.buffer, mem04_exit)
	/* Fill "SharedMem2" with signature based on the previously
		stored Digest value after TEE_DigestDoFinal */
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM05, 512,
					TEEC_MEM_INPUT,
					in_sdgst->size, in_sdgst->buffer, mem05_exit)

	op.params[0].value.a = (uint32_t)op1;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
					      saved_digest.size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM05, in_sdgst->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_MEMREF_PARTIAL_INPUT);

	res = TEEC_InvokeCommand(s, CMD_AsymmetricVerifyDigest, &op, &ret_orig);

	if (res == TEEC_SUCCESS)
		is_valid = true;

	TEEC_ReleaseSharedMemory(SHARE_MEM05);
mem05_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM04);
mem04_exit:
	Invoke_Crypto_FreeOperation(c, s, CMD_FreeOperation, &op1);
exit:
	return is_valid;
}

static TEEC_Result mac_compute_final(
	ADBG_Case_t *c, TEEC_Session *s,
	const void *full_data, const size_t fdata_length,
	struct crypto_buffer *mac)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEE_OperationHandle op1 = (TEE_OperationHandle)3;
	uint32_t ret_orig;

	res = Invoke_Crypto_AllocateOperation(c, s, CMD_AllocateOperation,
					      saved_alloc.algo, TEE_MODE_MAC,
					      saved_alloc.obj_size, 0, &op1);

	if (res != TEEC_SUCCESS)
		goto exit;

	if (saved_obh.obh2 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey2(c, s, CMD_SetOperationKey2,
						     &op1, &saved_obh.obh1,
						     &saved_obh.obh2);

		if (res != TEEC_SUCCESS)
			goto exit;

	} else if (saved_obh.obh1 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey(c, s, CMD_SetOperationKey,
						    &op1, &saved_obh.obh1);

		if (res != TEEC_SUCCESS)
			goto exit;
	}

	res = Invoke_Crypto_MACInit(c, s, CMD_MACInit, &op1,
				    saved_mac_iv.buffer, saved_mac_iv.size);

	if (res != TEEC_SUCCESS)
		goto exit;

	/* CMD_MACComputeFinal */
	/* Fill SharedMem1 with full_data */
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM04, fdata_length,
					TEEC_MEM_INPUT, fdata_length,
					full_data, mem04_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM05, fdata_length,
			       TEEC_MEM_OUTPUT, mem05_exit)

	op.params[0].value.a = (uint32_t)op1;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
					      SHARE_MEM04->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM05,
					      SHARE_MEM05->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, CMD_MACComputeFinal, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		mac->size = op.params[3].memref.size;
		mac->buffer = malloc(mac->size);
		memcpy(mac->buffer, SHARE_MEM05->buffer, mac->size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM05);
mem05_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM04);
mem04_exit:
	Invoke_Crypto_FreeOperation(c, s, CMD_FreeOperation, &op1);
exit:
	return res;
}

static TEEC_Result cipher_do_final(
	ADBG_Case_t *c, TEEC_Session *s,
	const void *full_data, const size_t fdata_length,
	struct crypto_buffer *cipher)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEE_OperationHandle op1 = (TEE_OperationHandle)3;
	uint32_t ret_orig;

	res = Invoke_Crypto_AllocateOperation(c, s, CMD_AllocateOperation,
					      saved_alloc.algo,
					      TEE_MODE_ENCRYPT,
					      saved_alloc.obj_size, 0, &op1);

	if (res != TEEC_SUCCESS)
		goto crypto_alloc;

	if (saved_obh.obh2 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey2(c, s, CMD_SetOperationKey2,
						     &op1, &saved_obh.obh1,
						     &saved_obh.obh2);

		if (res != TEEC_SUCCESS)
			goto exit;

	} else if (saved_obh.obh1 != TEE_HANDLE_NULL) {
		res = Invoke_Crypto_SetOperationKey(c, s, CMD_SetOperationKey,
						    &op1, &saved_obh.obh1);

		if (res != TEEC_SUCCESS)
			goto exit;

	}

	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM04, fdata_length,
					TEEC_MEM_INPUT,
					saved_cipher_iv.size,
					saved_cipher_iv.buffer,
					mem04_exit)

	op.params[0].value.a = (uint32_t)op1;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
					      saved_cipher_iv.size)

	op.params[1].memref.offset = 0;
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, CMD_CipherInit, &op, &ret_orig);

	if (res != TEEC_SUCCESS)
		goto mem05_exit;

	TEEC_ReleaseSharedMemory(SHARE_MEM04);

	/* CMD_CipherDoFinal */
	/* Fill SharedMem1 with full_data */
	ALLOCATE_AND_FILL_SHARED_MEMORY(CONTEXT01, SHARE_MEM04, fdata_length,
					TEEC_MEM_INPUT, fdata_length,
					full_data, mem04_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM05, fdata_length,
			       TEEC_MEM_OUTPUT, mem05_exit)

	op.params[0].value.a = (uint32_t)op1;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM04,
					      SHARE_MEM04->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM05,
					      SHARE_MEM05->size)

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_PARTIAL_INPUT,
					 TEEC_NONE, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(s, CMD_CipherDoFinal, &op, &ret_orig);

	if (res == TEEC_SUCCESS) {
		cipher->size = op.params[3].memref.size;
		cipher->buffer = malloc(cipher->size);
		memcpy(cipher->buffer, SHARE_MEM05->buffer, cipher->size);
	}

	TEEC_ReleaseSharedMemory(SHARE_MEM05);
mem05_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM04);
mem04_exit:
exit:
	Invoke_Crypto_FreeOperation(c, s, CMD_FreeOperation, &op1);
crypto_alloc:
	return res;
}

#endif /* XML_CRYPTO_API_H_ */
