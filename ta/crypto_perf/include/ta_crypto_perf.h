/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#ifndef TA_CRYPTO_PERF_H
#define TA_CRYPTO_PERF_H

#define TA_CRYPTO_PERF_UUID { 0x02a42f43, 0xd8b7, 0x4a57, \
	{ 0xaa, 0x4d, 0x87, 0xbd, 0x9b, 0x55, 0x87, 0xcb } }

/*
 * Commands implemented by the TA
 */

#define TA_CRYPTO_PERF_CMD_CIPHER_PREPARE_KEY			0
#define TA_CRYPTO_PERF_CMD_CIPHER_PROCESS			1
#define TA_CRYPTO_PERF_CMD_CIPHER_PROCESS_SDP			2
#define TA_CRYPTO_PERF_CMD_HASH_PREPARE_OP			3
#define TA_CRYPTO_PERF_CMD_HASH_PROCESS				4
#define TA_CRYPTO_PERF_CMD_ASYM_PREPARE_OBJ			5
#define TA_CRYPTO_PERF_CMD_ASYM_PREPARE_HASH			6
#define TA_CRYPTO_PERF_CMD_ASYM_PREPARE_KEYPAIR			7
#define TA_CRYPTO_PERF_CMD_ASYM_PREPARE_ENC_SIGN		8
#define TA_CRYPTO_PERF_CMD_ASYM_PREPARE_ATTRS			9
#define TA_CRYPTO_PERF_CMD_ASYM_PROCESS_GEN_KEYPAIR		10
#define TA_CRYPTO_PERF_CMD_ASYM_PROCESS				11
#define TA_CRYPTO_PERF_CMD_ASYM_FREE_ATTRS			12

/*
 * Supported AES modes of operation
 */

#define TA_AES_ECB	0
#define TA_AES_CBC	1
#define TA_AES_CTR	2
#define TA_AES_XTS	3
#define TA_AES_GCM	4
#define TA_SM4_ECB	5
#define TA_SM4_CBC	6
#define TA_SM4_CTR	7
#define TA_SM4_XTS	8

/*
 * AES key sizes
 */
#define AES_128	128
#define AES_192	192
#define AES_256	256

/*
 * Supported hash algorithms
 */

#define TA_SHA_SHA1	0
#define TA_SHA_SHA224	1
#define TA_SHA_SHA256	2
#define TA_SHA_SHA384	3
#define TA_SHA_SHA512	4
#define TA_SM3		5
#define TA_HMAC_SHA1	6
#define TA_HMAC_SHA224	7
#define TA_HMAC_SHA256	8
#define TA_HMAC_SHA384	9
#define TA_HMAC_SHA512	10
#define TA_HMAC_SM3	11

/*
 * Asymmetric cryptographic algorithms
 */
#define PKCS_V1_5_MIN		11
#define BITS_TO_BYTES(len)	(((len) + 7) / 8)
#define OAEP_HASH_LEN(hsz)	((hsz) * 2)
#define OAEP_OTHER_LEN		2
#define PSS_OTHER_LEN		2

#define DERCODE_SHA1_LEN 15
#define DERCODE_SHA_LEN 19
#define SHA1_LEN 20
#define SHA224_LEN 28
#define SHA256_LEN 32
#define SHA384_LEN 48
#define SHA512_LEN 64

#define WIDTH_BITS_25519 256

#define ECC_CURVE_192 192
#define ECC_CURVE_224 224
#define ECC_CURVE_256 256
#define ECC_CURVE_384 384
#define ECC_CURVE_521 521

#define TEE_MAX_OUT_SIZE 4096

#define DH_MAX_SIZE 4096
#define DH_G_SIZE 1

enum symm_cipher {
	AES = 0,
	SM4 = 1,
};

enum symm_mode {
	ECB = 0,
	CBC = 1,
	CTR = 2,
	XTS = 3,
	GCM = 4,
};

enum asym_algorithm {
	ALGO_DH = 1,
	ALGO_RSA = 2,
	ALGO_ECDSA = 3,
	ALGO_ECDH = 4,
	ALGO_X25519 = 5,
	ALGO_SM2 = 6,
};

enum asym_cipher_mode {
	MODE_ENCRYPT = 0,
	MODE_DECRYPT = 1,
	MODE_SIGN = 2,
	MODE_VERIFY = 3,
	MODE_GENKEYPAIR = 4,
};

enum rsa_mode {
	RSA_NOPAD = 0,
	RSAES_PKCS1_V1_5 = 1,
	RSAES_PKCS1_OAEP_SHA1 = 2,
	RSAES_PKCS1_OAEP_SHA224 = 3,
	RSAES_PKCS1_OAEP_SHA256 = 4,
	RSAES_PKCS1_OAEP_SHA384 = 5,
	RSAES_PKCS1_OAEP_SHA512 = 6,
	RSASSA_PKCS1_V1_5_SHA1 = 7,
	RSASSA_PKCS1_V1_5_SHA224 = 8,
	RSASSA_PKCS1_V1_5_SHA256 = 9,
	RSASSA_PKCS1_V1_5_SHA384 = 10,
	RSASSA_PKCS1_V1_5_SHA512 = 11,
	RSASSA_PKCS1_PSS_MGF1_SHA1 = 12,
	RSASSA_PKCS1_PSS_MGF1_SHA224 = 13,
	RSASSA_PKCS1_PSS_MGF1_SHA256 = 14,
	RSASSA_PKCS1_PSS_MGF1_SHA384 = 15,
	RSASSA_PKCS1_PSS_MGF1_SHA512 = 16,
};

#endif /* TA_CRYPTO_PERF_H */
