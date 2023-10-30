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

/*
 * Supported AES modes of operation
 */

#define TA_AES_ECB	0
#define TA_AES_CBC	1
#define TA_AES_CTR	2
#define TA_AES_XTS	3
#define TA_AES_GCM	4

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

#endif /* TA_CRYPTO_PERF_H */
