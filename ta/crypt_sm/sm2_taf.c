// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd
 */

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <sm2.h>
#include <stdint.h>
#include <string.h>
#include <tee_api.h>
#include <trace.h>

#include "sm2_taf.h"

/*
 * https://tools.ietf.org/html/draft-shen-sm2-ecdsa-02
 * Appendix D. Recommended Parameters
 */
static const char *sm2_rec_p[] = {
	/* p */
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
	/* a */
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
	/* b */
	"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
	/* n */
	"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
	/* G_x */
	"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
	/* G_y */
	"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
};

enum {
	PARAM_p = 0,
	PARAM_a,
	PARAM_b,
	PARAM_n,
	PARAM_G_x,
	PARAM_G_y
};

uint8_t msg1[] = "HELLOWORLD";
uint8_t ID_A[] = "192.168.0.1";

TEE_Result ta_entry_sm2(uint32_t param_types, TEE_Param params[4])
{
	int res = 0;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ecp_group ecp_g;   /* parameter */
	mbedtls_ecp_keypair ecp_k; /* key */
	struct sm2_sign_ctx ctx = { };

	(void)params;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE)) {
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Random number generator is only used to generate a key */
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL,
			      0);

	mbedtls_ecp_group_init(&ecp_g);
	mbedtls_ecp_keypair_init(&ecp_k);

	/* Initialize curve parameters */
	res = mbedtls_mpi_read_string(&ecp_g.P, 16, sm2_rec_p[PARAM_p]);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_read_string(&ecp_g.A, 16, sm2_rec_p[PARAM_a]);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_read_string(&ecp_g.B, 16, sm2_rec_p[PARAM_b]);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_read_string(&ecp_g.G.X, 16, sm2_rec_p[PARAM_G_x]);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_read_string(&ecp_g.G.Y, 16, sm2_rec_p[PARAM_G_y]);
	if (res)
		goto cleanup;
	res = mbedtls_mpi_read_string(&ecp_g.G.Z, 16, "1");
	if (res)
		goto cleanup;
	res = mbedtls_mpi_read_string(&ecp_g.N, 16, sm2_rec_p[PARAM_n]);
	if (res)
		goto cleanup;
	ecp_g.nbits = mbedtls_mpi_bitlen(&ecp_g.N);
	ecp_g.pbits = mbedtls_mpi_bitlen(&ecp_g.P);

	/* Verify curve */
	res = mbedtls_ecp_check_pubkey(&ecp_g, &ecp_g.G);
	if (res)
		goto cleanup;

	/* Generate a key */
	res = mbedtls_ecp_gen_keypair_base(&ecp_g, &ecp_g.G, &ecp_k.d, &ecp_k.Q,
					   mbedtls_ctr_drbg_random, &ctr_drbg);
	ctx.key_pair = &ecp_k;

	/* Set message to sign and associated data */
	ctx.message = msg1;
	ctx.message_size = sizeof(msg1) - 1;
	ctx.ID = ID_A;
	ctx.ENTL = sizeof(ID_A);

	/* Sign and verify */
	res = sm2_sign(&ecp_g, &ctx);
	if (res) {
		DMSG("SM2: sign error");
		goto cleanup;
	}
	res = sm2_verify(&ecp_g, &ctx);
	if (res)
		DMSG("SM2: verify error");

cleanup:
	mbedtls_ecp_group_free(&ecp_g);
	mbedtls_ecp_keypair_free(&ecp_k);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return res ? TEE_ERROR_GENERIC : TEE_SUCCESS;
}
