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

#ifndef XTEST_TEST_H
#define XTEST_TEST_H
#include <adbg.h>
#include <tee_client_api.h>

/*ADBG Cases declaration.*/
ADBG_CASE_DECLARE(XTEST_TEE_1001);
ADBG_CASE_DECLARE(XTEST_TEE_1004);
ADBG_CASE_DECLARE(XTEST_TEE_1005);
ADBG_CASE_DECLARE(XTEST_TEE_1006);
ADBG_CASE_DECLARE(XTEST_TEE_1007);
ADBG_CASE_DECLARE(XTEST_TEE_1008);
ADBG_CASE_DECLARE(XTEST_TEE_1009);
ADBG_CASE_DECLARE(XTEST_TEE_1010);
ADBG_CASE_DECLARE(XTEST_TEE_1011);
ADBG_CASE_DECLARE(XTEST_TEE_1012);
ADBG_CASE_DECLARE(XTEST_TEE_1013);

ADBG_CASE_DECLARE(XTEST_TEE_2001);
ADBG_CASE_DECLARE(XTEST_TEE_2002);

ADBG_CASE_DECLARE(XTEST_TEE_4001);
ADBG_CASE_DECLARE(XTEST_TEE_4002);
ADBG_CASE_DECLARE(XTEST_TEE_4003_NO_XTS);
ADBG_CASE_DECLARE(XTEST_TEE_4003_XTS);
ADBG_CASE_DECLARE(XTEST_TEE_4004);
ADBG_CASE_DECLARE(XTEST_TEE_4005);
ADBG_CASE_DECLARE(XTEST_TEE_4006);
ADBG_CASE_DECLARE(XTEST_TEE_4007);
ADBG_CASE_DECLARE(XTEST_TEE_4008);
ADBG_CASE_DECLARE(XTEST_TEE_4009);
ADBG_CASE_DECLARE(XTEST_TEE_4010);
ADBG_CASE_DECLARE(XTEST_TEE_4011);

ADBG_CASE_DECLARE(XTEST_TEE_5006);

ADBG_CASE_DECLARE(XTEST_TEE_6001);
ADBG_CASE_DECLARE(XTEST_TEE_6002);
ADBG_CASE_DECLARE(XTEST_TEE_6003);
ADBG_CASE_DECLARE(XTEST_TEE_6004);
ADBG_CASE_DECLARE(XTEST_TEE_6005);
ADBG_CASE_DECLARE(XTEST_TEE_6006);
ADBG_CASE_DECLARE(XTEST_TEE_6007);
ADBG_CASE_DECLARE(XTEST_TEE_6008);
ADBG_CASE_DECLARE(XTEST_TEE_6009);
ADBG_CASE_DECLARE(XTEST_TEE_6010);
#ifdef WITH_GP_TESTS
ADBG_CASE_DECLARE(XTEST_TEE_6011);
#endif
ADBG_CASE_DECLARE(XTEST_TEE_6012);
ADBG_CASE_DECLARE(XTEST_TEE_6013);
ADBG_CASE_DECLARE(XTEST_TEE_6014);
ADBG_CASE_DECLARE(XTEST_TEE_6015);
ADBG_CASE_DECLARE(XTEST_TEE_6016);
ADBG_CASE_DECLARE(XTEST_TEE_7001);
ADBG_CASE_DECLARE(XTEST_TEE_7002);
ADBG_CASE_DECLARE(XTEST_TEE_7003);
ADBG_CASE_DECLARE(XTEST_TEE_7004);
ADBG_CASE_DECLARE(XTEST_TEE_7005);
ADBG_CASE_DECLARE(XTEST_TEE_7006);
ADBG_CASE_DECLARE(XTEST_TEE_7007);
ADBG_CASE_DECLARE(XTEST_TEE_7008);
ADBG_CASE_DECLARE(XTEST_TEE_7009);
ADBG_CASE_DECLARE(XTEST_TEE_7010);
ADBG_CASE_DECLARE(XTEST_TEE_7013);
ADBG_CASE_DECLARE(XTEST_TEE_7016);
ADBG_CASE_DECLARE(XTEST_TEE_7017);
ADBG_CASE_DECLARE(XTEST_TEE_7018);
ADBG_CASE_DECLARE(XTEST_TEE_7019);

ADBG_CASE_DECLARE(XTEST_TEE_10001);
ADBG_CASE_DECLARE(XTEST_TEE_10002);

#if defined(CFG_ENC_FS) && defined(CFG_REE_FS)
ADBG_CASE_DECLARE(XTEST_TEE_20001);
ADBG_CASE_DECLARE(XTEST_TEE_20002);
ADBG_CASE_DECLARE(XTEST_TEE_20003);
ADBG_CASE_DECLARE(XTEST_TEE_20004);
ADBG_CASE_DECLARE(XTEST_TEE_20021);
ADBG_CASE_DECLARE(XTEST_TEE_20022);
ADBG_CASE_DECLARE(XTEST_TEE_20023);

ADBG_CASE_DECLARE(XTEST_TEE_20501);
ADBG_CASE_DECLARE(XTEST_TEE_20502);
ADBG_CASE_DECLARE(XTEST_TEE_20503);
ADBG_CASE_DECLARE(XTEST_TEE_20521);
ADBG_CASE_DECLARE(XTEST_TEE_20522);
ADBG_CASE_DECLARE(XTEST_TEE_20523);
#endif /* defined(CFG_ENC_FS) && !defined(CFG_ENC_FS) */

ADBG_CASE_DECLARE(XTEST_TEE_BENCHMARK_1001);
ADBG_CASE_DECLARE(XTEST_TEE_BENCHMARK_1002);
ADBG_CASE_DECLARE(XTEST_TEE_BENCHMARK_1003);

/* SHA benchmarks */
ADBG_CASE_DECLARE(XTEST_TEE_BENCHMARK_2001);
ADBG_CASE_DECLARE(XTEST_TEE_BENCHMARK_2002);

/* AES benchmarks */
ADBG_CASE_DECLARE(XTEST_TEE_BENCHMARK_2011);
ADBG_CASE_DECLARE(XTEST_TEE_BENCHMARK_2012);

#ifdef WITH_GP_TESTS
#include "adbg_case_declare.h"
ADBG_CASE_DECLARE_AUTO_GENERATED_TESTS()
#endif

/* TEEC_Result */
ADBG_ENUM_TABLE_DECLARE(TEEC_Result);

#define ADBG_EXPECT_TEEC_RESULT(c, exp, got) \
	ADBG_EXPECT_ENUM(c, exp, got, ADBG_EnumTable_TEEC_Result)

#define ADBG_EXPECT_TEEC_SUCCESS(c, got) \
	ADBG_EXPECT_ENUM(c, TEEC_SUCCESS, got, ADBG_EnumTable_TEEC_Result)

/* TEEC_ErrorOrigin */
ADBG_ENUM_TABLE_DECLARE(TEEC_ErrorOrigin);

#define ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, exp, got) \
	ADBG_EXPECT_ENUM(c, exp, got, ADBG_EnumTable_TEEC_ErrorOrigin)

/* bass_return_code */
ADBG_ENUM_TABLE_DECLARE(bass_return_code);

#define ADBG_EXPECT_BASS_RETURN_CODE(c, exp, got) \
	ADBG_EXPECT_ENUM(c, exp, got, ADBG_EnumTable_bass_return_code)

#define ADBG_EXPECT_BASS_RC_SUCCESS(c, got) \
	ADBG_EXPECT_ENUM(c, BASS_RC_SUCCESS, got, \
			 ADBG_EnumTable_bass_return_code)


extern const char crypt_user_ta[];
extern const unsigned int crypt_user_ta_size;

extern const char os_test_ta[];
extern const unsigned int os_test_ta_size;

extern const char create_fail_test_ta[];
extern const unsigned int create_fail_test_ta_size;

extern const char rpc_test_ta[];
extern const unsigned int rpc_test_ta_size;

extern const char sims_test_ta[];
extern const unsigned int sims_test_ta_size;

extern const char gp_tta_testing_client_api_ta[];
extern const unsigned int gp_tta_testing_client_api_ta_size;

extern const char gp_tta_answer_success_to_open_session_invoke_ta[];
extern const unsigned int gp_tta_answer_success_to_open_session_invoke_ta_size;

extern const char gp_tta_answer_error_to_invoke_ta[];
extern const unsigned int gp_tta_answer_error_to_invoke_ta_size;

extern const char gp_tta_answer_error_to_open_session_ta[];
extern const unsigned int gp_tta_answer_error_to_open_session_ta_size;

extern const char gp_tta_check_open_session_with_4_parameters_ta[];
extern const unsigned int gp_tta_check_open_session_with_4_parameters_ta_size;

extern const char gp_tta_ds_ta[];
extern const unsigned int gp_tta_ds_ta_size;

extern const char storage_ta[];
extern const unsigned int storage_ta_size;

extern const char gp_tta_time_ta[];
extern const unsigned int gp_tta_time_ta_size;

extern const char gp_tta_tcf_ta[];
extern const unsigned int gp_tta_tcf_ta_size;

extern const char gp_tta_crypto_ta[];
extern const unsigned int gp_tta_crypto_ta_size;

extern const char gp_tta_arithm_ta[];
extern const unsigned int gp_tta_arithm_ta_size;

extern const char gp_tta_ica_ta[];
extern const unsigned int gp_tta_ica_ta_size;

extern const char gp_tta_ica2_ta[];
extern const unsigned int gp_tta_ica2_ta_size;

extern const char gp_tta_tcf_singleinstance_ta[];
extern const unsigned int gp_tta_tcf_singleinstance_ta_size;

extern const char gp_tta_tcf_multipleinstance_ta[];
extern const unsigned int gp_tta_tcf_multipleinstance_ta_size;

extern const TEEC_UUID crypt_user_ta_uuid;
extern const TEEC_UUID os_test_ta_uuid;
extern const TEEC_UUID create_fail_test_ta_uuid;
extern const TEEC_UUID rpc_test_ta_uuid;
extern const TEEC_UUID sims_test_ta_uuid;
extern const TEEC_UUID gp_tta_testing_client_api_uuid;
extern const TEEC_UUID gp_tta_answer_success_to_open_session_invoke_uuid;
extern const TEEC_UUID gp_tta_answer_error_to_invoke_uuid;
extern const TEEC_UUID gp_tta_answer_error_to_open_session_uuid;
extern const TEEC_UUID gp_tta_check_OpenSession_with_4_parameters_uuid;
extern const TEEC_UUID gp_tta_ds_uuid;
extern const TEEC_UUID storage_ta_uuid;
extern const TEEC_UUID storage2_ta_uuid;
extern const TEEC_UUID enc_fs_key_manager_test_ta_uuid;
extern const TEEC_UUID ecc_test_ta_uuid;
extern const TEEC_UUID sta_test_ta_uuid;
extern const TEEC_UUID gp_tta_time_uuid;
extern const TEEC_UUID concurrent_ta_uuid;
extern const TEEC_UUID concurrent_large_ta_uuid;
extern const TEEC_UUID storage_benchmark_ta_uuid;
extern char *_device;

#endif /*XTEST_TEST_H*/
