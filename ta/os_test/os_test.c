/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdint.h>
#include <setjmp.h>

#include <compiler.h>
#include <ta_crypt.h>
#include <ta_os_test.h>
#include <tee_internal_api_extensions.h>

#include "os_test.h"
#include "testframework.h"
#include "test_float_subj.h"

enum p_type {
	P_TYPE_BOOL,
	P_TYPE_INT,
	P_TYPE_UUID,
	P_TYPE_IDENTITY,
	P_TYPE_STRING,
	P_TYPE_BINARY_BLOCK,
};

struct p_attr {
	const char *str;
	enum p_type type;
	bool retrieved;
};

static TEE_Result check_returned_prop(
		int line __maybe_unused, char *prop_name __maybe_unused,
		TEE_Result return_res, TEE_Result expected_res,
		uint32_t return_len, uint32_t expected_len)
{
	if (return_res != expected_res) {
		EMSG("From line %d (property name=%s): return_res=0x%x  vs  expected_res=0x%x",
		     line, (prop_name ? prop_name : "unknown"),
		     (unsigned int)return_res, (unsigned int)expected_res);
		return TEE_ERROR_GENERIC;
	}
	if (return_len != expected_len) {
		EMSG("From line %d (property name=%s): return_len=%u  vs  expected_res=%u",
		     line, (prop_name ? prop_name : "unknown"),
		     return_len, expected_len);
		return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}

static TEE_Result print_properties(TEE_PropSetHandle h,
				   TEE_PropSetHandle prop_set,
				   struct p_attr *p_attrs, size_t num_p_attrs)
{
TEE_Result res;
size_t n;

TEE_StartPropertyEnumerator(h, prop_set);

while (true) {
	char nbuf[256];
	char nbuf_small[256];
	char vbuf[256];
	char vbuf2[256];
	uint32_t nblen = sizeof(nbuf);
	uint32_t nblen_small;
	uint32_t vblen = sizeof(vbuf);
	uint32_t vblen2 = sizeof(vbuf2);

	res = TEE_GetPropertyName(h, nbuf, &nblen);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_GetPropertyName returned 0x%x\n",
		     (unsigned int)res);
		return res;
	}
	if (nblen != strlen(nbuf) + 1) {
		EMSG("Name has wrong size: %u vs %zu", nblen, strlen(nbuf) + 1);
		return TEE_ERROR_GENERIC;
	}


	/* Get the property name with a very small buffer */
	nblen_small = 2;
	res = TEE_GetPropertyName(h, nbuf_small, &nblen_small);
	res = check_returned_prop(__LINE__, nbuf, res, TEE_ERROR_SHORT_BUFFER,
				  nblen_small, nblen);
	if (res != TEE_SUCCESS)
		return res;

	/* Get the property name with almost the correct buffer */
	nblen_small = nblen - 1;
	res = TEE_GetPropertyName(h, nbuf_small, &nblen_small);
	res = check_returned_prop(__LINE__, nbuf, res, TEE_ERROR_SHORT_BUFFER,
				  nblen_small, nblen);
	if (res != TEE_SUCCESS)
		return res;

	/* Get the property name with the exact buffer length */
	nblen_small = nblen;
	res = TEE_GetPropertyName(h, nbuf_small, &nblen_small);
	res = check_returned_prop(__LINE__, nbuf, res, TEE_SUCCESS,
				  nblen_small, nblen);
	if (res != TEE_SUCCESS)
		return res;

	/* Get the property value */
	res = TEE_GetPropertyAsString(h, NULL, vbuf, &vblen);
	res = check_returned_prop(__LINE__, nbuf, res, TEE_SUCCESS,
				  vblen, strlen(vbuf) + 1);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GetPropertyAsString(prop_set, nbuf, vbuf2, &vblen2);
	res = check_returned_prop(__LINE__, nbuf, res, TEE_SUCCESS,
				  vblen2, strlen(vbuf2) + 1);
	if (res != TEE_SUCCESS)
		return res;

	if (my_strcmp(vbuf, vbuf2) != 0) {
		EMSG("String of \"%s\" differs\n", nbuf);
		return TEE_ERROR_GENERIC;
	}

	/* Get the property with a very small buffer */
	vblen2 = 1;
	res = TEE_GetPropertyAsString(prop_set, nbuf, vbuf2, &vblen2);
	res = check_returned_prop(__LINE__, nbuf, res, TEE_ERROR_SHORT_BUFFER,
				  vblen2, vblen);
	if (res != TEE_SUCCESS)
		return res;

	/* Get the property with almost the correct buffer */
	vblen2 = vblen - 1;
	res = TEE_GetPropertyAsString(prop_set, nbuf, vbuf2, &vblen2);
	res = check_returned_prop(__LINE__, nbuf, res, TEE_ERROR_SHORT_BUFFER,
				  vblen2, vblen);
	if (res != TEE_SUCCESS)
		return res;

	/* Get the property name with the exact buffer length */
	vblen2 = vblen;
	res = TEE_GetPropertyAsString(prop_set, nbuf, vbuf2, &vblen2);
	res = check_returned_prop(__LINE__, nbuf, res, TEE_SUCCESS, vblen2, vblen);
	if (res != TEE_SUCCESS)
		return res;

	/* check specific myprop.hello property, which is larger than 80 */
	if (!strcmp("myprop.hello", nbuf) &&
	    vblen2 != 1 + strlen("hello property, larger than 80 characters, so that it checks that it is not truncated by anything in the source code which may be wrong")) {
		EMSG("TEE_GetPropertyAsString(\"%s\") is truncated - returned \"%s\"\n",
		     nbuf, vbuf);
		return TEE_ERROR_GENERIC;
	}

	DMSG("Found \"%s\" value \"%s\"\n", nbuf, vbuf);

	for (n = 0; n < num_p_attrs; n++) {
		if (my_strcmp(nbuf, p_attrs[n].str) != 0)
			continue;

		if (p_attrs[n].retrieved) {
			EMSG("Value \"%s\" already retrieved\n",
			     p_attrs[n].str);
			return TEE_ERROR_GENERIC;
		}
		p_attrs[n].retrieved = true;

		switch (p_attrs[n].type) {
		case P_TYPE_BOOL:
			{
				bool v;

				res =
				    TEE_GetPropertyAsBool(h, NULL, &v);
				if (res != TEE_SUCCESS) {
					EMSG(
					"TEE_GetPropertyAsBool(\"%s\") returned 0x%x\n",
					nbuf, (unsigned int)res);
					return res;
				}
			}
			break;

		case P_TYPE_INT:
			{
				uint32_t v;

				res = TEE_GetPropertyAsU32(h, NULL, &v);
				if (res != TEE_SUCCESS) {
					EMSG(
					"TEE_GetPropertyAsU32(\"%s\") returned 0x%x\n",
					nbuf, (unsigned int)res);
					return res;
				}
			}
			break;

		case P_TYPE_UUID:
			{
				TEE_UUID v;

				res =
				    TEE_GetPropertyAsUUID(h, NULL, &v);
				if (res != TEE_SUCCESS) {
					EMSG(
					"TEE_GetPropertyAsUUID(\"%s\") returned 0x%x\n",
					nbuf, (unsigned int)res);
					return res;
				}
			}
			break;

		case P_TYPE_IDENTITY:
			{
				TEE_Identity v;

				res =
				    TEE_GetPropertyAsIdentity(h, NULL,
							      &v);
				if (res != TEE_SUCCESS) {
					EMSG(
					"TEE_GetPropertyAsIdentity(\"%s\") returned 0x%x\n",
					nbuf, (unsigned int)res);
					return res;
				}
			}
			break;

		case P_TYPE_STRING:
			/* Already read as string */
			break;

		case P_TYPE_BINARY_BLOCK:
			{
				char bbuf[80];
				uint32_t bblen = sizeof(bbuf);

				res =
				    TEE_GetPropertyAsBinaryBlock(h,
								 NULL,
								 bbuf,
								 &bblen);
				if (res != TEE_SUCCESS) {
					EMSG(
					"TEE_GetPropertyAsBinaryBlock(\"%s\") returned 0x%x\n",
					nbuf, (unsigned int)res);
					return res;
				}
				if (my_strcmp
				    ("myprop.binaryblock", nbuf) == 0) {
					const char exp_bin_value[] =
					    "Hello world!";

					if (bblen !=
					    my_strlen(exp_bin_value)
					    ||
					    TEE_MemCompare
					    (exp_bin_value, bbuf,
					     bblen) != 0) {
						EMSG(
						"Binary buffer of \"%s\" differs from \"%s\"\n",
							nbuf, exp_bin_value);
						EMSG(
						"Got \"%s\"\n",
						     bbuf);
						return
						    TEE_ERROR_GENERIC;
					}
				}

			}
			break;

		default:
			EMSG("Unknown type (%d) for \"%s\"\n",
			     p_attrs[n].type, p_attrs[n].str);
			return TEE_ERROR_GENERIC;
		}
	}

	res = TEE_GetNextProperty(h);
	if (res != TEE_SUCCESS) {
		if (res == TEE_ERROR_ITEM_NOT_FOUND)
			return TEE_SUCCESS;
		return res;
	}
}
}

static TEE_Result test_malloc(void)
{
	void *p = TEE_Malloc(4, 0);

	if (p == NULL) {
		EMSG("TEE_Malloc failed\n");
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_Free(p);
	TEE_Free(NULL);

	return TEE_SUCCESS;
}

static TEE_Result test_properties(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	TEE_PropSetHandle h;
	struct p_attr p_attrs[] = {
		{"gpd.ta.appID", P_TYPE_UUID},
		{"gpd.ta.singleInstance", P_TYPE_BOOL},
		{"gpd.ta.multiSession", P_TYPE_BOOL},
		{"gpd.ta.instanceKeepAlive", P_TYPE_BOOL},
		{"gpd.ta.dataSize", P_TYPE_INT},
		{"gpd.ta.stackSize", P_TYPE_INT},
		{"gpd.ta.version", P_TYPE_STRING},
		{"gpd.ta.description", P_TYPE_STRING},
		{"gpd.client.identity", P_TYPE_IDENTITY},
		{"gpd.tee.apiversion", P_TYPE_STRING},
		{"gpd.tee.description", P_TYPE_STRING},
		{"gpd.tee.deviceID", P_TYPE_UUID},
		{"gpd.tee.systemTime.protectionLevel", P_TYPE_INT},
		{"gpd.tee.TAPersistentTime.protectionLevel", P_TYPE_INT},
		{"gpd.tee.arith.maxBigIntSize", P_TYPE_INT},
		{"gpd.tee.cryptography.ecc", P_TYPE_BOOL},
		{"gpd.tee.trustedStorage.antiRollback.protectionLevel", P_TYPE_INT},
		{"gpd.tee.trustedos.implementation.version", P_TYPE_STRING},
		{"gpd.tee.trustedos.implementation.binaryversion", P_TYPE_INT},
		{"gpd.tee.trustedos.manufacturer", P_TYPE_STRING},
		{"gpd.tee.firmware.implementation.version", P_TYPE_STRING},
		{"gpd.tee.firmware.implementation.binaryversion", P_TYPE_INT},
		{"gpd.tee.firmware.manufacturer", P_TYPE_STRING},
		{"myprop.true", P_TYPE_BOOL},
		{"myprop.42", P_TYPE_INT},
		{"myprop.123", P_TYPE_UUID},
		{"myprop.1234", P_TYPE_IDENTITY},
		{"myprop.hello", P_TYPE_STRING},
		{"myprop.binaryblock", P_TYPE_BINARY_BLOCK},
	};
	const size_t num_p_attrs = sizeof(p_attrs) / sizeof(p_attrs[0]);
	size_t n;

	res = TEE_AllocatePropertyEnumerator(&h);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_AllocatePropertyEnumerator: returned 0x%x\n",
		     (unsigned int)res);
		return TEE_ERROR_GENERIC;
	}

	printf("Getting properties for current TA\n");
	res = print_properties(h, TEE_PROPSET_CURRENT_TA, p_attrs, num_p_attrs);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	printf("Getting properties for current client\n");
	res = print_properties(h, TEE_PROPSET_CURRENT_CLIENT, p_attrs,
			       num_p_attrs);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	printf("Getting properties for implementation\n");
	res = print_properties(h, TEE_PROPSET_TEE_IMPLEMENTATION, p_attrs,
			       num_p_attrs);
	if (res != TEE_SUCCESS)
		goto cleanup_return;

	for (n = 0; n < num_p_attrs; n++) {
		if (!p_attrs[n].retrieved) {
			EMSG("\"%s\" not retrieved\n", p_attrs[n].str);
			res = TEE_ERROR_GENERIC;
			goto cleanup_return;
		}
	}

cleanup_return:
	TEE_FreePropertyEnumerator(h);
	return res;
}

static TEE_Result test_mem_access_right(uint32_t param_types,
					TEE_Param params[4])
{
	static const TEE_UUID test_uuid = TA_OS_TEST_UUID;
	TEE_Result res;
	uint32_t ret_orig;
	uint32_t l_pts;
	TEE_Param l_params[4] = { { {0} } };
	uint8_t buf[32];
	TEE_TASessionHandle sess = TEE_HANDLE_NULL;

	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, 0, 0, 0))
		return TEE_ERROR_GENERIC;
	res =
	    TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					params[0].memref.buffer,
					params[0].memref.size);
	if (res != TEE_SUCCESS)
		return res;
	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ,
					  params[0].memref.buffer,
					  params[0].memref.size);
	if (res != TEE_ERROR_ACCESS_DENIED)
		return TEE_ERROR_GENERIC;

	res = TEE_OpenTASession(&test_uuid, 0, 0, NULL, &sess, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("test_mem_access_right: TEE_OpenTASession failed\n");
		goto cleanup_return;
	}

	l_pts = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, 0, 0, 0);
	l_params[0].memref.buffer = buf;
	l_params[0].memref.size = sizeof(buf);
	res = TEE_InvokeTACommand(sess, 0, TA_OS_TEST_CMD_PRIVATE_PARAMS,
				  l_pts, l_params, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("test_mem_access_right: TEE_InvokeTACommand failed\n");
		goto cleanup_return;
	}

cleanup_return:
	TEE_CloseTASession(sess);
	return res;
}

static TEE_Result test_time(void)
{
	TEE_Result res;
	TEE_Time t;
	TEE_Time sys_t;

	static const TEE_Time null_time = { 0, 0 };
	static const TEE_Time wrap_time = { UINT32_MAX, 999 };

	TEE_GetSystemTime(&sys_t);
	printf("system time %u.%03u\n", (unsigned int)sys_t.seconds,
	       (unsigned int)sys_t.millis);

	TEE_GetREETime(&t);
	printf("REE time %u.%03u\n", (unsigned int)t.seconds,
	       (unsigned int)t.millis);

	res = TEE_GetTAPersistentTime(&t);
	switch (res) {
	case TEE_SUCCESS:
		printf("Stored TA time %u.%03u\n", (unsigned int)t.seconds,
		       (unsigned int)t.millis);
		break;
	case TEE_ERROR_OVERFLOW:
		EMSG("Stored TA time overflowed %u.%03u\n",
		     (unsigned int)t.seconds, (unsigned int)t.millis);
		break;
	case TEE_ERROR_TIME_NOT_SET:
		EMSG("TA time not stored\n");
		break;
	case TEE_ERROR_TIME_NEEDS_RESET:
		EMSG("TA time needs reset\n");
		break;
	default:
		return res;
	}

	res = TEE_SetTAPersistentTime(&null_time);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetTAPersistentTime: failed\n");
		return res;
	}

	res = TEE_GetTAPersistentTime(&t);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_GetTAPersistentTime null: failed\n");
		return res;
	}
	printf("TA time %u.%03u\n", (unsigned int)t.seconds,
	       (unsigned int)t.millis);
	/*
	 * The time between TEE_SetTAPersistentTime() and
	 * TEE_GetTAPersistentTime() should be much less than 1 second, in fact
	 * it's not even a millisecond.
	 */
	if (t.seconds > 1 || t.millis >= 1000) {
		EMSG("Unexpected stored TA time %u.%03u\n",
		     (unsigned int)t.seconds, (unsigned int)t.millis);
		return TEE_ERROR_BAD_STATE;
	}

	res = TEE_SetTAPersistentTime(&wrap_time);
	if (res != TEE_SUCCESS) {
		EMSG("TEE_SetTAPersistentTime wrap: failed\n");
		return res;
	}

	res = TEE_Wait(1000);
	if (res != TEE_SUCCESS)
		EMSG("TEE_Wait wrap: failed\n");

	res = TEE_GetTAPersistentTime(&t);
	if (res != TEE_ERROR_OVERFLOW) {
		EMSG("TEE_GetTAPersistentTime: failed\n");
		return TEE_ERROR_BAD_STATE;
	}
	printf("TA time %u.%03u\n", (unsigned int)t.seconds,
	       (unsigned int)t.millis);

	if (t.seconds > sys_t.seconds) {
		EMSG("Unexpected wrapped time %u.%03u (sys_t %u.%03u)\n",
		     (unsigned int)t.seconds, (unsigned int)t.millis,
		     (unsigned int)sys_t.seconds, (unsigned int)sys_t.millis);
		return TEE_ERROR_BAD_STATE;
	}

	return TEE_SUCCESS;
}

#ifdef CFG_TA_FLOAT_SUPPORT
static bool my_dcmpeq(double v1, double v2, double prec)
{
	return v1 > (v2 - prec) && v1 < (v2 + prec);
}

static bool my_fcmpeq(float v1, float v2, float prec)
{
	return v1 > (v2 - prec) && v1 < (v2 + prec);
}


static TEE_Result test_float(void)
{
#define VAL1		2.6
#define VAL1_INT	2
#define VAL2		5.3
#define DPREC		0.000000000000001
#define FPREC		0.000001
#define EXPECT(expr) do { \
		if (!(expr)) { \
			EMSG("Expression %s failed", #expr); \
			return TEE_ERROR_GENERIC; \
		} \
	} while (0)

	IMSG("Testing floating point operations");

	EXPECT(my_dcmpeq(test_float_dadd(VAL1, VAL2), VAL1 + VAL2, DPREC));
	EXPECT(my_dcmpeq(test_float_ddiv(VAL1, VAL2), VAL1 / VAL2, DPREC));
	EXPECT(my_dcmpeq(test_float_dmul(VAL1, VAL2), VAL1 * VAL2, DPREC));
	EXPECT(my_dcmpeq(test_float_drsub(VAL1, VAL2), VAL2 - VAL1, DPREC));
	EXPECT(my_dcmpeq(test_float_dsub(VAL1, VAL2), VAL1 - VAL2, DPREC));

	EXPECT(test_float_dcmpeq(VAL1, VAL1) == 1);
	EXPECT(test_float_dcmplt(VAL1, VAL2) == 1);
	EXPECT(test_float_dcmple(VAL1, VAL1) == 1);
	EXPECT(test_float_dcmpge(VAL1, VAL1) == 1);
	EXPECT(test_float_dcmpgt(VAL2, VAL1) == 1);

	EXPECT(my_fcmpeq(test_float_fadd(VAL1, VAL2), VAL1 + VAL2, FPREC));
	EXPECT(my_fcmpeq(test_float_fdiv(VAL1, VAL2), VAL1 / VAL2, FPREC));
	EXPECT(my_fcmpeq(test_float_fmul(VAL1, VAL2), VAL1 * VAL2, FPREC));
	EXPECT(my_fcmpeq(test_float_frsub(VAL1, VAL2), VAL2 - VAL1, FPREC));
	EXPECT(my_fcmpeq(test_float_fsub(VAL1, VAL2), VAL1 - VAL2, FPREC));

	EXPECT(test_float_fcmpeq(VAL1, VAL1) == 1);
	EXPECT(test_float_fcmplt(VAL1, VAL2) == 1);
	EXPECT(test_float_fcmple(VAL1, VAL1) == 1);
	EXPECT(test_float_fcmpge(VAL1, VAL1) == 1);
	EXPECT(test_float_fcmpgt(VAL2, VAL1) == 1);

	EXPECT(test_float_d2iz(VAL1) == VAL1_INT);
	EXPECT(test_float_d2uiz(VAL1) == VAL1_INT);
	EXPECT(test_float_d2lz(VAL1) == VAL1_INT);
	EXPECT(test_float_d2ulz(VAL1) == VAL1_INT);

	EXPECT(test_float_f2iz(VAL1) == VAL1_INT);
	EXPECT(test_float_f2uiz(VAL1) == VAL1_INT);
	EXPECT(test_float_f2lz(VAL1) == VAL1_INT);
	EXPECT(test_float_f2ulz(VAL1) == VAL1_INT);

	EXPECT(my_fcmpeq(test_float_d2f(VAL1), VAL1, FPREC));
	EXPECT(my_dcmpeq(test_float_f2d(VAL1), VAL1, FPREC));

	EXPECT(my_dcmpeq(test_float_i2d(VAL1_INT), VAL1_INT, DPREC));
	EXPECT(my_dcmpeq(test_float_ui2d(VAL1_INT), VAL1_INT, DPREC));
	EXPECT(my_dcmpeq(test_float_l2d(VAL1_INT), VAL1_INT, DPREC));
	EXPECT(my_dcmpeq(test_float_ul2d(VAL1_INT), VAL1_INT, DPREC));

	EXPECT(my_fcmpeq(test_float_i2f(VAL1_INT), VAL1_INT, FPREC));
	EXPECT(my_fcmpeq(test_float_ui2f(VAL1_INT), VAL1_INT, FPREC));
	EXPECT(my_fcmpeq(test_float_l2f(VAL1_INT), VAL1_INT, FPREC));
	EXPECT(my_fcmpeq(test_float_ul2f(VAL1_INT), VAL1_INT, FPREC));
	return TEE_SUCCESS;
}
#else /*CFG_TA_FLOAT_SUPPORT*/
static TEE_Result test_float(void)
{
	IMSG("Floating point disabled");
	return TEE_SUCCESS;
}
#endif /*CFG_TA_FLOAT_SUPPORT*/

static __noinline void call_longjmp(jmp_buf env)
{
	DMSG("Calling longjmp");
	longjmp(env, 1);
	EMSG("error: longjmp returned to calling function");
}

static TEE_Result test_setjmp(void)
{
	jmp_buf env;

	if (setjmp(env)) {
		IMSG("Returned via longjmp");
		return TEE_SUCCESS;
	} else {
		call_longjmp(env);
		return TEE_ERROR_GENERIC;
	}
}

TEE_Result ta_entry_basic(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_ERROR_GENERIC;

	printf("ta_entry_basic: enter\n");

	res = test_malloc();
	if (res != TEE_SUCCESS)
		return res;

	res = test_properties();
	if (res != TEE_SUCCESS)
		return res;

	res = test_mem_access_right(param_types, params);
	if (res != TEE_SUCCESS)
		return res;

	res = test_time();
	if (res != TEE_SUCCESS)
		return res;

	res = test_float();
	if (res != TEE_SUCCESS)
		return res;

	res = test_setjmp();
	if (res != TEE_SUCCESS)
		return res;

	/* mpa lib test bench, panics TA on failure */
	tb_main();

	return TEE_SUCCESS;
}

TEE_Result ta_entry_panic(uint32_t param_types, TEE_Param params[4])
{
	volatile bool mytrue = true;
	(void)param_types;
	(void)params;

	printf("ta_entry_panic: enter\n");
	/*
	 * Somewhat clumsy way of avoiding compile errors if TEE_Panic() has
	 * the __noreturn attribute.
	 */
	if (mytrue)
		TEE_Panic(0xbeef);

	/*
	 * Should not be reached, but if it is the testsuite can detect that
	 * TEE_Panic() returned instead of panicking the TA.
	 */
	return TEE_SUCCESS;
}

TEE_Result ta_entry_client_with_timeout(uint32_t param_types,
					TEE_Param params[4])
{
	static const TEE_UUID os_test_uuid = TA_OS_TEST_UUID;
	TEE_Result res;
	TEE_TASessionHandle sess;
	uint32_t ret_orig;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE,
					   TEE_PARAM_TYPE_NONE)) {
		EMSG("ta_entry_client_with_timeout: bad parameters\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	res = TEE_OpenTASession(&os_test_uuid, 0, 0, NULL, &sess, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG(
		"ta_entry_client_with_timeout: TEE_OpenTASession failed\n");
		return res;
	}

	res =
	    TEE_InvokeTACommand(sess, params[0].value.a / 2,
				TA_OS_TEST_CMD_WAIT, param_types, params,
				&ret_orig);

	if (ret_orig != TEE_ORIGIN_TRUSTED_APP || res != TEE_ERROR_CANCEL) {
		EMSG("ta_entry_client_with_timeout: TEE_InvokeTACommand: "
		     "res 0x%x ret_orig 0x%x\n", (unsigned int)res,
		     (unsigned int)ret_orig);
		res = TEE_ERROR_GENERIC;
	} else
		res = TEE_SUCCESS;

	TEE_CloseTASession(sess);
	return res;

}

TEE_Result ta_entry_client(uint32_t param_types, TEE_Param params[4])
{
	static const TEE_UUID crypt_uuid = TA_CRYPT_UUID;
	TEE_Result res;
	uint32_t l_pts;
	TEE_Param l_params[4] = { { {0} } };
	TEE_TASessionHandle sess;
	uint32_t ret_orig;
	static const uint8_t sha256_in[] = { 'a', 'b', 'c' };
	static const uint8_t sha256_out[] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
	};
	uint8_t out[32] = { 0 };
	void *in = NULL;

	(void)param_types;
	(void)params;

	printf("ta_entry_client: enter\n");

	in = TEE_Malloc(sizeof(sha256_in), 0);
	if (in == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(in, sha256_in, sizeof(sha256_in));

	res = TEE_OpenTASession(&crypt_uuid, 0, 0, NULL, &sess, &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("ta_entry_client: TEE_OpenTASession failed\n");
		goto cleanup_return;
	}

	l_pts = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT, 0, 0);
	l_params[0].memref.buffer = in;
	l_params[0].memref.size = sizeof(sha256_in);
	l_params[1].memref.buffer = out;
	l_params[1].memref.size = sizeof(out);

	res = TEE_InvokeTACommand(sess, 0, TA_CRYPT_CMD_SHA256, l_pts, l_params,
				  &ret_orig);
	if (res != TEE_SUCCESS) {
		EMSG("ta_entry_client: TEE_InvokeTACommand failed\n");
		goto cleanup_return;
	}

	if (TEE_MemCompare(sha256_out, out, sizeof(sha256_out)) != 0) {
		EMSG("ta_entry_client: out parameter failed\n");
		res = TEE_ERROR_GENERIC;
		goto cleanup_return;
	}

cleanup_return:
	TEE_Free(in);
	TEE_CloseTASession(sess);
	return res;
}

TEE_Result ta_entry_private_params(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;

	if (param_types !=
	    TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, 0, 0, 0))
		return TEE_ERROR_GENERIC;
	res =
	    TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ |
					TEE_MEMORY_ACCESS_ANY_OWNER,
					params[0].memref.buffer,
					params[0].memref.size);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ,
					  params[0].memref.buffer,
					  params[0].memref.size);

	return res;
}

TEE_Result ta_entry_wait(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	(void)param_types;

	printf("ta_entry_wait: waiting %d\n", (unsigned int)params[0].value.a);
	/* Wait */
	res = TEE_Wait(params[0].value.a);

	return res;
}

static void undef_instr(void)
{
#if defined(ARM64)
	__asm__(".word 0x0");
#elif defined(ARM32)
	__asm__(".word 0xe7ffffff");
#else
#error "Unsupported architecture"
#endif
}

TEE_Result ta_entry_bad_mem_access(uint32_t param_types, TEE_Param params[4])
{
	long stack;
	long stack_addr = (long)&stack;

	if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, 0, 0, 0))
		return TEE_ERROR_GENERIC;

	switch (params[0].value.a) {
	case 1:
		*((uint32_t *) 0) = 0;
		break;
	case 2:
		*((uint32_t *)(stack_addr + 0x40000000)) = 0;
		break;
	case 3:
		((void (*)(void))0) ();
		break;
	case 4:
		((void (*)(void))(stack_addr + 0x40000000)) ();
		break;
	case 5:
		undef_instr();
		break;
	default:
		break;
	}

	return TEE_SUCCESS;
}
