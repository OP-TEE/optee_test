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

#ifndef XTEST_HELPERS_H
#define XTEST_HELPERS_H

#include <stdlib.h>
#include <tee_client_api.h>
#include <tee_api_types.h>
#include <adbg.h>

extern unsigned int level;

struct statistics {
	int n;
	double m;
	double M2;
	double min;
	double max;
	int initialized;
};

/* Global context to use if any context is needed as input to a function */
extern TEEC_Context xtest_teec_ctx;

/*
 * Initializes the context above, should be called before the ADBG test
 * cases are run.
 */
TEEC_Result xtest_teec_ctx_init(void);
void xtest_teec_ctx_deinit(void);

/* Opens a session */
TEEC_Result xtest_teec_open_session(TEEC_Session *session,
				    const TEEC_UUID *uuid, TEEC_Operation *op,
				    uint32_t *ret_orig);

TEEC_Result xtest_teec_open_static_session(TEEC_Session *session,
					   TEEC_Operation *op,
					   uint32_t *ret_orig);

#define TEEC_OPERATION_INITIALIZER { 0 }

/* IO access macro */
#define  IO(addr)  (*((volatile unsigned long *)(addr)))

#define UNUSED(x) (void)(x)
/*
 * Helpers for commands towards the crypt TA
 */
TEEC_Result ta_crypt_cmd_allocate_operation(ADBG_Case_t *c,
			   TEEC_Session *s,
			   TEE_OperationHandle *oph,
			   uint32_t algo,
			   uint32_t mode,
			   uint32_t max_key_size);

TEEC_Result ta_crypt_cmd_allocate_transient_object(ADBG_Case_t *c,
	TEEC_Session *s,
	TEE_ObjectType obj_type, uint32_t max_obj_size,
	TEE_ObjectHandle *o);

TEEC_Result ta_crypt_cmd_populate_transient_object(ADBG_Case_t *c,
	TEEC_Session *s,
	TEE_ObjectHandle o,
	const TEE_Attribute *attrs,
	uint32_t attr_count);

TEE_Result ta_crypt_cmd_set_operation_key(ADBG_Case_t *c,
			 TEEC_Session *s,
			 TEE_OperationHandle oph,
			 TEE_ObjectHandle key);

TEEC_Result ta_crypt_cmd_free_transient_object(ADBG_Case_t *c,
			      TEEC_Session *s,
			      TEE_ObjectHandle o);

TEEC_Result ta_crypt_cmd_derive_key(ADBG_Case_t *c,
					   TEEC_Session *s,
					   TEE_OperationHandle oph,
					   TEE_ObjectHandle o,
					   const TEE_Attribute *params,
					   uint32_t paramCount);

TEEC_Result ta_crypt_cmd_get_object_buffer_attribute(ADBG_Case_t *c,
				    TEEC_Session *s,
				    TEE_ObjectHandle o,
				    uint32_t attr_id,
				    void *buf,
				    size_t *blen);

TEEC_Result ta_crypt_cmd_free_operation(ADBG_Case_t *c,
					       TEEC_Session *s,
					       TEE_OperationHandle oph);

void xtest_add_attr(size_t *attr_count, TEE_Attribute *attrs,
			   uint32_t attr_id, const void *buf, size_t len);
void xtest_add_attr_value(size_t *attr_count, TEE_Attribute *attrs,
			  uint32_t attr_id, uint32_t value_a, uint32_t value_b);

TEE_Result pack_attrs(const TEE_Attribute *attrs, uint32_t attr_count,
			     uint8_t **buf, size_t *blen);

int ree_fs_get_ta_dirname(TEEC_UUID *p_uuid, char *buffer, uint32_t len);

void tee_errx(const char *msg, TEEC_Result res) __attribute__((noreturn));
void tee_check_res(TEEC_Result res, const char *errmsg);

/* Knuth/Welford algorithm implementation */
void update_stats(struct statistics *s, uint64_t t);
double stddev(struct statistics *s);

#endif /*XTEST_HELPERS_H*/
