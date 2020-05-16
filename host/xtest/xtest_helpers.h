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

#include <adbg.h>
#include <pthread.h>
#include <tee_api_types.h>
#include <tee_client_api.h>

extern unsigned int level;

/* OP-TEE driver is introduced in kernel v4.5 */
#define KERNEL_MAJOR_MIN	4
#define KERNEL_MINOR_MIN	5
/* As of now, v5.8 is the next kernel */
#define KERNEL_MAJOR_NEXT	5
#define KERNEL_MINOR_NEXT	8

/* Return a signed +1, 0 or -1 value based on data comparison */
#define CMP_TRILEAN(a, b) \
	(__extension__({ \
		__typeof__(a) _a = (a); \
		__typeof__(b) _b = (b); \
		\
		_a > _b ? 1 : _a < _b ? -1 : 0; \
	}))

extern unsigned int xtest_kernel_major;
extern unsigned int xtest_kernel_minor;

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

/* Return true is OS kernel restriction do not comply provided version */
static inline int cmp_kernel_version(unsigned int a_major, unsigned int a_minor,
				      unsigned int b_major, unsigned int b_minor)
{
	int cmp = CMP_TRILEAN(a_major, b_major);

	if (cmp)
		return cmp;

	return CMP_TRILEAN(a_minor, b_minor);
}

/* Return true is OS kernel restriction comply the registered kernel version */
static inline bool kernel_is_supported(unsigned int major, unsigned int minor)
{
	/* Test if registered version is higher or equal to caller arguments */
	return cmp_kernel_version(xtest_kernel_major, xtest_kernel_minor,
				  major, minor) >= 0;
}

#define TEEC_OPERATION_INITIALIZER	{ }

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

bool ta_crypt_cmd_is_algo_supported(ADBG_Case_t *c, TEEC_Session *s,
				    uint32_t alg, uint32_t element);

TEEC_Result ta_os_test_cmd_client_identity(TEEC_Session *session,
					   uint32_t *login,
					   TEEC_UUID *client_uuid);

void xtest_add_attr(size_t *attr_count, TEE_Attribute *attrs,
			   uint32_t attr_id, const void *buf, size_t len);
void xtest_add_attr_value(size_t *attr_count, TEE_Attribute *attrs,
			  uint32_t attr_id, uint32_t value_a, uint32_t value_b);

TEE_Result pack_attrs(const TEE_Attribute *attrs, uint32_t attr_count,
			     uint8_t **buf, size_t *blen);

void xtest_mutex_init(pthread_mutex_t *mutex);
void xtest_mutex_destroy(pthread_mutex_t *mutex);
void xtest_mutex_lock(pthread_mutex_t *mutex);
void xtest_mutex_unlock(pthread_mutex_t *mutex);

void xtest_barrier_init(pthread_barrier_t *barrier, unsigned count);
void xtest_barrier_destroy(pthread_barrier_t *barrier);
int xtest_barrier_wait(pthread_barrier_t *barrier);

#endif /*XTEST_HELPERS_H*/
