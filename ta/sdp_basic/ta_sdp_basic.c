/*
 * Copyright (c) 2016, Linaro Limited
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

#include <string.h>
#include <tee_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <tee_ta_api.h>
#include <trace.h>

#include <ta_sdp_basic.h>

/*
 * Basic Secure Data Path access test commands:
 * - command INJECT: copy from non secure input into secure output.
 * - command TRANSFROM: read, transform and write from/to secure in/out.
 * - command DUMP: copy from secure input into non secure output.
 */

static TEE_Result cmd_inject(uint32_t types,
			     TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result rc;
	const int sec_idx = 1;		/* highlight secure buffer index */
	const int ns_idx = 0;		/* highlight nonsecure buffer index */

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE)) {
		EMSG("bad parameters %x", (unsigned)types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (params[sec_idx].memref.size < params[ns_idx].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	/* intentionally check the overall buffers permissions */
	rc = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					 TEE_MEMORY_ACCESS_READ |
					 TEE_MEMORY_ACCESS_NONSECURE,
					 params[ns_idx].memref.buffer,
					 params[ns_idx].memref.size);
	if (rc != TEE_SUCCESS) {
		EMSG("TEE_CheckMemoryAccessRights(nsec) failed %x", rc);
		return rc;
	}

	rc = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					 TEE_MEMORY_ACCESS_WRITE |
					 TEE_MEMORY_ACCESS_SECURE,
					 params[sec_idx].memref.buffer,
					 params[sec_idx].memref.size);
	if (rc != TEE_SUCCESS) {
		EMSG("TEE_CheckMemoryAccessRights(secure) failed %x", rc);
		return rc;
	}


#ifdef CFG_CACHE_API
	/*
	 * we should invalidate cache (here we assume buffer were not
	 * filled through cpu core caches. We flush buffers so that
	 * cache is not corrupted in cache target buffer not aligned
	 * on cache line size.
	 */
	rc = TEE_CacheFlush(params[sec_idx].memref.buffer,
			    params[sec_idx].memref.size);
	if (rc != TEE_SUCCESS) {
		EMSG("TEE_CacheFlush(%p, %x) failed: 0x%x",
					params[sec_idx].memref.buffer,
					params[sec_idx].memref.size, rc);
		return rc;
	}
#endif /* CFG_CACHE_API */

	/* inject data */
	TEE_MemMove(params[sec_idx].memref.buffer,
		    params[ns_idx].memref.buffer,
		    params[sec_idx].memref.size);

#ifdef CFG_CACHE_API
	/* flush data to physical memory */
	rc = TEE_CacheFlush(params[sec_idx].memref.buffer,
			    params[sec_idx].memref.size);
	if (rc != TEE_SUCCESS) {
		EMSG("TEE_CacheFlush(%p, %x) failed: 0x%x",
					params[sec_idx].memref.buffer,
					params[sec_idx].memref.size, rc);
		return rc;
	}
#endif /* CFG_CACHE_API */

	return rc;
}

static TEE_Result cmd_transform(uint32_t types,
				TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result rc;
	unsigned char *p;
	size_t sz;

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	/* intentionally check the overall buffers permissions */
	rc = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					 TEE_MEMORY_ACCESS_READ |
					 TEE_MEMORY_ACCESS_WRITE |
					 TEE_MEMORY_ACCESS_SECURE,
					 params[0].memref.buffer,
					 params[0].memref.size);
	if (rc != TEE_SUCCESS) {
		EMSG("TEE_CheckMemoryAccessRights(secure) failed %x", rc);
		return rc;
	}


#ifdef CFG_CACHE_API
	/*
	 * we should invalidate cache (here we assume buffer were not
	 * filled through cpu core caches. We flush buffers so that
	 * cache is not corrupted in cache target buffer not aligned
	 * on cache line size.
	 */
	rc = TEE_CacheFlush(params[0].memref.buffer,
			    params[0].memref.size);
	if (rc != TEE_SUCCESS) {
		EMSG("TEE_CacheFlush(%p, %x) failed: 0x%x",
					params[0].memref.buffer,
					params[0].memref.size, rc);
		return rc;
	}
#endif /* CFG_CACHE_API */

	/* transform the data */
	p = (unsigned char *)params[0].memref.buffer;
	sz = params[0].memref.size;
	for (; sz; sz--, p++)
			*p = ~(*p) + 1;

#ifdef CFG_CACHE_API
	/* flush data to physical memory */
	rc = TEE_CacheFlush(params[0].memref.buffer,
			    params[0].memref.size);
	if (rc != TEE_SUCCESS) {
		EMSG("TEE_CacheFlush(%p, %x) failed: 0x%x",
					params[0].memref.buffer,
					params[0].memref.size, rc);
		return rc;
	}
#endif /* CFG_CACHE_API */

	return rc;
}

static TEE_Result cmd_dump(uint32_t types,
			   TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result rc;
	const int sec_idx = 0;		/* highlight secure buffer index */
	const int ns_idx = 1;		/* highlight nonsecure buffer index */

	if (types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				     TEE_PARAM_TYPE_MEMREF_OUTPUT,
				     TEE_PARAM_TYPE_NONE,
				     TEE_PARAM_TYPE_NONE))
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[ns_idx].memref.size < params[sec_idx].memref.size)
		return TEE_ERROR_SHORT_BUFFER;

	/* intentionally check the overall buffers permissions */
	rc = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					 TEE_MEMORY_ACCESS_WRITE |
					 TEE_MEMORY_ACCESS_NONSECURE,
					 params[ns_idx].memref.buffer,
					 params[ns_idx].memref.size);
	if (rc != TEE_SUCCESS) {
		EMSG("TEE_CheckMemoryAccessRights(nsec) failed %x", rc);
		return rc;
	}

	rc = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_ANY_OWNER |
					 TEE_MEMORY_ACCESS_READ |
					 TEE_MEMORY_ACCESS_SECURE,
					 params[sec_idx].memref.buffer,
					 params[sec_idx].memref.size);
	if (rc != TEE_SUCCESS) {
		EMSG("TEE_CheckMemoryAccessRights(secure) failed %x", rc);
		return rc;
	}

#ifdef CFG_CACHE_API
	/*
	 * we should invalidate cache (here we assume buffer were not
	 * filled through cpu core caches. We flush buffers so that
	 * cache is not corrupted in cache target buffer not aligned
	 * on cache line size.
	 */
	rc = TEE_CacheFlush(params[sec_idx].memref.buffer,
			    params[sec_idx].memref.size);
	if (rc != TEE_SUCCESS) {
		EMSG("TEE_CacheFlush(%p, %x) failed: 0x%x",
					params[sec_idx].memref.buffer,
					params[sec_idx].memref.size, rc);
		return rc;
	}
#endif /* CFG_CACHE_API */

	/* dump the data */
	TEE_MemMove(params[ns_idx].memref.buffer,
		    params[sec_idx].memref.buffer,
		    params[sec_idx].memref.size);

	return rc;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes,
				    TEE_Param pParams[TEE_NUM_PARAMS],
				    void **ppSessionContext)
{
	(void)nParamTypes;
	(void)pParams;
	(void)ppSessionContext;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *pSessionContext)
{
	(void)pSessionContext;
}

TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
				      uint32_t nCommandID, uint32_t nParamTypes,
				      TEE_Param pParams[TEE_NUM_PARAMS])
{
	(void)pSessionContext;

	switch (nCommandID) {
	case TA_SDP_BASIC_CMD_INJECT:
		return cmd_inject(nParamTypes, pParams);
	case TA_SDP_BASIC_CMD_TRANSFORM:
		return cmd_transform(nParamTypes, pParams);
	case TA_SDP_BASIC_CMD_DUMP:
		return cmd_dump(nParamTypes, pParams);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
