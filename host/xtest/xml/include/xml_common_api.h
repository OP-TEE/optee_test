/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#ifndef XML_COMMON_API_H_
#define XML_COMMON_API_H_

/*Helper functions/macros*/
#define IDENTIFIER_NOT_USED(x) { if (sizeof(&x)) {} }

#define ALLOCATE_SHARED_MEMORY(context, sharedMemory, sharedMemorySize, \
			       memoryType, exit_label) \
	res = AllocateSharedMemory(context, sharedMemory, sharedMemorySize, \
				   memoryType); \
	if (res != TEEC_SUCCESS) { \
		goto exit_label; \
	} \
	memset(sharedMemory->buffer, 0, sharedMemorySize);

#define ALLOCATE_AND_FILL_SHARED_MEMORY(context, sharedMemory, \
					sharedMemorySize, \
					memoryType, copySize, data, \
					exit_label) \
	res = AllocateSharedMemory(context, sharedMemory, sharedMemorySize, \
				   memoryType); \
	if (res != TEEC_SUCCESS) { \
		goto exit_label; \
	} \
	memset(sharedMemory->buffer, 0, sharedMemorySize); \
	if (data != NULL) { \
		memcpy(sharedMemory->buffer, data, copySize); \
	}
#define ALLOCATE_AND_FILL_SHARED_MEMORY_6(a,b,c,d,e,f) \
		        ALLOCATE_AND_FILL_SHARED_MEMORY(a,b,c,d,c,e,f)

#define SET_SHARED_MEMORY_OPERATION_PARAMETER(parameterNumber, \
					      sharedMemoryOffset, \
					      sharedMemory, \
					      sharedMemorySize) \
	op.params[parameterNumber].memref.offset = sharedMemoryOffset; \
	op.params[parameterNumber].memref.size = sharedMemorySize; \
	op.params[parameterNumber].memref.parent = sharedMemory;

#endif /* XML_COMMON_API_H_ */
