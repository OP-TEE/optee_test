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

#ifndef INCLUSION_GUARD_SECURITY_UTILS_MEM_H
#define INCLUSION_GUARD_SECURITY_UTILS_MEM_H

/*************************************************************************
* 1. Includes
*************************************************************************/

#include <stdbool.h>
/*************************************************************************
* 2. Types, constants and external variables
*************************************************************************/

/*************************************************************************
* 3. Functions and macros
*************************************************************************/

/**
 * Creates an allocated copy if a string while keeping track of
 * where the memory allocation was initiated.
 *
 * The copy should later be freed with HEAP_FREE
 *
 * @param in String_p The string to be copied
 *
 * @return Returns a pointer to a copy of String_p on success and NULL
 *         if memory allocation failed.
 */
#define SECUTIL_HEAP_STRDUP(String_p) \
	SecUtil_Heap_StrDup((String_p), false, __FILE__, __LINE__)

/**
 * Creates an allocated copy if a string while keeping track of
 * where the memory allocation was initiated.
 *
 * The copy should later be freed with HEAP_UNSAFE_FREE
 *
 * @param in String_p The string to be copied
 *
 * @return Returns a pointer to a copy of String_p on success and NULL
 *         if memory allocation failed.
 */
#define SECUTIL_HEAP_UNSAFE_STRDUP(String_p) \
	SecUtil_Heap_StrDup((String_p), true, __FILE__, __LINE__)

/**
 * This function is a helper function for the two macros
 * SECUTIL_HEAP_STRDUP and SECUTIL_HEAP_UNSAFE_STRDUP.
 *
 * The function allocates sufficient memroy for
 * a copy of the string String_p.
 *
 * @param in String_p The string to be copied
 * @param in Unsafe   If true use HEAP_UNSAFE_UNTYPED_ALLOC_DBG else
 *                    use HEAP_UNTYPED_ALLOC_DBG
 * @param in File_p   Name of the file where the function is called
 * @param in Line     Line number of the file where the function is called
 *
 * @return Returns a pointer to a copy of String_p on success and NULL
 *         if memory allocation failed.
 */
char *SecUtil_Heap_StrDup(const char *const String_p, const bool Unsafe,
			  const char *const File_p, const unsigned int Line);

/**
 * Wipes the buffer using several different bit patterns to avoid
 * leaking information.
 *
 * This function should preferably be used as a help function in
 * a FREE macro.
 *
 * @param in  Buffer_p      Pointer to the buffer to wipe
 * @param in  BufferLength  Length (in bytes) of the buffer to wipe
 */
void SecUtil_WipeMemory(void *const Buffer_p, const size_t BufferLength);


/*
 * Modules using the SECURE_HEAP macros below should use them through
 * a private define. This makes it easier during code inspection to see
 * that the policy for handling memory is consistent.
 */

/**
 * Macro for secure memory allocation. Only a wrapper for
 * HEAP_ALLOC. The interesting part is SECUTIL_SECURE_HEAP_FREE
 * below.
 *
 * @param in  Type  The type that memory should be allocated for
 *
 * @return a pointer to a buffer large enough to hald the supplied type,
 *         or NULL on failure.
 */
#define SECUTIL_SECURE_HEAP_ALLOC(Type)   HEAP_ALLOC((TypeNmae))

/**
 * Macro for secure memory allocation. Only a wrapper for
 * HEAP_UNTYPED_ALLOC. The interesting part is SECUTIL_SECURE_HEAP_FREE
 * below.
 *
 * @param in  Size  The size of the buffer to be allocated
 *
 * @return a pointer to a buffer of the specified size,
 *         or NULL on failure.
 */
#define SECUTIL_SECURE_UNTYPED_HEAP_ALLOC(Size) \
	HEAP_UNTYPED_ALLOC((Size))

/**
 * Macro for secure memory free. Secure is in the sense that information
 * leakage is avoided by wiping the memory before it's released.
 *
 * Note that buffer must have been allocated with SECUTIL_SECURE_HEAP_ALLOC
 * or SECUTIL_SECURE_UNTYPED_HEAP_ALLOC before of anything could happen
 * (most likely a crash).
 *
 * @param in Buffer_pp  A pointer to a pointer of the buffer to free.
 */
#define SECUTIL_SECURE_HEAP_FREE(Buffer_pp) \
	SecUtil_SecureHeapFree_helper((void **)(Buffer_pp))


/**
 * Helper function for SECUTIL_SECURE_HEAP_FREE. The function
 * calls HEAP_BUFFER_SIZE to determine the size of the buffer
 * and then calls SecUtil_WipeMemory to wipe the memory. Finally
 * the buffer is freed with HEAP_FREE
 *
 * If the supplied buffer is NULL this function does nothing.
 *
 * Note that the buffer has be allocated with HEAP_ALLOC or
 * HEAP_UNTYPED_HEAP_ALLOC before or anything could happen.
 *
 * @param in Buffer_pp  A pointer to a pointer of the buffer to
 *                      wipe and free
 */
void SecUtil_SecureHeapFree_helper(void **const Buffer_pp);

/**
 * Macro for unaligned memcpy(). To be used when source or destination
 * may not be properly aligned. Usage of this macro will only affect
 * performance when copying large chunks of data (which is already
 * present in the memory cache).
 *
 * Use this macro if you cannot guarantee that the pointers
 * have properly aligned values.
 */
#define SEC_MEMCPY_UNALIGNED(x, y, z) \
	do { \
		void *memcpy_hack_dst = (x); \
		const void *memcpy_hack_src = (y); \
		memcpy(memcpy_hack_dst, memcpy_hack_src, (z)); \
	} while (0)

/**
 * Macros for secure erase.
 */
#define SECUTIL_SECURE_ERASE_UINT32(X) { \
		*((volatile uint32*)(&X)) = 0 }

#define SECUTIL_SECURE_ERASE_UINT16(X) { \
		*((volatile uint16*)(&X)) = 0 }

#define SECUTIL_SECURE_ERASE_UINT8(X) { \
		*((volatile uint8*)(&X)) = 0 }

#define SECUTIL_SECURE_ERASE_BOOLEAN(X) { \
		*((volatile bool*)(&X)) = 0 }

#define SECUTIL_SECURE_ERASE_ARRAY(X) { \
		memset(((void *)(X)), 0x0, sizeof(X)) }

#define SECUTIL_SECURE_ERASE_TYPED_ARRAY(X) { \
		SECUTIL_SECURE_ERASE_UNTYPED_ARRAY(X, sizeof(X)) }

#define SECUTIL_SECURE_ERASE_UNTYPED_ARRAY(X, L) { \
		memset(((void *)(X)), 0x0, L) }

#define SECUTIL_SECURE_ERASE_STRUCT(X) { \
		memset(((void *)(&X)), 0x0, sizeof(X)) }

#endif /* INCLUSION_GUARD_SECURITY_UTILS_MEM_H */
