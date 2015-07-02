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

#ifndef INCLUSION_GUARD_T_LIST_H
#define INCLUSION_GUARD_T_LIST_H

/*************************************************************************
**************************************************************************
*
* DESCRIPTION:
*
* Header file containing external type declaration for the doubly linked
* list category "list"
*
*************************************************************************/

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define List_t DL_List_t

/**
 * The client using the Util_ListDelete() and Util_ListDestroy()
 * functions can provide a function that knows how to delete the client's
 * elements. This is to simplify the client's code when destroying the list.
 */
typedef void (*ListDeleteFunction_t)(void *);

/**
 * Compare with ListDeleteFunction_t. Key and value is handled separately in
 * general map style.
 *
 * @param  [in, out] Key_p     A  pointer to the elements key for the element to be removed.
 * @param  [in, out] Value_p     A  pointer to the elements body for the element to be removed.
 * @return void
 */

typedef void (*ListDeleteFunctionGeneralMap_t)(void *Key_p, void *Value_p);

/**
 * Compare with ListDeleteFunctionGeneralMap_t. Extra parameter for client handle
 * used for ClientHandle style callbacks
 *
 * @param  [in] ClientHandle_p     A pointer to client handle.
 * @param  [in, out] Key_p     A  pointer to the element's key for the element to be removed.
 * @param  [in, out] Value_p     A  pointer to the element's body for the element to be removed.
 * @return void
 */
typedef void (*ListDeleteFunctionGeneralMapClientHandleStyle_t)(const void *
								const
								ClientHandle_p,
								void *Key_p,
void *Value_p);

/**
 * This is a help function provided by the client. The function should
 * print information about the client's elements. The function is used
 * when printing the content of a list using Util_ListPrintDebug().
 * The list library function prints information about the list while
 * the client's function prints information about the elements that
 * are in the list. One special version exist for General Map callback.
 */

typedef void (*ListDebugFunction_t)(void *);

/**
 * Compare with ListDebugFunction_t, this function type is harmonized with the
 * style used in general Map. The ListDebugFunctionGeneralMap_t function
 * is applied to each element when scanning through the entire List.
 *
 * @param [in] Key_p    A pointer to the element's key for the current element
 *                 (i.e. the element currently being iterated)
 * @param [in, out] Value_p  A pointer to the element's body for the current element
 *                 (i.e. the element currently being iterated)
 * @param [in, out] Data_pp   A pointer to client's data (may also be used as output data)
 * @param [in, out] Break_p  TRUE if the client wants to break the iteration loop. FALSE
 *           otherwise.
 *
 *
 */

typedef void (*ListDebugFunctionGeneralMap_t)(const void *const Key_p,
					      void *const Value_p,
					      void **const Data_pp,
					      bool *const Break_p);

/**
 * This is a key comparison function provided by the client.
 * When adding an element into a list, the client may provide a key.
 * The key may then be used to find the element in the list.
 * When the data type of the key is other than an integer
 * (when Util_EListMatchingKey() is used) or an ascii string
 * (when Util_ListMatchingKey() is used), the client has to provide a
 * ListKeyMatchingFunction_t function that is called when comparing keys.
 */

typedef bool (*ListKeyMatchingFunction_t)(const void *, const void *);

/**
 * Compare with ListKeyMatchingFunction_t, only added an extra parameter for client handle
 * used for ClientHandle style callbacks
 *
 * @param  [in] ClientHandle_p     A pointer to client handle.
 * @param [in] KeyA_p   A pointer to the first key. Must not be NULL.
 * @param [in] KeyB_p   A pointer to the second key. Must not be NULL.
 * @return bool TRUE if the first and second key are identical.
 *                 FALSE otherwise
 */
typedef bool (*ListKeyMatchingFunctionClientHandleStyle_t)(const void *
							   ClientHandle_p,
							   const void *KeyA_p,
							   const void *KeyB_p);

/**
 * This is a memory allocation function provided by the client.
 * The client using Util_EListCreate() provides a memory allocation function.
 * This may be useful in cases where a list is created in one context
 * and freed in another context. Note that this usage (e.g. a list being
 * used to share information between two or more processes) is strongly
 * discouraged. Use Util_ListCreate() instead
 */

typedef void * (*ListMemAllocFunction_t)(size_t);

/**
 * This is a memory de-allocation function provided by the client.
 * The client using Util_EListCreate() provides a memory allocation
 * and de-allocation functions. This may be useful in cases where a
 * list is created in one context and freed in another context.
 * Note that this usage (e.g. a list being used to share information
 * between two or more processes) is strongly discouraged.
 * Use Util_ListCreate() instead.
 */

typedef void (*ListMemFreeFunction_t)(void *);


/**
 * Type used to link element in the list. LListItem is not publicized.
 */

typedef struct LListItem ListItem_t;

/**
 * Type used to hold a linked list. A pointer to a list is returned
 * to the client after a call to Util_ListCreate(). Then, the list
 * pointer is used as input to the other functions in the category.
 * DL_List is not publicized.
 */

typedef struct DL_List DL_List_t;

/**
 * Completion code returned by some of the linked list library functions.
 * The constant names are self explanatory.
 */

enum {
	LIST_SUCCESS = 0,
	LIST_ERROR_COULD_NOT_ALLOC_MEM,
	LIST_ERROR_INVALID_LIST,
	LIST_ERROR_INVALID_PARAM,
	LIST_ERROR_CURRENT_PTR_OFF_LIST,
	LIST_ERROR_NO_MATCH_FOUND,
	LIST_ERROR_UNKNOWN
};
typedef uint8_t ListResult_t;


/**
 * The list status indicates whether conditions of interest
 *
 * \li  a) whether the list is empty
 * \li  b) whether the current pointer points to the head
 * \li  c) whether the current pointer points to the tail
 * \li  d) whether the current pointer does not point inside the list
 * \li  e) whether the list is valid (ie. list pointer is not NULL)
 *
 *  Note: b) and c) can be true at the same time.
 *
 */

enum {
	LIST_STATUS_NOTHING_TO_REPORT  = 0x00,
	LIST_STATUS_PTR_TO_TAIL        = 0x01,  /* to be used as bit mask */
	LIST_STATUS_PTR_TO_HEAD        = 0x02,  /* to be used as bit mask */
	LIST_STATUS_PTR_OFF_LIST       = 0x04,  /* 2 LSB must be 0 */
	LIST_STATUS_LIST_EMPTY         = 0x08,  /* 2 LSB must be 0 */
	LIST_STATUS_INVALID_LIST       = 0x80
};
typedef uint8_t ListStatus_t;

#endif /* INCLUSION_GUARD_T_LIST_H */
