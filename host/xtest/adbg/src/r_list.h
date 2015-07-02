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

#ifndef INCLUSION_GUARD_R_LIST_H
#define INCLUSION_GUARD_R_LIST_H

/*************************************************************************
**************************************************************************
*
* DESCRIPTION:
*
* Header file containing the function prototypes for the doubly linked list
* function category
*
*************************************************************************/

#include <stdbool.h>
#include "t_list.h"

#define xmalloc malloc
#define xfree free


/** AUTOGEN_SWBP_FUNCTION_NOT_FOUND_IN_REFERENCE_MANUAL */
bool ListStrComparisonFunc(const void *AnElementKey_p,
			   const void *KeyToMatch_p);

#define Util_ListInsertBefore(a, b, c) \
	Util_EListInsertBefore((a), (void *)(b), \
	(c))
#define Util_ListInsertAfter(a, b, c)  \
	Util_EListInsertAfter((a), (void *)(b), \
	(c))
#define Util_ListMatchingKey(a, b) \
	Util_EListMatchingKey((a), (void *)(b), \
	ListStrComparisonFunc)
#define Util_ListCreate() \
	Util_EListCreate(xmalloc, xfree)

/* These structure are not public. They are included here
 * to allow for macro
 * definition (see the macros at the end of the file) */

struct LListItem {
	struct LListItem *Prev_p;
	struct LListItem *Next_p;
	void *Body_p;
	const void *EKey_p;
};

struct DL_List {
	uint16_t NbrOfElements; /* Number of elements
				in the linked list */
	ListItem_t *Head_p; /* first item in the list */
	ListItem_t *Tail_p; /* last item in the list */
	ListItem_t *Curr_p; /* the "current" item in the list */
	ListMemAllocFunction_t MemAllocFunc_p; /* pointer to
					allocator function */
	ListMemFreeFunction_t MemFreeFunc_p; /* pointer to the
					memory freeing function */
	bool ClientHandleStyle; /* True if General Map style
					is applied */
	void *ClientHandle_p; /* Store the client handle pointer if
				callbacks is of ClientHandle style */
};

/**
 * This function creates an empty list.
 *
 * @param [in] MemAlloc_p	Pointer to an allocation function that complies to
 *			the following interface: void* Allocator(size_t Size);
 * @param [in] MemFree_p	Pointer to a de-allocation function that complies to
 *				the following interface: void Free(void* Mem_p);
 *
 * @return List_p     Pointer to the list, null if unable to create list.
 *
 */
List_t *Util_EListCreate(const ListMemAllocFunction_t MemAlloc_p,
			 const ListMemFreeFunction_t MemFree_p);
/**
 * This function creates an empty list with a client handle as input parameter.
 * This client handle will be an input parameter in all callbacks to the client
 * functions. For memory allocation and de-allocation is xmalloc and xfree are
 * automatically selected.
 *
 * @param [in] ClientHandle_p  Pointer to a client handle used in client callbacks
 *
 * @return List_p     Pointer to the list, null if unable to create list.
 *
 */
List_t *Util_EListCreateClientHandleStyle(const void *const ClientHandle_p);

/**
 * This function makes sure that the list pointer is not NULL. If it is, the
 * function immediately returns LIST_STATUS_INVALID_LIST. Then the function
 * returns the status of the list pointed to by List_p. The list status
 * returned is a bit map. The returned value has to be bitwise ANDed with the
 * status codes listed above in Return Values. See also Util_ListHead(),
 * Util_ListTail(), Util_ListIsEmpty() and Util_ListOffList().
 *
 * @param [in] List_p Pointer to the list whose status will be obtained.
 *
 * @retval LIST_STATUS_LIST_EMPTY
 * @retval LIST_STATUS_NOTHING_TO_REPORT
 * @retval LIST_STATUS_PTR_OFF_LIST
 * @retval LIST_STATUS_PTR_TO_TAIL
 * @retval LIST_STATUS_PTR_TO_HEAD
 * @retval LIST_STATUS_INVALID_LIST
 *
 */

ListStatus_t Util_ListStatus(const List_t *const List_p);


/**
 * This function returns the number of elements in the list pointed to by
 * List_p.
 *
 * @param [in] List_p        Pointer to the list whose length will be
 *                 obtained.
 * @param [out] ListLength_p Number of elements in the list.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 * @retval LIST_ERROR_INVALID_PARAM
 *
 */

ListResult_t Util_ListLength(const List_t *const List_p,
			     uint16_t *const ListLength_p);


/**
 * This function makes sure that the list pointer is not NULL. If it is, the
 * function immediately returns LIST_STATUS_INVALID_LIST. Then the function
 * checks whether the list's current pointer for the list pointed to by List_p
 * points to the tail of the list. If so the function returns
 * LIST_STATUS_PTR_TO_TAIL, otherwise the function returns
 * LIST_STATUS_NOTHING_TO_REPORT. See also Util_ListStatus(), Util_ListHead(),
 * Util_ListIsEmpty() and Util_ListOffList().
 *
 * @param [in] List_p Pointer to the list whose current pointer will be
 *          checked against the list's tail.
 *
 * @retval LIST_STATUS_NOTHING_TO_REPORT
 * @retval LIST_STATUS_PTR_TO_TAIL
 * @retval LIST_STATUS_INVALID_LIST
 *
 */

ListStatus_t Util_ListTail(const List_t *const List_p);


/**
 * This function makes sure that the list pointer is not NULL. If it is, the
 * function immediately returns LIST_STATUS_INVALID_LIST. Then the function
 * checks whether the list's current pointer for the list pointed to by List_p
 * is pointing to an element inside the list. If so the function returns
 * LIST_STATUS_NOTHING_TO_REPORT, otherwise the function returns
 * LIST_STATUS_PTR_OFF_LIST. See also Util_ListStatus(), Util_ListTail(),
 * Util_ListHead() and Util_ListIsEmpty().
 *
 * @param [in] List_p Pointer to the list whose current pointer is checked for
 *          validity. An invalid pointer is not pointing to an
 *          element inside the list.
 *
 * @retval LIST_STATUS_NOTHING_TO_REPORT
 * @retval LIST_STATUS_PTR_OFF_LIST
 * @retval LIST_STATUS_INVALID_LIST
 *
 */

ListStatus_t Util_ListOffList(const List_t *const List_p);


/**
 * This function makes sure that the list pointer is not NULL. If it is, the
 * function immediately returns LIST_STATUS_INVALID_LIST. Then the function
 * checks whether the list's current pointer for the list pointed to by List_p
 * points to the head of the list. If so the function returns
 * LIST_STATUS_PTR_TO_HEAD, otherwise the function returns
 * LIST_STATUS_NOTHING_TO_REPORT. See also Util_ListStatus(), Util_ListTail(),
 * Util_ListIsEmpty() and Util_ListOffList().
 *
 * @param [in] List_p Pointer to the list whose current pointer will be
 *          checked against the list's head.
 *
 * @retval LIST_STATUS_NOTHING_TO_REPORT
 * @retval LIST_STATUS_PTR_TO_HEAD
 * @retval LIST_STATUS_INVALID_LIST
 *
 */
ListStatus_t Util_ListHead(const List_t *const List_p);


/**
 * This function makes sure that the list pointer is not NULL. If it is, the
 * function immediately returns LIST_STATUS_INVALID_LIST. Then the function
 * checks whether the list pointed to by List_p is empty (i.e. created but no
 * element in the list). If so the function returns LIST_STATUS_LIST_EMPTY,
 * otherwise the function returns LIST_STATUS_NOTHING_TO_REPORT. See also
 * Util_ListStatus(), Util_ListTail(), Util_ListHead() and Util_ListOffList().
 *
 * @param [in] List_p Pointer to the list to be verified for emptiness.
 *
 * @retval LIST_STATUS_NOTHING_TO_REPORT
 * @retval LIST_STATUS_LIST_EMPTY
 * @retval LIST_STATUS_INVALID_LIST
 *
 */
ListStatus_t Util_ListIsEmpty(const List_t *const List_p);


/**
 * This function inserts the element pointed to by ElemContent_p before the
 * element pointed to by the list's current pointer. When the function returns,
 * the list's current pointer points to the newly added element.
 *
 * A key may be used to mark elements in the list. The list can then be
 * searched using Util_ListMatchingKey() or Util_EListMatchingKey().
 *
 * In Util_ListInsertBefore(), the client provided key must be a NULL
 * terminated string while in Util_EListInsertBefore(), the client provided key
 * may be of any type.
 *
 * Notice that Util_ListInsertBefore() is provided for backward compatibility
 * reason only. Use of Util_EListInsertBefore() is recommended in new
 * implementations.
 *
 * See also Util_EListInsertAfter(), Util_ListInsertFirst(),
 * Util_ListInsertLast(), Util_List_Remove(), Util_ListKeyedRemove() and
 * Util_ListDelete().
 *
 * @param [in, out] List_p        Pointer to the list in which the element will be
 *                 inserted.
 * @param [in] Key_p         Pointer to a client's key. Key_p may be NULL.
 * @param [in] ElemContent_p Pointer to the element to be inserted in the
 *                 list.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 * @retval LIST_ERROR_COULD_NOT_ALLOC_MEM
 *
 */

ListResult_t Util_EListInsertBefore(List_t *const List_p,
				    const void *const Key_p,
				    void *const ElemContent_p);


/**
 * This function Util_ListInsertFirst() inserts the element pointed to by
 * ElemContent_p at the head of the list. The
 * list's current pointer remains unchanged.
 *
 * A key may be used to mark elements in the list. The list can then be
 * searched using Util_ListMatchingKey() or Util_EListMatchingKey().
 *
 * See also Util_ListInsertAfter(), Util_EListInsertAfter(),
 * Util_ListInsertLast(), Util_List_Remove(),
 * Util_ListKeyedRemove() and Util_ListDelete().
 *
 * @param [in, out] List_p        Pointer to the list in which the element will be
 *                 inserted.
 * @param [in] Key_p         Pointer to a client's key. Key_p may be NULL.
 * @param [in] ElemContent_p Pointer to the element to be inserted in the
 *                 list.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 * @retval LIST_ERROR_COULD_NOT_ALLOC_MEM
 *
 */
ListResult_t Util_ListInsertFirst(List_t *const List_p, const void *const Key_p,
				  void *const ElemContent_p);


/**
 * This function inserts the element pointed to by ElemContent_p after the
 * element pointed to by the list's current pointer. When the function returns,
 * the list's current pointer points to the newly added element.
 *
 * A key may be used to mark elements in the list. The list can then be
 * searched using Util_ListMatchingKey() or Util_EListMatchingKey().
 *
 * In Util_ListInsertAfter(), the client provided key must be a NULL terminated
 * string while in Util_EListInsertAfter(), the client provided key may be of
 * any type.
 *
 * Notice that Util_ListInsertAfter() is provided for backward compatibility
 * reason only. Use of Util_EListInsertAfter() is recommended in new
 * implementations.
 *
 * See also Util_EListInsertBefore(), Util_ListInsertFirst(),
 * Util_ListInsertLast(), Util_List_Remove(), Util_ListKeyedRemove() and
 * Util_ListDelete().
 *
 * @param [in, out] List_p        Pointer to the list in which the element will be
 *                 inserted.
 * @param [in] Key_p         Pointer to a client's key. Key_p must point to a
 *                 NULL terminated string. Key_p may be NULL.
 * @param [in] ElemContent_p Pointer to the element to be inserted in the
 *                 list.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 * @retval LIST_ERROR_COULD_NOT_ALLOC_MEM
 *
 */

ListResult_t Util_EListInsertAfter(List_t *const List_p,
				   const void *const Key_p,
				   void *const ElemContent_p);


/**
 * This function Util_ListInsertLast()
 * inserts the element pointed to by ElemContent_p at the tail of the list. The
 * list's current pointer remains unchanged.
 *
 * A key may be used to mark elements in the list. The list can then be
 * searched using Util_ListMatchingKey() or Util_EListMatchingKey().
 *
 * See also Util_ListInsertAfter(), Util_EListInsertAfter(),
 * Util_ListInsertFirst(), Util_List_Remove(),
 * Util_ListKeyedRemove() and Util_ListDelete().
 *
 * @param [in, out] List_p        Pointer to the list in which the element will be
 *                 inserted.
 * @param [in] Key_p         Pointer to a client's key. Key_p may be NULL.
 * @param [in] ElemContent_p Pointer to the element to be inserted in the
 *                 list.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 * @retval LIST_ERROR_COULD_NOT_ALLOC_MEM
 *
 */
ListResult_t Util_ListInsertLast(List_t *const List_p, const void *const Key_p,
				 void *const ElemContent_p);


/**
 * This function scans the list pointed to by List_p starting from the list's
 * current pointer. Once the tail of the list has been searched, if an element
 * has still not been found, the search resumes from the head of the list. The
 * first element whose key matches the key pointed to by Key_p is removed.
 *
 * If a match is found, the list's current pointer will point to the element
 * after the one removed. If the element removed is the tail of the list, the
 * list's current pointer will point to the tail. When the last element is
 * removed, the current pointer is set to NULL.  If no match is found, the list
 * is left unchanged.
 *
 * If the matching function is NULL, Util_ListKeyedRemove() will perform an
 * integer comparison. Otherwise, the client provided routine will be used to
 * compare keys.
 *
 * See also Util_EListInsertAfter(),
 * Util_EListInsertBefore (), Util_ListInsertFirst(), Util_ListInsertLast(),
 * Util_List_Remove() and Util_ListDelete().
 *
 * @param [in, out] List_p            Pointer to the list to be searched and from
 *                     which the found element will be removed
 * @param [in] Key_p             Pointer to the key that identifies the
 *                     element to be removed.
 * @param [in] KeyMatchingFunc_p Client function that knows how to compare
 *                     keys of the client specific key data type.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_PARAM
 * @retval LIST_ERROR_NO_MATCH_FOUND
 *
 */

ListResult_t Util_ListKeyedRemove(List_t *const List_p,
	const void *const Key_p,
	const ListKeyMatchingFunction_t KeyMatchingFunc_p);

/**
 * This function scans the list pointed to by List_p starting from the list's
 * current pointer. Once the tail of the list has been searched, if a matching
 * element has still not been found, the search resumes from the head of the
 * list.
 *
 * The first element whose key matches the key pointed to by Key_p is returned.
 * Notice that if more than one element in the list match the specified key,
 * only the first one (from and including the element at the current pointer)
 * is returned. If more matching elements are desired, the client must
 * increment the current pointer (using Util_ListNext() or Util_ListIsNext())
 * and call the matching function again (Util_EListMatchingKey() or
 * Util_ListMatchingKey).
 *
 * If no element in the list matches or if invalid parameters are specified,
 * the function returns NULL.
 *
 * Note that for Util_ListMatchingKey, the key matching function is a string
 * comparison and is case sensitive. The string matching only matches the
 * characters in Key_p (e.g. key_p = "Blue" will match "BlueSky" and "Blue
 * Color" but not "blueSky" or  "Blu").
 *
 * In Util_EListMatchingKey, KeyMatchingFunc_p is a client specific comparison
 * function. If NULL is specified, an integer comparison (i.e. the element
 * pointed to by Key_p is assumed to be a signed integer) will be performed by
 * default. If KeyMatchingFunc_p is not NULL, the client specific comparison
 * function will be used to match the Key_p.
 *
 * @param [in, out] List_p	Pointer to the list to be searched.
 * @param [in] Key_p		Pointer to a client's key. In Util_ListMatchingKey(),
 *				Key_p must point to a NULL terminated string. In
 *			Util_EListMatchingKey(), Key_p points to a key for which
 *				the type is not known to the list library.
 * @param [in] KeyMatchingFunc_p The client's function to be used to compare keys
 *
 * @return void* Address of the element whose key has matched Key_p. NULL if no
 *	match has been found or if the list is invalid. The current pointer
 *	into the list points to the element returned or is not changed if
 *	the function returns NULL.
 *
 */

void *Util_EListMatchingKey(List_t *const List_p, const void *const Key_p,
			    const ListKeyMatchingFunction_t KeyMatchingFunc_p);

/**
 * This function is similar to Util_EListMatchingKey except that the the comparison
 * function follows the General Map ClientHandle style with client handle as a
 * parameter in the callback.
 * @param [in, out] List_p       Pointer to the list to be searched.
 * @param [in] Key_p        Pointer to a client's key. In Util_ListMatchingKey(),
 *        Key_p must point to a NULL terminated string. In
 *        Util_EListMatchingKey(), Key_p points to a key for which
 *        the type is not known to the list library.
 * @param [in] KeyMatchingFunc  The client's function to be used to compare keys with
 *                      general map ClientHandle style.
 *
 * @return void* Address of the element whose key has matched Key_p. NULL if no
 *     match has been found or if the list is invalid. The current pointer
 *     into the list points to the element returned or is not changed if
 *     the function returns NULL.
 *
 */
void *Util_EListMatchingKeyClientHandleStyle(List_t *const List_p,
	const void *const Key_p,
	const ListKeyMatchingFunctionClientHandleStyle_t KeyMatchingFunc);

/**
 * This function scans the list pointed to by List_p starting from the list's
 * current pointer. Once the tail of the list has been searched, if an element
 * has still not been found, the search resumes from the head of the list. The
 * position in the list of the first element whose key matches the key pointed
 * to by Key_p is returned. The position is counted from the head to the tail
 * starting at position 1 for the head.
 *
 * If a match is found, the list's current pointer will point to the matched
 * element. If no match is found, the list is left unchanged.
 *
 * If the matching function is NULL, Util_ListKeyedIndex() will perform an
 * integer comparison. Otherwise, the client provided routine will be used to
 * compare keys.
 *
 * See also Util_ListCurrIndex().
 *
 * @param [in, out] List_p            Pointer to the list to be searched and from
 *                     which the index to the matched element will be
 *                     returned.
 * @param [in] Key_p             Pointer to the key that identifies the
 *                     element for which the index will be returned.
 * @param [in] KeyMatchingFunc_p Client function that knows how to compare
 *             keys of the client specific key data type.
 *
 * @return int	Position of the element found in the list or -1 if the element
 *		could not be found (because the specified key is not found or
 *		input parameters are invalid).
 */

int Util_ListKeyedIndex(List_t *const List_p, const void *const Key_p,
			const ListKeyMatchingFunction_t KeyMatchingFunc_p);


/**
 * This function returns the index of the list's current element or -1 if the
 * current element is not valid. The index of the element at the head of the
 * list is 1.
 *
 * See also Util_ListKeyedIndex().
 *
 * @param [in] List_p Pointer to the list from which the index to the current
 *          element will be returned.
 *
 * @return int	Position of the element pointed to by the list's current pointer
 *				or -1 if the list's current pointer is NULL or
 *				input parameters are invalid).
 */
int Util_ListCurrIndex(const List_t *const List_p);


/**
 * This function relinks the elements from index First to Last inclusively
 * after the element at position "To". After the function has executed
 * successfully, the element at index First will appear directly after the
 * element at index To. "To" may not be between First and Last but may be
 * smaller than First or larger than Last. After successful completion, the
 * list's current pointer is reset (see Util_ListResetCurr()).
 *
 * @param [in, out] List_p Pointer to the list in which a range of elements will be
 *          moved.
 * @param [in] First  The position of the first element to be relinked.
 * @param [in] Last	  The position of the last element to be relinked.
 *	    First and Last Indices defines the range of elements to move.
 *          The range includes First and Last elements. Last must be
 *          greater or equal to First. Notice that these are not
 *          const because the function uses these variables
 *          internally and changes their values. This is done to
 *          avoid defining extra local variables and initialising
 *          them with input parameters.
 * @param [in] To     The index of the element in the list AFTER which the
 *          range of elements from First to Last will be linked.
 *          Notice that this is not a const because the function uses
 *          this variable internally and changes its value. This is
 *          done to avoid defining an extra local variable and
 *          initialising it with the input parameter.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_PARAM
 *
 */

ListResult_t Util_ListMoveSubrange(List_t *const List_p, uint16_t First,
				   uint16_t Last, uint16_t To);

/**
 * This function removes the elements from index First to index Last
 * inclusively from FromList_p and links them to the tail of the list pointed
 * to by ToList_p.
 *
 * The list current pointer is reset in both FromList_p and ToList_p.
 *
 * @param [in, out] List_p   Pointer to the list from which a range of elements
 *            will be removed.
 * @param [in] First	The position of the first element to be relinked.
 * @param [in] Last	The position of the last element to be relinked.
 *		First and Last Indices defines the range of elements to move.
 *		The range includes First and Last elements. Last must be
 *		greater or equal to First. Notice that these are not
 *		const because the function uses these variables
 *		internally and changes their values. This is done to
 *		avoid defining extra local variables and initialising
 *		them with input parameters.
 * @param [in, out] ToList_p The list where the range of elements from List_p will
 *            be linked.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_PARAM
 *
 */

ListResult_t Util_ListGetSubrange(List_t *const FromList_p, uint16_t First,
				  uint16_t Last, List_t *const ToList_p);

/**
 * This function sets the list's current pointer to NULL.
 *
 * It is typically used to prepare the list before an iteration through the
 * list using  Util_ListIsNext() or Util_ListIsPrev(). Util_ListIsNext() is
 * used to start iterating from the head and Util_ListIsPrev() is used to start
 * iterating from the tail.
 *
 * @param [in, out] List_p Pointer to the list whose current element pointer will
 *          be reset.
 *
 * @return TRUE if the list's current pointer can be reset.
 *    Otherwise, it returns FALSE (i.e. if the list is empty)
 */

bool Util_ListResetCurr(List_t *const List_p);


/**
 * This function moves the list's current pointer to the tail of the list. It
 * returns the pointer to the element at the tail of the list or NULL if the
 * list is empty.
 *
 * See also Util_ListNext(), Util_ListPrev(), Util_ListGotoHead(),
 * Util_ListGotoIth() and Util_ListCurr().
 *
 * @param [in, out] List_p Pointer to the list whose current pointer will be moved.
 *
 * @return     void* Address of the tail element. NULL if list empty.
 */
void *Util_ListGotoTail(List_t *const List_p);

/**
 * This function moves the list's current pointer to the head of the list. It
 * returns the pointer to the element at the head of the list or NULL if the
 * list is empty.
 *
 * See also Util_ListNext(), Util_ListPrev(), Util_ListGotoTail(),
 * Util_ListGotoIth() and Util_ListCurr().
 *
 * @param [in, out] List_p Pointer to the list whose current pointer will be moved.
 *
 * @return     void* Address of the head element. NULL if list empty.
 */

void *Util_ListGotoHead(List_t *const List_p);


/**
 * This function moves the list's current pointer to the i:th element of the
 * list. The head of the list is element 1, the next one is element 2 and so
 * on. It returns the pointer to the element or NULL if the list does not
 * contain at least i element(s).
 *
 * See also Util_ListNext(), Util_ListPrev(), Util_ListGotoHead(),
 * Util_ListGotoTail() and Util_ListCurr().
 *
 * @param [in, out] List_p Pointer to the list whose current pointer will be moved.
 * @param [in] i	  The element rank in the list. The head of the list is
 *          element 1, the next one is element 2 and so on.
 *
 * @return      void* Address of the current element. NULL if list empty
 *    or not long enough.
 */

void *Util_ListGotoIth(List_t *const List_p, uint16_t i);

/**
 * This function returns the pointer to the element pointed to by the list's
 * current pointer or NULL if the current pointer points outside the list.
 *
 * See also Util_ListNext(), Util_ListPrev(), Util_ListGotoHead(),
 * Util_ListGotoTail() and Util_ListGotoIth().
 *
 * @param [in] List_p Pointer to the list whose element pointed to by the
 *          list's current pointer will be returned
 *
 * @return      void* The address of the contents of the current element, null
 *    if there is no current element.
 */
void *Util_ListCurr(const List_t *const List_p);


/**
 * This function advances the list's current pointer by one element towards the
 * tail of the list. It returns the pointer to the element or NULL if the
 * current  pointer pointed to the tail of the list prior to the call.
 *
 * If the current pointer is NULL prior to the call and the list is not empty,
 * the current pointer will point to the head of the list.
 *
 * See also Util_ListPrev(), Util_ListGotoHead(), Util_ListGotoTail(),
 * Util_ListGotoIth(), Util_ListCurr() and Util_ListIsNext().
 *
 * @param [in, out] List_p Pointer to the list whose current pointer will be moved.
 *
 * @return      void* The address of the contents of the next element, NULL
 *    if there is no next element or list is empty.
 */
void *Util_ListNext(List_t *const List_p);


/**
 * This function advances the list's current pointer by one element towards the
 * tail of the list.
 *
 * If the current pointer is NULL prior to the call and the list is not empty,
 * the current pointer will point to the head of the list.
 *
 * The function returns TRUE if the current pointer has been stepped, otherwise
 * it returns FALSE.
 *
 * See also Util_ListResetCurr(), Util_ListIsPrev() and Util_ListNext().
 *
 * @param [in, out] List_p Pointer to the list whose current pointer will be moved.
 *
 * @return TRUE if the current list pointer was not already at the tail before
 *    call. Otherwise, it returns FALSE (e.g. if the list is empty)
 *
 */
bool Util_ListIsNext(List_t *const List_p);


/**
 * This function moves the list's current pointer by one element towards the
 * head of the list. It returns the pointer to the element or NULL if the
 * current  pointer pointed to the head of the list prior to the call.
 *
 * If the current pointer is NULL prior to the call and the list is not empty,
 * the current pointer will point to the tail of the list.
 *
 * See also Util_ListNext(), Util_ListGotoHead(), Util_ListGotoTail(),
 * Util_ListGotoIth(), Util_ListCurr() and Util_ListIsPrev().
 *
 * @param [in, out] List_p Pointer to the list whose current pointer will be moved.
 *
 * @return void* The address of the contents of the previous element, NULL
 *    if there is no prev element or list is empty.
 *
 */
void *Util_ListPrev(List_t *const List_p);



/**
 * This function advances the list's current pointer by one element towards the
 * head of the list.
 *
 * If the current pointer is NULL prior to the call and the list is not empty,
 * the current pointer will point to the tail of the list.
 *
 * The function returns TRUE if the current pointer has been stepped, otherwise
 * it returns FALSE.
 *
 * See also Util_ListResetCurr(), Util_ListIsNext() and Util_ListPrev().
 *
 * @param [in, out] List_p Pointer to the list whose current pointer will be moved.
 *
 * @return  TRUE if the current pointer has been stepped, otherwise
 *     it returns FALSE.
 */

bool Util_ListIsPrev(List_t *const List_p);


/**
 * This function removes the element pointed to by the list's current pointer
 * from the list. After the function has completed, the list's current pointer
 * will point to the next element or the previous element if the list's tail is
 * removed. The current pointer will be NULL after the last element in the list
 * has been removed.
 *
 * See also Util_ListDelete(), Util_ListKeyedRemove(),
 * Util_ListInsertAfter(),
 * Util_EListInsertAfter, Util_ListInsertFirst(),
 * Util_ListInsertLast(), Util_EListInsertBefore() and
 * Util_ListInsertBefore().
 *
 * @param [in, out] List_p Pointer to the list from which the element pointed to by
 *          the list's current pointer will be removed.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 * @retval LIST_ERROR_CURRENT_PTR_OFF_LIST
 *
 */

ListResult_t Util_ListRemove(List_t *const List_p);


/**
 * This function deletes the element pointed to by the list's current pointer
 * from the list. If DelFunc is not NULL, the client's delete function will
 * be called prior to removing the current element from the list. If DelFunc
 * is NULL, the element is not freed.
 *
 * See also Util_ListRemove(), Util_ListInsertAfter(), Util_EListInsertBefore()
 * and Util_ListInsertBefore().
 *
 * @param [in, out] List_p    Pointer to the list whose status will be obtained.
 * @param [in] DelFunc   Function provided by client that knows how to
 *             deallocate the resources associated with the element
 *             to be deleted. NULL indicates that the client does not
 *             require the element's resources to be deallocated
 *             within the Util_ListDelete() function.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 * @retval LIST_ERROR_CURRENT_PTR_OFF_LIST
 *
 */

ListResult_t Util_ListDelete(List_t *const List_p,
			     const ListDeleteFunction_t DelFunc);
/**
 * This function deletes the element pointed to by the list's current pointer
 * from the list. If DelFunc_p is not NULL, the client's delete function will
 * be called prior to removing the current element from the list. If DelFunc
 * is NULL, the element is not freed.
 *
 * See also Util_ListRemove(), Util_ListInsertAfter(), Util_EListInsertBefore()
 * and Util_ListInsertBefore().
 *
 * @param [in, out] List_p    Pointer to the list whose status will be obtained.
 * @param [in] DelFunc   Function provided by client that knows how to
 *             deallocate the resources associated with the element
 *             to be deleted. NULL indicates that the client does not
 *             require the element's resources to be deallocated
 *             within the Util_ListDelete() function. The DelFunc should
 *             be of type ListDeleteFunctionGeneralMap_t (see t_list.h) and
 *             is slightly different from the one used in Util_ListDelete.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 * @retval LIST_ERROR_CURRENT_PTR_OFF_LIST
 *
 */

ListResult_t Util_ListDeleteGeneralMap(List_t *const List_p,
	const ListDeleteFunctionGeneralMap_t DelFunc);

/**
 * This function deletes the element pointed to by the list's current pointer
 * from the list. If DelFunc is not NULL, the client's delete function will
 * be called prior to removing the current element from the list. If DelFunc
 * is NULL, the element is not freed. This function is slightly
 * different from above
 * Util_ListDeleteGeneralMap. Support for Client Handle is added in the
 * callback function.
 *
 * See also Util_ListRemove(), Util_ListInsertAfter(), Util_EListInsertBefore()
 * and Util_ListInsertBefore().
 *
 * @param [in, out] List_p    Pointer to the list whose status will be obtained.
 * @param [in] DelFunc   Function provided by client that knows how to
 *             deallocate the resources associated with the element
 *             to be deleted. NULL indicates that the client does not
 *             require the element's resources to be deallocated
 *             within the Util_ListDelete() function. The DelFunc should
 *             be of type ListDeleteFunctionGeneralMapClientHandleStyle_t
 *             (see t_list.h) and is slightly different from the one
 *             used in Util_ListDeleteGeneralMap. This function type
 *             include support for client handles in user callbacks.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 * @retval LIST_ERROR_CURRENT_PTR_OFF_LIST
 *
 */

ListResult_t Util_ListDeleteGeneralMapClientHandleStyle(List_t *const List_p,
	const ListDeleteFunctionGeneralMapClientHandleStyle_t DelFunc);

/**
 * This function removes and deletes all the elements in the list pointed to by
 * List_pp. If the client specified a delete function (i.e. DelFunc is not
 * NULL), it is called for each element in the list. If DelFunc_p is set to
 * NULL, the list is destroyed but the elements are not freed.
 *
 * The pointer to the list is set to NULL upon return.
 *
 * See also Util_ListCreate(), Util_EListCreate().
 *
 * @param [in, out] List_pp   Pointer to the list pointer to be destroyed.
 * @param [in] DelFunc   Function provided by client that knows how a
 *             client's element can be destroyed. NULL indicates that
 *             the elements in the list don't need to be freed while
 *             destroying the list.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 *
 */

ListResult_t Util_ListDestroy(List_t **List_pp,
			      const ListDeleteFunction_t DelFunc);

/**
 * This function removes and deletes all the elements in the list pointed to by
 * List_pp. If the client specified a delete function (i.e. DelFunc is not
 * NULL), it is called for each element in the list. If DelFunc_p is set to
 * NULL, the list is destroyed but the elements are not freed.
 *
 * The pointer to the list is set to NULL upon return.
 *
 * See also Util_ListCreate(), Util_EListCreate().
 *
 * @param [in, out] List_pp   Pointer to the list pointer to be destroyed.
 * @param [in] DelFunc   Function provided by client that knows how a
 *             client's element can be destroyed. NULL indicates that
 *             the elements in the list don't need to be freed while
 *             destroying the list.  The DelFunc should
 *             be of type ListDeleteFunctionGeneralMap_t (see t_list.h) and
 *             is slightly different from the one used in Util_ListDestroy.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 *
 */

ListResult_t Util_ListDestroyGeneralMap(List_t **List_pp,
	const ListDeleteFunctionGeneralMap_t DelFunc);

/**
 * This function removes and deletes all the elements in the list pointed to by
 * List_pp. If the client specified a delete function (i.e. DelFunc is not
 * NULL), it is called for each element in the list. If DelFunc_p is set to
 * NULL, the list is destroyed but the elements are not freed. This function is
 * slightly different from above
 * Util_ListDestroyGeneralMap. Support for Client Handle is added in the
 * callback function.
 *
 * The pointer to the list is set to NULL upon return.
 *
 * See also Util_ListCreate(), Util_EListCreate().
 *
 * @param [in, out] List_pp   Pointer to the list pointer to be destroyed.
 * @param [in] DelFunc   Function provided by client that knows how a
 *             client's element can be destroyed. NULL indicates that
 *             the elements in the list don't need to be freed while
 *             destroying the list. The DelFunc should
 *             be of type ListDeleteFunctionGeneralMapClientHandleStyle_t
 *             (see t_list.h) and is slightly different from the one
 *             used in Util_ListDestroyGeneralMap. This function type
 *             include support for client handles in user callbacks.
 *
 * @retval LIST_SUCCESS
 * @retval LIST_ERROR_INVALID_LIST
 *
 */
ListResult_t Util_ListDestroyGeneralMapClientHandleStyle(List_t **List_pp,
	const ListDeleteFunctionGeneralMapClientHandleStyle_t DelFunc);

/**
 * This function prints the information about the list. While printing
 * information about the list, the list is scanned. If debug information about
 * the element content is desired, the client must specify the debug routine,
 * DbgFunc_p, that knows how to print this information. DbgFunc_p equal to NULL
 * indicates that no debug information about the element's contents is desired.
 *
 *
 * It is ONLY meant to be used during development and integration. It should be
 * configured out of the library before the release. This can be done by
 * defining REMOVE_UF_LISTPRINTDEBUG in the product's product.defines file.
 *
 * @param [in, out] List_p    Pointer to the list whose debug information will be
 *             printed.
 * @param [in] DbgFunc Client's function that is called to
 *             print debug information about the content of the
 *             elements in the list. DbgFunc_p can be NULL.
 *
 */

void Util_ListPrintDebug(List_t *const List_p,
			 const ListDebugFunction_t DbgFunc);

/**
 * This function prints the information about the list. While printing
 * information about the list, the list is scanned. If debug information about
 * the element content is desired, the client must specify the debug routine,
 * DbgFunc_p, that knows how to print this information. DbgFunc_p equal to NULL
 * indicates that no debug information about the element's contents is desired.
 *
 * This function has been added to conform with the function type used in
 *  General Map for Util_Map_CallForEach.
 *
 * It is ONLY meant to be used during development and integration. It should be
 * configured out of the library before the release. This can be done by
 * defining REMOVE_UF_LISTPRINTDEBUGGENERALMAP in the
 * product's product.defines file.
 *
 * @param [in, out] List_p    Pointer to the list whose debug information will be
 *             printed.
 * @param [in] DbgFunc   Function of type ListDebugFunctionGeneralMap_t
 *             that agrees with the style used in general Map.
 *
 */

void Util_ListPrintDebugGeneralMap(List_t *const List_p,
				   const ListDebugFunctionGeneralMap_t DbgFunc);

/*************************************************************************
 * Macros
 **************************************************************************/

/**
 * LIST_APPEND(Element_p, Key_p, List_p) is used to insert an element at the
 * tail of a doubly linked list.
 * Example:
 *
 * List* MyList_p = NULL;
 * ClientElementType_t* MyElement_p;
 * ....
 * MyElement_p = HEAP_ALLOC(ClientElementType_t);
 * ....
 * LIST_APPEND(MyElement_p, NULL, MyList_p)
 *
 *
 * @param [in] Element_p  Pointer to the client's element to be inserted in the list
 * @param [in] Key_p      Pointer the the element's key. Key_p can be NULL.
 * @param [in] List_p     Pointer to the doubly linked list. If List_p points to NULL,
 *              then the macro will create the list.
 *
 */

#define LIST_APPEND(Element_p, Key_p, List_p) \
	{ \
		if ((List_p) == NULL) \
			(List_p) = Util_EListCreate(xmalloc, xfree); \
		Util_ListGotoTail(List_p); \
		Util_ListInsertAfter((List_p), (Key_p), (Element_p)); \
	}

/**
 * LIST_FOR_EACH_ELEMENT_IN_LIST(ElementDataType_t, Element_p, List_p)
 * iterates through all elements in the list from head to tail.
 * Example:
 * Given that the list MyList_p has been created and several elements added to
 * it, the client could iterate through the list from head to tail using the
 * following simple construct.
 *
 * LIST_FOR_EACH_ELEMENT_IN_LIST(ElementType_t, ThisElement_p, MyList_p)
 * {
 * // Here is the client code to manipulate
 *	each element (pointed to by ThisElement_p)
 * }
 *
 * @param [in] ElementDataType_t The data type of the elements in the list pointed to by List_p)
 * @param [in] Element_p         Points to the element being iterated.
 * @param [in] List_p            Pointer to the doubly linked list to be iterated.
 *
 */

#define LIST_FOR_EACH_ELEMENT_IN_LIST(ElementDataType_t, Element_p, List_p) \
	{ \
		if (!(List_p)) \
			; \
		else \
			for ((List_p)->Curr_p = (List_p)->Head_p \
			     ; \
			     (List_p)->Curr_p && NULL != \
			     ((Element_p) = \
				 (ElementDataType_t *)(List_p)->\
					Curr_p->Body_p) \
			     ; \
			     ((List_p)->Curr_p = (List_p)->Curr_p->Next_p)) \
				; \
	}

/**
 *
 * LIST_LENGTH(List_p) returns the number of elements in the list.
 * Example:
 * Given that the list MyList_p has been created and several elements added to
 * it, the client could obtain the number of elements in the list using this
 *  macro.
 *
 * uint16_t ListLength;
 * ....
 *
 * if (MyList_p)
 * {
 * ListLength = LIST_LENGTH(MyList_p);
 * }
 *
 *
 * @param [in] List_p   A pointer to the doubly linked list whose length will be obtained.
 *            LIST_LENGTH must not be expanded with a pointer to NULL
 *
 */

#define LIST_LENGTH(List_p) { (List_p)->NbrOfElements }



#endif /* INCLUSION_GUARD_R_LIST_H */
