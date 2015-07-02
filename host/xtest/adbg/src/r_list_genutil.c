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

/*************************************************************************
**************************************************************************
*
* DESCRIPTION:
*
* Source file containing the functions for the manipulation of doubly
* linked lists.
* A linked list can be created/deleted, elements can be added/removed,
* the list can be
* traversed in both directions, the current list index can be moved in
* different ways
* (to head, to tail, to a specific index). The elements in a list can be
* identified with a key (NULL terminated character string).
* The key is specified by the client.
* A function allows the client to look for the next (from head to tail)
* element with a given key. Key usage is of course optional.
* The library allocates memory only for the management of the list.
* The client's data must be allocated by the client.
* If so desired by the client, the client's data
* can however be freed when the list is destroyed.
*************************************************************************/

/*************************************************************************
* Includes
*************************************************************************/

#include "r_list.h"
#include <stdlib.h>
#include <string.h>

#define C_(x)
#define B_(x)
#define PRE_CONDITION(a, b)
#define IDENTIFIER_NOT_USED(x) { if (sizeof(&x)) {} }

/*************************************************************************
* Definition of external constants and variables
*************************************************************************/

/*************************************************************************
* File scope types, constants and variables
*************************************************************************/

/*************************************************************************
*   Declaration of file local functions
*************************************************************************/
static bool ListIntComparisonFunc(const void *AnElementKey_p,
				  const void *KeyToMatch_p);

static bool ListMoveForward(uint16_t NbrOfElement, ListItem_t **Element_pp);

/*************************************************************************
* Definition of functions
*************************************************************************/

/*************************************************************************
 *
 * Name:          ListIntComparisonFunc
 *
 * Parameters:    AnElementKey_p [In]
 *                      A pointer to an element's key
 *                KeyToMatch_p [In]
 *                      The pointer to the key to match
 *
 * Returns:       true if the element's key is equal to the key to match
 *
 * Description:   This function is used in conjunction to trying to find a key
 *                match in a linked list. The function is only used when the
 *                client of the list library does not provide a key matching
 *                function when calling Util_EListMatchingKey(), in which case,
 *                it is assumed that the key is a 32 bit unsigned integer.
 *
 **************************************************************************/
bool ListIntComparisonFunc(const void *AnElementKey_p, const void *KeyToMatch_p)
{
	if (*((uint32_t *)(AnElementKey_p)) == *((uint32_t *)(KeyToMatch_p)))
		return true;
	else
		return false;
}

/*************************************************************************
 *
 * Name:          ListMoveForward
 *
 * Parameters:    NbrOfElements [In]
 *                      Nbr of elements the list should be traversed by
 *                Element_pp [In/Out]
 *                      The pointer to the list element pointer from where
 *                      the list will be traversed.
 *                      On return, Element_pp will point to the element
 *                      That is linked NbrOfElements after the starting element.
 *
 * Returns:       true if the list could be traversed by NbrOfElements.
 *                false if the end of the list is reached before
 *		  having traversed the list by NbrOfElements.
 *
 * Description:   This function is used in conjunction with ListMoveSubrange().
 *
 **************************************************************************/
static bool ListMoveForward(uint16_t NbrOfElements, ListItem_t **Element_pp)
{
	while (NbrOfElements != 0 && *Element_pp != NULL) {
		*Element_pp = (*Element_pp)->Next_p;
		NbrOfElements--;
	}
	if (*Element_pp == NULL)
		return false;
	else
		return true;
}


/*************************************************************************
 *
 * Name:          ListStrComparisonFunc
 *
 * Parameters:    AnElementKey_p [In]
 *                      A pointer to an element's key
 *                KeyToMatch_p [In]
 *                      The pointer to the key to match
 *
 * Returns:       true if the element's key is equal to the key to match
 *
 * Description:   This function is used in conjunction to trying to find a key
 *                match in a linked list. The function is only used when the
 *                client of the list library use the obsolete
 *		  Util_ListMatchingKey()
 *                function which always expects the key to be a NULL terminated
 *                string.
 *
 **************************************************************************/
bool ListStrComparisonFunc(const void *AnElementKey_p, const void *KeyToMatch_p)
{
	if (strncmp(AnElementKey_p, KeyToMatch_p, strlen(KeyToMatch_p)) == 0)
		return true;
	else
		return false;
}

/*
 * NAME
 *	Util_EListCreate
 */
#ifndef REMOVE_UF_LISTCREATE
List_t *Util_EListCreate(const ListMemAllocFunction_t MemAlloc_p,
			 const ListMemFreeFunction_t MemFree_p)
{
	List_t *List_p;
	ListMemAllocFunction_t MyMemAlloc_p;
	ListMemFreeFunction_t MyMemFree_p;

	/* if no allocation function or no free function
		specified, then use xmalloc and xfree */
	if (MemAlloc_p && MemFree_p) {
		MyMemAlloc_p = MemAlloc_p;
		MyMemFree_p = MemFree_p;
	} else {
		MyMemAlloc_p = xmalloc;
		MyMemFree_p = xfree;
	}

	List_p = (List_t *)MyMemAlloc_p(sizeof(List_t));
	if (List_p != NULL) {
		List_p->Head_p = NULL;
		List_p->Tail_p = NULL;
		List_p->Curr_p = NULL;
		List_p->NbrOfElements = 0;
		List_p->MemAllocFunc_p = MyMemAlloc_p;
		List_p->MemFreeFunc_p = MyMemFree_p;
		List_p->ClientHandleStyle = false;
		List_p->ClientHandle_p = NULL;
	}

	C_(printf("\nUtil_EListCreate: List = 0x%x", (int)List_p);)

	return List_p;
}
#endif /* REMOVE_UF_LISTCREATE */
/*
 * NAME
 *  Util_EListCreateClientHandleStyle
 */
#ifndef REMOVE_UF_LISTCREATECLIENTHANDLESTYLE
List_t *Util_EListCreateClientHandleStyle(const void *const ClientHandle_p)
{
	List_t *List_p;

	List_p = (List_t *)xmalloc(sizeof(List_t));
	if (NULL != List_p) {
		List_p->Head_p = NULL;
		List_p->Tail_p = NULL;
		List_p->Curr_p = NULL;
		List_p->NbrOfElements = 0;
		List_p->MemAllocFunc_p = xmalloc;
		List_p->MemFreeFunc_p = xfree;
		List_p->ClientHandleStyle = true;
		List_p->ClientHandle_p = (void *)ClientHandle_p;
	}

	C_(printf("\nUtil_EListCreate: List = 0x%x", (int)List_p);)

	return List_p;
}
#endif /* REMOVE_UF_LISTCREATECLIENTHANDLESTYLE */

/*
 * NAME
 *	Util_ListLength
 *
 */
#ifndef REMOVE_UF_LISTLENGTH
ListResult_t Util_ListLength(const List_t *const List_p,
			     uint16_t *const ListLength_p)
{
	PRE_CONDITION(List_p != NULL, return LIST_ERROR_INVALID_LIST);
	PRE_CONDITION(ListLength_p != NULL, return LIST_ERROR_INVALID_PARAM);

	*ListLength_p = List_p->NbrOfElements;
	return LIST_SUCCESS;
}

#endif /* REMOVE_UF_LISTLENGTH */
/*
 * NAME
 *	Util_ListTail
 *
 *
 */
#ifndef REMOVE_UF_LISTTAIL
ListStatus_t Util_ListTail(const List_t *const List_p)
{
	ListStatus_t Result;

	PRE_CONDITION(List_p != NULL, return LIST_STATUS_INVALID_LIST);

	Result = LIST_STATUS_NOTHING_TO_REPORT;

	if (List_p->Curr_p != NULL) {
		if (List_p->Curr_p->Next_p == NULL)
			Result = LIST_STATUS_PTR_TO_TAIL;

	}
	C_(printf("\nUtil_ListHead: %d, List = 0x%x", Result, (int)List_p);)
	return Result;
}
#endif /* REMOVE_UF_LISTTAIL */

/*
 * NAME
 *	Util_ListOffList
 *
 */
#ifndef REMOVE_UF_LISTOFFLIST
ListStatus_t Util_ListOffList(const List_t *const List_p)
{
	ListStatus_t Result;

	PRE_CONDITION(List_p != NULL, return LIST_STATUS_INVALID_LIST);

	if (List_p->Curr_p == NULL)
		Result = LIST_STATUS_PTR_OFF_LIST;
	else
		Result = LIST_STATUS_NOTHING_TO_REPORT;

	C_(printf("\nUtil_ListOffList: %d, List = 0x%x", Result, (int)List_p);)
	return Result;
}
#endif /* REMOVE_UF_LISTOFFLIST */
/*
 * NAME
 *	Util_ListHead
 *
 *
 */
#ifndef REMOVE_UF_LISTHEAD
ListStatus_t Util_ListHead(const List_t *const List_p)
{
	ListStatus_t Result;

	PRE_CONDITION(List_p != NULL, return LIST_STATUS_INVALID_LIST);

	Result = LIST_STATUS_NOTHING_TO_REPORT;

	if (List_p->Curr_p != NULL) {
		if (List_p->Curr_p->Prev_p == NULL)
			Result = LIST_STATUS_PTR_TO_HEAD;

	}
	C_(printf("\nUtil_ListHead: %d, List = 0x%x", Result, (int)List_p);)
	return Result;
}
#endif /* REMOVE_UF_UTIL_LISTHEAD */
/*
 * NAME
 *	Uilt_ListIsEmpty
 *
 */
#ifndef REMOVE_UF_LISTISEMPTY
ListStatus_t Util_ListIsEmpty(const List_t *const List_p)
{
	ListStatus_t Result;

	PRE_CONDITION(List_p != NULL, return LIST_STATUS_INVALID_LIST);

	if (List_p->Head_p == NULL)
		Result = LIST_STATUS_LIST_EMPTY;
	else
		Result = LIST_STATUS_NOTHING_TO_REPORT;

	C_(printf("\nUtil_ListIsEmpty: %d, List = 0x%x", Result, (int)List_p);)
	return Result;
}
#endif
/*
 * NAME
 *	Util_EListInsertBefore
 *
 */
#ifndef REMOVE_UF_ELISTINSERTBEFORE

ListResult_t Util_EListInsertBefore(List_t *const List_p,
				    const void *const Key_p,
				    void *const ElemContent_p)
{
	ListItem_t *ListItem_p;


	PRE_CONDITION(List_p != NULL, return LIST_ERROR_INVALID_LIST);


	ListItem_p =
		(ListItem_t *)(*List_p->MemAllocFunc_p)(sizeof(ListItem_t));
	if (ListItem_p == NULL) {
		B_(printf(
			   "\nUtil_EListInsertBefore:\n  LIST_ERROR_COULD_NOT_ALLOC_MEM for Element_p = 0x%x, Key_p = 0x%x, List_p = 0x%x",
			   (int)ElemContent_p, (int)Key_p, (int)List_p);)
		return LIST_ERROR_COULD_NOT_ALLOC_MEM;
	}

	ListItem_p->EKey_p = Key_p;
	ListItem_p->Body_p = ElemContent_p;

	List_p->NbrOfElements++;

	if (List_p->Curr_p == NULL) {
		/* list is empty or we're off the list,
			add item at the head of the list */
		/* and set the current pointer to point
			to the newly added element */
		ListItem_p->Next_p = List_p->Head_p;

		if (List_p->Head_p == NULL)
			List_p->Tail_p = ListItem_p;
		else
			List_p->Head_p->Prev_p = ListItem_p;

		ListItem_p->Prev_p = NULL;
		List_p->Head_p = ListItem_p;
		List_p->Curr_p = ListItem_p;
	} else {
		if (List_p->Curr_p->Prev_p == NULL) {
			/* The current pointer points to the head of the list */
			List_p->Head_p->Prev_p = ListItem_p;
			ListItem_p->Prev_p = NULL;
			ListItem_p->Next_p = List_p->Head_p;
			List_p->Head_p = ListItem_p;
			List_p->Curr_p = ListItem_p;
		} else {
			ListItem_p->Prev_p = List_p->Curr_p->Prev_p;
			ListItem_p->Next_p = List_p->Curr_p;
			List_p->Curr_p->Prev_p->Next_p = ListItem_p;
			List_p->Curr_p->Prev_p = ListItem_p;
			List_p->Curr_p = ListItem_p;
		}
	}
	C_(printf(
		   "\nUtil_EListInsertBefore:\n  LIST_SUCCESS for Element_p = 0x%x, Key_p = 0x%x, List_p = 0x%x",
		   (int)ElemContent_p, (int)Key_p, (int)List_p);)
	return LIST_SUCCESS;
}

#endif /* REMOVE_UF_ELISTINSERTBEFORE */


/*
 * NAME
 *	Util_ListInsertFirst
 *
 */
#ifndef REMOVE_UF_LISTINSERTFIRST

ListResult_t Util_ListInsertFirst(List_t *const List_p,
				  const void *const Key_p,
				  void *const ElemContent_p)
{
	ListItem_t *ListItem_p;

	PRE_CONDITION(List_p != NULL, return LIST_ERROR_INVALID_LIST);


	ListItem_p =
		(ListItem_t *)(*List_p->MemAllocFunc_p)(sizeof(ListItem_t));
	if (ListItem_p == NULL) {
		B_(printf(
			   "\nUtil_EListInsertBefore:\n  LIST_ERROR_COULD_NOT_ALLOC_MEM for Element_p = 0x%x, Key_p = 0x%x, List_p = 0x%x",
			   (int)ElemContent_p, (int)Key_p, (int)List_p);)
		return LIST_ERROR_COULD_NOT_ALLOC_MEM;
	}

	ListItem_p->EKey_p = Key_p;
	ListItem_p->Body_p = ElemContent_p;
	List_p->NbrOfElements++;


	ListItem_p->Next_p = List_p->Head_p;

	if (List_p->Head_p == NULL) {
		/* list is empty */
		List_p->Tail_p = ListItem_p;
	} else {
		/* list is not empty, link element at the head */
		List_p->Head_p->Prev_p = ListItem_p;
	}
	ListItem_p->Prev_p = NULL;
	List_p->Head_p = ListItem_p;

	C_(printf(
		   "\nUtil_ListInsertFirst:\n  LIST_SUCCESS for Element_p = 0x%x, Key_p = 0x%x, List_p = 0x%x",
		   (int)ElemContent_p, (int)Key_p, (int)List_p);)
	return LIST_SUCCESS;
}
#endif /* REMOVE_UF_LISTINSERTFIRST */


/*
 * NAME
 *	Util_EListInsertAfter
 *
 */
#ifndef REMOVE_UF_ELISTINSERTAFTER

ListResult_t Util_EListInsertAfter(List_t *const List_p,
				   const void *const Key_p,
				   void *const ElemContent_p)
{
	ListItem_t *ListItem_p;

	PRE_CONDITION(List_p != NULL, return LIST_ERROR_INVALID_LIST);

	ListItem_p =
		(ListItem_t *)(*List_p->MemAllocFunc_p)(sizeof(ListItem_t));
	if (ListItem_p == NULL) {
		B_(printf(
			   "\nUtil_EListInsertAfter:\n  LIST_ERROR_COULD_NOT_ALLOC_MEM for Element = 0x%x, Key_p = 0x%x, List = 0x%x",
			   (int)ElemContent_p, (int)Key_p, (int)List_p);)
		return LIST_ERROR_COULD_NOT_ALLOC_MEM;
	}

	ListItem_p->EKey_p = Key_p;
	ListItem_p->Body_p = ElemContent_p;

	List_p->NbrOfElements++;

	if (List_p->Curr_p == NULL) {
		/* list is empty or we're off the list,
			add item at the tail of the list */
		ListItem_p->Prev_p = List_p->Tail_p;
		if (List_p->Head_p == NULL)
			List_p->Head_p = ListItem_p;
		else
			List_p->Tail_p->Next_p = ListItem_p;

		ListItem_p->Next_p = NULL;
		List_p->Tail_p = ListItem_p;
		List_p->Curr_p = ListItem_p;
	} else {
		if (List_p->Curr_p->Next_p == NULL) {
			List_p->Tail_p->Next_p = ListItem_p;
			ListItem_p->Next_p = NULL;
			ListItem_p->Prev_p = List_p->Tail_p;
			List_p->Tail_p = ListItem_p;
			List_p->Curr_p = ListItem_p;
		} else {
			ListItem_p->Next_p = List_p->Curr_p->Next_p;
			ListItem_p->Prev_p = List_p->Curr_p;
			List_p->Curr_p->Next_p->Prev_p = ListItem_p;
			List_p->Curr_p->Next_p = ListItem_p;
			List_p->Curr_p = ListItem_p;
		}
	}
	C_(printf(
		   "\nUtil_EListInsertAfter:\n  LIST_SUCCESS for Element_p = 0x%x, Key_p = 0x%x, List_p = 0x%x",
		   (int)ElemContent_p, (int)Key_p, (int)List_p);)
	return LIST_SUCCESS;
}
#endif /* REMOVE_UF_ELISTINSERTAFTER */


/*
 * NAME
 *	Util_ListInsertLast
 *
 */
#ifndef REMOVE_UF_LISTINSERTLAST

ListResult_t Util_ListInsertLast(List_t *const List_p,
				 const void *const Key_p,
				 void *const ElemContent_p)
{
	ListItem_t *ListItem_p;

	PRE_CONDITION(List_p != NULL, return LIST_ERROR_INVALID_LIST);


	ListItem_p =
		(ListItem_t *)(*List_p->MemAllocFunc_p)(sizeof(ListItem_t));
	if (ListItem_p == NULL) {
		B_(printf(
			   "\nUtil_ListInsertLast:\n  LIST_ERROR_COULD_NOT_ALLOC_MEM for Element = 0x%x, Key_p = 0x%x, List = 0x%x",
			   (int)ElemContent_p, (int)Key_p, (int)List_p);)
		return LIST_ERROR_COULD_NOT_ALLOC_MEM;
	}

	ListItem_p->EKey_p = Key_p;
	ListItem_p->Body_p = ElemContent_p;

	List_p->NbrOfElements++;

	/* Insert the element at the tail of the list */
	ListItem_p->Prev_p = List_p->Tail_p;
	if (List_p->Head_p == NULL) {
		/* list is empty */
		List_p->Head_p = ListItem_p;
	} else {
		/* list is not empty, link element at the tail */
		List_p->Tail_p->Next_p = ListItem_p;
	}

	ListItem_p->Next_p = NULL;
	List_p->Tail_p = ListItem_p;

	C_(printf(
		   "\nUtil_ListInsertLast:\n  LIST_SUCCESS for Element_p = 0x%x, Key_p = 0x%x, List_p = 0x%x",
		   (int)ElemContent_p, (int)Key_p, (int)List_p);)
	return LIST_SUCCESS;
}
#endif /* REMOVE_UF_LISTINSERTLAST */


/*
 * NAME
 *	Util_ListGotoTail
 *
 */
#ifndef REMOVE_UF_LISTGOTOTAIL
#ifdef REMOVE_UF_LISTCURR
#undef REMOVE_UF_LISTCURR
#endif
void *Util_ListGotoTail(List_t *const List_p)
{
	PRE_CONDITION(List_p != NULL, return NULL);

	List_p->Curr_p = List_p->Tail_p;
	C_(printf("\nUtil_ListGotoTail: List = 0x%x", (int)List_p);)
	return Util_ListCurr(List_p);
}
#endif /* REMOVE_UF_LISTGOTOTAIL */

#ifndef REMOVE_UF_LISTRESETCURR
bool Util_ListResetCurr(List_t *const List_p)
{
	PRE_CONDITION(List_p != NULL, return false);

	List_p->Curr_p = NULL;
	C_(printf("\nUtil_ListResetCurr: List = 0x%x", (int)List_p);)
	return true;
}
#endif /* REMOVE_UF_LISTRESETCURR */

/*
 * NAME
 *	Util_ListGotoHead
 *
 */
#ifndef REMOVE_UF_LISTGOTOHEAD
#ifdef REMOVE_UF_LISTCURR
#undef REMOVE_UF_LISTCURR
#endif
void *Util_ListGotoHead(List_t *const List_p)
{
	PRE_CONDITION(List_p != NULL, return NULL);

	List_p->Curr_p = List_p->Head_p;
	C_(printf("\nUtil_ListGotoHead: List = 0x%x", (int)List_p);)
	return Util_ListCurr(List_p);
}
#endif /* REMOVE_UF_LISTGOTOHEAD */


/*
 * NAME
 *	Util_ListGotoIth
 *
 */
#ifndef REMOVE_UF_LISTGOTOITH
#ifdef REMOVE_UF_LISTCURR
#undef REMOVE_UF_LISTCURR
#endif
void *Util_ListGotoIth(List_t *const List_p, uint16_t i)
{
	PRE_CONDITION((List_p != NULL) && (i >= 1), return NULL);

	List_p->Curr_p = List_p->Head_p;
	while ((List_p->Curr_p != NULL) && (i > 1)) {
		List_p->Curr_p = List_p->Curr_p->Next_p;
		i--;
	}
	C_(printf("\nUtil_ListGotoIth: list 0x%x pointing to the %dth element",
		  (int)List_p, i);)
	return Util_ListCurr(List_p);
}
#endif /* REMOVE_UF_LISTGOTOITH */


/*
 * NAME
 *	Util_ListIsNext
 */
#ifndef REMOVE_UF_LISTISNEXT
#ifdef REMOVE_UF_LISTSTATUS
#undef REMOVE_UF_LISTSTATUS
#endif
bool Util_ListIsNext(List_t *const List_p)
{
	ListStatus_t Status;

	Status = Util_ListStatus(List_p);
	if (Status &
	    (LIST_STATUS_PTR_TO_TAIL |
	     LIST_STATUS_LIST_EMPTY |
	     LIST_STATUS_INVALID_LIST)
	    ) {
		return false;
	} else {
		if (Status & LIST_STATUS_PTR_OFF_LIST)
			List_p->Curr_p = List_p->Head_p;
		else
			List_p->Curr_p = List_p->Curr_p->Next_p;

		return true;
	}
}
#endif

/*
 * NAME
 *	Util_ListIsPrev
 */
#ifndef REMOVE_UF_LISTISPREV
#ifdef REMOVE_UF_LISTSTATUS
#undef REMOVE_UF_LISTSTATUS
#endif
bool Util_ListIsPrev(List_t *const List_p)
{
	ListStatus_t Status;

	Status = Util_ListStatus(List_p);
	if (Status &
	    (LIST_STATUS_PTR_TO_HEAD |
	     LIST_STATUS_LIST_EMPTY |
	     LIST_STATUS_INVALID_LIST)
	    ) {
		return false;
	} else {
		if (Status & LIST_STATUS_PTR_OFF_LIST)
			List_p->Curr_p = List_p->Tail_p;
		else
			List_p->Curr_p = List_p->Curr_p->Prev_p;

		return true;
	}
}
#endif

/*
 * NAME
 *	Util_ListStatus
 *
 */
#ifndef REMOVE_UF_LISTSTATUS
ListStatus_t Util_ListStatus(const List_t *const List_p)
{
	ListStatus_t Result = LIST_STATUS_NOTHING_TO_REPORT; /* = 0 */

	PRE_CONDITION(List_p != NULL, return LIST_STATUS_INVALID_LIST);

	if (List_p->Head_p == NULL) {
		Result = LIST_STATUS_LIST_EMPTY;
	} else if (List_p->Curr_p == NULL) {
		Result = LIST_STATUS_PTR_OFF_LIST;
	} else {
		if (List_p->Curr_p->Next_p == NULL)
			Result = LIST_STATUS_PTR_TO_TAIL;

		if (List_p->Curr_p->Prev_p == NULL)
			Result |= LIST_STATUS_PTR_TO_HEAD;

	}
	C_(printf("\nUtil_ListStatus: %d, List = 0x%x", Result, (int)List_p);)
	return Result;
}
#endif /* REMOVE_UF_LISTSTATUS */


/*
 * NAME
 *	Util_ListNext
 *
 */
#ifndef REMOVE_UF_LISTNEXT
#ifdef REMOVE_UF_LISTCURR
#undef REMOVE_UF_LISTCURR
#endif
void *Util_ListNext(List_t *const List_p)
{
	PRE_CONDITION(List_p != NULL, return NULL);

	if (List_p->Curr_p == NULL) {
		if (List_p->Head_p == NULL) {
			B_(printf("\nUtil_ListNext: List = 0x%x is empty",
				  (int)List_p);)
			return NULL;
		} else {
			List_p->Curr_p = List_p->Head_p;
		}
	} else {
		List_p->Curr_p = List_p->Curr_p->Next_p;
	}
	return Util_ListCurr(List_p);
}
#endif /* REMOVE_UF_LISTNEXT */


/*
 * NAME
 *	Util_ListPrev
 *
 */
#ifndef REMOVE_UF_LISTPREV
#ifdef REMOVE_UF_LISTCURR
#undef REMOVE_UF_LISTCURR
#endif
void *Util_ListPrev(List_t *const List_p)
{
	PRE_CONDITION(List_p != NULL, return NULL);

	if (List_p->Curr_p == NULL) {
		if (List_p->Head_p == NULL) {
			B_(printf("\nUtil_ListPrev: List = 0x%x is empty",
				  (int)List_p);)
			return NULL;
		} else {
			List_p->Curr_p = List_p->Tail_p;
		}
	} else {
		List_p->Curr_p = List_p->Curr_p->Prev_p;
	}

	return Util_ListCurr(List_p);
}
#endif /* REMOVE_UF_LISTPREV */


/*
 * NAME
 *	Util_ListKeyedRemove
 *
 */
#ifndef REMOVE_UF_LISTKEYEDREMOVE
#ifdef REMOVE_UF_LISTREMOVE
#undef REMOVE_UF_LISTREMOVE
#endif

ListResult_t Util_ListKeyedRemove(List_t *const List_p,
				  const void *const Key_p,
				  const ListKeyMatchingFunction_t
					KeyMatchingFunc_p)
{
	PRE_CONDITION((List_p != NULL) && (Key_p != NULL),
		      return LIST_ERROR_INVALID_PARAM);

	/* Make sure the list is not empty */
	if (List_p->Head_p == NULL) {
		return LIST_ERROR_NO_MATCH_FOUND;
	} else {
		/* the "current" item in the list at
			the time the function is entered */
		ListItem_t *Temp_p;
		/* Last element of the list that
			should be checked for a matchhing key */
		ListItem_t *LastElement_p;
		ListKeyMatchingFunction_t ComparisonFunc_p;

		Temp_p = List_p->Curr_p;
		LastElement_p = Temp_p;

		if (List_p->Curr_p == NULL) {
			List_p->Curr_p = List_p->Head_p;
			LastElement_p = List_p->Head_p;
		}

		if (KeyMatchingFunc_p == NULL)
			ComparisonFunc_p = ListIntComparisonFunc;
		else
			ComparisonFunc_p = KeyMatchingFunc_p;

		do {
			if (List_p->Curr_p->EKey_p != NULL) {
				if ((*ComparisonFunc_p)(List_p->Curr_p->EKey_p,
							Key_p)) {
					C_(printf(
						   "\nUtil_ListKeyedRemove: Found a match, List = 0x%x",
						   (int)List_p);)
					return Util_ListRemove(List_p);
				}
			}
			List_p->Curr_p = List_p->Curr_p->Next_p;
			/* wrap around */
			if (List_p->Curr_p == NULL)
				List_p->Curr_p = List_p->Head_p;

		} while (List_p->Curr_p != LastElement_p);

		C_(printf("\nUtil_ListKeyedRemove: NULL, List = 0x%x",
			  (int)List_p);)
		List_p->Curr_p = Temp_p;

		return LIST_ERROR_NO_MATCH_FOUND;
	}
}
#endif /* REMOVE_UF_LISTKEYEDREMOVE */

/*
 * NAME
 *	Util_EListMatchingKey
 *
 */
#ifndef REMOVE_UF_ELISTMATCHINGKEY
#ifdef REMOVE_UF_LISTCURR
#undef REMOVE_UF_LISTCURR
#endif

void *Util_EListMatchingKey(List_t *const List_p,
			    const void *const Key_p,
			    const ListKeyMatchingFunction_t KeyMatchingFunc_p)
{
	PRE_CONDITION((List_p != NULL) && (Key_p != NULL), return NULL);

	/* Make sure the list is not empty */
	if (List_p->Head_p == NULL) {
		return NULL;
	} else {
		/* the "current" item in the
			list at the time the function is entered */
		ListItem_t *Temp_p;
		/* Last element of the list
			that should be checked for a matchhing key */
		ListItem_t *LastElement_p;
		ListKeyMatchingFunction_t ComparisonFunc_p;

		Temp_p = List_p->Curr_p;
		LastElement_p = Temp_p;

		if (List_p->Curr_p == NULL) {
			List_p->Curr_p = List_p->Head_p;
			LastElement_p = List_p->Head_p;
		}

		if (KeyMatchingFunc_p == NULL)
			ComparisonFunc_p = ListIntComparisonFunc;
		else
			ComparisonFunc_p = KeyMatchingFunc_p;

		do {
			if (List_p->Curr_p->EKey_p != NULL) {
				if ((*ComparisonFunc_p)(List_p->Curr_p->EKey_p,
							Key_p)) {
					C_(printf(
						   "\nUtil_EListMatchingKey: Found a match, List = 0x%x",
						   (int)List_p);)
					return Util_ListCurr(List_p);
				}
			}
			List_p->Curr_p = List_p->Curr_p->Next_p;
			/* wrap around */
			if (List_p->Curr_p == NULL)
				List_p->Curr_p = List_p->Head_p;

		} while (List_p->Curr_p != LastElement_p);

		C_(printf("\nUtil_EListMatchingKey: NULL, List = 0x%x",
			  (int)List_p);)
		List_p->Curr_p = Temp_p;
		return NULL;
	}
}

#endif /* REMOVE_UF_ELISTMATCHINGKEY */

/*
 * NAME
 *  Util_EListMatchingKeyClientHandleStyle
 *
 */
#ifndef REMOVE_UF_ELISTMATCHINGKEYREMOVECLIENTHANDLESTYLE
#ifdef REMOVE_UF_LISTCURR
#undef REMOVE_UF_LISTCURR
#endif

void *Util_EListMatchingKeyClientHandleStyle(List_t *const List_p,
			const void *const Key_p,
			const ListKeyMatchingFunctionClientHandleStyle_t
			KeyMatchingFunc_p)
{
	PRE_CONDITION((NULL != List_p) && (NULL != Key_p), return NULL);

	/* Make sure the list is not empty */
	if (NULL == List_p->Head_p) {
		return NULL;
	} else {
		/* the "current" item in the
			list at the time the function is entered */
		ListItem_t *Temp_p;
		/* Last element of the list
			that should be checked for a matchhing key */
		ListItem_t *LastElement_p;

		Temp_p = List_p->Curr_p;
		LastElement_p = Temp_p;

		if (NULL == List_p->Curr_p) {
			List_p->Curr_p = List_p->Head_p;
			LastElement_p = List_p->Head_p;
		}

		do {
			if (NULL != List_p->Curr_p->EKey_p) {
				if ((*KeyMatchingFunc_p)(List_p->ClientHandle_p,
							 List_p->Curr_p->EKey_p,
							 Key_p)) {
					C_(printf(
						   "\nUtil_EListMatchingKey: Found a match, List = 0x%x",
						   (int)List_p);)
					return Util_ListCurr(List_p);
				}
			}
			List_p->Curr_p = List_p->Curr_p->Next_p;
			/* wrap around */
			if (List_p->Curr_p == NULL)
				List_p->Curr_p = List_p->Head_p;

		} while (List_p->Curr_p != LastElement_p);

		C_(printf("\nUtil_EListMatchingKey: NULL, List = 0x%x",
			  (int)List_p);)
		List_p->Curr_p = Temp_p;
		return NULL;
	}
}
#endif /* REMOVE_UF_ELISTMATCHINGKEYREMOVECLIENTHANDLESTYLE */

/*
 * NAME
 *	Util_ListKeyedIndex
 *
 */
#ifndef REMOVE_UF_LISTKEYEDINDEX

int Util_ListKeyedIndex(List_t *const List_p,
			const void *const Key_p,
			const ListKeyMatchingFunction_t KeyMatchingFunc_p)
{
	PRE_CONDITION((List_p != NULL) && (Key_p != NULL), return -1);

	/* Make sure the list is not empty */
	if (List_p->Head_p == NULL) {
		return -1;
	} else {
		/* the "current" item in the
			list at the time the function is entered */
		ListItem_t *Temp_p;

		ListKeyMatchingFunction_t ComparisonFunc_p;
		int PositionInList;

		if (KeyMatchingFunc_p == NULL)
			ComparisonFunc_p = ListIntComparisonFunc;
		else
			ComparisonFunc_p = KeyMatchingFunc_p;

		Temp_p = List_p->Curr_p;
		List_p->Curr_p = List_p->Head_p;
		PositionInList = 1;
		do {
			if (List_p->Curr_p->EKey_p != NULL) {
				if ((*ComparisonFunc_p)(List_p->Curr_p->EKey_p,
							Key_p)) {
					C_(printf(
						   "\nUtil_ListKeyedIndex: Found, List = 0x%x",
						   (int)List_p);)
					return PositionInList;
				}
			}
			PositionInList++;
			List_p->Curr_p = List_p->Curr_p->Next_p;
		} while (List_p->Curr_p != NULL);

		C_(printf("\nUtil_ListKeyedIndex: Not Found, List = 0x%x",
			  (int)List_p);)
		List_p->Curr_p = Temp_p;
		return -1;
	}
}

#endif /* REMOVE_UF_LISTKEYEDINDEX */


/*
 * NAME
 *	Util_ListCurrIndex
 *
 */
#ifndef REMOVE_UF_LISTCURRINDEX

int Util_ListCurrIndex(const List_t *const List_p)
{
	if (List_p == NULL || List_p->Curr_p == NULL || List_p->Head_p ==
	    NULL) {
		B_(printf(
			   "\nUtil_ListKeyedIndex: invalid input parameters, \n  List = 0x%x",
			   (int)List_p);)
		return -1;
	}

	/* the "current" item in the
		list at the time the function is entered */
	ListItem_t *Temp_p;

	int PositionInList;

	Temp_p = List_p->Head_p;
	PositionInList = 1;

	while (Temp_p != List_p->Curr_p && Temp_p != NULL) {
		PositionInList++;
		Temp_p = Temp_p->Next_p;
	}
	if (Temp_p == List_p->Curr_p) {
		C_(printf("\nUtil_ListCurrIndex: Found, List = 0x%x",
			  (int)List_p);)
		return PositionInList;
	} else {
		C_(printf("\nUtil_ListCurrIndex: Not Found, List = 0x%x",
			  (int)List_p);)
		return -1;
	}
}

#endif /* REMOVE_UF_LISTCURRINDEX */



#ifndef REMOVE_UF_LISTMOVESUBRANGE

ListResult_t Util_ListMoveSubrange(List_t *const List_p,
				   uint16_t First,
				   uint16_t Last,
				   uint16_t To)
{
	ListItem_t *First_p;
	ListItem_t *Last_p;

	ListItem_t *After_p;
	ListItem_t *BeforeFirst_p;
	uint16_t DeltaIndexToNext;
	ListItem_t *To_p = NULL;

	First--;
	Last--;
	To--;

	PRE_CONDITION((List_p != NULL) &&
		      ((First > To) || (To > Last)) && (First <= Last),
		      return LIST_ERROR_INVALID_PARAM);

	if (To < First) {
		To_p = List_p->Head_p;
		if (!ListMoveForward(To, &To_p))
			return LIST_ERROR_INVALID_PARAM;

		DeltaIndexToNext = First - To;
		First_p = To_p;
	} else {
		DeltaIndexToNext = First;
		First_p = List_p->Head_p;
	}


	if (!ListMoveForward(DeltaIndexToNext, &First_p))
		return LIST_ERROR_INVALID_PARAM;

	DeltaIndexToNext = Last - First;
	Last_p = First_p;
	if (!ListMoveForward(DeltaIndexToNext, &Last_p))
		return LIST_ERROR_INVALID_PARAM;

	if (To > Last) {
		DeltaIndexToNext = To - Last;
		To_p = Last_p;
		if (!ListMoveForward(DeltaIndexToNext, &To_p))
			return LIST_ERROR_INVALID_PARAM;
	}

	/* Patch the hole left after removing the
		elements from first to last. */
	BeforeFirst_p = First_p->Prev_p;
	After_p = Last_p->Next_p;
	if (BeforeFirst_p != NULL) {
		BeforeFirst_p->Next_p = After_p;
	} else {
		/* The head of the list pointed to
			First_p before the call, */
		/* It should now point to the first
			element after Last_p */
		List_p->Head_p = After_p;
	}

	if (After_p != NULL) {
		After_p->Prev_p = BeforeFirst_p;
	} else {
		/* The tail of the list pointed to Last_p before the call, */
		/* It should now point to the element
			before the first element removed */
		List_p->Tail_p = BeforeFirst_p;
	}

	/* Insert the removed elements after the element pointed to by To_p */
	if (To_p != NULL) {
		After_p = To_p->Next_p;

		To_p->Next_p = First_p;
		First_p->Prev_p = To_p;
	}
	Last_p->Next_p = After_p;
	if (After_p != NULL) {
		After_p->Prev_p = Last_p;
	} else {
		/* The tail of the list pointed to To_p prior to the call, */
		/* The tail of the list becomes the last element moved */
		List_p->Tail_p = Last_p;
	}

	List_p->Curr_p = NULL;

	C_(printf(
		   "\nUtil_ListMoveSub: Reordered elements in list OK, List = 0x%x",
		   (int)List_p);)
	return LIST_SUCCESS;
}
#endif /* REMOVE_UF_LISTMOVESUBRANGE */


#ifndef REMOVE_UF_LISTGETSUBRANGE

ListResult_t Util_ListGetSubrange(List_t *const FromList_p,
				  uint16_t First,
				  uint16_t Last,
				  List_t *const ToList_p)
{
	ListItem_t *First_p;
	ListItem_t *Last_p;
	ListItem_t *BeforeFirst_p;
	ListItem_t *AfterLast_p;
	uint16_t NbrOfElementsToMove;

	First--;
	Last--;

	PRE_CONDITION((FromList_p != NULL) && (ToList_p != NULL) &&
		      (First <= Last),
		      return LIST_ERROR_INVALID_PARAM);

	NbrOfElementsToMove = Last + 1 - First;

	First_p = FromList_p->Head_p;
	if (!ListMoveForward(First, &First_p))
		return LIST_ERROR_INVALID_PARAM;

	Last -= First;
	Last_p = First_p;
	if (!ListMoveForward(Last, &Last_p))
		return LIST_ERROR_INVALID_PARAM;

	/* relink the elements in FromList_p */
	BeforeFirst_p = First_p->Prev_p;
	AfterLast_p = Last_p->Next_p;
	if (BeforeFirst_p != NULL) {
		BeforeFirst_p->Next_p = AfterLast_p;
	} else {
		/* The head of the list pointed to
			First_p before the call, */
		/* It should now point to the first
			element after Last_p */
		FromList_p->Head_p = AfterLast_p;
	}

	if (AfterLast_p != NULL) {
		AfterLast_p->Prev_p = BeforeFirst_p;
	} else {
		/* The tail of the list pointed to
			Last_p before the call, */
		/* It should now point to the element
			before the first element removed */
		FromList_p->Tail_p = BeforeFirst_p;
	}

	ToList_p->NbrOfElements += NbrOfElementsToMove;
	FromList_p->NbrOfElements -= NbrOfElementsToMove;

	/* Initialize the ToList */
	if (ToList_p->Tail_p == NULL) {
		/* ToList_p is empty, First_p becomes
			the head and Last_p becomes the tail */
		ToList_p->Head_p = First_p;
		First_p->Prev_p = NULL;

		ToList_p->Tail_p = Last_p;
		Last_p->Next_p = NULL;
	} else {
		/* Link the elements removed from
			FromList_p to the tail of ToList_p */
		ToList_p->Tail_p->Next_p = First_p;
		First_p->Prev_p = ToList_p->Tail_p;

		ToList_p->Tail_p = Last_p;
		Last_p->Next_p = NULL;
	}

	/* The current pointer in FromList_p and ToList_p are reset. */
	ToList_p->Curr_p = NULL;
	FromList_p->Curr_p = NULL;

	C_(printf("\nUtil_ListGetSubrange: OK, ToList = 0x%x", (int)ToList_p);)
	return LIST_SUCCESS;
}
#endif /* REMOVE_UF_LISTGETSUBRANGE */

/*
 * NAME
 *	Util_ListCurr
 *
 */
#ifndef REMOVE_UF_LISTCURR
void *Util_ListCurr(const List_t *const List_p)
{
	PRE_CONDITION(List_p != NULL, return NULL);

	if (List_p->Curr_p == NULL) {
		C_(printf(
			   "\nUtil_ListCurrent: list element pointer is NULL, List = 0x%x",
			   (int)List_p);)
		return NULL;
	} else {
		C_(printf(
			   "\nUtil_ListCurrent: list element pointer is 0x%x, List = 0x%x",
			   (int)List_p->Curr_p->Body_p, (int)List_p);)
		return List_p->Curr_p->Body_p;
	}
}
#endif /* REMOVE_UF_LISTCURR */

/*
 * NAME
 *	Util_ListDestroy
 *
 */
#ifndef REMOVE_UF_LISTDESTROY
#ifdef REMOVE_UF_LISTDELETE
#undef REMOVE_UF_LISTDELETE
#endif
ListResult_t Util_ListDestroy(List_t **List_pp,
			      const ListDeleteFunction_t DelFunc_p)
{
	ListResult_t Result = LIST_SUCCESS;
	List_t *List_p = *List_pp;

	PRE_CONDITION(List_p != NULL, return LIST_ERROR_INVALID_LIST);

	/* traverse the list from the head */
	List_p->Curr_p = List_p->Head_p;

	while ((List_p->Curr_p != NULL) && (Result == LIST_SUCCESS))
		Result = Util_ListDelete(List_p, DelFunc_p);

	if (Result == LIST_SUCCESS) {
		(*List_p->MemFreeFunc_p)(List_p);
		*List_pp = NULL;
	}
	C_(printf("\nUtil_ListDestroy: Return = %d, List = 0x%x is destroyed",
		  Result, (int)List_p);)
	return Result;
}
#endif /* REMOVE_UF_LISTDESTROY */

/*
 * NAME
 *  Util_ListDestroyGeneralMap
 * special attention for the delete function callback due to general map.
 * General map allows seperate allocation for key and value therefore must
 * the callback include both these parameters
 */
#ifndef REMOVE_UF_LISTDESTROYGENERALMAP
#ifdef REMOVE_UF_LISTDELETEGENERALMAP
#undef REMOVE_UF_LISTDELETEGENERALMAP
#endif
ListResult_t Util_ListDestroyGeneralMap(List_t **List_pp,
			const ListDeleteFunctionGeneralMap_t DelFunc_p)
{
	ListResult_t Result = LIST_SUCCESS;
	List_t *List_p = *List_pp;

	PRE_CONDITION(NULL != List_p, return LIST_ERROR_INVALID_LIST);

	/* traverse the list from the head */
	List_p->Curr_p = List_p->Head_p;

	while ((NULL != List_p->Curr_p) && (LIST_SUCCESS == Result))
		Result = Util_ListDeleteGeneralMap(List_p, DelFunc_p);

	if (LIST_SUCCESS == Result) {
		(*List_p->MemFreeFunc_p)(List_p);
		*List_pp = NULL;
	}
	C_(printf("\nUtil_ListDestroy: Return = %d, List = 0x%x is destroyed",
		  Result, (int)List_p);)
	return Result;
}
#endif /* REMOVE_UF_LISTDESTROYGENERALMAP */

/*
 * NAME
 *  Util_ListDestroyGeneralMap
 * Special attention to ClientHandle style with client handler in callbacks
 */
#ifndef REMOVE_UF_LISTDESTROYGENERALMAPCLIENTHANDLESTYLE
#ifdef REMOVE_UF_LISTDELETEGENERALMAPCLIENTHANDLESTYLE
#undef REMOVE_UF_LISTDELETEGENERALMAPCLIENTHANDLESTYLE
#endif
ListResult_t Util_ListDestroyGeneralMapClientHandleStyle(List_t **List_pp,
		const ListDeleteFunctionGeneralMapClientHandleStyle_t DelFunc_p)
{
	ListResult_t Result = LIST_SUCCESS;
	List_t *List_p = *List_pp;

	PRE_CONDITION(NULL != List_p, return LIST_ERROR_INVALID_LIST);

	/* traverse the list from the head */
	List_p->Curr_p = List_p->Head_p;

	while ((NULL != List_p->Curr_p) && (LIST_SUCCESS == Result))
		Result = Util_ListDeleteGeneralMapClientHandleStyle(List_p,
								    DelFunc_p);

	if (LIST_SUCCESS == Result) {
		(*List_p->MemFreeFunc_p)(List_p);
		*List_pp = NULL;
	}
	C_(printf("\nUtil_ListDestroy: Return = %d, List = 0x%x is destroyed",
		  Result, (int)List_p);)
	return Result;
}
#endif /* REMOVE_UF_LISTDESTROYGENERALMAPCLIENTHANDLESTYLE */


/*
 * NAME
 *	Util_ListDelete
 *
 */
#ifndef REMOVE_UF_LISTDELETE
#ifdef REMOVE_UF_LISTREMOVE
#undef REMOVE_UF_LISTREMOVE
#endif
ListResult_t Util_ListDelete(List_t *const List_p,
			     const ListDeleteFunction_t DelFunc_p)
{
	PRE_CONDITION(List_p != NULL, return LIST_ERROR_INVALID_LIST);

	if (List_p->Curr_p == NULL) {
		/* list is empty or no current element, nothing to remove */
		B_(printf(
			   "\nUtil_ListDelete: LIST_ERROR_CURRENT_PTR_OFF_LIST, List = 0x%x is empty",
			   (int)List_p);)
		return LIST_ERROR_CURRENT_PTR_OFF_LIST;
	}

	/* delete the element body using the application's delete callback */
	if (DelFunc_p != NULL) {
		C_(printf(
			   "\nUtil_ListDelete: Calling application delete function: List_p = 0x%x",
			   (int)List_p);)
			(*(DelFunc_p)) (List_p->Curr_p->Body_p);
	}

	return Util_ListRemove(List_p);
}
#endif /* REMOVE_UF_LISTDELETE */

/*
 * NAME
 *  Util_ListDeleteGeneralMap
 * Changes due to general map is propagated from destoy function
 */
#ifndef REMOVE_UF_LISTDELETEGENERALMAP
#ifdef REMOVE_UF_LISTREMOVE
#undef REMOVE_UF_LISTREMOVE
#endif
ListResult_t Util_ListDeleteGeneralMap(List_t *const List_p,
	const ListDeleteFunctionGeneralMap_t DelFunc_p)
{
	PRE_CONDITION(NULL != List_p, return LIST_ERROR_INVALID_LIST);

	if (NULL == List_p->Curr_p) {
		/* list is empty or no current element, nothing to remove */
		B_(printf(
			   "\nUtil_ListDelete: LIST_ERROR_CURRENT_PTR_OFF_LIST, List = 0x%x is empty",
			   (int)List_p);)
		return LIST_ERROR_CURRENT_PTR_OFF_LIST;
	}

	/* delete the element body using the application's delete callback */
	if (NULL != DelFunc_p) {
		C_(printf(
			   "\nUtil_ListDelete: Calling application delete function: List_p = 0x%x",
			   (int)List_p);)
			(*(DelFunc_p)) ((void *)List_p->Curr_p->EKey_p,
					List_p->Curr_p->Body_p);
	}

	return Util_ListRemove(List_p);
}
#endif /* REMOVE_UF_LISTDELETEGENERALMAP */

/*
 * NAME
 *  Util_ListDeleteGeneralMapClientHandleStyle
 * Changes due to general map and ClientHandle style is
 * propagated from destoy function
 *
 */
#ifndef REMOVE_UF_LISTDELETEGENERALMAPCLIENTHANDLESTYLE
#ifdef REMOVE_UF_LISTREMOVE
#undef REMOVE_UF_LISTREMOVE
#endif
ListResult_t Util_ListDeleteGeneralMapClientHandleStyle(List_t *const List_p,
	const ListDeleteFunctionGeneralMapClientHandleStyle_t DelFunc_p)
{
	PRE_CONDITION(NULL != List_p, return LIST_ERROR_INVALID_LIST);

	if (NULL == List_p->Curr_p) {
		/* list is empty or no current element, nothing to remove */
		B_(printf(
			   "\nUtil_ListDelete: LIST_ERROR_CURRENT_PTR_OFF_LIST, List = 0x%x is empty",
			   (int)List_p);)
		return LIST_ERROR_CURRENT_PTR_OFF_LIST;
	}

	/* delete the element body using the application's delete callback */
	if (NULL != DelFunc_p) {
		C_(printf(
			   "\nUtil_ListDelete: Calling application delete function: List_p = 0x%x",
			   (int)List_p);)
			(*(DelFunc_p)) (List_p->ClientHandle_p, NULL,
					List_p->Curr_p->Body_p);
	}

	return Util_ListRemove(List_p);
}
#endif /* REMOVE_UF_LISTDELETEGENERALMAPCLIENTHANDLESTYLE */

/*
 * NAME
 *	Util_ListRemove
 *
 */
#ifndef REMOVE_UF_LISTREMOVE
ListResult_t Util_ListRemove(List_t *const List_p)
{
	PRE_CONDITION(List_p != NULL, return LIST_ERROR_INVALID_LIST);

	if (List_p->Curr_p == NULL) {
		/* list is empty or no current element, nothing to remove */
		B_(printf(
			   "\nUtil_ListRemove: LIST_ERROR_CURRENT_PTR_OFF_LIST, List = 0x%x is empty",
			   (int)List_p);)
		return LIST_ERROR_CURRENT_PTR_OFF_LIST;
	}

	List_p->NbrOfElements--;
	if (List_p->Curr_p->Next_p == NULL) {           /* tail?? */
		if (List_p->Curr_p->Prev_p == NULL) {   /* head?? */
			/* list has only one element */
			(*List_p->MemFreeFunc_p)(List_p->Curr_p);
			List_p->Curr_p = NULL;
			List_p->Head_p = NULL;
			List_p->Tail_p = NULL;
		} else {
			/* item to be removed is at the tail of list */
			List_p->Tail_p = List_p->Curr_p->Prev_p;
			List_p->Tail_p->Next_p = NULL;
			(*List_p->MemFreeFunc_p)(List_p->Curr_p);
			List_p->Curr_p = List_p->Tail_p;
		}
	} else {
		ListItem_t *Temp_p;

		if (List_p->Curr_p->Prev_p == NULL) { /* head?? */
			/* item to be removed is at the head of the list */
			List_p->Head_p = List_p->Head_p->Next_p;
			List_p->Head_p->Prev_p = NULL;
		} else {
			/* item to be removed is located in the middle
				of the list */
			List_p->Curr_p->Prev_p->Next_p = List_p->Curr_p->Next_p;
			List_p->Curr_p->Next_p->Prev_p = List_p->Curr_p->Prev_p;
		}

		/* de-allocate memory and set current pointer to point
			to next element in list. */
		Temp_p = List_p->Curr_p->Next_p;
		(*List_p->MemFreeFunc_p)(List_p->Curr_p);
		List_p->Curr_p = Temp_p;
	}
	C_(printf(
		   "\nUtil_ListRemove: LIST_SUCCESS, Current element on List = 0x%x is removed",
		   (int)List_p);)

	return LIST_SUCCESS;
}
#endif /* REMOVE_UF_LISTREMOVE */


#ifndef REMOVE_UF_LISTPRINTDEBUG
/*
 * NAME
 *	Util_ListPrintDebug
 *
 */
void Util_ListPrintDebug(List_t *const List_p,
			 const ListDebugFunction_t DbgFunc_p)
{
	PRE_CONDITION(List_p != NULL, C_(printf(
						 "\nInvalid List Specified");
					 ) return );

	C_(printf("\nLIST STATUS:");)
	if (List_p->Head_p == NULL) {
		C_(printf(" Empty\n");)
		C_(printf("DONE\n");)
	} else {
		ListItem_t *TempCurr_p = List_p->Curr_p;
		uint16_t Index = 1;
		IDENTIFIER_NOT_USED(Index); /*Removes Lint warning*/
		if (List_p->Curr_p == NULL) {
			C_(printf(" Off List: true");)
		} else {
			C_(printf(" Off List: false");)
		}

		C_(printf(" Head: 0x%x", (int)List_p->Head_p);)
		C_(printf(" Tail: 0x%x", (int)List_p->Tail_p);)
		C_(printf(" Current: 0x%x", (int)List_p->Curr_p);)
		C_(printf(" NbrOfElements: %d", (int)List_p->NbrOfElements);)
		C_(printf("\nLIST CONTENTS: ");)

		List_p->Curr_p = List_p->Head_p;
		while (List_p->Curr_p != NULL) {
			C_(printf("\nElement number: %d", Index);)
			Index++;
			C_(printf("\n  Element ptr:  0x%x",
				  (int)List_p->Curr_p);)
			C_(printf("\n  Contents ptr: 0x%x",
				  (int)List_p->Curr_p->Body_p);)
			C_(printf("\n  Key ptr:      0x%x\n",
				  (int)List_p->Curr_p->EKey_p);)
			if (DbgFunc_p != NULL)
				(*DbgFunc_p)(List_p->Curr_p->Body_p);

			List_p->Curr_p = List_p->Curr_p->Next_p;
		}
		C_(printf("DONE\n");)
		List_p->Curr_p = TempCurr_p;
	}
}
#endif /* REMOVE_UF_LISTPRINTDEBUG */

#ifndef REMOVE_UF_LISTPRINTDEBUGGENERALMAP
/*
 * NAME
 *  Util_ListPrintDebugGeneralMap
 *  To comply with callforeach in general map style the callback
 *  declaration had to be modified
 */
void Util_ListPrintDebugGeneralMap(List_t *const List_p,
	const ListDebugFunctionGeneralMap_t DbgFunc_p)
{
	PRE_CONDITION(NULL != List_p, C_(printf(
						 "\nInvalid List Specified");
					 ) return );

	C_(printf("\nLIST STATUS:");)
	if (NULL == List_p->Head_p) {
		C_(printf(" Empty\n");)
		C_(printf("DONE\n");)
	} else {
		ListItem_t *TempCurr_p = List_p->Curr_p;
		uint16_t Index = 1;
		IDENTIFIER_NOT_USED(Index); /* Removes Lint warning */
		if (NULL == List_p->Curr_p) {
			C_(printf(" Off List: true");)
		} else {
			C_(printf(" Off List: false");)
		}

		C_(printf(" Head: 0x%x", (int)List_p->Head_p);)
		C_(printf(" Tail: 0x%x", (int)List_p->Tail_p);)
		C_(printf(" Current: 0x%x", (int)List_p->Curr_p);)
		C_(printf(" NbrOfElements: %d", (int)List_p->NbrOfElements);)
		C_(printf("\nLIST CONTENTS: ");)

		List_p->Curr_p = List_p->Head_p;
		while (NULL != List_p->Curr_p) {
			C_(printf("\nElement number: %d", Index);)
			Index++;
			C_(printf("\n  Element ptr:  0x%x",
				  (int)List_p->Curr_p);)
			C_(printf("\n  Contents ptr: 0x%x",
				  (int)List_p->Curr_p->Body_p);)
			C_(printf("\n  Key ptr:      0x%x\n",
				  (int)List_p->Curr_p->EKey_p);)
			if (NULL != DbgFunc_p)
				(*DbgFunc_p)(NULL, List_p->Curr_p->Body_p, NULL,
					     NULL);

			List_p->Curr_p = List_p->Curr_p->Next_p;
		}
		C_(printf("DONE\n");)
		List_p->Curr_p = TempCurr_p;
	}
}
#endif /* REMOVE_UF_LISTPRINTDEBUGGENERALMAP */
