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

#ifndef XML_TIMEARITHM_API_H_
#define XML_TIMEARITHM_API_H_

#include <openssl/bn.h>
#include "xml_common_api.h"

#define Invoke_GetSystemTime Invoke_Simple_Function
#define Invoke_GetREETime Invoke_Simple_Function
#define Invoke_SetTAPersistentTime_and_GetTAPersistentTime_Overflow \
	Invoke_Simple_Function
#define Invoke_SetTAPersistentTime_and_GetTAPersistentTime \
	Invoke_Simple_Function
#define Invoke_BigIntConvertToOctetStringOverflow Invoke_Simple_Function
#define Invoke_BigIntConvertFromOctetStringOverflow Invoke_Simple_Function
#define Invoke_GetTAPersistentTime_NotSet_and_SetTAPersistentTime \
	Invoke_Simple_Function
#define Test_Tool_Erase_Persistent_Time Invoke_Simple_Function

#define Invoke_BigIntMod Invoke_BigIntDiv_Remain

#define Invoke_BigIntSquareMod Invoke_BigIntMulMod

static TEEC_SharedMemory *SHARE_MEM01;
static TEEC_SharedMemory *SHARE_MEM02;
static TEEC_SharedMemory *SHARE_MEM03;
static TEEC_Session *SESSION01;
static TEEC_Context *CONTEXT01;
static TEEC_Context *CONTEXT02;
static TEEC_Operation *OPERATION01;

#define CMD_TEE_SetTAPersistentTime_and_GetTAPersistentTime_Overflow \
	CMD_TEE_SetTAPersistentTime_and_GetTAPersistentTimeOverflow

#define CLIENT_APP01                    NULL

#define TEEC_UNDEFINED_ERROR 0xDEADDEAD

#define TEEC_ORIGIN_ANY_NOT_TRUSTED_APP  0x00000005
/* same as TEE_ORIGIN_NOT_TRUSTED_APP */

/* Return ORIGIN */
static uint32_t ret_orig;

/*Test data defines*/
static pthread_t THREAD01_DEFAULT;
static pthread_t THREAD02;

#define BIT0_MASK 1
#define BIT1_MASK 2
#define BIT2_MASK 4

#define NEGATIVE 0
#define POSITIVE 1

#define RESULT_NOT_A_PRIME 0
#define RESULT_PRIME 1

#define RESULT_EQUAL 0
#define RESULT_INTEGER_GREATER_THAN_ZERO 1
#define RESULT_INTEGER_LOWER_THAN_ZERO 2

#define CASE_WAIT_CANCELLED 1
#define CASE_WAIT_SUCCESS 2

static uint32_t CONFIDENCE_LEVEL_80 = 80;

static uint8_t BIG_VALUE1_SIZE_64_BITS[] = {
	0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};


static uint8_t BIG_VALUE2_SIZE_64_BITS[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static uint8_t BIG_VALUE3_SIZE_32_BITS[] = {
	0x0F, 0xFF, 0xFF, 0xFF,
};

static uint8_t BIG_VALUE4_SIZE_32_BITS[] = {
	0x01, 0x00, 0x00, 0x00,
};

static uint8_t BIG_VALUE5_SIZE_2048_BITS[] = {
	0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
};

static uint8_t BIG_VALUE6_SIZE_2048_BITS[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

static uint8_t BIG_VALUE7_SIZE_1024_BITS[] = {
	0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF,
};

static uint8_t BIG_VALUE10_SIZE_32_BITS_PRIME_WITH_VALUE3[] = {
	0x0E, 0xFF, 0xFF, 0xFF,
};

static uint8_t BIG_VALUE13_SIZE_32_BITS_PRIME[] = {
	0x00, 0x00, 0x0D, 0x69,
};

static uint8_t BIG_VALUE14_SIZE_32_BITS_NOT_PRIME[] = {
	0x00, 0x00, 0x0D, 0x68,
};

static uint8_t BIG_VALUE15_SIZE_32_BITS[] = {
	0x00, 0x00, 0x00, 0x03,
};

static uint8_t BIG_VALUE16_SIZE_64_BITS[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
};

static uint8_t BIG_VALUE17_SIZE_1024_BITS[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03,
};

static uint8_t BIG_VALUE18_SIZE_2048_BITS[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x03,
};

static uint8_t BIG_VALUE19_SIZE_32_BITS_PRIME_WITH_VALUE_3[] = {
	0x00, 0x00, 0x00, 0x04,
};

static uint8_t BIG_VALUE20_SIZE_2048_BITS_PRIME_WITH_VALUE5[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x04,
};

static uint8_t BIG_VALUE_ONE_SIZE_64_BITS[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

static uint8_t BIG_VALUE_ZERO_SIZE_32_BITS[] = {
	0x00, 0x00, 0x00, 0x00,
};

static uint8_t BIG_VALUE_ZERO_SIZE_64_BITS[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static uint8_t BIG_VALUE_ZERO_SIZE_2048_BITS[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

static uint8_t VALUE1_32_BITS[] = {
	0x01, 0x23, 0x45, 0x67,
};


/** ALL_TEEC_UUID
 *
 * These constants are the UUID of existing
 * Trusted Applications
 */
/* "SMARTCLSARITHMET" */
static TEEC_UUID UUID_TTA_testingInternalAPI_Arithmetique = {
	0x534D4152, 0x5443, 0x4C53,
	{ 0x41, 0x52, 0x49, 0x54, 0x48, 0x4D, 0x45, 0x54 }
};
/* "SMARTCSL_TIMEAPI" */
static TEEC_UUID UUID_TTA_testingInternalAPI_Time = {
	0x534D4152, 0x5443, 0x534C,
	{ 0x5F, 0x54, 0x49, 0x4D, 0x45, 0x41, 0x50, 0x49 }
};

/*Helper functions/macros*/

#define BN_DECLARE_AND_INIT(exit_label) \
	BN_CTX *ctx = NULL; \
	BIGNUM *a = NULL, *b = NULL, *s = NULL, *d = NULL, \
		*m = NULL, *l = NULL, \
	*r = NULL; \
	ctx = BN_CTX_new(); \
	if (ctx == NULL) { \
		goto exit_label; \
	} \
	a = BN_new(); \
	b = BN_new(); \
	s = BN_new(); \
	d = BN_new(); \
	m = BN_new(); \
	l = BN_new(); \
	r = BN_new();

#define BN_FREE() \
	BN_free(a); \
	BN_free(b); \
	BN_free(s); \
	BN_free(d); \
	BN_free(m); \
	BN_free(l); \
	BN_free(r); \
	if (ctx) { \
		BN_CTX_free(ctx); \
	}

/* XML_VERIFY macro define.
 *
 * Use ADBG_EXPECT or ADBG_EXPECT_NOT depending on the expected return value.
 *
 * ADBG_EXPECT() -> IF(EXP == GOT) RETURN TRUE
 * ADBG_EXPECT() -> IF(EXP != GOT) RETURN TRUE
 */
#define XML_VERIFY(c, exp, got) \
	do { \
		if (exp == TEEC_UNDEFINED_ERROR) \
			ADBG_EXPECT_NOT(c, exp, got); \
		else \
			ADBG_EXPECT(c, exp, got); \
	} while (0)

/* Initialize context using TEEC_InitializeContext and
	check the returned value. */
#define XML_InitializeContext(c, name, context, expected) \
		XML_VERIFY(c, expected, TEEC_InitializeContext(name, context))

/* Open session using TEEC_OpenSession and
	check the returned value and/or returned origin. */
#define XML_OpenSession(c, context, session, destination, connectionMethod, \
			connectionData, operation, returnOrigin, expected) \
	do { \
		XML_VERIFY(c, expected, \
			   TEEC_OpenSession(context, session, destination, \
					    connectionMethod, connectionData, \
					    operation, &ret_orig)); \
		if ((returnOrigin != 0) && \
		    ((int)returnOrigin != TEEC_ORIGIN_ANY_NOT_TRUSTED_APP)) \
			ADBG_EXPECT(c, (int)returnOrigin, ret_orig); \
		else \
			ADBG_EXPECT_NOT(c, (int)returnOrigin, ret_orig); \
	} while (0)

#define OPERATION_TEEC_PARAM_TYPES(op, p0, p1, p2, p3) \
	do { \
		op->paramTypes = TEEC_PARAM_TYPES(p0, p1, p2, p3); \
	} while (0)


/*dummy functions*/
#define TEEC_SelectApp(a, b)    /*do nothing for now*/
#define TEEC_createThread(a, b) /*do nothing for now*/

static void *cancellation_thread(void *arg)
{
	TEEC_RequestCancellation((TEEC_Operation *)arg);
	return NULL;
}

#define RequestCancellation(op) \
	(void)ADBG_EXPECT(c, 0, \
			  pthread_create(&THREAD02, NULL, cancellation_thread, \
					 (void *)op)); \
	(void)ADBG_EXPECT(c, 0, pthread_join(THREAD02, NULL));

/*Allocates TEEC_SharedMemory inside of the TEE*/
static TEEC_Result AllocateSharedMemory(TEEC_Context *ctx,
					TEEC_SharedMemory *shm, uint32_t size,
					uint32_t flags)
{
	shm->flags = flags;
	shm->size = size;
	return TEEC_AllocateSharedMemory(ctx, shm);
}

static TEEC_Result Invoke_Simple_Function(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_BigIntCmpS32(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t expectedComparisonResult)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT, value2, mem02_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	op.params[3].value.a = expectedComparisonResult;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_INPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_BigIntShiftRight(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint32_t bits)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0, sign_cmp = 0;
	uint8_t *tmp1 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM02, ((size_N2 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem02_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;

	op.params[0].value.a = tmp;
	op.params[0].value.b = (uint32_t)bits;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	tmp1 = (uint8_t *)malloc(SHARE_MEM02->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM02->size);

	if (!BN_bin2bn(SHARE_MEM01->buffer, SHARE_MEM01->size, a))
		goto exit;

	if (!BN_rshift(b, a, (int)bits))
		goto exit;

	BN_bn2bin(b, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM02->buffer,
						SHARE_MEM02->size));

	tmp = op.params[0].value.b;
	if (tmp & BIT0_MASK)
		sign_cmp = POSITIVE;
	else
		sign_cmp = NEGATIVE;

	/* This is not implemented according to the Adaptation layer
	 *  specification document.
	 * In case when the number of bits to be shifted right is equal
	 * or bigger then the actual size of the buffer,
	 * the returned buffer (big number) will be zero and the returned
	 * sign will be positive, so the returned
	 * sign check should be performed against the POSITIVE sign
	 * instead of the original (input) number sign.
	 */
	if (size_N1 > bits) {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c, sign_cmp, ==, sign1);
	} else {
		(void)ADBG_EXPECT_COMPARE_SIGNED(c, sign_cmp, ==,
						 (uint32_t)POSITIVE);
	}

exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntDiv_Remain(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT,
					value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT,
					value2, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM02->buffer), SHARE_MEM02->size,
		       b))
		goto exit;

	if (!BN_div(d, m, a, b, ctx))
		goto exit;

	BN_bn2bin(m, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntDiv_Quotient(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT,
					value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT,
					value2, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM02->buffer), SHARE_MEM02->size,
		       b))
		goto exit;

	if (!BN_div(d, m, a, b, ctx))
		goto exit;

	BN_bn2bin(d, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntAdd(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT,
					value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT,
					value2, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM02->buffer), SHARE_MEM02->size,
		       b))
		goto exit;

	if (!BN_add(d, a, b))
		goto exit;

	BN_bn2bin(d, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntIsProbablePrime(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t confidenceLevel, uint32_t expectedProbabilityResult)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT,
					value1, mem01_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;

	op.params[0].value.a = tmp;
	op.params[0].value.b = confidenceLevel;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	op.params[3].value.a = expectedProbabilityResult;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
		TEEC_VALUE_INPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_BigIntConvert_and_ComputeFMM(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t size_N3, uint32_t sign3, uint8_t *value3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT, value2, mem02_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM03,
					((size_N3 + 7) / 8),
					TEEC_MEM_INPUT, value3, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;
	if (sign3)
		tmp = tmp | BIT2_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_INPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_BigIntAddMod(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT, value2, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);
	if (res != TEE_SUCCESS)
		goto exit;

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM02->buffer), SHARE_MEM02->size,
		       b))
		goto exit;

	if (!BN_add(s, a, a))
		goto exit;

	if (!BN_div(d, m, s, b, ctx))
		goto exit;

	BN_bn2bin(m, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntSubMod(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT, value2, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);
	if (res != TEE_SUCCESS)
		goto exit;

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM02->buffer), SHARE_MEM02->size,
		       b))
		goto exit;

	if (!BN_sub(s, a, a))
		goto exit;

	if (!BN_div(d, m, s, b, ctx))
		goto exit;

	BN_bn2bin(m, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntGetBit(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t BitIndex, bool expectedBooleanResult)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT,
					value1, mem01_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;

	op.params[0].value.a = tmp;
	op.params[0].value.b = BitIndex;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
		TEEC_VALUE_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[3].value.a, ==,
					 expectedBooleanResult);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_BigIntMulMod(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT, value2, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);
	if (res != TEE_SUCCESS)
		goto exit;

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM02->buffer), SHARE_MEM02->size,
		       b))
		goto exit;

	if (!BN_sqr(s, a, ctx))
		goto exit;

	if (!BN_div(d, m, s, b, ctx))
		goto exit;

	BN_bn2bin(m, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_Wait(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t Case)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = Case;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_BigIntComputeExtendedGcd(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT, value2, mem02_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_BigIntGetBitCount(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t ExpectedBitCount)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
		TEEC_VALUE_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c, op.params[3].value.a, ==,
					 ExpectedBitCount);

	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_BigIntSub(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT,  value2, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM02->buffer), SHARE_MEM02->size,
		       b))
		goto exit;

	if (!BN_sub(s, a, b))
		goto exit;

	BN_bn2bin(s, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntNeg(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL, *tmp2 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
		TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	tmp2 = (uint8_t *)malloc(SHARE_MEM01->size);
	if (tmp2 == NULL)
		goto tmp2_exit;
	memset(tmp2, 0, SHARE_MEM01->size);


	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;
	if (!BN_bin2bn(tmp2, SHARE_MEM01->size, b))
		goto exit;

	if (!BN_sub(s, b, a))
		goto exit;

	BN_bn2bin(s, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp2);
tmp2_exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntCmp(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t ExpectedComparisonResult)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT, value2, mem02_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	op.params[3].value.a = ExpectedComparisonResult;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_INPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

static TEEC_Result Invoke_BigIntInit(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t size_N)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = size_N;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_BigIntConvertFromS32AndToS32(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t sign, uint8_t *shortVal)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;

	if (sign)
		tmp = tmp | BIT0_MASK;

	op.params[0].value.a = (uint32_t)(*shortVal);
	op.params[0].value.b = tmp;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_BigIntMul(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT, value2, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;
	if (!BN_bin2bn((uint8_t *)(SHARE_MEM02->buffer), SHARE_MEM02->size,
		       b))
		goto exit;

	if (!BN_mul(s, a, b, ctx))
		goto exit;

	BN_bn2bin(s, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntInvMod(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL, *tmp2 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT, value2, mem02_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);
	if (res != TEE_SUCCESS)
		goto exit;

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	tmp2 = (uint8_t *)malloc(SHARE_MEM01->size);
	if (tmp2 == NULL)
		goto tmp2_exit;

	memset(tmp2, 0, SHARE_MEM01->size);
	tmp2[0] = 1;

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM02->buffer), SHARE_MEM02->size,
		       b))
		goto exit;

	if (!BN_bin2bn(tmp2, SHARE_MEM01->size, l))
		goto exit;

	if (!BN_div(d, m, l, a, ctx))
		goto exit;

	if (!BN_div(s, m, d, b, ctx))
		goto exit;

	BN_bn2bin(m, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp2);
tmp2_exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntSquare(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N3)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;
	uint8_t *tmp1 = NULL;

	BN_DECLARE_AND_INIT(bn_exit)

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_SHARED_MEMORY(CONTEXT01, SHARE_MEM03, ((size_N3 + 7) / 8),
			       TEEC_MEM_OUTPUT, mem03_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(3, 0, SHARE_MEM03,
					      SHARE_MEM03->size)

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INOUT, TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
		TEEC_MEMREF_PARTIAL_OUTPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	tmp1 = (uint8_t *)malloc(SHARE_MEM03->size);
	if (tmp1 == NULL)
		goto tmp1_exit;

	memset(tmp1, 0, SHARE_MEM03->size);

	if (!BN_bin2bn((uint8_t *)(SHARE_MEM01->buffer), SHARE_MEM01->size,
		       a))
		goto exit;

	if (!BN_sqr(s, a, ctx))
		goto exit;

	BN_bn2bin(s, tmp1);

	(void)ADBG_EXPECT_COMPARE_SIGNED(c,
					 0, ==,
					 memcmp(tmp1, SHARE_MEM03->buffer,
						SHARE_MEM03->size));

exit:
	free(tmp1);
tmp1_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM03);
mem03_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	BN_FREE()
bn_exit:
	return res;
}

static TEEC_Result Invoke_BigIntConvertToS32Overflow(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId, uint32_t size_N)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;

	op.params[0].value.a = size_N;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	return res;
}

static TEEC_Result Invoke_BigIntRelativePrime(
	ADBG_Case_t *c, TEEC_Session *sess, uint32_t cmdId,
	uint32_t size_N1, uint32_t sign1, uint8_t *value1,
	uint32_t size_N2, uint32_t sign2, uint8_t *value2,
	bool expectedBooleanResult)
{
	TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t org;
	uint32_t tmp = 0;

	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM01,
					((size_N1 + 7) / 8),
					TEEC_MEM_INPUT, value1, mem01_exit)
	ALLOCATE_AND_FILL_SHARED_MEMORY_6(CONTEXT01, SHARE_MEM02,
					((size_N2 + 7) / 8),
					TEEC_MEM_INPUT, value2, mem02_exit)

	if (sign1)
		tmp = tmp | BIT0_MASK;
	if (sign2)
		tmp = tmp | BIT1_MASK;

	op.params[0].value.a = tmp;
	SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, SHARE_MEM01,
					      SHARE_MEM01->size)
	SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, SHARE_MEM02,
					      SHARE_MEM02->size)
	op.params[3].value.a = (uint32_t)expectedBooleanResult;

	op.paramTypes = TEEC_PARAM_TYPES(
		TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_INPUT,
		TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_INPUT);

	res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

	TEEC_ReleaseSharedMemory(SHARE_MEM02);
mem02_exit:
	TEEC_ReleaseSharedMemory(SHARE_MEM01);
mem01_exit:
	return res;
}

#endif /* XML_TIMEARITHM_API_H_ */
