// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026, Jaehun Lee */
#include <core_fuzz_ta.h>
#include <pta_core_fuzz_cov.h>
#include <tee_internal_api.h>
#include <utee_syscalls.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if CORE_FUZZ_TA_COVERAGE_SIZE != PTA_CORE_FUZZ_COV_MAP_SIZE
#error "TA and PTA coverage sizes differ"
#endif

static uint16_t read_u16(const uint8_t *data)
{
	return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static bool valid_input(const uint8_t *input, size_t size)
{
	size_t offset = CORE_FUZZ_TA_HEADER_SIZE;
	uint8_t count = 0;
	uint8_t i = 0;

	if (size < CORE_FUZZ_TA_HEADER_SIZE ||
		size > CORE_FUZZ_TA_MAX_INPUT ||
		TEE_MemCompare(input, CORE_FUZZ_TA_MAGIC,
					   CORE_FUZZ_TA_MAGIC_SIZE))
		return false;
	count = input[CORE_FUZZ_TA_MAGIC_SIZE];
	if (count > CORE_FUZZ_TA_MAX_RECORDS)
		return false;

	for (i = 0; i < count; i++) {
		uint8_t opcode = 0;
		uint16_t length = 0;

		if (size - offset < CORE_FUZZ_TA_RECORD_HEADER_SIZE)
			return false;
		opcode = input[offset];
		length = read_u16(input + offset + 2);
		if (opcode > CORE_FUZZ_OP_FREE ||
			input[offset + 1] >= CORE_FUZZ_TA_SLOTS ||
			length > CORE_FUZZ_TA_MAX_PAYLOAD ||
			length > size - offset - CORE_FUZZ_TA_RECORD_HEADER_SIZE)
			return false;
		if (((opcode == CORE_FUZZ_OP_DIGEST_ALLOC ||
			  opcode == CORE_FUZZ_OP_FREE) && length) ||
			((opcode == CORE_FUZZ_OP_AES_ALLOC ||
			  opcode == CORE_FUZZ_OP_AES_INIT) && length != 16))
			return false;
		offset += CORE_FUZZ_TA_RECORD_HEADER_SIZE + length;
	}
	return offset == size;
}

/* Use raw syscalls so invalid state sequences reach core validation. */
static TEE_Result execute_step(uint8_t opcode, uint32_t *state,
			const uint8_t *data, size_t length)
{
	TEE_Result result = TEE_SUCCESS;
	uint64_t output_size = 0;
	uint8_t output[CORE_FUZZ_TA_MAX_PAYLOAD] = { 0 };
	uint32_t new_state = 0;
	uint32_t key = 0;

	switch (opcode) {
	case CORE_FUZZ_OP_DIGEST_ALLOC:
		if (*state)
			_utee_cryp_state_free(*state);
		*state = 0;
		result = _utee_cryp_state_alloc(TEE_ALG_SHA256, TEE_MODE_DIGEST,
			0, 0, &new_state);
		if (!result) {
			result = _utee_hash_init(new_state, NULL, 0);
			if (!result)
				*state = new_state;
			else
				_utee_cryp_state_free(new_state);
		} else if (new_state) {
			_utee_cryp_state_free(new_state);
		}
		break;
	case CORE_FUZZ_OP_DIGEST_UPDATE:
		result = _utee_hash_update(*state, data, length);
		break;
	case CORE_FUZZ_OP_DIGEST_FINAL:
		output_size = 32;
		result = _utee_hash_final(*state, data, length, output,
			&output_size);
		break;
	case CORE_FUZZ_OP_AES_ALLOC: {
		struct utee_attribute attr = {
			.attribute_id = TEE_ATTR_SECRET_VALUE,
			.a = (uintptr_t)data,
			.b = length,
		};

		if (*state)
			_utee_cryp_state_free(*state);
		*state = 0;
		result = _utee_cryp_obj_alloc(TEE_TYPE_AES, 128, &key);
		if (result)
			break;
		result = _utee_cryp_obj_populate(key, &attr, 1);
		if (result)
			goto close_key;
		result = _utee_cryp_state_alloc(TEE_ALG_AES_CTR,
			TEE_MODE_ENCRYPT, key, 0,
			&new_state);
		if (result) {
			if (new_state) {
				_utee_cryp_state_free(new_state);
				key = 0;
			}
			goto close_key;
		}
		/* Freeing this state also closes its busy key object in core. */
		*state = new_state;
		break;
close_key:
		if (key)
			_utee_cryp_obj_close(key);
		break;
	}
	case CORE_FUZZ_OP_AES_INIT:
		result = _utee_cipher_init(*state, data, length);
		break;
	case CORE_FUZZ_OP_AES_UPDATE:
		output_size = sizeof(output);
		result = _utee_cipher_update(*state, data, length, output,
			&output_size);
		break;
	case CORE_FUZZ_OP_FREE:
		result = _utee_cryp_state_free(*state);
		if (!result)
			*state = 0;
		break;
	default:
		result = TEE_ERROR_BAD_PARAMETERS;
		break;
	}
	return result;
}

static TEE_Result run(uint32_t param_types, TEE_Param params[4])
{
	const uint32_t expected = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT,
		TEE_PARAM_TYPE_NONE);
	const TEE_UUID coverage_uuid = PTA_CORE_FUZZ_COV_UUID;
	TEE_TASessionHandle coverage_session = TEE_HANDLE_NULL;
	TEE_Param coverage_params[4] = { 0 };
	uint32_t state[CORE_FUZZ_TA_SLOTS] = { 0 };
	uint8_t *input = NULL;
	size_t offset = CORE_FUZZ_TA_HEADER_SIZE;
	size_t input_size = 0;
	uint8_t count = 0;
	uint8_t i = 0;
	TEE_Result result = TEE_SUCCESS;

	if (param_types != expected || !params[0].memref.buffer ||
		params[0].memref.size < CORE_FUZZ_TA_HEADER_SIZE ||
		params[0].memref.size > CORE_FUZZ_TA_MAX_INPUT)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[1].memref.size < PTA_CORE_FUZZ_COV_MAP_SIZE) {
		params[1].memref.size = PTA_CORE_FUZZ_COV_MAP_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}
	if (!params[1].memref.buffer)
		return TEE_ERROR_BAD_PARAMETERS;
	input_size = params[0].memref.size;
	input = TEE_Malloc(input_size, 0);
	if (!input)
		return TEE_ERROR_OUT_OF_MEMORY;
	TEE_MemMove(input, params[0].memref.buffer, input_size);
	if (!valid_input(input, input_size)) {
		result = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}
	params[2].value.a = 0;
	params[2].value.b = TEE_SUCCESS;
	count = input[CORE_FUZZ_TA_MAGIC_SIZE];

	result = TEE_OpenTASession(&coverage_uuid, TEE_TIMEOUT_INFINITE, 0,
			NULL, &coverage_session, NULL);
	if (result)
		goto out;
	result = TEE_InvokeTACommand(coverage_session, TEE_TIMEOUT_INFINITE,
			PTA_CORE_FUZZ_COV_BEGIN, 0, NULL, NULL);
	if (result)
		goto out;

	for (i = 0; i < count; i++) {
		uint8_t opcode = input[offset];
		uint8_t slot = input[offset + 1];
		uint16_t length = read_u16(input + offset + 2);
		TEE_Result step = execute_step(opcode, &state[slot],
			input + offset +
			CORE_FUZZ_TA_RECORD_HEADER_SIZE,
			length);

		if (step == TEE_SUCCESS)
			params[2].value.a++;
		params[2].value.b = step;
		offset += CORE_FUZZ_TA_RECORD_HEADER_SIZE + length;
	}

	coverage_params[0].memref.buffer = params[1].memref.buffer;
	coverage_params[0].memref.size = params[1].memref.size;
	result = TEE_InvokeTACommand(coverage_session, TEE_TIMEOUT_INFINITE,
			PTA_CORE_FUZZ_COV_END,
			TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE), coverage_params, NULL);
	params[1].memref.size = coverage_params[0].memref.size;
out:
	if (coverage_session != TEE_HANDLE_NULL)
		TEE_CloseTASession(coverage_session);
	for (i = 0; i < CORE_FUZZ_TA_SLOTS; i++) {
		if (state[i])
			_utee_cryp_state_free(state[i]);
	}
	TEE_Free(input);
	return result;
}

TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
			TEE_Param params[4] __unused,
			void **session_context)
{
	if (param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	*session_context = NULL;
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session_context __unused)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void *session_context __unused,
			uint32_t command,
			uint32_t param_types,
			TEE_Param params[4])
{
	if (command != CORE_FUZZ_TA_CMD_RUN)
		return TEE_ERROR_NOT_SUPPORTED;
	return run(param_types, params);
}
