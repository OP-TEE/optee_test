/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <tee_ta_api.h>
#include <user_ta_header_defines.h>
#include <ta_sims.h>

/*
 * Trusted Application Entry Points
 */

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4],
				    void **session_context)
{
	return sims_entry_open_session(session_context, param_types, params);
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *session_context)
{
	sims_entry_close_session(session_context);
}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *session_context,
				      uint32_t command_id, uint32_t param_types,
				      TEE_Param params[4])
{
	switch (command_id) {
	case TA_SIMS_OPEN_TA_SESSION:
		return sims_open_ta_session(session_context,
					    param_types, params);

	case TA_SIMS_CMD_READ:
		return sims_read(param_types, params);

	case TA_SIMS_CMD_WRITE:
		return sims_write(param_types, params);

	case TA_SIMS_CMD_GET_COUNTER:
		return sims_get_counter(session_context, param_types, params);

	case TA_SIMS_CMD_PANIC:
		return sims_entry_panic(session_context, param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
