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

#ifndef TA_SIMS_TEST_H
#define TA_SIMS_TEST_H

/* This UUID is generated with uuidgen */
#define TA_SIMS_TEST_UUID { 0xe6a33ed4, 0x562b, 0x463a, \
	{ 0xbb, 0x7e, 0xff, 0x5e, 0x15, 0xa4, 0x93, 0xc8 } }

/*
 * Open session invocation interface
 *
 * When opening a session, client may provide additional request through
 * the TEE invocation parameters. When parameter types are not all of type None
 * below lists the parameters usage.
 *
 * param#0: [in]	value.a = Request based on below supported values:
 *			TA_SIMS_CMD_PANIC: TA to panic during session opening
 */

/* Command invocation interface */

/*
 * TA_SIMS_CMD_READ	Read a binary blob previously written
 *
 * param#0: [in]	value.a = index of blob in the storage array
 * param#1: [out]	memref = output buffer for blob
 */
#define TA_SIMS_CMD_READ		1

/*
 * TA_SIMS_CMD_WRITE	Read a binary blob previously written
 *
 * param#0: [in]	value.a = index of blob in the storage array
 * param#1: [in]	memref = blob to store
 */
#define TA_SIMS_CMD_WRITE		2

/*
 * TA_SIMS_CMD_GET_COUNTER	Read counter value that is (session count - 1)
 *
 * param#0: [out]	value.a = counter value
 */
#define TA_SIMS_CMD_GET_COUNTER		3

/*
 * TA_SIMS_CMD_PANIC	Make the TA panicking
 *
 * Optional parameters:
 *
 * param#0: [in]	memref = UUID of a TA
 *			If provided, open a session towards this TA and
 *			invoke it with command TA_SIMS_CMD_PANIC.
 */
#define TA_SIMS_CMD_PANIC		4

/*
 * TA_SIMS_OPEN_TA_SESSION	Open a session towards a TA
 *
 * param#0: [in]	memref = target TA UUID
 */
#define TA_SIMS_CMD_OPEN_TA_SESSION	5

#endif
