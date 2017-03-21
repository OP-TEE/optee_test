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

#ifndef TA_SDP_BASIC_H
#define TA_SDP_BASIC_H

#define TA_SDP_BASIC_UUID { 0x12345678, 0x5b69, 0x11e4, \
	{ 0x9d, 0xbb, 0x10, 0x1f, 0x74, 0xf0, 0x00, 0x99 } }

#define TA_SDP_BASIC_CMD_INJECT			0
#define TA_SDP_BASIC_CMD_TRANSFORM		1
#define TA_SDP_BASIC_CMD_DUMP			2

#define TA_SDP_BASIC_CMD_INVOKE_INJECT		3
#define TA_SDP_BASIC_CMD_INVOKE_TRANSFORM	4
#define TA_SDP_BASIC_CMD_INVOKE_DUMP		5

#define TA_SDP_BASIC_CMD_PTA_INJECT		6
#define TA_SDP_BASIC_CMD_PTA_TRANSFORM		7
#define TA_SDP_BASIC_CMD_PTA_DUMP		8

#endif /* TA_SDP_BASIC_H */
