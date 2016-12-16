/*
 * Copyright (c) 2016, Linaro Limited
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

#ifndef __RAND_STREAM_H
#define __RAND_STREAM_H

#include <sys/types.h>

struct rand_stream;

struct rand_stream *rand_stream_alloc(int seed, size_t stream_buffer_size);
void rand_stream_free(struct rand_stream *rs);

const void *rand_stream_peek(struct rand_stream *rs, size_t *num_bytes);
void rand_stream_advance(struct rand_stream *rs, size_t num_bytes);
void rand_stream_read(struct rand_stream *rs, void *buf, size_t num_bytes);

#endif /*__RAND_STREAM_H*/
