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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>

#include "rand_stream.h"

#define STREAM_BUF_MIN_SIZE	4

struct rand_stream {
	struct random_data random_data;
	char state_buf[128];
	uint8_t word_buf[4];
	size_t w_offs;
	size_t sb_size;
	size_t sb_offs;
	uint8_t stream_buf[];
};

struct rand_stream *rand_stream_alloc(int seed, size_t stream_buffer_size)
{
	size_t sb_size = MAX(stream_buffer_size, STREAM_BUF_MIN_SIZE);
	struct rand_stream *rs = calloc(1, sizeof(*rs) + sb_size);

	if (!rs)
		return NULL;

	rs->sb_size = sb_size;;
	rs->sb_offs = rs->sb_size;
	rs->w_offs = sizeof(rs->word_buf);

	if (initstate_r(seed, rs->state_buf, sizeof(rs->state_buf),
			&rs->random_data)) {
		free(rs);
		return NULL;
	}

	return rs;
}

void rand_stream_free(struct rand_stream *rs)
{
	free(rs);
}

static void get_random(struct rand_stream *rs, uint8_t *buf, size_t blen)
{
	uint8_t *b = buf;
	size_t l = blen;

	while (l) {
		size_t t = MIN(sizeof(rs->word_buf) - rs->w_offs, l);

		memcpy(b, rs->word_buf + rs->w_offs, t);
		rs->w_offs += t;
		l -= t;
		b += t;

		if (rs->w_offs == sizeof(rs->word_buf)) {
			int32_t r;

			random_r(&rs->random_data, &r);
			memcpy(rs->word_buf, &r, sizeof(r));
			rs->w_offs = 0;
		}
	}
}

const void *rand_stream_peek(struct rand_stream *rs, size_t *num_bytes)
{
	if (rs->sb_offs == rs->sb_size) {
		rs->sb_offs = 0;
		get_random(rs, rs->stream_buf, rs->sb_size);
	}

	*num_bytes = MIN(*num_bytes, rs->sb_size - rs->sb_offs);
	return rs->stream_buf + rs->sb_offs;
}

void rand_stream_read(struct rand_stream *rs, void *buf, size_t num_bytes)
{
	size_t peek_bytes = num_bytes;
	const void *peek = rand_stream_peek(rs, &peek_bytes);

	memcpy(buf, peek, peek_bytes);
	rand_stream_advance(rs, peek_bytes);

	if (num_bytes - peek_bytes)
		get_random(rs, (uint8_t *)buf + peek_bytes,
			   num_bytes - peek_bytes);
}

void rand_stream_advance(struct rand_stream *rs, size_t num_bytes)
{
	size_t nb = num_bytes;

	if (nb <= (rs->sb_size - rs->sb_offs)) {
		rs->sb_offs += nb;
		return;
	}

	nb -= rs->sb_size - rs->sb_offs;
	rs->sb_offs = rs->sb_size;

	while (nb > rs->sb_size) {
		get_random(rs, rs->stream_buf, rs->sb_size);
		nb -= rs->sb_size;
	}

	get_random(rs, rs->stream_buf, rs->sb_size);
	rs->sb_offs = nb;
}
