// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026, Jaehun Lee */
#include <core_fuzz_ta.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <tee_client_api.h>

#define CORPUS_LIMIT 4096

struct input {
	uint8_t bytes[CORE_FUZZ_TA_MAX_INPUT];
	size_t size;
};

struct record {
	size_t offset;
	size_t length;
	uint8_t opcode;
};

struct runner {
	TEEC_Context context;
	TEEC_Session session;
	uint8_t seen[CORE_FUZZ_TA_COVERAGE_SIZE];
	size_t edges;
};

static uint64_t rng_state;

static uint32_t random_u32(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (uint32_t)((rng_state * UINT64_C(2685821657736338717)) >> 32);
}

static bool parse_input(const struct input *input,
			struct record records[CORE_FUZZ_TA_MAX_RECORDS])
{
	size_t offset = CORE_FUZZ_TA_HEADER_SIZE;
	uint8_t count = 0;
	uint8_t i = 0;

	if (input->size < offset || input->size > CORE_FUZZ_TA_MAX_INPUT ||
	    memcmp(input->bytes, CORE_FUZZ_TA_MAGIC, CORE_FUZZ_TA_MAGIC_SIZE))
		return false;
	count = input->bytes[CORE_FUZZ_TA_MAGIC_SIZE];
	if (!count || count > CORE_FUZZ_TA_MAX_RECORDS)
		return false;
	for (i = 0; i < count; i++) {
		uint8_t opcode = 0;
		size_t length = 0;

		if (input->size - offset < CORE_FUZZ_TA_RECORD_HEADER_SIZE)
			return false;
		opcode = input->bytes[offset];
		length = input->bytes[offset + 2] |
			 ((size_t)input->bytes[offset + 3] << 8);
		if (opcode > CORE_FUZZ_OP_FREE ||
		    input->bytes[offset + 1] >= CORE_FUZZ_TA_SLOTS ||
		    length > CORE_FUZZ_TA_MAX_PAYLOAD ||
		    input->size - offset - CORE_FUZZ_TA_RECORD_HEADER_SIZE <
			    length)
			return false;
		if (((opcode == CORE_FUZZ_OP_DIGEST_ALLOC ||
		      opcode == CORE_FUZZ_OP_FREE) &&
		     length) ||
		    ((opcode == CORE_FUZZ_OP_AES_ALLOC ||
		      opcode == CORE_FUZZ_OP_AES_INIT) &&
		     length != 16))
			return false;
		records[i].offset = offset;
		records[i].length = length;
		records[i].opcode = opcode;
		offset += CORE_FUZZ_TA_RECORD_HEADER_SIZE + length;
	}
	return offset == input->size;
}

static bool valid_input(const struct input *input)
{
	struct record records[CORE_FUZZ_TA_MAX_RECORDS] = { };

	return parse_input(input, records);
}

static bool append_record(struct input *input, uint8_t opcode, uint8_t slot,
			  const uint8_t *payload, size_t length)
{
	size_t offset = input->size;

	if (input->bytes[CORE_FUZZ_TA_MAGIC_SIZE] >= CORE_FUZZ_TA_MAX_RECORDS ||
	    length > CORE_FUZZ_TA_MAX_PAYLOAD ||
	    offset + CORE_FUZZ_TA_RECORD_HEADER_SIZE + length >
		    sizeof(input->bytes))
		return false;
	input->bytes[offset] = opcode;
	input->bytes[offset + 1] = slot;
	input->bytes[offset + 2] = (uint8_t)length;
	input->bytes[offset + 3] = (uint8_t)(length >> 8);
	if (length)
		memcpy(input->bytes + offset + CORE_FUZZ_TA_RECORD_HEADER_SIZE,
		       payload, length);
	input->bytes[CORE_FUZZ_TA_MAGIC_SIZE]++;
	input->size += CORE_FUZZ_TA_RECORD_HEADER_SIZE + length;
	return true;
}

static void start_input(struct input *input)
{
	memset(input, 0, sizeof(*input));
	memcpy(input->bytes, CORE_FUZZ_TA_MAGIC, CORE_FUZZ_TA_MAGIC_SIZE);
	input->size = CORE_FUZZ_TA_HEADER_SIZE;
}

static bool make_digest_seed(struct input *input)
{
	static const uint8_t abc[] = {'a', 'b', 'c'};

	start_input(input);
	return append_record(input, CORE_FUZZ_OP_DIGEST_ALLOC, 0, NULL, 0) &&
	       append_record(input, CORE_FUZZ_OP_DIGEST_UPDATE, 0, abc,
			     sizeof(abc)) &&
	       append_record(input, CORE_FUZZ_OP_DIGEST_FINAL, 0, NULL, 0) &&
	       append_record(input, CORE_FUZZ_OP_FREE, 0, NULL, 0);
}

static bool make_aes_seed(struct input *input)
{
	static const uint8_t key[16] = {0, 1, 2,  3,  4,  5,  6,  7,
					8, 9, 10, 11, 12, 13, 14, 15};
	static const uint8_t iv[16] = {0};
	static const uint8_t data[16] = {0};

	start_input(input);
	return append_record(input, CORE_FUZZ_OP_AES_ALLOC, 0, key,
			     sizeof(key)) &&
	       append_record(input, CORE_FUZZ_OP_AES_INIT, 0, iv, sizeof(iv)) &&
	       append_record(input, CORE_FUZZ_OP_AES_UPDATE, 0, data,
			     sizeof(data)) &&
	       append_record(input, CORE_FUZZ_OP_FREE, 0, NULL, 0);
}

static bool variable_length(uint8_t opcode)
{
	return opcode == CORE_FUZZ_OP_DIGEST_UPDATE ||
	       opcode == CORE_FUZZ_OP_DIGEST_FINAL ||
	       opcode == CORE_FUZZ_OP_AES_UPDATE;
}

static bool mutate(struct input *output, const struct input *parent)
{
	struct record records[CORE_FUZZ_TA_MAX_RECORDS] = {};
	uint8_t count = 0;
	unsigned int attempt = 0;

	*output = *parent;
	if (!parse_input(parent, records))
		return false;
	count = output->bytes[CORE_FUZZ_TA_MAGIC_SIZE];
	for (attempt = 0; attempt < 12; attempt++) {
		struct record *record = &records[random_u32() % count];
		size_t payload =
			record->offset + CORE_FUZZ_TA_RECORD_HEADER_SIZE;
		uint32_t choice = random_u32() % 4;

		if (choice == 0 && record->length) {
			size_t byte = payload + random_u32() % record->length;

			output->bytes[byte] ^= 1U << (random_u32() % 8);
			return true;
		}
		if (choice == 1 && variable_length(record->opcode)) {
			size_t new_length = record->length;
			size_t tail = output->size - payload - record->length;

			if (random_u32() & 1) {
				if (new_length == CORE_FUZZ_TA_MAX_PAYLOAD ||
				    output->size == sizeof(output->bytes))
					continue;
				new_length++;
			} else {
				if (!new_length)
					continue;
				new_length--;
			}
			memmove(output->bytes + payload + new_length,
				output->bytes + payload + record->length, tail);
			if (new_length > record->length)
				output->bytes[payload + new_length - 1] =
					(uint8_t)random_u32();
			output->bytes[record->offset + 2] = (uint8_t)new_length;
			output->bytes[record->offset + 3] =
				(uint8_t)(new_length >> 8);
			if (new_length > record->length)
				output->size++;
			else
				output->size--;
			return true;
		}
		if (choice == 2) {
			output->bytes[record->offset + 1] =
				(uint8_t)(random_u32() % CORE_FUZZ_TA_SLOTS);
			return true;
		}
		if (choice == 3 && count < CORE_FUZZ_TA_MAX_RECORDS) {
			uint8_t saved[CORE_FUZZ_TA_RECORD_HEADER_SIZE +
				      CORE_FUZZ_TA_MAX_PAYLOAD] = {};
			size_t length = CORE_FUZZ_TA_RECORD_HEADER_SIZE +
					record->length;
			size_t insertion = records[count - 1].offset;

			if (output->size + length > sizeof(output->bytes))
				continue;
			memcpy(saved, output->bytes + record->offset, length);
			memmove(output->bytes + insertion + length,
				output->bytes + insertion,
				output->size - insertion);
			memcpy(output->bytes + insertion, saved, length);
			output->bytes[CORE_FUZZ_TA_MAGIC_SIZE]++;
			output->size += length;
			return true;
		}
	}
	return false;
}

struct outcome {
	size_t coverage_bits;
	size_t new_edges;
	uint32_t successful_steps;
	uint32_t last_result;
};

static bool save_input(const char *path, const struct input *input)
{
	FILE *file = fopen(path, "wb");
	bool ok = false;

	if (!file) {
		perror(path);
		return false;
	}
	ok = fwrite(input->bytes, 1, input->size, file) == input->size;
	if (fclose(file))
		ok = false;
	if (!ok)
		fprintf(stderr, "failed to write %s\n", path);
	return ok;
}

static bool load_input(const char *path, struct input *input)
{
	FILE *file = fopen(path, "rb");
	int extra = 0;
	bool ok = false;

	if (!file) {
		perror(path);
		return false;
	}
	input->size = fread(input->bytes, 1, sizeof(input->bytes), file);
	extra = fgetc(file);
	ok = !ferror(file) && extra == EOF;
	fclose(file);
	if (!ok ||
	    !valid_input(input)) {
		fprintf(stderr, "invalid input: %s\n", path);
		return false;
	}
	return true;
}

static bool make_directory(const char *path)
{
	if (!mkdir(path, 0755) || errno == EEXIST)
		return true;
	perror(path);
	return false;
}

static bool path_join(char *path, size_t capacity, const char *dir,
		      const char *name)
{
	int size = snprintf(path, capacity, "%s/%s", dir, name);

	return size > 0 && (size_t)size < capacity;
}

static bool start_runner(struct runner *runner)
{
	const TEEC_UUID uuid = CORE_FUZZ_TA_UUID;
	TEEC_Result result = TEEC_SUCCESS;
	uint32_t origin = 0;

	memset(runner, 0, sizeof(*runner));
	result = TEEC_InitializeContext(NULL, &runner->context);
	if (result != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_InitializeContext: 0x%08" PRIx32 "\n",
			result);
		return false;
	}
	result = TEEC_OpenSession(&runner->context, &runner->session, &uuid,
				  TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (result != TEEC_SUCCESS) {
		fprintf(stderr,
			"TEEC_OpenSession: 0x%08" PRIx32 " origin=%" PRIu32
			"\n",
			result, origin);
		TEEC_FinalizeContext(&runner->context);
		return false;
	}
	return true;
}

static void stop_runner(struct runner *runner)
{
	TEEC_CloseSession(&runner->session);
	TEEC_FinalizeContext(&runner->context);
}

static bool run_input(struct runner *runner, const struct input *input,
		      struct outcome *outcome)
{
	uint8_t map[CORE_FUZZ_TA_COVERAGE_SIZE] = {};
	TEEC_Operation operation = {};
	TEEC_Result result = TEEC_SUCCESS;
	uint32_t origin = 0;
	size_t i = 0;

	memset(outcome, 0, sizeof(*outcome));
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						TEEC_MEMREF_TEMP_OUTPUT,
						TEEC_VALUE_OUTPUT, TEEC_NONE);
	operation.params[0].tmpref.buffer = (void *)input->bytes;
	operation.params[0].tmpref.size = input->size;
	operation.params[1].tmpref.buffer = map;
	operation.params[1].tmpref.size = sizeof(map);
	result = TEEC_InvokeCommand(&runner->session, CORE_FUZZ_TA_CMD_RUN,
				    &operation, &origin);
	if (result != TEEC_SUCCESS) {
		fprintf(stderr,
			"TEEC_InvokeCommand: 0x%08" PRIx32 " origin=%" PRIu32
			"\n",
			result, origin);
		return false;
	}
	if (operation.params[1].tmpref.size != sizeof(map)) {
		fprintf(stderr, "unexpected coverage map size: %zu\n",
			operation.params[1].tmpref.size);
		return false;
	}
	outcome->successful_steps = operation.params[2].value.a;
	outcome->last_result = operation.params[2].value.b;
	for (i = 0; i < sizeof(map); i++) {
		if (!map[i])
			continue;
		outcome->coverage_bits++;
		if (!runner->seen[i]) {
			runner->seen[i] = 1;
			runner->edges++;
			outcome->new_edges++;
		}
	}
	return true;
}

static bool parse_number(const char *text, uint64_t *number)
{
	char *end = NULL;
	unsigned long long value = 0;

	if (!*text || *text == '-')
		return false;
	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno || *end)
		return false;
	*number = value;
	return true;
}

static int replay(const char *path)
{
	struct input input = {};
	struct runner runner = {};
	struct outcome outcome = {};

	if (!load_input(path, &input) || !start_runner(&runner))
		return 1;
	if (!run_input(&runner, &input, &outcome)) {
		stop_runner(&runner);
		return 1;
	}
	printf("REPLAY size=%zu coverage_bits=%zu successful_steps=%" PRIu32
	       " last_result=0x%08" PRIx32 "\n",
	       input.size, outcome.coverage_bits, outcome.successful_steps,
	       outcome.last_result);
	stop_runner(&runner);
	return 0;
}

static int fuzz(uint64_t iterations, uint64_t seed, const char *output_dir)
{
	struct input *corpus = NULL;
	struct input candidate = {};
	struct runner runner = {};
	struct outcome outcome = {};
	char corpus_dir[1024] = {};
	char path[1024] = {};
	char filename[64] = {};
	size_t corpus_count = 0;
	size_t new_entries = 0;
	uint64_t iteration = 0;
	int status = 1;

	corpus = calloc(CORPUS_LIMIT, sizeof(*corpus));
	if (!corpus)
		return 1;
	if (!path_join(corpus_dir, sizeof(corpus_dir), output_dir, "corpus") ||
	    !make_directory(output_dir) || !make_directory(corpus_dir) ||
	    !start_runner(&runner))
		goto out;
	rng_state = seed ? seed : UINT64_C(0x9e3779b97f4a7c15);
	if (!make_digest_seed(&corpus[0]) || !make_aes_seed(&corpus[1]))
		goto out_runner;
	corpus_count = 2;
	for (size_t i = 0; i < corpus_count; i++) {
		if (!path_join(path, sizeof(path), output_dir, "current.bin") ||
		    !save_input(path, &corpus[i]) ||
		    !run_input(&runner, &corpus[i], &outcome))
			goto out_runner;
		if (!outcome.coverage_bits ||
		    outcome.successful_steps !=
			    corpus[i].bytes[CORE_FUZZ_TA_MAGIC_SIZE] ||
		    outcome.last_result != TEEC_SUCCESS) {
			fprintf(stderr, "seed %zu: coverage=%zu ok=%" PRIu32
				" last=0x%08" PRIx32 "\n", i,
				outcome.coverage_bits, outcome.successful_steps,
				outcome.last_result);
			goto out_runner;
		}
		printf("SEED id=%zu coverage_bits=%zu new_edges=%zu\n", i,
		       outcome.coverage_bits, outcome.new_edges);
		snprintf(filename, sizeof(filename), "id-%06zu.bin", i);
		if (!path_join(path, sizeof(path), corpus_dir, filename) ||
		    !save_input(path, &corpus[i]))
			goto out_runner;
	}
	if (!runner.edges) {
		fprintf(stderr, "all valid seeds produced zero core coverage; "
				"check PTA and instrumentation\n");
		goto out_runner;
	}
	for (iteration = 1; iteration <= iterations; iteration++) {
		const struct input *parent =
			&corpus[random_u32() % corpus_count];

		if (!mutate(&candidate, parent))
			continue;
		if (!valid_input(&candidate)) {
			fprintf(stderr, "mutator created an invalid input\n");
			goto out_runner;
		}
		if (!path_join(path, sizeof(path), output_dir, "current.bin") ||
		    !save_input(path, &candidate) ||
		    !run_input(&runner, &candidate, &outcome))
			goto out_runner;
		if (outcome.new_edges) {
			if (corpus_count < CORPUS_LIMIT)
				corpus[corpus_count++] = candidate;
			new_entries++;
			snprintf(filename, sizeof(filename), "id-%06zu.bin",
				 new_entries + 1);
			if (!path_join(path, sizeof(path), corpus_dir,
				       filename) ||
			    !save_input(path, &candidate))
				goto out_runner;
			printf("NEW_COVERAGE iteration=%" PRIu64
			       " new_edges=%zu total_edges=%zu corpus=%zu\n",
			       iteration, outcome.new_edges, runner.edges,
			       corpus_count);
		}
		if (iteration % 100 == 0 || iteration == iterations)
			printf("PROGRESS executions=%" PRIu64
			       " coverage_bits=%zu new_corpus_entries=%zu\n",
			       iteration + 2, runner.edges, new_entries);
	}
	status = 0;
	printf("DONE executions=%" PRIu64 " coverage_bits=%zu",
	       iterations + 2, runner.edges);
	printf(" new_corpus_entries=%zu corpus=%zu\n",
	       new_entries, corpus_count);
out_runner:
	stop_runner(&runner);
out:
	free(corpus);
	return status;
}

int main(int argc, char *argv[])
{
	uint64_t iterations = 0;
	uint64_t seed = 0;

	if (argc == 3 && !strcmp(argv[1], "replay"))
		return replay(argv[2]);
	if (argc == 5 && !strcmp(argv[1], "fuzz") &&
	    parse_number(argv[2], &iterations) &&
	    parse_number(argv[3], &seed) && iterations)
		return fuzz(iterations, seed, argv[4]);
	fprintf(stderr,
		"usage: %s replay INPUT\n"
		"       %s fuzz ITERATIONS SEED OUTPUT_DIR\n",
		argv[0], argv[0]);
	return 2;
}
