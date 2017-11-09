/*
 * Copyright (c) 2017, Linaro Limited
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <compiler.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <pta_secstor_ta_mgmt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <tee_client_api.h>
#include <unistd.h>
#include "xtest_test.h"
#include "install_ta.h"

static void *read_ta(const char *dname, const char *fname, size_t *size)
{
	char nbuf[PATH_MAX];
	FILE *f;
	void *buf;
	size_t s;

	if (dname)
		snprintf(nbuf, sizeof(nbuf), "%s/%s", dname, fname);
	else
		snprintf(nbuf, sizeof(nbuf), "%s", fname);

	f = fopen(nbuf, "rb");
	if (!f)
		err(1, "fopen(\"%s\")", nbuf);

	if (fseek(f, 0, SEEK_END))
		err(1, "fseek");

	s = ftell(f);
	rewind(f);

	buf = malloc(s);
	if (!buf)
		err(1, "malloc(%zu)", s);

	if (fread(buf, 1, s, f) != s)
		err(1, "fread");

	*size = s;
	return buf;
}

static void install_ta(TEEC_Session *sess, void *buf, size_t blen)
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_Operation op;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = buf;
	op.params[0].tmpref.size = blen;

	res = TEEC_InvokeCommand(sess, PTA_SECSTOR_TA_MGMT_BOOTSTRAP, &op,
				 &err_origin);
	if (res)
		errx(1, "install_ta: TEEC_InvokeCommand: %#" PRIx32
			" err_origin %#" PRIx32, res, err_origin);
}

static void install_file(TEEC_Session *sess, const char *dirname,
			 const char *filename)
{
	void *ta;
	size_t ta_size;

	printf("Installing \"%s\"\n", filename);
	ta = read_ta(dirname, filename, &ta_size);
	install_ta(sess, ta, ta_size);
	free(ta);
}

static void install_dir(TEEC_Session *sess, const char *dirname)
{
	DIR *dirp;

	printf("Searching directory \"%s\" for TAs\n", dirname);
	dirp = opendir(dirname);
	if (!dirp)
		err(1, "opendir(\"%s\")", dirname);

	while (true) {
		struct dirent *dent = readdir(dirp);

		if (!dent)
			break;

		if (fnmatch("*.ta", dent->d_name, 0))
			continue;

		install_file(sess, dirname, dent->d_name);
	}

	closedir(dirp);
}

int install_ta_runner_cmd_parser(int argc, char *argv[])
{
	TEEC_Result res;
	uint32_t err_origin;
	TEEC_UUID uuid = PTA_SECSTOR_TA_MGMT_UUID;
	TEEC_Context ctx;
	TEEC_Session sess;
	int i;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res)
		errx(1, "TEEC_InitializeContext: %#" PRIx32, res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	if (res)
		errx(1, "TEEC_OpenSession: res %#" PRIx32 " err_orig %#" PRIx32,
			res, err_origin);

	for (i = 1; i < argc; i++) {
		struct stat sb;

		if (stat(argv[i], &sb)) {
			printf("Skipping \"%s\": %s", argv[i], strerror(errno));
			continue;
		}

		if (S_ISDIR(sb.st_mode))
			install_dir(&sess, argv[i]);
		else if (S_ISREG(sb.st_mode))
			install_file(&sess, NULL, argv[i]);
		else
			printf("Skipping unknown file type \"%s\", mode 0%o",
			       argv[i], sb.st_mode);
	}

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	printf("Installing TAs done\n");

	return 0;
}
