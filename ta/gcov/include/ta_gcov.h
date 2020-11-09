/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2020 NXP
 */

#ifndef TA_GCOV_H
#define TA_GCOV_H

#define TA_GCOV_UUID { 0xa424901c, 0x4810, 0x4e4d, \
		{ 0xaa, 0x76, 0x62, 0xef, 0x00, 0x45, 0x34, 0x3f} }

/*
 * TA_GCOV_CMD_GET_VERSION - Proxy function which calls gcov_get_version()
 *
 * [out]    value[0].a	    version of gcov
 */
#define TA_GCOV_CMD_GET_VERSION	0

/*
 * TA_GCOV_CMD_DUMP_CORE - Proxy function which invoke
 * PTA_CMD_GCOV_CORE_DUMP_ALL from gcov PTA
 *
 * [in]    memref[0]	     Name of the dump
*/
#define TA_GCOV_CMD_DUMP_CORE	1

/*
 * TA_GCOV_CMD_DUMP_TA - Proxy function which calls
 * gcov_dump_all_coverage_data()
 *
 * [in]    memref[0]	    Name of the dump
 */
#define TA_GCOV_CMD_DUMP_TA	2

#endif /* TA_GCOV_H */
