/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2018, Linaro Limited
 */

#ifndef SEED_RNG_TAF_H
#define SEED_RNG_TAF_H

#ifdef CFG_SYSTEM_PTA

#include <pta_system.h>

TEE_Result seed_rng_pool(uint32_t param_types, TEE_Param params[4]);

#endif /* CFG_SYSTEM_PTA */

#endif /* SEED_RNG_TAF_H */
