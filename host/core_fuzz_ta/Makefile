# SPDX-License-Identifier: GPL-2.0
# Copyright (c) 2026, Jaehun Lee

O ?= $(CURDIR)/out/demo
OPTEE_CLIENT_EXPORT ?= ../../../optee_client/out/export
CC = $(CROSS_COMPILE)gcc
CPPFLAGS += -I$(OPTEE_CLIENT_EXPORT)/include
CPPFLAGS += -I../../ta/core_fuzz_ta/include
CFLAGS += -O2 -Wall -Wextra -Werror -std=gnu11
LDLIBS += -L$(OPTEE_CLIENT_EXPORT)/lib -lteec
binary := $(abspath $(O))/core-fuzz-demo

.PHONY: all
all: $(binary)

$(binary): main.c ../../ta/core_fuzz_ta/include/core_fuzz_ta.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ main.c $(LDLIBS)
