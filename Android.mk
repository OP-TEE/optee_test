LOCAL_PATH := $(call my-dir)

VERSION = $(shell git describe --always --dirty=-dev 2>/dev/null || echo Unknown)
OPTEE_CLIENT_PATH ?= $(LOCAL_PATH)/../optee_client

-include $(TA_DEV_KIT_DIR)/host_include/conf.mk

include $(CLEAR_VARS)
LOCAL_MODULE := xtest
LOCAL_SHARED_LIBRARIES := libteec

srcs := xtest_1000.c \
	xtest_4000.c \
	xtest_5000.c \
	xtest_6000.c \
	xtest_7000.c \
	xtest_10000.c \
	xtest_20000.c \
	xtest_benchmark_1000.c \
	xtest_helpers.c \
	xtest_main.c \
	xtest_test.c \
	adbg/src/adbg_case.c \
	adbg/src/adbg_enum.c \
	adbg/src/adbg_expect.c \
	adbg/src/adbg_log.c \
	adbg/src/adbg_mts.c \
	adbg/src/adbg_run.c \
	adbg/src/adbg_util.c \
	adbg/src/r_list_genutil.c \
	adbg/src/security_utils_hex.c \
	adbg/src/security_utils_mem.c

LOCAL_SRC_FILES := $(patsubst %,host/xtest/%,$(srcs))

LOCAL_C_INCLUDES += host/xtest
LOCAL_C_INCLUDES += host/xtest/adbg/include
LOCAL_C_INCLUDES += host/xtest/xml/include
LOCAL_C_INCLUDES += $(TA_DEV_KIT_DIR)/host_include

LOCAL_C_INCLUDES += ta/concurrent/include
LOCAL_C_INCLUDES += ta/create_fail_test/include
LOCAL_C_INCLUDES += ta/crypt/include
LOCAL_C_INCLUDES += ta/enc_fs/include
LOCAL_C_INCLUDES += ta/os_test/include
LOCAL_C_INCLUDES += ta/rpc_test/include
LOCAL_C_INCLUDES += ta/sims/include
LOCAL_C_INCLUDES += ta/storage/include
LOCAL_C_INCLUDES += ta/storage_benchmark/include

ifeq ($(CFG_ENC_FS),y)
LOCAL_CFLAGS += -DCFG_ENC_FS
endif
ifeq ($(CFG_RPMB_FS),y)
LOCAL_CFLAGS += -DCFG_RPMB_FS
endif

LOCAL_CFLAGS += -DUSER_SPACE
LOCAL_CFLAGS += -DTA_DIR=\"/system/lib/optee_armtz\"
LOCAL_CFLAGS += -pthread

include $(BUILD_EXECUTABLE)
