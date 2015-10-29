LOCAL_PATH := $(call my-dir)

VERSION = $(shell git describe --always --dirty=-dev 2>/dev/null || echo Unknown)
OPTEE_CLIENT_PATH ?= $(LOCAL_PATH)/../optee_client

include $(CLEAR_VARS)
LOCAL_MODULE := teec
LOCAL_SRC_FILES := $(OPTEE_CLIENT_PATH)/libs/$(TARGET_ARCH_ABI)/libteec.so
LOCAL_EXPORT_C_INCLUDES := $(OPTEE_CLIENT_PATH)/public
include $(PREBUILT_SHARED_LIBRARY)

-include $(TA_DEV_KIT_DIR)/host_include/conf.mk

include $(CLEAR_VARS)
LOCAL_MODULE := xtest
LOCAL_SHARED_LIBRARIES := teec

ifdef CFG_GP_PACKAGE_PATH
GP := _gp
endif

srcs := xtest_1000.c \
	xtest_4000.c \
	xtest_5000.c \
	xtest_6000.c \
	xtest_7000$(GP).c \
	xtest_10000.c \
	xtest_20000.c \
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

ifdef CFG_GP_PACKAGE_PATH
LOCAL_CFLAGS += -DWITH_GP_TESTS

srcs  += xtest_7500.c \
	 xtest_8000.c \
	 xtest_8500.c \
	 xtest_9000.c
endif

LOCAL_SRC_FILES := $(patsubst %,host/xtest/%,$(srcs))

LOCAL_C_INCLUDES += host/xtest
LOCAL_C_INCLUDES += host/xtest/adbg/include
LOCAL_C_INCLUDES += host/xtest/xml/include
LOCAL_C_INCLUDES += $(TA_DEV_KIT_DIR)/host_include

LOCAL_C_INCLUDES += ta/create_fail_test/include
LOCAL_C_INCLUDES += ta/crypt/include
LOCAL_C_INCLUDES += ta/enc_fs/include
LOCAL_C_INCLUDES += ta/os_test/include
LOCAL_C_INCLUDES += ta/rpc_test/include
LOCAL_C_INCLUDES += ta/sims/include
LOCAL_C_INCLUDES += ta/storage/include
ifdef CFG_GP_PACKAGE_PATH
LOCAL_C_INCLUDES += ta/GP_TTA_Arithmetical
LOCAL_C_INCLUDES += ta/GP_TTA_Crypto
LOCAL_C_INCLUDES += ta/GP_TTA_DS
LOCAL_C_INCLUDES += ta/GP_TTA_TCF
LOCAL_C_INCLUDES += ta/GP_TTA_TCF_ICA
LOCAL_C_INCLUDES += ta/GP_TTA_TCF_ICA2
LOCAL_C_INCLUDES += ta/GP_TTA_TCF_MultipleInstanceTA
LOCAL_C_INCLUDES += ta/GP_TTA_TCF_SingleInstanceTA
LOCAL_C_INCLUDES += ta/GP_TTA_Time
LOCAL_C_INCLUDES += ta/GP_TTA_answerErrorTo_Invoke
LOCAL_C_INCLUDES += ta/GP_TTA_answerErrorTo_OpenSession
LOCAL_C_INCLUDES += ta/GP_TTA_answerSuccessTo_OpenSession_Invoke
LOCAL_C_INCLUDES += ta/GP_TTA_check_OpenSession_with_4_parameters
LOCAL_C_INCLUDES += ta/GP_TTA_testingClientAPI
LOCAL_C_INCLUDES += host/xtest/for_gp/include
ifeq ($(CFG_ARM32),y)
LOCAL_LDLIBS += host/lib/armv7/libcrypto.a
else
LOCAL_LDLIBS += host/lib/armv8/libcrypto.a
endif
endif # CFG_GP_PACKAGE_PATH

ifeq ($(CFG_ENC_FS),y)
LOCAL_CFLAGS += -DCFG_ENC_FS
endif

#ifndef CFG_GP_PACKAGE_PATH
#LOCAL_CFLAGS += -Wall -Wcast-align -Werror \
#		-Werror-implicit-function-declaration -Wextra -Wfloat-equal \
#		-Wformat-nonliteral -Wformat-security -Wformat=2 -Winit-self \
#		-Wmissing-declarations -Wmissing-format-attribute \
#		-Wmissing-include-dirs -Wmissing-noreturn \
#		-Wmissing-prototypes -Wnested-externs -Wpointer-arith \
#		-Wshadow -Wstrict-prototypes -Wswitch-default \
#		-Wwrite-strings \
#		-Wno-missing-field-initializers -Wno-format-zero-length
#endif

LOCAL_CFLAGS += -DUSER_SPACE
LOCAL_CFLAGS += -pthread

include $(BUILD_EXECUTABLE)
