LOCAL_PATH := $(call my-dir)

ifeq ($(CFG_CACHE_API),y)
CFLAGS += -DCFG_CACHE_API=y
endif

local_module := 12345678-5b69-11e4-9dbb101f74f00099.ta
include $(BUILD_OPTEE_MK)
