BINARY = e626662e-c0e2-485c-b8c8-09fbce6edf3d

include $(TA_DEV_KIT_DIR)/host_include/conf.mk

ifeq ($(CFG_CACHE_API),y)
CFLAGS += -DCFG_CACHE_API=y
endif
ifeq ($(CFG_SECURE_DATA_PATH),y)
CFLAGS += -DCFG_SECURE_DATA_PATH=y
endif

include ../ta_common.mk

