include $(TA_DEV_KIT_DIR)/mk/conf.mk

ifeq ($(CFG_TA_DL),y) # OP-TEE provides libdl

SHLIBNAME = libos_test_dl
SHLIBUUID = b3091a65-9751-4784-abf7-0298a7cc35ba
include ../ta_common.mk

else

# For the buildroot environment
all:

endif
