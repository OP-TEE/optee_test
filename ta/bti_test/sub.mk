global-incdirs-y += include

srcs-y += ta_entry.c
ifeq ($(sm),ta_arm64)
srcs-$(CFG_TA_BTI) += bti_stubs_a64.S
srcs-$(CFG_TA_BTI) += ta_arm_bti.c
endif
