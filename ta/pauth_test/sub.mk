global-incdirs-y += include

srcs-y += ta_entry.c
ifeq ($(sm),ta_arm64)
srcs-$(CFG_TA_PAUTH) += pauth_a64.S
srcs-$(CFG_TA_PAUTH) += ta_arm_pauth.c
# -march=armv8.3-a enables the non-nops instructions for PAC. We are using one
#  such instruction in the PAC test.
cflags-$(CFG_TA_PAUTH) += -march=armv8.3-a
endif
