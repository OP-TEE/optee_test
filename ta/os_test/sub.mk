cppflags-$(CFG_TA_FLOAT_SUPPORT) += -DCFG_TA_FLOAT_SUPPORT=1

global-incdirs-y += include
global-incdirs-y += ../crypt/include
global-incdirs-y += ../os_test_lib/include
cflags-y += -Wno-float-equal
srcs-y += init.c
srcs-y += os_test.c
srcs-y += ta_entry.c
srcs-$(CFG_TA_FLOAT_SUPPORT) += test_float_subj.c
