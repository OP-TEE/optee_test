cppflags-$(CFG_TA_FLOAT_SUPPORT) += -DCFG_TA_FLOAT_SUPPORT=1

global-incdirs-y += include
global-incdirs-y += ../crypt/include
global-incdirs-y += ../os_test_lib/include
cflags-y += -Wno-float-equal
srcs-y += init.c
srcs-y += os_test.c
srcs-y += ta_entry.c
srcs-$(CFG_TA_FLOAT_SUPPORT) += test_float_subj.c
ifneq ($(COMPILER),clang)
# Profiling (-pg) is disabled for C++ tests because in case it is used for
# function tracing (CFG_FTRACE_SUPPORT=y) then the exception handling code in
# the C++ runtime won't be able to unwind the (modified) stack.
# https://github.com/OP-TEE/optee_os/issues/4022
srcs-y += cxx_tests.cpp
cxxflags-remove-cxx_tests.cpp-y += -pg
srcs-y += cxx_tests_c.c
cflags-remove-cxx_tests_c.c-y += -pg
endif
