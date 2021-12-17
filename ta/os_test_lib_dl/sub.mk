global-incdirs-y += include
srcs-y += os_test_lib_dl.c
ifeq ($(WITH_CXX_TESTS),y)
ifneq ($(COMPILER),clang)
srcs-y += os_test_lib_dl_cxx.cpp
endif
endif
