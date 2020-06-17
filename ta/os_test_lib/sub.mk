global-incdirs-y += include
srcs-y += os_test_lib.c
ifneq ($(COMPILER),clang)
srcs-y += os_test_lib_cxx.cpp
endif
