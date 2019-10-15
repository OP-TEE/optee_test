include $(TA_DEV_KIT_DIR)/mk/conf.mk

BINARY = 5b9e0e40-2636-11e1-ad9e-0002a5d5c51b

ifeq ($(CFG_TA_DYNLINK),y)
# Hack: to locate the os_test library, we assume that its output path
# follows the same scheme as the output path of the os_test application.
# Therefore, simply replacing os_test by os_test_lib in the absolute path
# should get us a valid path
OS_TEST_LIB_LDADD = -L$(subst os_test,os_test_lib,$(abspath $O)) -los_test
OS_TEST_LIB = os_test_lib
endif

LDADD += -ldl

# ensure os_test_lib is present
.PHONY: os_test_lib
os_test_lib:
	@$(MAKE) -C $(subst os_test,os_test_lib,$(abspath $(@D))) all

all: $(OS_TEST_LIB)
	@LDADD="$(OS_TEST_LIB_LDADD) $(LDADD)" $(MAKE) -f ../ta_common.mk BINARY=$(BINARY) $@

%:
	@LDADD="$(OS_TEST_LIB_LDADD) $(LDADD)" $(MAKE) -f ../ta_common.mk BINARY=$(BINARY) $@