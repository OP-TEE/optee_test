ifneq ($O,)
	out-dir := $O
else
	# If no build folder has been specified, then create all build files in
	# the current directory under a folder named out.
	out-dir := $(CURDIR)/out
endif

ifneq ($V,1)
	q := @
else
	q :=
endif

.PHONY: all
all: xtest ta

.PHONY: xtest
xtest:
	$(q)$(MAKE) -C host/xtest CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			     q=$(q) \
			     O=$(out-dir)/xtest \
			     $@

.PHONY: ta
ta:
	$(q)$(MAKE) -C ta CROSS_COMPILE="$(CROSS_COMPILE_TA)" \
			  q=$(q) \
			  O=$(out-dir)/ta \
			  $@

.PHONY: clean
clean:
	$(q)$(MAKE) -C host/xtest O=$(out-dir)/xtest q=$(q) $@
	$(q)$(MAKE) -C ta O=$(out-dir)/ta q=$(q) $@

.PHONY: patch
patch:
ifeq ($(CFG_GP_TESTSUITE_ENABLE),y)
CFG_GP_API?=1.0
CFG_GP_XSL_PACKAGE_PATH?=$(CFG_DEV_PATH)/optee_test/package/testsuite/global_platform/api_1.0/GP_XSL_TEE_Initial_Configuration-Test_Suite_v1_0_0-2014-12-03-STM
patch:
	$(q) CFG_GP_API=$(CFG_GP_API) CFG_GP_XSL_PACKAGE_PATH=$(CFG_GP_XSL_PACKAGE_PATH) $(CURDIR)/scripts/patch_gp_testsuite.sh
endif
