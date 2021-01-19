ifeq ($O,)
out-dir := $(CURDIR)/out
else
include scripts/common.mk
out-dir := $(call strip-trailing-slashes-and-dots,$(O))
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif
endif

-include $(TA_DEV_KIT_DIR)/host_include/conf.mk
-include $(OPTEE_CLIENT_EXPORT)/../optee_client_config.mk

ifneq ($V,1)
	q := @
	echo := @echo
else
	q :=
	echo := @:
endif
# export 'q', used by sub-makefiles.
export q

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
CROSS_COMPILE_HOST ?= $(CROSS_COMPILE)
CROSS_COMPILE_TA ?= $(CROSS_COMPILE)

.PHONY: all
ifneq ($(wildcard $(TA_DEV_KIT_DIR)/host_include/conf.mk),)
all: xtest ta test_plugin
else
all:
	$(q)echo "TA_DEV_KIT_DIR is not correctly defined" && false
endif

.PHONY: xtest
xtest:
	$(q)$(MAKE) -C host/xtest CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			     --no-builtin-variables \
			     O=$(out-dir) \
			     $@

.PHONY: ta
ta:
	$(q)$(MAKE) -C ta CROSS_COMPILE="$(CROSS_COMPILE_TA)" \
			  O=$(out-dir) \
			  $@

.PHONY: test_plugin
test_plugin:
	$(q)$(MAKE) -C host/supp_plugin CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			     O=$(out-dir)

.PHONY: clean
ifneq ($(wildcard $(TA_DEV_KIT_DIR)/host_include/conf.mk),)
clean:
	$(q)$(MAKE) -C host/xtest O=$(out-dir) $@
	$(q)$(MAKE) -C ta O=$(out-dir) $@
	$(q)$(MAKE) -C host/supp_plugin O=$(out-dir) $@
else
clean:
	$(q)echo "TA_DEV_KIT_DIR is not correctly defined"
	$(q)echo "You can remove manually $(out-dir)"
endif

.PHONY: checkpatch checkpatch-staging checkpatch-working
checkpatch: checkpatch-staging checkpatch-working

checkpatch-working:
	@./scripts/checkpatch.sh

checkpatch-staging:
	@./scripts/checkpatch.sh --cached

install:
	$(echo) '  INSTALL ${DESTDIR}/lib/optee_armtz'
	$(q)mkdir -p ${DESTDIR}/lib/optee_armtz
	$(q)find $(out-dir) -name \*.ta -exec cp -a {} ${DESTDIR}/lib/optee_armtz \;
	$(echo) '  INSTALL ${DESTDIR}/bin'
	$(q)mkdir -p ${DESTDIR}/bin
	$(q)cp -a $(out-dir)/xtest/xtest ${DESTDIR}/bin
	$(echo) '  INSTALL ${DESTDIR}/$(CFG_TEE_PLUGIN_LOAD_PATH)'
	$(q)mkdir -p ${DESTDIR}/$(CFG_TEE_PLUGIN_LOAD_PATH)
	$(q)cp $(out-dir)/supp_plugin/*.plugin ${DESTDIR}/$(CFG_TEE_PLUGIN_LOAD_PATH)

.PHONY: cscope
cscope:
	$(echo) '  CSCOPE  .'
	${q}rm -f cscope.*
	${q}find $(PWD) -name "*.[ch]" -o -name "*.cpp" | grep -v /package/ > cscope.files
	${q}cscope -b -q -k
