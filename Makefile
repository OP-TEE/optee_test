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
all: xtest ta
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

.PHONY: clean
ifneq ($(wildcard $(TA_DEV_KIT_DIR)/host_include/conf.mk),)
clean:
	$(q)$(MAKE) -C host/xtest O=$(out-dir) $@
	$(q)$(MAKE) -C ta O=$(out-dir) $@
else
clean:
	$(q)echo "TA_DEV_KIT_DIR is not correctly defined"
	$(q)echo "You can remove manually $(out-dir)"
endif

.PHONY: patch
patch:
ifdef CFG_GP_PACKAGE_PATH
CFG_GP_API?=1.0
CFG_GP_XSL_PACKAGE_PATH?=$(CURDIR)/package/testsuite/global_platform/api_1.0/GP_XSL_TEE_Initial_Configuration-Test_Suite_v1_0_0-2014-12-03-STM

ifeq "$(wildcard $(CFG_GP_XSL_PACKAGE_PATH) )" ""
$(error CFG_GP_XSL_PACKAGE_PATH must contain the xsl package)
endif

ifeq "$(wildcard $(CFG_GP_PACKAGE_PATH) )" ""
$(error CFG_GP_PACKAGE_PATH must contain the xml package from GP)
endif

# Note that only TEE_Initial_Configuration-Test_Suite_v1_1_0_4-2014_11_07 is supported

GP_XTEST_OUT_DIR=$(CURDIR)/host/xtest
GP_XTEST_IN_DIR=${GP_XTEST_OUT_DIR}/global_platform/${CFG_GP_API}
GP_USERTA_DIR=$(CURDIR)/ta

define patch-file
	@if [ ! -e ${1} ]; then \
		echo "Error: File to patch is unknown: $1"; \
		return 1; \
	fi
	@if [ ! -e ${2} ]; then \
		echo "Error: Patch to apply is unknown: $2"; \
		return 1; \
	fi
	@if [ ! -e ${1}.orig ]; then \
		patch -N -b ${1} < ${2}; \
	else \
		echo "Warning: Patch already applied on `basename $1`"; \
	fi
endef

define mv-package
	@if [ -d ${1} ]; then \
		mv ${1} ${CFG_GP_PACKAGE_PATH}/packages ;\
	fi
endef

define patch-xalan
	$(q)rm -f ${GP_XTEST_OUT_DIR}/${3} ${GP_XTEST_OUT_DIR}/${3}.orig
	$(q)xalan -in ${GP_XTEST_IN_DIR}/${1} -xsl ${GP_XTEST_IN_DIR}/${2} -out ${GP_XTEST_OUT_DIR}/${3}
endef

# Generate host files
define patch-cp-ta
	$(q)rm -rf $(GP_USERTA_DIR)/${3}
	$(q)mkdir -p $(GP_USERTA_DIR)/${3}
	$(q)cp -p $(CFG_GP_PACKAGE_PATH)/${1}/* $(GP_USERTA_DIR)/${3}
	$(q)cp -p $(CFG_GP_XSL_PACKAGE_PATH)/${2}/* $(GP_USERTA_DIR)/${3}
endef

.PHONY: patch-generate-host
patch-generate-host: patch-package
	@echo "INFO: Generate host tests"
	$(q) mkdir -p ${GP_XTEST_IN_DIR} ${GP_XTEST_IN_DIR}
	$(q)find ${CFG_GP_PACKAGE_PATH}/packages -type f -name "*.xml" -exec cp -p {} ${GP_XTEST_IN_DIR} \;
	$(q)find ${CFG_GP_XSL_PACKAGE_PATH}/packages -type f -name "*.xsl" -exec cp -p {} ${GP_XTEST_IN_DIR} \;
	$(call patch-xalan,TEE.xml,TEE.xsl,gp_7000.c)
	$(call patch-xalan,TEE_DataStorage_API.xml,TEE_DataStorage_API.xsl,gp_7500.c)
	$(call patch-xalan,TEE_Internal_API.xml,TEE_Internal_API.xsl,gp_8000.c)
	$(call patch-xalan,TEE_TimeArithm_API.xml,TEE_TimeArithm_API.xsl,gp_8500.c)
	$(call patch-xalan,TEE_Crypto_API.xml,TEE_Crypto_API.xsl,gp_9000.c)
	@echo "INFO: Patch host tests"
	# $(q)sed -i '752 c\    xtest_tee_deinit();\n' ${GP_XTEST_OUT_DIR}/xtest_7000.c
	# $(q)sed -i '1076 c\    xtest_tee_deinit();\n' ${GP_XTEST_OUT_DIR}/xtest_8000.c
	# $(q)sed -i '2549 c\    xtest_tee_deinit();\n' ${GP_XTEST_OUT_DIR}/xtest_8500.c
	# $(q)sed -i '246 c\    xtest_tee_deinit();\n' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	$(call patch-file,host/xtest/gp_9000.c,${CFG_GP_XSL_PACKAGE_PATH}/host/xtest/gp_9000.c.patch)

.PHONY: patch-generate-ta
patch-generate-ta: patch-package
	@echo "INFO: Generate TA"
	$(call patch-cp-ta,TTAs/TTA_Arithmetical/TTA_Arithmetical/code_files,TTAs/TTA_Arithmetical/code_files,GP_TTA_Arithmetical)
	$(call patch-cp-ta,TTAs/TTA_DS/TTA_DS/code_files,TTAs/TTA_DS/code_files,GP_TTA_DS)
	$(call patch-cp-ta,TTAs/TTA_ClientAPI/TTA_answerErrorTo_Invoke/code_files,TTAs/TTA_ClientAPI/TTA_answerErrorTo_Invoke/code_files,GP_TTA_answerErrorTo_Invoke)
	$(call patch-cp-ta,TTAs/TTA_ClientAPI/TTA_check_OpenSession_with_4_parameters/code_files,TTAs/TTA_ClientAPI/TTA_check_OpenSession_with_4_parameters/code_files,GP_TTA_check_OpenSession_with_4_parameters)
	$(q) cp $(CFG_GP_PACKAGE_PATH)/TTAs/TTA_ClientAPI/ta_check_OpenSession_with_4_parameters/code_files/TTA_check_OpenSession_with_4_parameters_protocol.h $(GP_USERTA_DIR)/GP_TTA_check_OpenSession_with_4_parameters
	$(call patch-cp-ta,TTAs/TTA_ClientAPI/TTA_answerErrorTo_OpenSession/code_files,TTAs/TTA_ClientAPI/TTA_answerErrorTo_OpenSession/code_files,GP_TTA_answerErrorTo_OpenSession)
	$(call patch-cp-ta,TTAs/TTA_ClientAPI/TTA_testingClientAPI/code_files,TTAs/TTA_ClientAPI/TTA_testingClientAPI/code_files,GP_TTA_testingClientAPI)
	$(call patch-cp-ta,TTAs/TTA_ClientAPI/TTA_answerSuccessTo_OpenSession_Invoke/code_files,TTAs/TTA_ClientAPI/TTA_answerSuccessTo_OpenSession_Invoke/code_files,GP_TTA_answerSuccessTo_OpenSession_Invoke)
	$(call patch-cp-ta,TTAs/TTA_Crypto/TTA_Crypto/code_files,TTAs/TTA_Crypto/code_files,GP_TTA_Crypto)
	$(call patch-cp-ta,TTAs/TTA_Time/TTA_Time/code_files,TTAs/TTA_Time/code_files,GP_TTA_Time)
	$(call patch-cp-ta,TTAs/TTA_TCF/TTA_TCF_SingleInstanceTA/code_files,TTAs/TTA_TCF/TTA_TCF_SingleInstanceTA/code_files,GP_TTA_TCF_SingleInstanceTA)
	$(call patch-cp-ta,TTAs/TTA_TCF/TTA_TCF_ICA/code_files,TTAs/TTA_TCF/TTA_TCF_ICA/code_files,GP_TTA_TCF_ICA)
	$(call patch-cp-ta,TTAs/TTA_TCF/TTA_TCF_MultipleInstanceTA/code_files,TTAs/TTA_TCF/TTA_TCF_MultipleInstanceTA/code_files,GP_TTA_TCF_MultipleInstanceTA)
	$(call patch-cp-ta,TTAs/TTA_TCF/TTA_TCF_ICA2/code_files,TTAs/TTA_TCF/TTA_TCF_ICA2/code_files,GP_TTA_TCF_ICA2)
	$(call patch-cp-ta,TTAs/TTA_TCF/TTA_TCF/code_files,TTAs/TTA_TCF/TTA_TCF/code_files,GP_TTA_TCF)

# Patch the GP package
.PHONY: patch-package
patch-package:
	@echo "INFO: Patch provided tests"
	$(q)mkdir -p ${CFG_GP_PACKAGE_PATH}/packages
	$(call mv-package,${CFG_GP_PACKAGE_PATH}/ClientAPI)
	$(call mv-package,${CFG_GP_PACKAGE_PATH}/Crypto)
	$(call mv-package,${CFG_GP_PACKAGE_PATH}/DataStorage)
	$(call mv-package,${CFG_GP_PACKAGE_PATH}/Time_Arithmetical)
	$(call mv-package,${CFG_GP_PACKAGE_PATH}/TrustedCoreFw)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/packages/ClientAPI/xmlStable/TEE.xml,${CFG_GP_XSL_PACKAGE_PATH}/packages/ClientAPI/xmlpatch/v1_1_0_4-2014_11_07/TEE.xml.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/packages/Crypto/xmlStable/TEE_Crypto_API.xml,${CFG_GP_XSL_PACKAGE_PATH}/packages/Crypto/xmlpatch/v1_1_0_4-2014_11_07/TEE_Crypto_API.xml.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/packages/DataStorage/xmlStable/TEE_DataStorage_API.xml,${CFG_GP_XSL_PACKAGE_PATH}/packages/DataStorage/xmlpatch/v1_1_0_4-2014_11_07/TEE_DataStorage_API.xml.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/packages/Time_Arithmetical/xmlStable/TEE_TimeArithm_API.xml,${CFG_GP_XSL_PACKAGE_PATH}/packages/Time_Arithmetical/xmlpatch/v1_1_0_4-2014_11_07/TEE_TimeArithm_API.xml.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/packages/TrustedCoreFw/xmlStable/TEE_Internal_API.xml,${CFG_GP_XSL_PACKAGE_PATH}/packages/TrustedCoreFw/xmlpatch/v1_1_0_4-2014_11_07/TEE_Internal_API.xml.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Arithmetical/TTA_Arithmetical/code_files/TTA_Arithmetical.c,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Arithmetical/code_patches/v1_1_0_4-2014_11_07/TTA_Arithmetical.c.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Arithmetical/TTA_Arithmetical/code_files/TTA_Arithmetical_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Arithmetical/code_patches/v1_1_0_4-2014_11_07/TTA_Arithmetical_protocol.h.patch)
	# $(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/ta_check_OpenSession_with_4_parameters/code_files/TTA_check_OpenSession_with_4_parameters_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_check_OpenSession_with_4_parameters/code_patches/v1_1_0_4-2014_11_07/TTA_check_OpenSession_with_4_parameters_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_testingClientAPI/code_files/TTA_testingClientAPI_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_testingClientAPI/code_patches/v1_1_0_4-2014_11_07/TTA_testingClientAPI_protocol.h.patch)
	# $(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerSuccessTo_OpenSession_Invoke/code_files/TTA_answerSuccessTo_OpenSession_Invoke_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerSuccessTo_OpenSession_Invoke/code_patches/v1_1_0_4-2014_11_07/TTA_answerSuccessTo_OpenSession_Invoke_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerErrorTo_OpenSession/code_files/TTA_answerErrorTo_OpenSession_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerErrorTo_OpenSession/code_patches/v1_1_0_4-2014_11_07/TTA_answerErrorTo_OpenSession_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerErrorTo_Invoke/code_files/TTA_answerErrorTo_Invoke_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerErrorTo_Invoke/code_patches/v1_1_0_4-2014_11_07/TTA_answerErrorTo_Invoke_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Crypto/TTA_Crypto/code_files/TTA_Crypto.c,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Crypto/code_patches/v1_1_0_4-2014_11_07/TTA_Crypto.c.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Crypto/TTA_Crypto/code_files/TTA_Crypto_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Crypto/code_patches/v1_1_0_4-2014_11_07/TTA_Crypto_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_DS/TTA_DS/code_files/TTA_DS_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_DS/code_patches/v1_1_0_4-2014_11_07/TTA_DS_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_DS/TTA_DS/code_files/TTA_DS.c,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_DS/code_patches/v1_1_0_4-2014_11_07/TTA_DS.c.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TEE_include/tee_internal_api.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TEE_include/code_patches/v1_1_0_4-2014_11_07/tee_internal_api.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_ICA/code_files/TTA_TCF_ICA_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_ICA/code_patches/v1_1_0_4-2014_11_07/TTA_TCF_ICA_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_MultipleInstanceTA/code_files/TTA_TCF_MultipleInstanceTA_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_MultipleInstanceTA/code_patches/v1_1_0_4-2014_11_07/TTA_TCF_MultipleInstanceTA_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_MultipleInstanceTA/code_files/TTA_TCF_MultipleInstanceTA.c,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_MultipleInstanceTA/code_patches/v1_1_0_4-2014_11_07/TTA_TCF_MultipleInstanceTA.c.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_SingleInstanceTA/code_files/TTA_TCF_SingleInstanceTA.c,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_SingleInstanceTA/code_patches/v1_1_0_4-2014_11_07/TTA_TCF_SingleInstanceTA.c.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF/code_files/TTA_TCF.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF/code_patches/v1_1_0_4-2014_11_07/TTA_TCF.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_SingleInstanceTA/code_files/TTA_TCF_SingleInstanceTA_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_SingleInstanceTA/code_patches/v1_1_0_4-2014_11_07/TTA_TCF_SingleInstanceTA_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Time/TTA_Time/code_files/TTA_Time_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Time/code_patches/v1_1_0_4-2014_11_07/TTA_Time_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Time/TTA_Time/code_files/TTA_Time.c,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Time/code_patches/v1_1_0_4-2014_11_07/TTA_Time.c.patch)

define patch-filter-one
	$(q)sed -i 's|^\(ADBG_CASE_DEFINE(gp,\) $1,\(.*\)$$|/\*\1 $1,\2\*/|g' ${GP_XTEST_OUT_DIR}/$2

endef

.PHONY: patch-filter
patch-filter:
	@echo "INFO: Filter out some tests"
	@# 7001-7010, 7013, 7016-7019 are in regression_7000.c already
	$(foreach n,7001 7002 7003 7004 7005 7006 7007 7008 7009 7010 7013 7016 7017 7018 7019,$(call patch-filter-one,$(n),gp_7000.c))
	$(call patch-filter-one,7038,gp_7000.c)
	$(foreach n,7522 7538 7540 7546 7557 7559 7577 7641 7642 7643 7644 7686,$(call patch-filter-one,$(n),gp_7500.c))
	$(foreach n,8025 8030 8058 8059 8066,$(call patch-filter-one,$(n),gp_8000.c))
	$(foreach n,8614 8643 8644 8673 8674,$(call patch-filter-one,$(n),gp_8500.c))
	$(foreach n,9001 9072 9073 9075 9079 9080 9082 9085 9086 9088 9090 9091 9093 9095 9096 9098 9099 9109 9110 9160 9174 9195 9196 9204 9239,$(call patch-filter-one,$(n),gp_9000.c))

.PHONY: patch
patch: patch-generate-host patch-generate-ta
	$(MAKE) patch-filter

else
.PHONY: patch
patch:
	$(q) echo "Please define CFG_GP_PACKAGE_PATH" && false
endif

install:
	$(echo) '  INSTALL ${DESTDIR}/lib/optee_armtz'
	$(q)mkdir -p ${DESTDIR}/lib/optee_armtz
	$(q)find $(out-dir) -name \*.ta -exec cp -a {} ${DESTDIR}/lib/optee_armtz \;
	$(echo) '  INSTALL ${DESTDIR}/bin'
	$(q)mkdir -p ${DESTDIR}/bin
	$(q)cp -a $(out-dir)/xtest/xtest ${DESTDIR}/bin
