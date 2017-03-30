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

ifeq "$(wildcard /usr/include/openssl )" ""
$(error openssl must be installed)
endif

# Note that only TEE_Initial_Configuration-Test_Suite_v1_1_0_4-2014_11_07 is supported

GP_XTEST_OUT_DIR=$(CURDIR)/host/xtest
GP_XTEST_IN_DIR=${GP_XTEST_OUT_DIR}/global_platform/${CFG_GP_API}
GP_USERTA_DIR=$(CURDIR)/ta

define patch-file
	@if [ ! -e ${1}.orig ]; then \
		echo "  PATCH   ${1}"; \
		patch -s -N -b ${1} < ${2}; \
	fi
endef

# openssl .h file installation
forgpdir=${CURDIR}/host/xtest/for_gp
.PHONY: patch-openssl
patch-openssl:
	$(q)mkdir -p ${forgpdir}/include/openssl ${forgpdir}/lib
	$(q)if [ -d /usr/include/x86_64-linux-gnu/openssl ]; then \
		cp -r /usr/include/x86_64-linux-gnu/openssl ${forgpdir}/include ; \
	fi
	$(q)cp /usr/include/openssl/*.h $f ${forgpdir}/include/openssl

define mv-package
	@if [ -d ${1} ]; then \
		mv ${1} ${CFG_GP_PACKAGE_PATH}/packages ;\
	fi
endef

define rm-file
	@if [ -e ${1} ]; then echo "  RM      ${1}"; rm -f ${1}; fi
endef

define patch-xalan
	$(call rm-file,${GP_XTEST_OUT_DIR}/${3})
	$(call rm-file,${GP_XTEST_OUT_DIR}/${3}.orig)
	@echo "  XALAN   ${GP_XTEST_OUT_DIR}/${3}"
	$(q)xalan -in ${GP_XTEST_IN_DIR}/${1} -xsl ${GP_XTEST_IN_DIR}/${2} -out ${GP_XTEST_OUT_DIR}/${3}
endef

# Generate host files
define patch-cp-ta
	$(q)rm -rf $(GP_USERTA_DIR)/${3}
	$(q)mkdir -p $(GP_USERTA_DIR)/${3}
	$(q)cp -p $(CFG_GP_PACKAGE_PATH)/${1}/* $(GP_USERTA_DIR)/${3}
	$(q)cp -p $(CFG_GP_XSL_PACKAGE_PATH)/${2}/* $(GP_USERTA_DIR)/${3}
endef

define copy-file
	@echo "  CP      ${2}/$$(basename ${1})"
	$(q)cp -p ${1} ${2}
endef

.PHONY: patch-generate-host
patch-generate-host: patch-package
	$(q)mkdir -p ${GP_XTEST_IN_DIR} ${GP_XTEST_IN_DIR}
	$(call copy-file,${CFG_GP_PACKAGE_PATH}/packages/ClientAPI/xmlStable/TEE.xml,${GP_XTEST_IN_DIR})
	$(call copy-file,${CFG_GP_PACKAGE_PATH}/packages/DataStorage/xmlStable/TEE_DataStorage_API.xml,${GP_XTEST_IN_DIR})
	$(call copy-file,${CFG_GP_PACKAGE_PATH}/packages/TrustedCoreFw/xmlStable/TEE_Internal_API.xml,${GP_XTEST_IN_DIR})
	$(call copy-file,${CFG_GP_PACKAGE_PATH}/packages/Time_Arithmetical/xmlStable/TEE_TimeArithm_API.xml,${GP_XTEST_IN_DIR})
	$(call copy-file,${CFG_GP_PACKAGE_PATH}/packages/Crypto/xmlStable/TEE_Crypto_API.xml,${GP_XTEST_IN_DIR})
	$(call copy-file,${CFG_GP_XSL_PACKAGE_PATH}/packages/ClientAPI/xslstable/TEE.xsl,${GP_XTEST_IN_DIR})
	$(call copy-file,${CFG_GP_XSL_PACKAGE_PATH}/packages/DataStorage/xslstable/TEE_DataStorage_API.xsl,${GP_XTEST_IN_DIR})
	$(call copy-file,${CFG_GP_XSL_PACKAGE_PATH}/packages/TrustedCoreFw/xslstable/TEE_Internal_API.xsl,${GP_XTEST_IN_DIR})
	$(call copy-file,${CFG_GP_XSL_PACKAGE_PATH}/packages/Time_Arithmetical/xslstable/TEE_TimeArithm_API.xsl,${GP_XTEST_IN_DIR})
	$(call copy-file,${CFG_GP_XSL_PACKAGE_PATH}/packages/Crypto/xslstable/TEE_Crypto_API.xsl,${GP_XTEST_IN_DIR})
	$(call patch-xalan,TEE.xml,TEE.xsl,xtest_7000_gp.c)
	$(call patch-xalan,TEE_DataStorage_API.xml,TEE_DataStorage_API.xsl,xtest_7500.c)
	$(call patch-xalan,TEE_Internal_API.xml,TEE_Internal_API.xsl,xtest_8000.c)
	$(call patch-xalan,TEE_TimeArithm_API.xml,TEE_TimeArithm_API.xsl,xtest_8500.c)
	$(call patch-xalan,TEE_Crypto_API.xml,TEE_Crypto_API.xsl,xtest_9000.c)
	$(call patch-file,host/xtest/xtest_9000.c,${CFG_GP_XSL_PACKAGE_PATH}/host/xtest/xtest_9000.c.patch)

.PHONY: patch-generate-ta
patch-generate-ta: patch-package
	$(call patch-cp-ta,TTAs/TTA_Arithmetical/TTA_Arithmetical/code_files,TTAs/TTA_Arithmetical/code_files,GP_TTA_Arithmetical)
	$(call patch-cp-ta,TTAs/TTA_DS/TTA_DS/code_files,TTAs/TTA_DS/code_files,GP_TTA_DS)
	$(call patch-cp-ta,TTAs/TTA_ClientAPI/TTA_answerErrorTo_Invoke/code_files,TTAs/TTA_ClientAPI/TTA_answerErrorTo_Invoke/code_files,GP_TTA_answerErrorTo_Invoke)
	$(call patch-cp-ta,TTAs/TTA_ClientAPI/TTA_check_OpenSession_with_4_parameters/code_files,TTAs/TTA_ClientAPI/TTA_check_OpenSession_with_4_parameters/code_files,GP_TTA_check_OpenSession_with_4_parameters)
	$(call copy-file, $(CFG_GP_PACKAGE_PATH)/TTAs/TTA_ClientAPI/ta_check_OpenSession_with_4_parameters/code_files/TTA_check_OpenSession_with_4_parameters_protocol.h,$(GP_USERTA_DIR)/GP_TTA_check_OpenSession_with_4_parameters)
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
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/ta_check_OpenSession_with_4_parameters/code_files/TTA_check_OpenSession_with_4_parameters_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_check_OpenSession_with_4_parameters/code_patches/v1_1_0_4-2014_11_07/TTA_check_OpenSession_with_4_parameters_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_testingClientAPI/code_files/TTA_testingClientAPI.c,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_testingClientAPI/code_patches/v1_1_0_4-2014_11_07/TTA_testingClientAPI.c.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_testingClientAPI/code_files/TTA_testingClientAPI_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_testingClientAPI/code_patches/v1_1_0_4-2014_11_07/TTA_testingClientAPI_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerSuccessTo_OpenSession_Invoke/code_files/TTA_answerSuccessTo_OpenSession_Invoke_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerSuccessTo_OpenSession_Invoke/code_patches/v1_1_0_4-2014_11_07/TTA_answerSuccessTo_OpenSession_Invoke_protocol.h.patch)
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
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF/code_files/TTA_TCF.c,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF/code_patches/v1_1_0_4-2014_11_07/TTA_TCF.c.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_SingleInstanceTA/code_files/TTA_TCF_SingleInstanceTA_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_SingleInstanceTA/code_patches/v1_1_0_4-2014_11_07/TTA_TCF_SingleInstanceTA_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Time/TTA_Time/code_files/TTA_Time_protocol.h,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Time/code_patches/v1_1_0_4-2014_11_07/TTA_Time_protocol.h.patch)
	$(call patch-file,${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Time/TTA_Time/code_files/TTA_Time.c,${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Time/code_patches/v1_1_0_4-2014_11_07/TTA_Time.c.patch)

define patch-filter-one
	@echo "  SED     ${GP_XTEST_OUT_DIR}/$2"
	$(q)sed -i 's|^\(ADBG_CASE_DEFINE(regression,\) $1,\(.*\)$$|/\*\1 $1,\2\*/|g' ${GP_XTEST_OUT_DIR}/$2
endef

.PHONY: patch-filter
patch-filter:
	$(call patch-filter-one,7038,xtest_7000_gp.c)
	$(call patch-filter-one,7522,xtest_7500.c)
	$(call patch-filter-one,7538,xtest_7500.c)
	$(call patch-filter-one,7540,xtest_7500.c)
	$(call patch-filter-one,7546,xtest_7500.c)
	$(call patch-filter-one,7557,xtest_7500.c)
	$(call patch-filter-one,7559,xtest_7500.c)
	$(call patch-filter-one,7577,xtest_7500.c)
	$(call patch-filter-one,7641,xtest_7500.c)
	$(call patch-filter-one,7642,xtest_7500.c)
	$(call patch-filter-one,7643,xtest_7500.c)
	$(call patch-filter-one,7644,xtest_7500.c)
	$(call patch-filter-one,7686,xtest_7500.c)
	$(call patch-filter-one,8025,xtest_8000.c)
	$(call patch-filter-one,8030,xtest_8000.c)
	$(call patch-filter-one,8058,xtest_8000.c)
	$(call patch-filter-one,8059,xtest_8000.c)
	$(call patch-filter-one,8066,xtest_8000.c)
	$(call patch-filter-one,8614,xtest_8500.c)
	$(call patch-filter-one,8643,xtest_8500.c)
	$(call patch-filter-one,8644,xtest_8500.c)
	$(call patch-filter-one,8673,xtest_8500.c)
	$(call patch-filter-one,8674,xtest_8500.c)
	$(call patch-filter-one,9001,xtest_9000.c)
	$(call patch-filter-one,9072,xtest_9000.c)
	$(call patch-filter-one,9073,xtest_9000.c)
	$(call patch-filter-one,9075,xtest_9000.c)
	$(call patch-filter-one,9079,xtest_9000.c)
	$(call patch-filter-one,9080,xtest_9000.c)
	$(call patch-filter-one,9082,xtest_9000.c)
	$(call patch-filter-one,9085,xtest_9000.c)
	$(call patch-filter-one,9086,xtest_9000.c)
	$(call patch-filter-one,9088,xtest_9000.c)
	$(call patch-filter-one,9090,xtest_9000.c)
	$(call patch-filter-one,9091,xtest_9000.c)
	$(call patch-filter-one,9093,xtest_9000.c)
	$(call patch-filter-one,9095,xtest_9000.c)
	$(call patch-filter-one,9096,xtest_9000.c)
	$(call patch-filter-one,9098,xtest_9000.c)
	$(call patch-filter-one,9099,xtest_9000.c)
	$(call patch-filter-one,9109,xtest_9000.c)
	$(call patch-filter-one,9110,xtest_9000.c)
	$(call patch-filter-one,9160,xtest_9000.c)
	$(call patch-filter-one,9174,xtest_9000.c)
	$(call patch-filter-one,9195,xtest_9000.c)
	$(call patch-filter-one,9196,xtest_9000.c)
	$(call patch-filter-one,9204,xtest_9000.c)
	$(call patch-filter-one,9239,xtest_9000.c)

.PHONY: patch
patch: patch-openssl patch-generate-host patch-generate-ta
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
