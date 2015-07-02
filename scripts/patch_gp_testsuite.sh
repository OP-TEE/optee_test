#!/bin/bash

cd $(dirname $0)
export CDIR=${PWD}

# Initialization
if [ -f .env ]; then
. .env
else
echo -e " ERROR: .env NOT FOUND";
echo -e " ERROR: .env must be at the same location as $0";
exit 0;
fi;

if [ ${CFG_GP_TESTSUITE_ENABLE} == "y" ]; then
	cd ${CDIR}
	echo ${CDIR}
	./enable_gp_testsuite.sh

	# openssl .h file installation
	if [ -d /usr/include/openssl ]; then
		forgpdir=${CFG_DEV_PATH}/optee_test/host/xtest/for_gp/
		mkdir -p ${forgpdir}/include/openssl ${forgpdir}/lib
		[ -d /usr/include/x86_64-linux-gnu/openssl ] && LCI_CPD /usr/include/x86_64-linux-gnu/openssl ${forgpdir}/include
		for f in /usr/include/openssl/*.h ; do
			LCI_CPF $f ${forgpdir}/include/openssl
		done
	else
		LCI_PRINT_WARNING "ERROR: '/usr/include/openssl' NOT FOUND"
		exit;
	fi;

	if [ "${CFG_ARM32}" = "y" ]; then
		LCI_CPF ${CFG_DEV_PATH}/optee_test/host/lib/armv7/libcrypto.a ${forgpdir}/lib
	else
		LCI_CPF ${CFG_DEV_PATH}/optee_test/host/lib/armv8/libcrypto.a ${forgpdir}/lib
	fi
fi

LCI_PRINT_SEPARATOR
LCI_PRINT_HEADER "Running `basename $0`"
LCI_PRINT_SEPARATOR
LCI_PRINT_HEADER "Patch Global Platform testsuite"
LCI_PRINT_L1 "global platform package: ${CFG_GP_PACKAGE_PATH}"
LCI_PRINT_L1 "stm package: ${CFG_GP_XSL_PACKAGE_PATH}"
LCI_PRINT_L1 "GP api: ${CFG_GP_API}"

if [ $(basename ${CFG_GP_PACKAGE_PATH}) == "TEE_Initial_Configuration-Test_Suite_v1_1_0_4-2014_11_07" ]; then
	LCI_PRINT_L1 "GP package $(basename ${CFG_GP_PACKAGE_PATH}) SUPPORTED"


else
	LCI_FORCE_QUIT "$(basename ${CFG_GP_PACKAGE_PATH}) NOT SUPPORTED"
 	exit;

fi


LCI_PRINT_SEPARATOR
LCI_PRINT_L1 "Patch directories structure"
if [ ! -d ${CFG_GP_PACKAGE_PATH}/packages ]; then
	LCI_PRINT_MSG "mkdir -p ${CFG_GP_PACKAGE_PATH}/packages"
	mkdir -p ${CFG_GP_PACKAGE_PATH}/packages
fi

DIRLIST="ClientAPI Crypto DataStorage Time_Arithmetical TrustedCoreFw"
for dir in ${DIRLIST}
	do
		if [ -d ${CFG_GP_PACKAGE_PATH}/${dir} ]; then
			LCI_PRINT_MSG "mv ${CFG_GP_PACKAGE_PATH}/${dir}"
			LCI_PRINT_MSG "to ${CFG_GP_PACKAGE_PATH}/packages"
			mv ${CFG_GP_PACKAGE_PATH}/${dir} \
			${CFG_GP_PACKAGE_PATH}/packages
		fi
done

LCI_PRINT_SEPARATOR
LCI_PRINT_L1 "Patch XML files"

declare -A ARRAY
function LCI_PATCHFILE () {
	#printf "${LCI_MSG} | apply patch %-s\n" "${2}";
	#printf "${LCI_MSG} |          on %-s\n" "${1}";
	if [ ! -e ${1}.orig ]; then
		patch -N -b ${1} < ${2};
	else
	LCI_PRINT_WARNING "${1}.orig ALREADY EXISTS"
	LCI_PRINT_WARNING "PATCH NOT APPLIED"
	fi
}

function LCI_PATCH () {
	LCI_PATCH_CHECKFILE ${1}
	LCI_PATCH_CHECKFILE "${2}"
	LCI_PATCHFILE  ${1} ${2}
}

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/packages/ClientAPI/xmlStable/TEE.xml" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/packages/ClientAPI/xmlpatch/v1_1_0_4-2014_11_07/TEE.xml.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/packages/Crypto/xmlStable/TEE_Crypto_API.xml" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/packages/Crypto/xmlpatch/v1_1_0_4-2014_11_07/TEE_Crypto_API.xml.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/packages/DataStorage/xmlStable/TEE_DataStorage_API.xml" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/packages/DataStorage/xmlpatch/v1_1_0_4-2014_11_07/TEE_DataStorage_API.xml.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/packages/Time_Arithmetical/xmlStable/TEE_TimeArithm_API.xml" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/packages/Time_Arithmetical/xmlpatch/v1_1_0_4-2014_11_07/TEE_TimeArithm_API.xml.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/packages/TrustedCoreFw/xmlStable/TEE_Internal_API.xml" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/packages/TrustedCoreFw/xmlpatch/v1_1_0_4-2014_11_07/TEE_Internal_API.xml.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

LCI_PRINT_SEPARATOR
LCI_PRINT_L1 "Patch TTAs files"

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Arithmetical/TTA_Arithmetical/code_files/TTA_Arithmetical.c" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Arithmetical/code_patches/v1_1_0_4-2014_11_07/TTA_Arithmetical.c.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Arithmetical/TTA_Arithmetical/code_files/TTA_Arithmetical_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Arithmetical/code_patches/v1_1_0_4-2014_11_07/TTA_Arithmetical_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_check_OpenSession_with_4_parameters/code_files/TTA_check_OpenSession_with_4_parameters_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_check_OpenSession_with_4_parameters/code_patches/v1_1_0_4-2014_11_07/TTA_check_OpenSession_with_4_parameters_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_testingClientAPI/code_files/TTA_testingClientAPI_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_testingClientAPI/code_patches/v1_1_0_4-2014_11_07/TTA_testingClientAPI_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerSuccessTo_OpenSession_Invoke/code_files/TTA_answerSuccessTo_OpenSession_Invoke_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerSuccessTo_OpenSession_Invoke/code_patches/v1_1_0_4-2014_11_07/TTA_answerSuccessTo_OpenSession_Invoke_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerErrorTo_OpenSession/code_files/TTA_answerErrorTo_OpenSession_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerErrorTo_OpenSession/code_patches/v1_1_0_4-2014_11_07/TTA_answerErrorTo_OpenSession_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerErrorTo_Invoke/code_files/TTA_answerErrorTo_Invoke_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_ClientAPI/TTA_answerErrorTo_Invoke/code_patches/v1_1_0_4-2014_11_07/TTA_answerErrorTo_Invoke_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Crypto/TTA_Crypto/code_files/TTA_Crypto.c" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Crypto/code_patches/v1_1_0_4-2014_11_07/TTA_Crypto.c.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Crypto/TTA_Crypto/code_files/TTA_Crypto_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Crypto/code_patches/v1_1_0_4-2014_11_07/TTA_Crypto_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_DS/TTA_DS/code_files/TTA_DS_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_DS/code_patches/v1_1_0_4-2014_11_07/TTA_DS_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_DS/TTA_DS/code_files/TTA_DS.c" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_DS/code_patches/v1_1_0_4-2014_11_07/TTA_DS.c.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TEE_include/tee_internal_api.h"
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TEE_include/code_patches/v1_1_0_4-2014_11_07/tee_internal_api.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_ICA/code_files/TTA_TCF_ICA_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_ICA/code_patches/v1_1_0_4-2014_11_07/TTA_TCF_ICA_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_MultipleInstanceTA/code_files/TTA_TCF_MultipleInstanceTA_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_MultipleInstanceTA/code_patches/v1_1_0_4-2014_11_07/TTA_TCF_MultipleInstanceTA_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF/code_files/TTA_TCF.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF/code_patches/v1_1_0_4-2014_11_07/TTA_TCF.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_SingleInstanceTA/code_files/TTA_TCF_SingleInstanceTA_protocol.h" 
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_TCF/TTA_TCF_SingleInstanceTA/code_patches/v1_1_0_4-2014_11_07/TTA_TCF_SingleInstanceTA_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Time/TTA_Time/code_files/TTA_Time_protocol.h"
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Time/code_patches/v1_1_0_4-2014_11_07/TTA_Time_protocol.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_GP_PACKAGE_PATH}/TTAs/TTA_Time/TTA_Time/code_files/TTA_Time.c"
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/TTAs/TTA_Time/code_patches/v1_1_0_4-2014_11_07/TTA_Time.c.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

LCI_PRINT_L1 "Patch HOST files"

ARRAY=(["FILE"]="${CFG_OPTEE_TEST_PATH}/host/xtest/xtest_6000.c"
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/host/xtest/xtest_6000.c.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_OPTEE_TEST_PATH}/host/xtest/xtest_main.c"
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/host/xtest/xtest_main.c.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_OPTEE_TEST_PATH}/host/xtest/xtest_test.c"
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/host/xtest/xtest_test.c.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

ARRAY=(["FILE"]="${CFG_OPTEE_TEST_PATH}/host/xtest/xtest_test.h"
	["PATCH"]="${CFG_GP_XSL_PACKAGE_PATH}/host/xtest/xtest_test.h.patch")
LCI_PATCH  ${ARRAY[FILE]} ${ARRAY[PATCH]}
LCI_PRINT_SEPARATOR

cd ${CDIR}

LCI_PRINT_SEPARATOR
LCI_PRINT_HEADER "`basename $0` finished";
LCI_PRINT_SEPARATOR
