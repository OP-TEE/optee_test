#!/bin/bash

# Initialization
if [ -f .env ]; then
. .env
else
echo -e " ERROR: .env NOT FOUND";
echo -e " ERROR: .env must be at the same location as $0";
exit 0;
fi;

LCI_PRINT_SEPARATOR
LCI_PRINT_HEADER "Running `basename $0`"
LCI_PRINT_SEPARATOR
LCI_PRINT_HEADER "Enable Global Platform testsuite"
LCI_PRINT_L1 "global platform package: ${CFG_GP_PACKAGE_PATH}"
LCI_PRINT_L1 "stm package: ${CFG_GP_XSL_PACKAGE_PATH}"
LCI_PRINT_L1 "GP api: ${CFG_GP_API}"

LCI_PRINT_SEPARATOR
echo -e "+ Install"
echo -e "| Checking \"xalan\" tool ..."
if [ "" = "`which xalan`" ]; then
    echo -e "ERROR: \"xalan\" is not detected on the system. Please install it."
    exit 1
else
    echo -e "OK: \"xalan\" is detected on the system."
fi

echo -e "| Processing ..."

GP_XTEST_OUT_DIR="${CFG_DEV_PATH}/optee_test/host/xtest"
export GP_XTEST_OUT_DIR
GP_XTEST_IN_DIR="${GP_XTEST_OUT_DIR}/global_platform/${CFG_GP_API}"
export GP_XTEST_IN_DIR

GP_USERTA_DIR="${CFG_DEV_PATH}/optee_test/ta"
export GP_USERTA_DIR

echo -e "| Clean"
RMFILELIST="adbg_case_declare.h adbg_entry_declare.h \
		xtest_7000.c xtest_7500.c xtest_8000.c \
		xtest_8500.c xtest_9000.c \
		"
for file in ${RMFILELIST}
do
	if [ -f ${GP_XTEST_OUT_DIR}/${file} ]; then
		echo "${GP_XTEST_OUT_DIR}/${file} DELETED"
		rm ${GP_XTEST_OUT_DIR}/$file
	fi
done

echo -e "| Import"
if [ ! -d ${GP_XTEST_IN_DIR} ]; then
	mkdir -p ${GP_XTEST_IN_DIR}
	fi
rm ${GP_XTEST_IN_DIR}/*

echo -e "   *.xml in \"${GP_XTEST_IN_DIR}\""
find ${CFG_GP_PACKAGE_PATH}/packages -type f -name "*.xml" -exec bash -c '\
									# echo -e "cp -p $0 ${GP_XTEST_IN_DIR}"; \
									cp -p $0 ${GP_XTEST_IN_DIR}; \
									' {} \;
									
echo -e "   *.xsl in \"${GP_XTEST_IN_DIR}\""
find ${CFG_GP_XSL_PACKAGE_PATH}/packages -type f -name "*.xsl" -exec bash -c '\
									# echo -e "cp -p $0 ${GP_XTEST_IN_DIR}"; \
									cp -p $0 ${GP_XTEST_IN_DIR}; \
									' {} \;

echo -e "   TTAs in \"${GP_USERTA_DIR}\""
find ${CFG_GP_PACKAGE_PATH}/TTAs -type d -name "code_files" -exec bash -c '\
									if [ -d ${GP_USERTA_DIR}/GP_$(basename $(dirname $0)) ]; then \
									# echo -e "rm ${GP_USERTA_DIR}/GP_$(basename $(dirname $0))/*" ;\
									rm -rf ${GP_USERTA_DIR}/GP_$(basename $(dirname $0))/* ;\
									else \
									# echo -e "mkdir -p ${GP_USERTA_DIR}/GP_$(basename $(dirname $0))" ;\
									mkdir -p ${GP_USERTA_DIR}/GP_$(basename $(dirname $0)) ;\
									fi ;\
									# echo -e "cp -p $0/* ${GP_USERTA_DIR}/GP_$(basename $(dirname $0))" ;\
									cp -p $0/* ${GP_USERTA_DIR}/GP_$(basename $(dirname $0)) ;\
									' {} \;

find ${CFG_GP_XSL_PACKAGE_PATH}/TTAs -type d -name "code_files" -exec bash -c '\
									# echo -e "cp -p $0/* ${GP_USERTA_DIR}/GP_$(basename $(dirname $0))" ;\
									cp -p $0/* ${GP_USERTA_DIR}/GP_$(basename $(dirname $0)) ;\
									' {} \;

echo -e "| Generate"

echo -e "   file \"${GP_XTEST_OUT_DIR}/adbg_case_declare.h\""
xalan -in ${GP_XTEST_IN_DIR}/TEE.xml -xsl ${GP_XTEST_IN_DIR}/adbg_case_declare.xsl -out ${GP_XTEST_OUT_DIR}/adbg_case_declare.h

echo -e "   file \"${GP_XTEST_OUT_DIR}/adbg_entry_declare.h\""
xalan -in ${GP_XTEST_IN_DIR}/TEE.xml -xsl ${GP_XTEST_IN_DIR}/adbg_entry_declare.xsl -out ${GP_XTEST_OUT_DIR}/adbg_entry_declare.h

echo -e "   file \"${GP_XTEST_OUT_DIR}/xtest_7000.c\""
xalan -in ${GP_XTEST_IN_DIR}/TEE.xml -xsl ${GP_XTEST_IN_DIR}/TEE.xsl -out ${GP_XTEST_OUT_DIR}/xtest_7000.c

echo -e "   file \"${GP_XTEST_OUT_DIR}/xtest_7500.c\""
xalan -in ${GP_XTEST_IN_DIR}/TEE_DataStorage_API.xml -xsl ${GP_XTEST_IN_DIR}/TEE_DataStorage_API.xsl -out ${GP_XTEST_OUT_DIR}/xtest_7500.c

echo -e "   file \"${GP_XTEST_OUT_DIR}/xtest_8000.c\""
xalan -in ${GP_XTEST_IN_DIR}/TEE_Internal_API.xml -xsl ${GP_XTEST_IN_DIR}/TEE_Internal_API.xsl -out ${GP_XTEST_OUT_DIR}/xtest_8000.c

echo -e "   file \"${GP_XTEST_OUT_DIR}/xtest_8500.c\""
xalan -in ${GP_XTEST_IN_DIR}/TEE_TimeArithm_API.xml -xsl ${GP_XTEST_IN_DIR}/TEE_TimeArithm_API.xsl -out ${GP_XTEST_OUT_DIR}/xtest_8500.c

echo -e "   file \"${GP_XTEST_OUT_DIR}/xtest_9000.c\""
xalan -in ${GP_XTEST_IN_DIR}/TEE_Crypto_API.xml -xsl ${GP_XTEST_IN_DIR}/TEE_Crypto_API.xsl -out ${GP_XTEST_OUT_DIR}/xtest_9000.c


echo -e "| Filtering (known failing/crashing test cases)"
# Linaro
TESTFILTERLIST="8058 8059"
# STM Legacy
TESTFILTERLIST="${TESTFILTERLIST} 6010"
TESTFILTERLIST="${TESTFILTERLIST} 7038"
TESTFILTERLIST="${TESTFILTERLIST} 7522 7538 7540 7546 7557"
TESTFILTERLIST="${TESTFILTERLIST} 7559 7577 7641 7642 7643"
TESTFILTERLIST="${TESTFILTERLIST} 7644 7686"
TESTFILTERLIST="${TESTFILTERLIST} 8025 8030 8066"
TESTFILTERLIST="${TESTFILTERLIST} 8614 8643 8644 8673 8674"
TESTFILTERLIST="${TESTFILTERLIST} 9001 9053 9072 9073 9074"
TESTFILTERLIST="${TESTFILTERLIST} 9075 9079 9080 9081 9082"
TESTFILTERLIST="${TESTFILTERLIST} 9085 9086 9087 9088 9090"
TESTFILTERLIST="${TESTFILTERLIST} 9091 9092 9093 9095 9096"
TESTFILTERLIST="${TESTFILTERLIST} 9098 9099 9104 9109 9110"
TESTFILTERLIST="${TESTFILTERLIST} 9111 9145 9146 9147 9148"
TESTFILTERLIST="${TESTFILTERLIST} 9149 9160 9174 9181 9182"
TESTFILTERLIST="${TESTFILTERLIST} 9183 9184 9186 9187 9195"
TESTFILTERLIST="${TESTFILTERLIST} 9196 9204 9239"

for TEST in ${TESTFILTERLIST}
do

	echo -en " ${TEST}"

	sed -i 's|^ADBG_SUITE_ENTRY(XTEST_TEE_'${TEST}', NULL)|/\*ADBG_SUITE_ENTRY(XTEST_TEE_'${TEST}', NULL)\*/|g' ${GP_XTEST_OUT_DIR}/xtest_main.c
	sed -i 's|    ADBG_SUITE_ENTRY(XTEST_TEE_'${TEST}', NULL)\\|    /\*ADBG_SUITE_ENTRY(XTEST_TEE_'${TEST}', NULL)\*/\\|g' ${GP_XTEST_OUT_DIR}/adbg_entry_declare.h
	
	# If this is the first/last test case we must move the init/deinit functions
	# and we add descriptions about why the test case is disabled.
	case ${TEST} in
	    "7038") #766
	        sed -i 's|/\*d3-ee-b1\*/|/*\n* XTEST test case 7038 fails.\n* TEEC_InvokeCommand: unexpected value 0xffff0000, expected 0xffff0002.\n*/\n\n/\*d3-ee-b1\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7000.c
		    sed -i '752 c\    xtest_tee_deinit();\n' ${GP_XTEST_OUT_DIR}/xtest_7000.c
	    ;;
	    "7522")
	        sed -i 's|/\*9d-76-9b\*/|/*\n* XTEST test case 7522 fails.\n* Invoke_Simple_Function_Object: unexpected value 0xffff3024, expected 0xffff0008.\n*/\n\n/\*9d-76-9b\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7538")
	        sed -i 's|/\*9d-56-33\*/|/*\n* XTEST test case 7538 fails.\n* Invoke_InitObjectAndAttributes: unexpected value 0xf004, expected 0x0.\n*/\n\n/\*9d-56-33\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7540")
	        sed -i 's|/\*9d-32-98\*/|/*\n* XTEST test case 7540 fails.\n* Invoke_InitObjectAndAttributes: unexpected value 0xf004, expected 0x0.\n*/\n\n/\*9d-32-98\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7546")
	        sed -i 's|/\*9d-2a-87\*/|/*\n* XTEST test case 7546 fails.\n* Invoke_GenerateKey: unexpected value 0xffff3024, expected 0xffff0006.\n*/\n\n/\*9d-2a-87\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7557")
	        sed -i 's|/\*9d-0c-88\*/|/*\n* XTEST test case 7557 fails.\n* Invoke_GenerateKey: unexpected value 0x0, expected 0xffff0006.\n*/\n\n/\*9d-0c-88\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7559")
	        sed -i 's|/\*9d-36-04\*/|/*\n* XTEST test case 7559 fails.\n* Invoke_InitObjectAndAttributes: unexpected value 0xf004, expected 0x0.\n*/\n\n/\*9d-36-04\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7577")
	        sed -i 's|/\*9d-ab-23\*/|/*\n* XTEST test case 7577 fails.\n* Invoke_InitObjectAndAttributes: unexpected value 0xffff3024, expected 0xffff0008.\n*/\n\n/\*9d-ab-23\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7641")
	        sed -i 's|/\*9d-bd-3c\*/|/*\n* XTEST test case 7641 fails.\n* Expressions in xml_datastorage_api.h on line 610 and line 613 are false.\n*/\n\n/\*9d-bd-3c\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7642")
	        sed -i 's|/\*9d-30-71\*/|/*\n* XTEST test case 7642 fails.\n* Expressions in xml_datastorage_api.h on line 610 and line 613 are false.\n*/\n\n/\*9d-30-71\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7643")
	        sed -i 's|/\*9d-e4-58\*/|/*\n* XTEST test case 7643 fails.\n* Expressions in xml_datastorage_api.h on line 610 and line 613 are false.\n*/\n\n/\*9d-e4-58\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7644")
	        sed -i 's|/\*9d-30-58\*/|/*\n* XTEST test case 7644 fails.\n* Expressions in xml_datastorage_api.h on line 610 and line 613 are false.\n*/\n\n/\*9d-30-58\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "7686")
	        sed -i 's|/\*9d-7e-c2\*/|/*\n* XTEST test case 7686 fails.\n* Invoke_SeekWriteReadObjectData: unexpected value 0xffff3024, expected 0xffff300f.\n* Expression in xml_datastorage_api.h on line 610 is false.\n*/\n\n/\*9d-7e-c2\*/|g' ${GP_XTEST_OUT_DIR}/xtest_7500.c
	    ;;
	    "8025")
	        sed -i 's|/\*a7-85-e1\*/|/*\n* XTEST test case 8025 fails.\n* Expression in xml_internal_api.h on line 333 is false.\n*/\n\n/\*a7-85-e1\*/|g' ${GP_XTEST_OUT_DIR}/xtest_8000.c
	    ;;
	    "8030")
	        sed -i 's|/\*a7-54-fd\*/|/*\n* XTEST test case 8030 fails.\n* TEEC_OpenSession: unexpected value 0xffff0008, expected 0x0.\n* Expression in xml_internal_api.h on line 450 is false.\n\* Invoke_ProcessInvokeTAOpenSession: unexpected value 0xffff0000, expected 0xffff000d.\n*/\n\n/\*a7-54-fd\*/|g' ${GP_XTEST_OUT_DIR}/xtest_8000.c
	    ;;
	    "8066")
	        sed -i 's|/\*a7-fe-d5\*/|/*\n* XTEST test case 8066 fails.\n* Invoke_GetCancellationFlag_RequestedCancel: unexpected value 0xffff0000, expected 0xffff0002.\n* Test case is crashing the XTEST application.\n*/\n\n/\*a7-fe-d5\*/|g' ${GP_XTEST_OUT_DIR}/xtest_8000.c
	        sed -i '1076 c\    xtest_tee_deinit();\n' ${GP_XTEST_OUT_DIR}/xtest_8000.c
	
	        # SED seems to have a bug i.e. it doesn't recognize the pattern below (the second one)
	        # The same two patterns are used in three other files and they work (files xtest_7000.c,
	        # xtest_8500.c and xtest_9000.c), but here in file xtest_8000.c the pattern doesn't work.
	        # That's why we use direct insertion on specific line.
	
	        #sed -i '{ N; N; s|\n/\*\n\* XTEST test case 8066 fails\.|    xtest_tee_deinit();\n\}\n\n/\*\n\* XTEST test case 8066 fails\.|g; }' ${GP_XTEST_OUT_DIR}/xtest_8000.c
	        #sed -i -e '{ N; s|}\n    xtest_tee_deinit();|    xtest_tee_deinit();|g; }' ${GP_XTEST_OUT_DIR}/xtest_8000.c
	    ;;
	    "8614")
	        sed -i 's|/\*ce-cb-68\*/|/*\n* XTEST test case 8614 fails.\n* Invoke_Simple_Function: unexpected value 0xffff0010, expected 0xffff300f.\n*/\n\n/\*ce-cb-68\*/|g' ${GP_XTEST_OUT_DIR}/xtest_8500.c
	    ;;
	    "8643")
	        sed -i 's|/\*ce-22-81\*/|/*\n* XTEST test case 8643 fails.\n* Expression in xml_timearithm_api.h on line 1426 is false.\n*/\n\n/\*ce-22-81\*/|g' ${GP_XTEST_OUT_DIR}/xtest_8500.c
	    ;;
	    "8644")
	        sed -i 's|/\*ce-8d-59\*/|/*\n* XTEST test case 8644 fails.\n* Expression in xml_timearithm_api.h on line 1426 is false.\n*/\n\n/\*ce-8d-59\*/|g' ${GP_XTEST_OUT_DIR}/xtest_8500.c
	    ;;
	    "8673")
	        sed -i 's|/\*ce-41-5f\*/|/*\n* XTEST test case 8673 fails.\n* Test case is crashing the XTEST application.\n*/\n\n/\*ce-41-5f\*/|g' ${GP_XTEST_OUT_DIR}/xtest_8500.c
	    ;;
	    "8674")
	        sed -i 's|/\*ce-06-ce\*/|/*\n* XTEST test case 8674 fails.\n* Invoke_Simple_Function: unexpected value 0xffff0000, expected 0x0.\n*/\n\n/\*ce-06-ce\*/|g' ${GP_XTEST_OUT_DIR}/xtest_8500.c
	        sed -i '2549 c\    xtest_tee_deinit();\n' ${GP_XTEST_OUT_DIR}/xtest_8500.c
	    ;;
	    "9001")
	        sed -i 's|/\*3b-4a-c9\*/|/*\n* XTEST test case 9001 fails.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff000a, expected 0xffff000c.\n*/\n\n/\*3b-4a-c9\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	        sed -i '246 c\    xtest_tee_deinit();\n' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9053")
	        sed -i 's|/\*b6-54-fb\*/|/*\n* XTEST test case 9053 fails.\n* Invoke_Crypto_CipherDoFinal: unexpected value: 0xffff3024, expected 0x0.\n* xml_crypto_api.h at line 1775: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*b6-54-fb\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9072")
	        sed -i 's|/\*50-b6-4b\*/|/*\n* XTEST test case 9072 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-b6-4b\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9073")
	        sed -i 's|/\*50-74-49\*/|/*\n* XTEST test case 9073 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-74-49\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9074")
	        sed -i 's|/\*50-a8-d1\*/|/*\n* XTEST test case 9074 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-a8-d1\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9075")
	        sed -i 's|/\*50-98-71\*/|/*\n* XTEST test case 9075 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-98-71\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9079")
	        sed -i 's|/\*50-36-58\*/|/*\n* XTEST test case 9079 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-36-58\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9080")
	        sed -i 's|/\*50-26-cd\*/|/*\n* XTEST test case 9080 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-26-cd\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9081")
	        sed -i 's|/\*50-d4-60\*/|/*\n* XTEST test case 9081 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-d4-60\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9082")
	        sed -i 's|/\*50-05-a3\*/|/*\n* XTEST test case 9082 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-05-a3\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9085")
	        sed -i 's|/\*50-13-32\*/|/*\n* XTEST test case 9085 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-13-32\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9086")
	        sed -i 's|/\*50-1d-5e\*/|/*\n* XTEST test case 9086 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-1d-5e\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9087")
	        sed -i 's|/\*50-5f-15\*/|/*\n* XTEST test case 9087 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-5f-15\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9088")
	        sed -i 's|/\*50-51-f3\*/|/*\n* XTEST test case 9088 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-51-f3\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9090")
	        sed -i 's|/\*50-47-84\*/|/*\n* XTEST test case 9090 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-47-84\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9091")
	        sed -i 's|/\*50-2a-85\*/|/*\n* XTEST test case 9091 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-2a-85\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9092")
	        sed -i 's|/\*50-df-71\*/|/*\n* XTEST test case 9092 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-df-71\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9093")
	        sed -i 's|/\*50-72-8d\*/|/*\n* XTEST test case 9093 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-72-8d\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9095")
	        sed -i 's|/\*50-bf-2e\*/|/*\n* XTEST test case 9095 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-bf-2e\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9096")
	        sed -i 's|/\*50-9c-c4\*/|/*\n* XTEST test case 9096 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-9c-c4\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9098")
	        sed -i 's|/\*50-e1-70\*/|/*\n* XTEST test case 9098 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-e1-70\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9099")
	        sed -i 's|/\*50-8d-0a\*/|/*\n* XTEST test case 9099 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-8d-0a\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9104")
	        sed -i 's|/\*50-7f-d0\*/|/*\n* XTEST test case 9104 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-7f-d0\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9109")
	        sed -i 's|/\*50-d0-59\*/|/*\n* XTEST test case 9109 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-d0-59\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9110")
	        sed -i 's|/\*50-31-23\*/|/*\n* XTEST test case 9110 fails.\n* Invoke_Crypto_AsymmetricVerifyDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-31-23\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9111")
	        sed -i 's|/\*50-a9-9d\*/|/*\n* XTEST test case 9111 fails.\n* Invoke_Crypto_AsymmetricSignDigest: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-a9-9d\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9145")
	        sed -i 's|/\*50-2b-7a\*/|/*\n* XTEST test case 9145 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-2b-7a\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9146")
	        sed -i 's|/\*50-e7-57\*/|/*\n* XTEST test case 9146 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_InitObjectWithKeys: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_SetOperationKey: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AsymmetricDecrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-e7-57\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9147")
	        sed -i 's|/\*50-49-d8\*/|/*\n* XTEST test case 9147 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_InitObjectWithKeys: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_SetOperationKey: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AsymmetricDecrypt: unexpected value 0xffff3024, expected 0xffff0010.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-49-d8\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9148")
	        sed -i 's|/\*50-51-15\*/|/*\n* XTEST test case 9148 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-51-15\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9149")
	        sed -i 's|/\*50-6d-0e\*/|/*\n* XTEST test case 9149 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0xffff0010.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-6d-0e\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9160")
	        sed -i 's|/\*50-83-fe\*/|/*\n* XTEST test case 9160 fails.\n* xml_crypto_api.h at line 1778: saved_cipher_update.buffer has an unexpected content.\n*/\n\n/\*50-83-fe\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9174")
	        sed -i 's|/\*50-7b-4d\*/|/*\n* XTEST test case 9174 fails.\n* Invoke_Crypto_AEInit: unexpected value 0x0, expected 0xffff3024.\n*/\n\n/\*50-7b-4d\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9181")
	        sed -i 's|/\*50-63-e5\*/|/*\n* XTEST test case 9181 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_InitObjectWithKeys: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_SetOperationKey: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AsymmetricDecrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-63-e5\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9182")
	        sed -i 's|/\*50-ef-f0\*/|/*\n* XTEST test case 9182 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_InitObjectWithKeys: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_SetOperationKey: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AsymmetricDecrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-ef-f0\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9183")
	        sed -i 's|/\*50-eb-0f\*/|/*\n* XTEST test case 9183 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_InitObjectWithKeys: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_SetOperationKey: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AsymmetricDecrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-eb-0f\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9184")
	        sed -i 's|/\*50-94-06\*/|/*\n* XTEST test case 9184 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_InitObjectWithKeys: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_SetOperationKey: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-94-06\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9186")
	        sed -i 's|/\*50-94-15\*/|/*\n* XTEST test case 9186 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_InitObjectWithKeys: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_SetOperationKey: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AsymmetricDecrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-94-15\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9187")
	        sed -i 's|/\*50-ba-29\*/|/*\n* XTEST test case 9187 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_InitObjectWithKeys: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-ba-29\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9195")
	        sed -i 's|/\*50-35-98\*/|/*\n* XTEST test case 9195 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_InitObjectWithKeys: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_SetOperationKey: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AsymmetricDecrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-35-98\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9196")
	        sed -i 's|/\*50-6f-dd\*/|/*\n* XTEST test case 9196 fails.\n* Invoke_Crypto_AsymmetricEncrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_InitObjectWithKeys: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AllocateOperation: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_SetOperationKey: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_AsymmetricDecrypt: unexpected value 0xffff3024, expected 0x0.\n* Invoke_Crypto_FreeAllKeysAndOperations: unexpected value 0xffff3024, expected 0x0.\n*/\n\n/\*50-6f-dd\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9204")
	        sed -i 's|/\*50-ea-af\*/|/*\n* XTEST test case 9204 fails.\n* Invoke_Crypto_MACInit: unexpected value 0x0, expected 0xffff3024.\n*/\n\n/\*50-ea-af\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	    "9239")
	        sed -i 's|/\*50-4a-56\*/|/*\n* XTEST test case 9239 fails.\n* xml_crypto_api.h at line 635: unexpected value 0x60000, expected 0xc0000.\n*/\n\n/\*50-4a-56\*/|g' ${GP_XTEST_OUT_DIR}/xtest_9000.c
	    ;;
	esac

done

cd ${CDIR}

echo -e ""
echo -e "--------------------------------------------------------------------------"
echo -e "+ `basename $0` finished";
echo -e "--------------------------------------------------------------------------"
