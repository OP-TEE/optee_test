project (xtest C)

include(${OPTEE_TEST_SDK}/host_include/conf.cmake)

################################################################################
# Packages
################################################################################
find_package(Threads REQUIRED)
if(NOT THREADS_FOUND)
	message(FATAL_ERROR "Threads not found")
endif()

find_package(OpenSSL)
if(OPENSSL_FOUND)
	add_compile_options(-DOPENSSL_FOUND=1 -DOPENSSL_API_COMPAT=10100)
	set (OPENSSL_PRIVATE_LINK OpenSSL::Crypto)
endif()

find_package(Python REQUIRED)

include(GNUInstallDirs)
include(ExternalProject)

macro(DOWNLOAD_FILE url filename hash)

	ExternalProject_Add(
		download_${hash}
		URL_HASH SHA256=${hash}
		DOWNLOAD_DIR ${CMAKE_CURRENT_BINARY_DIR}
		DOWNLOAD_COMMAND wget ${url}
		UPDATE_COMMAND ""
		PATCH_COMMAND ""
		CONFIGURE_COMMAND ""
		BUILD_COMMAND ""
		INSTALL_COMMAND unzip -o ${CMAKE_CURRENT_BINARY_DIR}/${filename} -d ${CMAKE_CURRENT_BINARY_DIR}
	)

endmacro(DOWNLOAD_FILE)

macro(EMBED_8100FILE prefix infile)
	add_custom_command(
		OUTPUT  regression_8100_${prefix}.h
		COMMAND ${Python_EXECUTABLE} ${OPTEE_TEST_ROOT_DIR}/scripts/file_to_c.py --inf ${infile}
	--out ${CMAKE_CURRENT_BINARY_DIR}/regression_8100_${prefix}.h
	--name regression_8100_${prefix}
		DEPENDS ${OPTEE_TEST_ROOT_DIR}/scripts/file_to_c.py ${infile}
	)

	set_property(SOURCE regression_8100.c APPEND PROPERTY OBJECT_DEPENDS
		     ${CMAKE_CURRENT_BINARY_DIR}/regression_8100_${prefix}.h)
endmacro(EMBED_8100FILE)

EMBED_8100FILE(ca_crt ${OPTEE_TEST_ROOT_DIR}/cert/ca.crt)
EMBED_8100FILE(mid_crt ${OPTEE_TEST_ROOT_DIR}/cert/mid.crt)
EMBED_8100FILE(my_crt ${OPTEE_TEST_ROOT_DIR}/cert/my.crt)
EMBED_8100FILE(my_csr ${OPTEE_TEST_ROOT_DIR}/cert/my.csr)

set (SRC
	adbg/src/adbg_case.c
	adbg/src/adbg_enum.c
	adbg/src/adbg_expect.c
	adbg/src/adbg_log.c
	adbg/src/adbg_run.c
	adbg/src/security_utils_hex.c
	aes_perf.c
	benchmark_1000.c
	benchmark_2000.c
	clear_storage.c
	regression_1000.c
	regression_4000.c
	regression_4100.c
	regression_5000.c
	regression_6000.c
	regression_8000.c
	regression_8100.c
	hash_perf.c
	stats.c
	xtest_helpers.c
	xtest_main.c
	xtest_test.c
	xtest_uuid_helpers.c
)
if(CFG_SECURE_PARTITION AND CFG_SPMC_TESTS)
	list (APPEND SRC ffa_spmc_1000.c)
endif()

if (WITH_GP_TESTS)
	add_compile_options(-DWITH_GP_TESTS=1)

	macro(__GEN_GP_FILE outfile xmldir name basedir)
		add_custom_command(
			OUTPUT	${outfile}
			COMMAND	xalan -in ${basedir}/${name}.xml
				      -xsl gp/${name}.xsl -out ${outfile}
			DEPENDS ${basedir}/${name}.xml gp/${name}.xsl
		)
	endmacro(__GEN_GP_FILE)
	macro(GEN_GP_FILE outfile xmldir name)
		__GEN_GP_FILE(${outfile} ${xmldir} ${name}
			      gp-suite/packages/${xmldir})
		list (APPEND SRC ${outfile})
	endmacro(GEN_GP_FILE)

	GEN_GP_FILE(gp_10000.c ClientAPI/xmlstable TEE)
	GEN_GP_FILE(gp_20000.c TrustedCoreFw/xmlstable TEE_Internal_API)
	GEN_GP_FILE(gp_30000.c DataStorage/xmlstable TEE_DataStorage_API)
	GEN_GP_FILE(gp_40000.c Time_Arithmetical/xmlstable TEE_TimeArithm_API)
	GEN_GP_FILE(gp_50000.c Crypto/xmlstable TEE_Crypto_API)
	set (GP_INCLUDES PRIVATE gp/include)
endif()

if (CFG_GP_SOCKETS)
	list (APPEND SRC
		regression_2000.c
		sock_server.c
		rand_stream.c
	)
endif()

if (CFG_SECSTOR_TA_MGMT_PTA)
	list (APPEND SRC install_ta.c)
endif()

if (CFG_SECURE_DATA_PATH)
	list (APPEND SRC sdp_basic.c)
endif()

if (CFG_PKCS11_TA)
	add_compile_options(-DCFG_PKCS11_TA)
	list (APPEND SRC pkcs11_1000.c)
endif()

if (CFG_CRYPTO_SE05X)
	add_compile_options(-DCFG_CRYPTO_SE05X)
endif()

if (CFG_GCM_NIST_VECTORS)
	add_compile_options(-DCFG_GCM_NIST_VECTORS)

	macro(CREATE_NIST_GCM_VECTORS infile mode)
		if (CFG_GCM_NIST_VECTORS_LIMITED)
			set(limited "--limited")
		endif()

		add_custom_command(
			OUTPUT  ${infile}.h
			COMMAND ${Python_EXECUTABLE} ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_gcm_test.py --inf ${infile}.rsp
		--outf ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h --mode=${mode} ${limited}
			DEPENDS ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_gcm_test.py ${infile}.rsp
			DEPENDS download_f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023
		)

		set_property(SOURCE regression_4000.c APPEND PROPERTY OBJECT_DEPENDS
			     ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h)
	endmacro(CREATE_NIST_GCM_VECTORS)

	DOWNLOAD_FILE(
		https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/mac/gcmtestvectors.zip
		gcmtestvectors.zip
		f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023
	)

	CREATE_NIST_GCM_VECTORS(gcmDecrypt128 decrypt)
	CREATE_NIST_GCM_VECTORS(gcmDecrypt192 decrypt)
	CREATE_NIST_GCM_VECTORS(gcmDecrypt256 decrypt)
	CREATE_NIST_GCM_VECTORS(gcmEncryptExtIV128 encrypt)
	CREATE_NIST_GCM_VECTORS(gcmEncryptExtIV192 encrypt)
	CREATE_NIST_GCM_VECTORS(gcmEncryptExtIV256 encrypt)
endif()

if (CFG_CMAC_NIST_VECTORS)
	add_compile_options(-DCFG_CMAC_NIST_VECTORS)

	macro(CREATE_NIST_CMAC_VECTORS infile mode)
		if (CFG_CMAC_NIST_VECTORS_LIMITED)
			set(limited "--limited")
		endif()

		add_custom_command(
			OUTPUT  ${infile}.h
			COMMAND ${Python_EXECUTABLE} ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_cmac_test.py --inf ${infile}.rsp
		--outf ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h --mode=${mode} ${limited}
			DEPENDS ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_cmac_test.py ${infile}.rsp
			DEPENDS download_bdda4edade394c9a2ae74d9cd0921caa120c911a5e735e37abf39d0d5f062be1
		)

		set_property(SOURCE regression_4000.c APPEND PROPERTY OBJECT_DEPENDS
			     ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h)
	endmacro(CREATE_NIST_CMAC_VECTORS)

	DOWNLOAD_FILE(
		https://csrc.nist.gov/csrc/media/projects/cryptographic-algorithm-validation-program/documents/mac/cmactestvectors.zip
		cmactestvectors.zip
		bdda4edade394c9a2ae74d9cd0921caa120c911a5e735e37abf39d0d5f062be1
	)

	CREATE_NIST_CMAC_VECTORS(CMACGenAES128 generate)
	CREATE_NIST_CMAC_VECTORS(CMACGenAES192 generate)
	CREATE_NIST_CMAC_VECTORS(CMACGenAES256 generate)
	CREATE_NIST_CMAC_VECTORS(CMACVerAES128 verify)
	CREATE_NIST_CMAC_VECTORS(CMACVerAES192 verify)
	CREATE_NIST_CMAC_VECTORS(CMACVerAES256 verify)
endif()

if (CFG_XTS_NIST_VECTORS)
	add_compile_options(-DCFG_XTS_NIST_VECTORS)

	macro(CREATE_NIST_XTS_VECTORS infile)
		if (CFG_XTS_NIST_VECTORS_LIMITED)
			set(limited "--limited")
		endif()

		add_custom_command(
			OUTPUT  ${infile}.h
			COMMAND ${Python_EXECUTABLE} ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_xts_test.py
		--inf "format\ tweak\ value\ input\ -\ 128\ hex\ str/${infile}.rsp"
		--outf ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h --mode=encrypt ${limited}
			COMMAND ${Python_EXECUTABLE} ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_xts_test.py
		--inf "format\ tweak\ value\ input\ -\ 128\ hex\ str/${infile}.rsp"
		--outf ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h --mode=decrypt ${limited}
			DEPENDS ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_xts_test.py
			DEPENDS "format\ tweak\ value\ input\ -\ 128\ hex\ str/${infile}.rsp"
			DEPENDS download_67bb04b018182f65530596786e7783f817d2e56509bf3b1f066609b8e3e29c36
		)

		set_property(SOURCE regression_4000.c APPEND PROPERTY OBJECT_DEPENDS
			     ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h)
	endmacro(CREATE_NIST_XTS_VECTORS)

	DOWNLOAD_FILE(
		https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/XTSTestVectors.zip
		XTSTestVectors.zip
		67bb04b018182f65530596786e7783f817d2e56509bf3b1f066609b8e3e29c36
	)

	CREATE_NIST_XTS_VECTORS(XTSGenAES128)
	CREATE_NIST_XTS_VECTORS(XTSGenAES256)
endif()

if (CFG_CCM_NIST_VECTORS)
	add_compile_options(-DCFG_CCM_NIST_VECTORS)

	macro(CREATE_NIST_CCM_VECTORS infile)
		if (CFG_CCM_NIST_VECTORS_LIMITED)
			set(limited "--limited")
		endif()

		add_custom_command(
			OUTPUT  ${infile}.h
			COMMAND ${Python_EXECUTABLE} ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_ccm_test.py --inf ${infile}.rsp
		--outf ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h --mode=encrypt ${limited}
			DEPENDS ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_ccm_test.py ${infile}.rsp
			DEPENDS download_0e3c96761bd8f1a0b4dfe666146c32f7d367a49968375ff091b8da9ecaa673aa
		)

		set_property(SOURCE regression_4000.c APPEND PROPERTY OBJECT_DEPENDS
			     ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h)
	endmacro(CREATE_NIST_CCM_VECTORS)

	DOWNLOAD_FILE(
		https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip
		ccmtestvectors.zip
		0e3c96761bd8f1a0b4dfe666146c32f7d367a49968375ff091b8da9ecaa673aa
	)

	CREATE_NIST_CCM_VECTORS(VTT128)
	CREATE_NIST_CCM_VECTORS(VTT192)
	CREATE_NIST_CCM_VECTORS(VTT256)
	CREATE_NIST_CCM_VECTORS(VPT128)
	CREATE_NIST_CCM_VECTORS(VPT192)
	CREATE_NIST_CCM_VECTORS(VPT256)
	CREATE_NIST_CCM_VECTORS(VNT128)
	CREATE_NIST_CCM_VECTORS(VNT192)
	CREATE_NIST_CCM_VECTORS(VNT256)
	CREATE_NIST_CCM_VECTORS(VADT128)
	CREATE_NIST_CCM_VECTORS(VADT192)
	CREATE_NIST_CCM_VECTORS(VADT256)
endif()

if (CFG_HASH_NIST_VECTORS)
	add_compile_options(-DCFG_HASH_NIST_VECTORS)

	macro(CREATE_NIST_SHA_VECTORS infile algo)
		if (CFG_HASH_NIST_VECTORS_LIMITED)
			set(limited "--limited")
		endif()

		add_custom_command(
			OUTPUT  ${infile}.h
			COMMAND ${Python_EXECUTABLE} ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_sha_test.py
		--inf "shabytetestvectors/${infile}.rsp"
		--outf ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h --algo=${algo} ${limited}
			DEPENDS ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_sha_test.py "shabytetestvectors/${infile}.rsp"
			DEPENDS download_929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8
		)

		set_property(SOURCE regression_4000.c APPEND PROPERTY OBJECT_DEPENDS
			     ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h)
	endmacro(CREATE_NIST_SHA_VECTORS)

	macro(CREATE_NIST_SHA3_VECTORS infile algo)
		if (CFG_HASH_NIST_VECTORS_LIMITED)
			set(limited "--limited")
		endif()

		add_custom_command(
			OUTPUT  ${infile}.h
			COMMAND ${Python_EXECUTABLE} ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_sha_test.py
		--inf ${infile}.rsp
		--outf ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h --algo=${algo} ${limited}
			DEPENDS ${OPTEE_TEST_ROOT_DIR}/scripts/rsp_to_sha_test.py ${infile}.rsp
			DEPENDS download_cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c
		)

		set_property(SOURCE regression_4000.c APPEND PROPERTY OBJECT_DEPENDS
			     ${CMAKE_CURRENT_BINARY_DIR}/${infile}.h)
	endmacro(CREATE_NIST_SHA3_VECTORS)

	DOWNLOAD_FILE(
		https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
		shabytetestvectors.zip
		929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8
	)
	DOWNLOAD_FILE(
		https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip
		sha-3bytetestvectors.zip
		cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c
	)

	CREATE_NIST_SHA_VECTORS(SHA1LongMsg SHA1)
	CREATE_NIST_SHA_VECTORS(SHA1ShortMsg SHA1)
	CREATE_NIST_SHA_VECTORS(SHA224LongMsg SHA224)
	CREATE_NIST_SHA_VECTORS(SHA224ShortMsg SHA224)
	CREATE_NIST_SHA_VECTORS(SHA256LongMsg SHA256)
	CREATE_NIST_SHA_VECTORS(SHA256ShortMsg SHA256)
	CREATE_NIST_SHA_VECTORS(SHA384LongMsg SHA384)
	CREATE_NIST_SHA_VECTORS(SHA384ShortMsg SHA384)
	CREATE_NIST_SHA_VECTORS(SHA512LongMsg SHA512)
	CREATE_NIST_SHA_VECTORS(SHA512ShortMsg SHA512)
	CREATE_NIST_SHA3_VECTORS(SHA3_224LongMsg SHA3_224)
	CREATE_NIST_SHA3_VECTORS(SHA3_224ShortMsg SHA3_224)
	CREATE_NIST_SHA3_VECTORS(SHA3_256LongMsg SHA3_256)
	CREATE_NIST_SHA3_VECTORS(SHA3_256ShortMsg SHA3_256)
	CREATE_NIST_SHA3_VECTORS(SHA3_384LongMsg SHA3_384)
	CREATE_NIST_SHA3_VECTORS(SHA3_384ShortMsg SHA3_384)
	CREATE_NIST_SHA3_VECTORS(SHA3_512LongMsg SHA3_512)
	CREATE_NIST_SHA3_VECTORS(SHA3_512ShortMsg SHA3_512)
endif()

################################################################################
# Built binary
################################################################################
add_executable (${PROJECT_NAME} ${SRC})

target_compile_options (${PROJECT_NAME} PRIVATE -include conf.h)

target_include_directories(${PROJECT_NAME}
	PRIVATE .
	PRIVATE ../supp_plugin/include
	PRIVATE adbg/include
	PRIVATE ${OPTEE_TEST_SDK}/host_include
	PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
	${GP_INCLUDES}
)

target_link_libraries (${PROJECT_NAME}
	PRIVATE ${CMAKE_THREAD_LIBS_INIT}
	PRIVATE xtest-ta-headers
	PRIVATE teec
	PRIVATE m
	PRIVATE ${OPENSSL_PRIVATE_LINK}
	PRIVATE ckteec
)

################################################################################
# Install targets
################################################################################
install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
