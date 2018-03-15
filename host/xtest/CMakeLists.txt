project (xtest C)

include(${OPTEE_TEST_SDK}/host_include/conf.cmake)

################################################################################
# Packages
################################################################################
find_package(Threads REQUIRED)
if(NOT THREADS_FOUND)
	message(FATAL_ERROR "Threads not found")
endif()

include(GNUInstallDirs)

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
	regression_1000.c
	regression_4000.c
	regression_5000.c
	regression_6000.c
	regression_7000.c
	regression_8000.c
	sha_perf.c
	xtest_helpers.c
	xtest_main.c
	xtest_test.c
)

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


if (CFG_GP_TEST_SUITE)
	list (APPEND SRC
		gp_7000.c
		 gp_7500.c
		 gp_8000.c
		 gp_8500.c
		 gp_9000.c
	)
endif()

################################################################################
# Built binary
################################################################################
add_executable (${PROJECT_NAME} ${SRC})

target_compile_options (${PROJECT_NAME} PRIVATE -include conf.h)

target_include_directories(${PROJECT_NAME}
	PRIVATE .
	PRIVATE adbg/include
	PRIVATE xml/include
	PRIVATE ${OPTEE_TEST_SDK}/host_include
)

target_link_libraries (${PROJECT_NAME}
	PRIVATE ${CMAKE_THREAD_LIBS_INIT}
	PRIVATE xtest-ta-headers
	PRIVATE teec
	PRIVATE m
)

if (CFG_GP_TEST_SUITE)
        target_compile_definitions (${PROJECT_NAME}
                PRIVATE -DWITH_GP_TESTS
	)

	target_compile_options (${PROJECT_NAME}
		PRIVATE -Wall
		PRIVATE -Wcast-align
		PRIVATE -Werror
		PRIVATE -Werror-implicit-function-declaration
		PRIVATE -Wextra
		PRIVATE -Wfloat-equal
		PRIVATE -Wformat-nonliteral
		PRIVATE -Wformat-security
		PRIVATE -Wformat=2
		PRIVATE -Winit-self
		PRIVATE -Wmissing-declarations
		PRIVATE -Wmissing-format-attribute
		PRIVATE -Wmissing-include-dirs
		PRIVATE -Wmissing-noreturn
		PRIVATE -Wmissing-prototypes
		PRIVATE -Wnested-externs
		PRIVATE -Wpointer-arith
		PRIVATE -Wshadow
		PRIVATE -Wstrict-prototypes
		PRIVATE -Wswitch-default
		PRIVATE -Wwrite-strings
		PRIVATE -Wno-missing-field-initializers
		PRIVATE -Wno-format-zero-length
		PRIVATE -Wno-format-zero-length
		# Too many unused resources: don't fail for them.
		PRIVATE -Wno-unused-function  
		PRIVATE -Wno-unused-label     
		PRIVATE -Wno-unused-value     
		PRIVATE -Wno-unused-variable  		
		PRIVATE -Wno-unused-parameter
	)

	target_include_directories(${PROJECT_NAME}
		PRIVATE ../../ta/GP_TTA_Arithmetical
		PRIVATE ../../ta/GP_TTA_Crypto
		PRIVATE ../../ta/GP_TTA_DS
		PRIVATE ../../ta/GP_TTA_TCF
		PRIVATE ../../ta/GP_TTA_TCF_ICA
		PRIVATE ../../ta/GP_TTA_TCF_ICA2
		PRIVATE ../../ta/GP_TTA_TCF_MultipleInstanceTA
		PRIVATE ../../ta/GP_TTA_TCF_SingleInstanceTA
		PRIVATE ../../ta/GP_TTA_Time
		PRIVATE ../../ta/GP_TTA_answerErrorTo_Invoke
		PRIVATE ../../ta/GP_TTA_answerErrorTo_OpenSession
		PRIVATE ../../ta/GP_TTA_answerSuccessTo_OpenSession_Invoke
		PRIVATE ../../ta/GP_TTA_check_OpenSession_with_4_parameters
		PRIVATE ../../ta/GP_TTA_testingClientAPI
		PRIVATE for_gp/include
	)

	target_link_libraries (${PROJECT_NAME}
		PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../lib/armv7/libcrypto.a
	)
endif()

################################################################################
# Install targets
################################################################################
install (TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
