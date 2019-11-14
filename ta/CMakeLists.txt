project (xtest-ta-headers C)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROJECT_NAME}
	INTERFACE include
	INTERFACE aes_perf/include
	INTERFACE concurrent/include
	INTERFACE concurrent_large/include
	INTERFACE create_fail_test/include
	INTERFACE crypt/include
	INTERFACE enc_fs/include
	INTERFACE os_test/include
	INTERFACE rpc_test/include
	INTERFACE sdp_basic/include
	INTERFACE sha_perf/include
	INTERFACE sims/include
	INTERFACE miss/include
	INTERFACE sims_keepalive/include
	INTERFACE socket/include
	INTERFACE storage_benchmark/include
)

project (xtest-tas)

set_directory_properties(
	PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${CMAKE_CURRENT_SOURCE_DIR}/out"
	)

add_custom_target (
	build-tas ALL
	)

add_custom_command (
	TARGET build-tas
	COMMAND make -f Makefile.tas O=${CMAKE_CURRENT_SOURCE_DIR}/out TA_DEV_KIT_DIR=${OPTEE_TEST_SDK} all
	COMMENT "Compiling xtest Trusted Applications"
	VERBATIM
	)

install (
	CODE "execute_process(COMMAND make -C ${CMAKE_CURRENT_SOURCE_DIR} -f Makefile.tas O=${CMAKE_CURRENT_SOURCE_DIR}/out TA_DEV_KIT_DIR=${OPTEE_TEST_SDK} install)"
	)
