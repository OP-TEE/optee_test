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
	INTERFACE socket/include
	INTERFACE storage_benchmark/include
)

if (CFG_GP_PACKAGE_PATH)
target_include_directories(${PROJECT_NAME}
	INTERFACE GP_TTA_Arithmetical
	INTERFACE GP_TTA_Crypto
	INTERFACE GP_TTA_DS
	INTERFACE GP_TTA_TCF
	INTERFACE GP_TTA_TCF_ICA
	INTERFACE GP_TTA_TCF_ICA2
	INTERFACE GP_TTA_TCF_MultipleInstanceTA
	INTERFACE GP_TTA_TCF_SingleInstanceTA
	INTERFACE GP_TTA_Time
	INTERFACE GP_TTA_answerErrorTo_Invoke
	INTERFACE GP_TTA_answerErrorTo_OpenSession
	INTERFACE GP_TTA_answerSuccessTo_OpenSession_Invoke
	INTERFACE GP_TTA_check_OpenSession_with_4_parameters
	INTERFACE GP_TTA_testingClientAPI
)
endif()
