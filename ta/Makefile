# Normally this makefile shouldn't be called directly and we expect the output
# path to be on a certain location to fit together with the other OP-TEE
# gits and helper scripts.
ifeq ($O,)
$(error output path should be specified when calling this makefile)
endif

TA_DIRS := create_fail_test \
	   crypt \
	   os_test \
	   rpc_test \
	   sims \
	   storage \
	   fake_uuid \
	   bad_payload

ifeq ($(CFG_GP_TESTSUITE_ENABLE), y)
TA_DIRS += GP_TTA_Arithmetical \
	   GP_TTA_Crypto \
	   GP_TTA_DS \
	   GP_TTA_TCF \
	   GP_TTA_TCF_ICA \
	   GP_TTA_TCF_ICA2 \
	   GP_TTA_TCF_MultipleInstanceTA \
	   GP_TTA_TCF_SingleInstanceTA \
	   GP_TTA_Time \
	   GP_TTA_answerErrorTo_Invoke \
	   GP_TTA_answerErrorTo_OpenSession \
	   GP_TTA_answerSuccessTo_OpenSession_Invoke \
	   GP_TTA_check_OpenSession_with_4_parameters \
	   GP_TTA_testingClientAPI
endif

.PHONY: all
all: ta

.PHONY: ta
ta: 
	$(q)$(foreach dir,$(TA_DIRS), $(MAKE) -C $(dir) O=$(O)/$(dir) &&) true

.PHONY: clean
clean:
	$(q)$(foreach dir,$(TA_DIRS), $(MAKE) -C $(dir) O=$(O)/$(dir) $@ &&) true
