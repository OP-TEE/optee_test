# Normally this makefile shouldn't be called directly and we expect the output
# path to be on a certain location to fit together with the other OP-TEE
# gits and helper scripts.
ifeq ($O,)
$(error output path should be specified when calling this makefile)
endif

# By default we expect optee_client exported folder to be on a certain relative
# path, but if the client specifies the OPTEE_CLIENT_EXPORT then that path will
# be used instead.
OPTEE_CLIENT_EXPORT ?= ../../../optee_client/out/export

CC		:= $(CROSS_COMPILE)gcc
CPP		:= $(CROSS_COMPILE)cpp
LD		:= $(CROSS_COMPILE)ld
AR		:= $(CROSS_COMPILE)ar
NM		:= $(CROSS_COMPILE)nm
OBJCOPY		:= $(CROSS_COMPILE)objcopy
OBJDUMP		:= $(CROSS_COMPILE)objdump
READELF		:= $(CROSS_COMPILE)readelf

srcs := xtest_1000.c \
	xtest_4000.c \
	xtest_5000.c \
	xtest_6000.c \
	xtest_7000.c \
	xtest_10000.c \
	xtest_helpers.c \
	xtest_main.c \
	xtest_test.c \
	adbg/src/adbg_case.c \
	adbg/src/adbg_enum.c \
	adbg/src/adbg_expect.c \
	adbg/src/adbg_log.c \
	adbg/src/adbg_mts.c \
	adbg/src/adbg_run.c \
	adbg/src/adbg_util.c \
	adbg/src/r_list_genutil.c \
	adbg/src/security_utils_hex.c \
	adbg/src/security_utils_mem.c

ifeq ($(CFG_GP_TESTSUITE_ENABLE), y)
srcs  += xtest_7500.c \
	 xtest_8000.c \
	 xtest_8500.c \
	 xtest_9000.c
endif

objs 	:= $(patsubst %.c,$(O)/%.o, $(srcs))

CFLAGS += -I./
CFLAGS += -I./adbg/include
CFLAGS += -I./xml/include

CFLAGS += -I$(OPTEE_CLIENT_EXPORT)/include
CFLAGS += -I$(TA_DEV_KIT_DIR)/host_include

CFLAGS += -I../../ta/create_fail_test/include
CFLAGS += -I../../ta/crypt/include
CFLAGS += -I../../ta/enc_fs/include
CFLAGS += -I../../ta/os_test/include
CFLAGS += -I../../ta/rpc_test/include
CFLAGS += -I../../ta/sims/include
CFLAGS += -I../../ta/storage/include
ifeq ($(CFG_GP_TESTSUITE_ENABLE),y)
CFLAGS += -I../../ta/GP_TTA_Arithmetical
CFLAGS += -I../../ta/GP_TTA_Crypto
CFLAGS += -I../../ta/GP_TTA_DS
CFLAGS += -I../../ta/GP_TTA_TCF
CFLAGS += -I../../ta/GP_TTA_TCF_ICA
CFLAGS += -I../../ta/GP_TTA_TCF_ICA2
CFLAGS += -I../../ta/GP_TTA_TCF_MultipleInstanceTA
CFLAGS += -I../../ta/GP_TTA_TCF_SingleInstanceTA
CFLAGS += -I../../ta/GP_TTA_Time
CFLAGS += -I../../ta/GP_TTA_answerErrorTo_Invoke
CFLAGS += -I../../ta/GP_TTA_answerErrorTo_OpenSession
CFLAGS += -I../../ta/GP_TTA_answerSuccessTo_OpenSession_Invoke
CFLAGS += -I../../ta/GP_TTA_check_OpenSession_with_4_parameters
CFLAGS += -I../../ta/GP_TTA_testingClientAPI

# need more include: openssl
CFLAGS += -Ifor_gp/include

# need more libraries: openssl
ifneq ($(PLATFORM_FLAVOR),qemu_virt)
LDFLAGS += for_gp/lib/libcrypto.a
else
LDFLAGS += -lcrypto
endif

# need more flags
CFLAGS += -DXTEST_WITH_GP_TESTS

endif

# FIXME: Check if and why we need this flag?
CFLAGS += -DUSER_SPACE

ifneq ($(CFG_GP_TESTSUITE_ENABLE),y)
CFLAGS += -Wall -Wcast-align -Werror \
	  -Werror-implicit-function-declaration -Wextra -Wfloat-equal \
	  -Wformat-nonliteral -Wformat-security -Wformat=2 -Winit-self \
	  -Wmissing-declarations -Wmissing-format-attribute \
	  -Wmissing-include-dirs -Wmissing-noreturn \
	  -Wmissing-prototypes -Wnested-externs -Wpointer-arith \
	  -Wshadow -Wstrict-prototypes -Wswitch-default \
	  -Wwrite-strings \
	  -Wno-missing-field-initializers -Wno-format-zero-length
endif

LDFLAGS += -L$(OPTEE_CLIENT_EXPORT)/lib -lteec
LDFLAGS += -lpthread

.PHONY: all
all: xtest

xtest: $(objs)
	@echo "  LD      $(O)/$@"
	$(q)@$(CC) -o $(O)/$@ $+ $(LDFLAGS)

$(O)/%.o: $(CURDIR)/%.c
	$(q)mkdir -p $(O)/adbg/src
	@echo '  CC      $<'
	$(q)$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	@echo '  CLEAN $(O)'
	$(q)rm -f $(O)/xtest
	$(q)$(foreach obj,$(objs), rm -f $(obj))
