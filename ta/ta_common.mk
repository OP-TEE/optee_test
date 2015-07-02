# Note that it is important that that $(BINARY) is set before we include
# ta_dev_kit.mk. In the optee_test this is done in the individual TA Makefiles.
include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

.PHONY: all
all: $(O)/$(BINARY).ta

$(O)/$(BINARY).ta: $(O)/$(BINARY).bin
	@echo '  INSTALL $@'
	@mkdir -p $(O)
	@rm -f $@
	@cat ../prebuilt/faked_armv7_uta_signed_header.bin $< > $@
