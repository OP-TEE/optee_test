FINAL_BINARY = 1cca17a0-5881-11e5-ad470002a5d5c51b
BINARY = $(FINAL_BINARY)-temp
include ../ta_common.mk
CORRUPT = ./corrupt.py

FINAL_TA = $(link-out-dir)/$(FINAL_BINARY).ta

all: $(FINAL_TA)

cleanfiles += $(FINAL_TA)

$(FINAL_TA): $(link-out-dir)/$(binary).ta $(CORRUPT)
	@echo ' CORRUPT $@'
	$(q)$(CORRUPT) $< $@
