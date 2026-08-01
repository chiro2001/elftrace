CC      ?= gcc
LD      ?= ld
OBJCOPY ?= objcopy
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
CFLAGS  += -Iinclude
LDFLAGS ?=

BUILD   := build
SRC     := src
INC     := include
STUB_LD := $(SRC)/stub.ld

TOOLS   := $(BUILD)/elftrace
OBJS    := $(BUILD)/main.o $(BUILD)/util.o $(BUILD)/freeze.o \
           $(BUILD)/build.o $(BUILD)/dump.o $(BUILD)/dwarf.o \
           $(BUILD)/stub_blob_x86_64.o

all: $(TOOLS)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/stub_x86_64.o: $(SRC)/stub_x86_64.S $(INC)/elftrace_stub.h | $(BUILD)
	$(CC) -c -I$(INC) -x assembler-with-cpp $(SRC)/stub_x86_64.S -o $@

$(BUILD)/stub_x86_64.bin: $(BUILD)/stub_x86_64.o $(STUB_LD)
	$(LD) -T $(STUB_LD) -o $(BUILD)/stub_x86_64.elf $<
	$(OBJCOPY) -O binary $(BUILD)/stub_x86_64.elf $@

$(BUILD)/stub_blob_x86_64.c: $(BUILD)/stub_x86_64.bin
	@echo '/* generated: do not edit */' > $@
	@echo '#include <stddef.h>' >> $@
	@echo 'const unsigned char stub_blob_x86_64[] = {' >> $@
	@xxd -i $< | sed '1d' | head -n -1 >> $@
	@echo 'const unsigned int stub_blob_x86_64_len = sizeof(stub_blob_x86_64);' >> $@

$(BUILD)/stub_blob_x86_64.o: $(BUILD)/stub_blob_x86_64.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: $(SRC)/%.c $(INC)/elftrace.h $(INC)/elftrace_stub.h $(INC)/elftrace.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(TOOLS): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean
