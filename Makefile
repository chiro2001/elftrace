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
OBJS    := $(BUILD)/main.o $(BUILD)/util.o $(BUILD)/freeze.o $(BUILD)/collect.o \
	$(BUILD)/build.o $(BUILD)/dump.o $(BUILD)/dwarf.o $(BUILD)/trace.o \
	$(BUILD)/inject.o $(BUILD)/bundle.o $(BUILD)/bundle_main.o \
	$(BUILD)/stub_blob_x86_64.o $(BUILD)/disasm.o

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

$(BUILD)/%.o: $(SRC)/%.c $(wildcard $(INC)/*.h) | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

# inject.c 的注入代码是手写字节序列, gcc -O2 的 store 合并/重排会
# 破坏 build_stage1/2 的生成顺序 (曾导致 fork 部分被覆盖、寄存器恢复
# 缺失, 目标执行错误 stage2 崩溃); 必须 -O0 编译
$(BUILD)/inject.o: $(SRC)/inject.c $(wildcard $(INC)/*.h) | $(BUILD)
	$(CC) -O0 $(CFLAGS) -c $< -o $@

$(TOOLS): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

clean:
	rm -rf $(BUILD)

.PHONY: all clean
