# 目标架构: x86_64 (本机构建) / aarch64
#   make                  # 本机架构
#   make ARCH=aarch64     # aarch64 (本机即 aarch64 时用原生工具链;
#                         # 在 x86_64 交叉构建需 aarch64-linux-gnu-* 工具链)
ARCH    ?= $(shell uname -m)
ifeq ($(ARCH),$(shell uname -m))
CROSS   :=
else ifeq ($(ARCH),aarch64)
CROSS   := aarch64-linux-gnu-
else
ARCH    := x86_64
CROSS   :=
endif

CC      := $(CROSS)gcc
LD      := $(CROSS)ld
OBJCOPY := $(CROSS)objcopy
CFLAGS  ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
CFLAGS  += -Iinclude
LDFLAGS ?=

BUILD   ?= build
SRC     := src
INC     := include
STUB_LD := $(SRC)/stub.ld

TOOLS   := $(BUILD)/elftrace
OBJS    := $(BUILD)/main.o $(BUILD)/util.o $(BUILD)/freeze.o $(BUILD)/collect.o \
	$(BUILD)/build.o $(BUILD)/dump.o $(BUILD)/dwarf.o $(BUILD)/trace.o \
	$(BUILD)/inject.o $(BUILD)/bundle.o $(BUILD)/bundle_main.o \
	$(BUILD)/stub_blob_$(ARCH).o $(BUILD)/disasm.o $(BUILD)/a64.o

all: $(TOOLS)

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/stub_$(ARCH).o: $(SRC)/stub_$(ARCH).S $(INC)/elftrace_stub.h | $(BUILD)
	$(CC) -c -I$(INC) -x assembler-with-cpp $(SRC)/stub_$(ARCH).S -o $@

$(BUILD)/stub_$(ARCH).bin: $(BUILD)/stub_$(ARCH).o $(STUB_LD)
	$(LD) -T $(STUB_LD) -o $(BUILD)/stub_$(ARCH).elf $<
	$(OBJCOPY) -O binary $(BUILD)/stub_$(ARCH).elf $@

$(BUILD)/stub_blob_$(ARCH).c: $(BUILD)/stub_$(ARCH).bin
	@echo '/* generated: do not edit */' > $@
	@echo '#include <stddef.h>' >> $@
	@echo 'const unsigned char stub_blob_$(ARCH)[] = {' >> $@
	@xxd -i $< | sed '1d' | head -n -1 >> $@
	@echo 'const unsigned int stub_blob_$(ARCH)_len = sizeof(stub_blob_$(ARCH));' >> $@

$(BUILD)/stub_blob_$(ARCH).o: $(BUILD)/stub_blob_$(ARCH).c
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
