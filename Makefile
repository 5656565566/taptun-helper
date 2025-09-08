# --- 目标平台 ---
# 例如 'make TARGET=windows' 或 'make TARGET=linux'。
# 如果不指定，则默认原生构建环境
TARGET ?= native


ifeq ($(OS), Windows_NT)
	NATIVE_OS = windows
else
	NATIVE_OS = linux
endif

ifeq ($(TARGET), native)
	TARGET := $(NATIVE_OS)
endif

# --- 工具链和编译标志配置 ---

ifeq ($(TARGET), windows)
	CC = gcc
	
	TARGET_LIB = bin/taptun.dll
	TARGET_IMPLIB = bin/libtaptun.dll.a
	
	LDFLAGS_EXTRA = -ladvapi32 -liphlpapi -lws2_32 -lole32

	TEST_EXE = bin/test_windows.exe
	TEST_SRC = tests/test_windows.c
	TEST_LDFLAGS_EXTRA =

else ifeq ($(TARGET), linux)
	CC = gcc

	TARGET_LIB = bin/libtaptun.so

	CFLAGS_EXTRA = -fPIC
	LDFLAGS_EXTRA =

	TEST_EXE = bin/test_linux
	TEST_SRC = tests/test_linux.c
	TEST_LDFLAGS_EXTRA = -lpthread -Wl,-rpath,'$$ORIGIN'

endif

# --- 通用变量 ---
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SOURCES))


CFLAGS = -I$(INCLUDE_DIR) -Wall -g $(CFLAGS_EXTRA)
LDFLAGS = -shared

# --- 构建规则 ---

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJECTS)
	@mkdir -p bin
	@echo "==> Linking library for $(TARGET)..."
ifeq ($(TARGET), windows)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDFLAGS_EXTRA) -Wl,--out-implib,$(TARGET_IMPLIB)
else
	$(CC) $(LDFLAGS) -o $@ $^ $(LDFLAGS_EXTRA)
endif
	@echo "==> Successfully created $@"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p build
	@echo "==> Compiling $< for $(TARGET)..."
	$(CC) $(CFLAGS) -DTUNTAP_EXPORTS -c $< -o $@

# --- 测试程序规则 ---

test: $(TEST_EXE)

$(TEST_EXE): $(TARGET_LIB)
	@echo "==> Linking test executable for $(TARGET)..."
	$(CC) $(TEST_SRC) -o $@ -I$(INCLUDE_DIR) -Lbin -ltuntap $(TEST_LDFLAGS_EXTRA)
	@echo "==> Successfully created $@"

# --- 工具规则 ---

# 清理所有构建生成的文件
clean:
	@echo "==> Cleaning project..."
	@rm -rf $(BUILD_DIR)/* bin/*

.PHONY: all test clean