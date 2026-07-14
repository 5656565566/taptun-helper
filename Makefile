# --- 目标平台 ---
# 支持 windows、linux、macos (未经测试) 以及仅包装外部 TUN 句柄的 posix 后端（如安卓 VPN 服务）
TARGET ?= native
BUILD ?= release
CC ?= gcc

ifeq ($(OS),Windows_NT)
	NATIVE_OS = windows
else ifeq ($(shell uname -s),Darwin)
	NATIVE_OS = macos
else ifeq ($(shell uname -s),Linux)
	NATIVE_OS = linux
else
	NATIVE_OS = posix
endif

ifeq ($(TARGET),native)
	TARGET := $(NATIVE_OS)
endif

ifeq ($(BUILD),release)
	CFLAGS_BUILD = -O3 -DNDEBUG
else ifeq ($(BUILD),debug)
	CFLAGS_BUILD = -O0 -g3
else
	$(error Unsupported build configuration: $(BUILD))
endif

SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build/$(TARGET)/$(BUILD)/$(notdir $(firstword $(CC)))
COMMON_SRC = $(SRC_DIR)/tun2tap.c

ifeq ($(TARGET),windows)
	TARGET_LIB = bin/taptun.dll
	TARGET_IMPLIB = bin/libtaptun.dll.a
	SRC = $(SRC_DIR)/taptun_win32.c $(COMMON_SRC)
	LDFLAGS_PLATFORM = -shared -liphlpapi -lws2_32 -ladvapi32 -Wl,--out-implib,$(TARGET_IMPLIB)
	TEST_EXE = bin/test_windows.exe
	TEST_SRC = tests/test_windows.c
	BENCHMARK_EXE = bin/benchmark_windows.exe
	BENCHMARK_SRC = benchmarks/benchmark_windows.c
	TEST_LDFLAGS_PLATFORM = -municode
else ifeq ($(TARGET),linux)
	TARGET_LIB = bin/libtaptun.so
	SRC = $(SRC_DIR)/taptun_linux.c $(SRC_DIR)/linux_uring.c $(SRC_DIR)/linux_offload.c $(COMMON_SRC)
	CFLAGS_PLATFORM = -D_GNU_SOURCE -fPIC -pthread
	LDFLAGS_PLATFORM = -shared -pthread
	TEST_EXE = bin/test_linux
	TEST_SRC = tests/test_linux.c
	TEST_LDFLAGS_PLATFORM = -pthread -Wl,-rpath,'$$ORIGIN'
	BENCHMARK_EXE = bin/benchmark_linux
	BENCHMARK_SRC = benchmarks/benchmark_posix.c
	BENCHMARK_LDFLAGS_PLATFORM = -pthread -Wl,-rpath,'$$ORIGIN'
	OFFLOAD_TEST_EXE = bin/test_linux_offload
else ifeq ($(TARGET),macos)
	TARGET_LIB = bin/libtaptun.dylib
	SRC = $(SRC_DIR)/taptun_apple.c $(COMMON_SRC)
	CFLAGS_PLATFORM = -fPIC -pthread
	LDFLAGS_PLATFORM = -dynamiclib -pthread
	TEST_EXE = bin/test_macos
	TEST_SRC = tests/test_posix.c
	TEST_LDFLAGS_PLATFORM = -pthread -Wl,-rpath,@loader_path
	BENCHMARK_EXE = bin/benchmark_macos
	BENCHMARK_SRC = benchmarks/benchmark_posix.c
	BENCHMARK_LDFLAGS_PLATFORM = -pthread -Wl,-rpath,@loader_path
else ifeq ($(TARGET),posix)
	TARGET_LIB = bin/libtaptun.so
	SRC = $(SRC_DIR)/taptun_posix.c $(COMMON_SRC)
	CFLAGS_PLATFORM = -fPIC -pthread
	LDFLAGS_PLATFORM = -shared -pthread
	TEST_EXE = bin/test_posix
	TEST_SRC = tests/test_posix.c
	TEST_LDFLAGS_PLATFORM = -pthread -Wl,-rpath,'$$ORIGIN'
	BENCHMARK_EXE = bin/benchmark_posix
	BENCHMARK_SRC = benchmarks/benchmark_posix.c
	BENCHMARK_LDFLAGS_PLATFORM = -pthread -Wl,-rpath,'$$ORIGIN'
else
	$(error Unsupported target: $(TARGET))
endif

OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC))
CFLAGS = -std=c11 -I$(INCLUDE_DIR) -Wall -Wextra $(CFLAGS_BUILD) $(CFLAGS_PLATFORM)
PROTOCOL_TEST_EXE = bin/test_tun2tap$(if $(filter windows,$(TARGET)),.exe,)
GENERATED_BINARIES = \
	bin/taptun.dll \
	bin/libtaptun.dll.a \
	bin/libtaptun.so \
	bin/libtaptun.dylib \
	bin/test_windows.exe \
	bin/test_linux \
	bin/test_posix \
	bin/test_macos \
	bin/test_linux_offload \
	bin/test_tun2tap \
	bin/test_tun2tap.exe \
	bin/benchmark_windows.exe \
	bin/benchmark_linux \
	bin/benchmark_macos \
	bin/benchmark_posix

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJECTS) FORCE
	@mkdir -p bin
	@echo "==> Linking library for $(TARGET)..."
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS_PLATFORM)
	@echo "==> Successfully created $@"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(BUILD_DIR)
	@echo "==> Compiling $< for $(TARGET) ($(BUILD))..."
	$(CC) $(CFLAGS) -DTUNTAP_EXPORTS -c $< -o $@

test: $(TEST_EXE) $(PROTOCOL_TEST_EXE) $(OFFLOAD_TEST_EXE)

$(TEST_EXE): $(TARGET_LIB) $(TEST_SRC) FORCE
	@echo "==> Linking test executable for $(TARGET)..."
	$(CC) $(CFLAGS) $(TEST_SRC) -o $@ -Lbin -ltaptun $(TEST_LDFLAGS_PLATFORM)
	@echo "==> Successfully created $@"

$(PROTOCOL_TEST_EXE): $(COMMON_SRC) tests/test_tun2tap.c FORCE
	@mkdir -p bin
	@echo "==> Linking tun2tap protocol test..."
	$(CC) $(CFLAGS) $(COMMON_SRC) tests/test_tun2tap.c -o $@
	@echo "==> Successfully created $@"

ifneq ($(OFFLOAD_TEST_EXE),)
$(OFFLOAD_TEST_EXE): $(SRC_DIR)/linux_offload.c tests/test_linux_offload.c FORCE
	@mkdir -p bin
	@echo "==> Linking Linux offload test..."
	$(CC) $(CFLAGS) $(SRC_DIR)/linux_offload.c tests/test_linux_offload.c -o $@
	@echo "==> Successfully created $@"
endif

benchmark: $(BENCHMARK_EXE)

$(BENCHMARK_EXE): $(TARGET_LIB) $(BENCHMARK_SRC) FORCE
	@echo "==> Linking benchmark executable for $(TARGET)..."
	$(CC) $(CFLAGS) $(BENCHMARK_SRC) -o $@ -Lbin -ltaptun $(BENCHMARK_LDFLAGS_PLATFORM)
	@echo "==> Successfully created $@"

clean:
	@echo "==> Cleaning project..."
	@rm -rf build/*
	@rm -f $(GENERATED_BINARIES)

FORCE:

.PHONY: all test benchmark clean FORCE
