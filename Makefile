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
	WINDOWS_IP_TEST_EXE = bin/test_windows_ip.exe
	NATIVE_SHUTDOWN_TEST_EXE = bin/test_windows_shutdown.exe
	NATIVE_SHUTDOWN_TEST_SRC = tests/test_windows_shutdown.c $(COMMON_SRC)
	NATIVE_SHUTDOWN_LDFLAGS = -liphlpapi -lws2_32 -ladvapi32
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
	URING_SHUTDOWN_TEST_EXE = bin/test_linux_uring_shutdown
	NATIVE_SHUTDOWN_TEST_EXE = bin/test_posix_shutdown
	NATIVE_SHUTDOWN_TEST_SRC = tests/test_posix_shutdown.c $(filter-out $(SRC_DIR)/taptun_linux.c,$(SRC))
	NATIVE_SHUTDOWN_CFLAGS = -DTAPTUN_TEST_LINUX
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
	NATIVE_SHUTDOWN_TEST_EXE = bin/test_posix_shutdown
	NATIVE_SHUTDOWN_TEST_SRC = tests/test_posix_shutdown.c $(COMMON_SRC)
else
	$(error Unsupported target: $(TARGET))
endif

OBJECTS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRC))
CFLAGS = -std=c11 -I$(INCLUDE_DIR) -Wall -Wextra $(CFLAGS_BUILD) $(CFLAGS_PLATFORM)
PROTOCOL_TEST_EXE = bin/test_tun2tap$(if $(filter windows,$(TARGET)),.exe,)
LIFECYCLE_TEST_EXE = bin/test_lifecycle$(if $(filter windows,$(TARGET)),.exe,)
GENERATED_BINARIES = \
	bin/taptun.dll \
	bin/libtaptun.dll.a \
	bin/libtaptun.so \
	bin/libtaptun.dylib \
	bin/test_windows.exe \
	bin/test_windows_ip.exe \
	bin/test_windows_shutdown.exe \
	bin/test_posix_shutdown \
	bin/test_linux_uring_shutdown \
	bin/test_linux \
	bin/test_posix \
	bin/test_macos \
	bin/test_linux_offload \
	bin/test_tun2tap \
	bin/test_tun2tap.exe \
	bin/test_lifecycle \
	bin/test_lifecycle.exe \
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

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(wildcard include/*.h src/*.h)
	@mkdir -p $(BUILD_DIR)
	@echo "==> Compiling $< for $(TARGET) ($(BUILD))..."
	$(CC) $(CFLAGS) -DTUNTAP_EXPORTS -c $< -o $@

test: $(TEST_EXE) $(PROTOCOL_TEST_EXE) $(LIFECYCLE_TEST_EXE) $(OFFLOAD_TEST_EXE) $(WINDOWS_IP_TEST_EXE) $(NATIVE_SHUTDOWN_TEST_EXE) $(URING_SHUTDOWN_TEST_EXE)

$(LIFECYCLE_TEST_EXE): $(TARGET_LIB) tests/test_lifecycle.c FORCE
	$(CC) $(CFLAGS) tests/test_lifecycle.c -o $@ -Lbin -ltaptun $(filter-out -municode,$(TEST_LDFLAGS_PLATFORM))

ifneq ($(NATIVE_SHUTDOWN_TEST_EXE),)
$(NATIVE_SHUTDOWN_TEST_EXE): $(NATIVE_SHUTDOWN_TEST_SRC) $(wildcard src/*.h include/*.h) FORCE
	$(CC) $(CFLAGS) -DTUNTAP_EXPORTS $(NATIVE_SHUTDOWN_CFLAGS) $(NATIVE_SHUTDOWN_TEST_SRC) -o $@ $(NATIVE_SHUTDOWN_LDFLAGS)
endif

ifneq ($(URING_SHUTDOWN_TEST_EXE),)
$(URING_SHUTDOWN_TEST_EXE): tests/test_linux_uring_shutdown.c $(SRC_DIR)/linux_uring.c FORCE
	$(CC) $(CFLAGS) -DTUNTAP_EXPORTS tests/test_linux_uring_shutdown.c -o $@
endif

$(TEST_EXE): $(TARGET_LIB) $(TEST_SRC) FORCE
	@echo "==> Linking test executable for $(TARGET)..."
	$(CC) $(CFLAGS) $(TEST_SRC) -o $@ -Lbin -ltaptun $(TEST_LDFLAGS_PLATFORM)
	@echo "==> Successfully created $@"

$(PROTOCOL_TEST_EXE): $(COMMON_SRC) tests/test_tun2tap.c FORCE
	@mkdir -p bin
	@echo "==> Linking tun2tap protocol test..."
	$(CC) $(CFLAGS) $(COMMON_SRC) tests/test_tun2tap.c -o $@
	@echo "==> Successfully created $@"

ifneq ($(WINDOWS_IP_TEST_EXE),)
$(WINDOWS_IP_TEST_EXE): $(SRC_DIR)/taptun_win32.c $(COMMON_SRC) tests/test_windows_ip.c FORCE
	@mkdir -p bin
	@echo "==> Linking Windows IP configuration test..."
	$(CC) $(CFLAGS) -DTUNTAP_EXPORTS $(COMMON_SRC) tests/test_windows_ip.c -o $@ -liphlpapi -lws2_32 -ladvapi32
endif

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
