#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include "../include/taptun_api.h"

typedef struct {
    int closed;
    int write_size;
} CallbackContext;

static int callback_read(void* context, unsigned char* buffer, int buffer_size) {
    (void)context;
    if (buffer_size < 4) return TAPTUN_ERROR_BUFFER_TOO_SMALL;
    const unsigned char packet[] = { 0x45, 0x00, 0x00, 0x14 };
    memcpy(buffer, packet, sizeof(packet));
    return sizeof(packet);
}

static int callback_write(void* context, const unsigned char* data, int data_size) {
    (void)data;
    ((CallbackContext*)context)->write_size = data_size;
    return data_size;
}

static void callback_close(void* context) {
    ((CallbackContext*)context)->closed = 1;
}

static int test_unsupported_zero_copy(TapTunDevice* device) {
    TapTunPacket packet;
    memset(&packet, 0, sizeof(packet));
    if (TapTun_GetCapabilities(device) != 0 || TapTun_GetQueueCount(device) != 1) return 1;
    if (TapTun_AcquireReceive(device, &packet) != TAPTUN_ERROR_UNSUPPORTED) return 1;
    if (TapTun_ReleaseReceive(device, &packet) != TAPTUN_ERROR_UNSUPPORTED) return 1;
    if (TapTun_AcquireSend(device, 20, &packet) != TAPTUN_ERROR_UNSUPPORTED) return 1;
    return TapTun_CommitSend(device, &packet) == TAPTUN_ERROR_UNSUPPORTED ? 0 : 1;
}

static int test_wintun_zero_copy_send(TapTunDevice* device) {
    uint32_t capabilities = TapTun_GetCapabilities(device);
    if ((capabilities & (TAPTUN_CAP_ZERO_COPY_RECEIVE | TAPTUN_CAP_ZERO_COPY_SEND)) !=
        (TAPTUN_CAP_ZERO_COPY_RECEIVE | TAPTUN_CAP_ZERO_COPY_SEND)) {
        return 1;
    }

    TapTunPacket packet;
    memset(&packet, 0, sizeof(packet));
    if (TapTun_AcquireSend(device, 20, &packet) != TAPTUN_OK || !packet.data || packet.size != 20) {
        return 1;
    }
    unsigned char* acquired_data = packet.data;
    void* acquired_token = packet.backend_token;
    if (TapTun_AcquireSend(device, 20, &packet) != TAPTUN_ERROR_BUSY ||
        packet.data != acquired_data || packet.backend_token != acquired_token) {
        TapTun_CommitSend(device, &packet);
        return 1;
    }

    memset(packet.data, 0, packet.size);
    packet.data[0] = 0x45;
    packet.data[2] = 0x00;
    packet.data[3] = 0x14;
    if (TapTun_CommitSend(device, &packet) != TAPTUN_OK || packet.data != NULL || packet.size != 0) {
        return 1;
    }
    return TapTun_CommitSend(device, &packet) == TAPTUN_ERROR_INVALID_ARGUMENT ? 0 : 1;
}

static char* utf8_from_wide(const wchar_t* value) {
    int length = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value,
        -1,
        NULL,
        0,
        NULL,
        NULL);
    if (length <= 0) return NULL;
    char* result = (char*)malloc((size_t)length);
    if (!result) return NULL;
    if (WideCharToMultiByte(
            CP_UTF8,
            WC_ERR_INVALID_CHARS,
            value,
            -1,
            result,
            length,
            NULL,
            NULL) == 0) {
        free(result);
        return NULL;
    }
    return result;
}

int wmain(int argc, wchar_t** argv) {
    TapTunPerformanceOptions performance;
    memset(&performance, 0, sizeof(performance));
    performance.struct_size = sizeof(performance);
    performance.required_features = TAPTUN_PERF_IO_URING_SEND;
    if (TapTun_OpenWithPerformance(NULL, &performance) != NULL ||
        GetLastError() != ERROR_NOT_SUPPORTED) {
        fprintf(stderr, "Unsupported required performance options were accepted.\n");
        return 1;
    }

    TapTunCallbackOptions callback_options;
    memset(&callback_options, 0, sizeof(callback_options));
    if (TapTun_OpenFromCallbacks(&callback_options) != NULL) {
        fprintf(stderr, "Invalid callback options were accepted.\n");
        return 1;
    }

    CallbackContext context = { 0, 0 };
    callback_options.context = &context;
    callback_options.read = callback_read;
    callback_options.write = callback_write;
    callback_options.close = callback_close;
    unsigned char packet[16];
    TapTunDevice* callback_device = TapTun_OpenFromCallbacks(&callback_options);
    if (!callback_device || TapTun_Read(callback_device, packet, sizeof(packet)) != 4 ||
        TapTun_Write(callback_device, packet, 4) != 4 ||
        test_unsupported_zero_copy(callback_device) != 0) {
        if (callback_device) TapTun_Close(callback_device);
        fprintf(stderr, "Callback TUN test failed.\n");
        return 1;
    }
    TapTunBuffer callback_batch[2] = {
        { packet, sizeof(packet), 4 },
        { packet, sizeof(packet), 4 }
    };
    if (TapTun_ReadBatch(callback_device, callback_batch, 2) != 1 ||
        callback_batch[0].size != 4) {
        TapTun_Close(callback_device);
        fprintf(stderr, "Callback batch API test failed.\n");
        return 1;
    }
    callback_batch[0].size = 4;
    callback_batch[1].size = 4;
    if (TapTun_WriteBatch(callback_device, callback_batch, 2) != 2) {
        TapTun_Close(callback_device);
        fprintf(stderr, "Callback batch API test failed.\n");
        return 1;
    }
    TapTun_Close(callback_device);
    if (!context.closed || context.write_size != 4) return 1;
    if (argc > 1 && wcscmp(argv[1], L"--callbacks-only") == 0) {
        printf("Windows callback and batch API tests passed.\n");
        return 0;
    }

    TapTunOptions invalid_options;
    memset(&invalid_options, 0, sizeof(invalid_options));
    invalid_options.ring_capacity = 12345;
    if (TapTun_Open(&invalid_options) != NULL) {
        fprintf(stderr, "Invalid Wintun ring capacity was accepted.\n");
        return 1;
    }

    TapTunOptions options;
    memset(&options, 0, sizeof(options));
    options.name = "taptun-test";
    options.open_mode = TAPTUN_OPEN_DEFAULT;
    int name_explicit = 0;
    char* requested_name = NULL;
    char* requested_dll = NULL;
    for (int index = 1; index < argc; ++index) {
        if (wcscmp(argv[index], L"--tap-auto") == 0) {
            options.mode = TAPTUN_MODE_TAP;
            options.tap_backend = TAPTUN_TAP_BACKEND_AUTO;
        } else if (wcscmp(argv[index], L"--tap-native") == 0) {
            options.mode = TAPTUN_MODE_TAP;
            options.tap_backend = TAPTUN_TAP_BACKEND_NATIVE_ONLY;
        } else if (wcscmp(argv[index], L"--tap-emulated") == 0) {
            options.mode = TAPTUN_MODE_TAP;
            options.tap_backend = TAPTUN_TAP_BACKEND_EMULATED_ONLY;
        } else if (wcscmp(argv[index], L"--name") == 0 && index + 1 < argc) {
            free(requested_name);
            requested_name = utf8_from_wide(argv[++index]);
            if (!requested_name) {
                fprintf(stderr, "Failed to convert the adapter name to UTF-8.\n");
                free(requested_dll);
                return 1;
            }
            options.name = requested_name;
            name_explicit = 1;
        } else {
            // 未指定路径时由库从应用程序目录安全加载 wintun.dll
            free(requested_dll);
            requested_dll = utf8_from_wide(argv[index]);
            if (!requested_dll) {
                fprintf(stderr, "Failed to convert the Wintun path to UTF-8.\n");
                free(requested_name);
                return 1;
            }
            options.wintun_dll_path = requested_dll;
        }
    }
    if (options.mode == TAPTUN_MODE_TAP && !name_explicit) options.name = NULL;
    TapTunDevice* device = TapTun_Open(&options);
    if (!device) {
        fprintf(
            stderr,
            "Failed to open the requested TUN/TAP backend. Win32 error: %lu.\n",
            (unsigned long)TapTun_GetLastSystemError());
        free(requested_name);
        free(requested_dll);
        return 1;
    }
    free(requested_name);
    free(requested_dll);

    int result = TapTun_Activate(device);
    if (result != TAPTUN_OK) {
        fprintf(stderr, "TapTun_Activate failed. Win32 error: %lu.\n",
            (unsigned long)TapTun_GetLastSystemError());
    }
    if (result == TAPTUN_OK) {
        result = TapTun_SetIPAddressV4(device, "10.10.0.1", 24);
        if (result != TAPTUN_OK) {
            fprintf(stderr, "TapTun_SetIPAddressV4 failed. Win32 error: %lu.\n",
                (unsigned long)TapTun_GetLastSystemError());
        }
    }
    if (result == TAPTUN_OK) {
        result = TapTun_SetIPAddressV6(device, "fd10::1", 64);
        if (result != TAPTUN_OK) {
            fprintf(stderr, "TapTun_SetIPAddressV6 failed. Win32 error: %lu.\n",
                (unsigned long)TapTun_GetLastSystemError());
        }
    }
    if (result == TAPTUN_OK && options.mode == TAPTUN_MODE_TUN &&
        test_wintun_zero_copy_send(device) != 0) {
        result = TAPTUN_ERROR;
    }
    uint32_t capabilities = TapTun_GetCapabilities(device);
    printf(
        "%s name=%s index=%u capabilities=0x%08lx\n",
        TapTun_GetMode(device) == TAPTUN_MODE_TAP ? "TAP" : "TUN",
        TapTun_GetName(device),
        TapTun_GetIndex(device),
        (unsigned long)capabilities);
    if (TapTun_GetMode(device) == TAPTUN_MODE_TAP) {
        unsigned char mac[6];
        if (TapTun_GetMacAddress(device, mac) != TAPTUN_OK) result = TAPTUN_ERROR;
        else printf(
            "TAP MAC=%02x:%02x:%02x:%02x:%02x:%02x backend=%s\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            (capabilities & TAPTUN_CAP_NATIVE_TAP) ? "tap-windows6" : "Wintun+tun2tap");
    }
    TapTun_Close(device);
    return result == TAPTUN_OK ? 0 : 1;
}
