#include "taptun_api.h"
#include "tap-windows6.h"
#include "tun2tap.h"
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#endif
#include "wintun.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include <iphlpapi.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winioctl.h>
#include <ws2tcpip.h>

#define TAPTUN_DEFAULT_RING_CAPACITY 0x400000

typedef enum {
    WINDOWS_BACKEND_WINTUN = 0,
    WINDOWS_BACKEND_TAP_WINDOWS6 = 1,
    WINDOWS_BACKEND_CALLBACKS = 2
} WindowsBackend;

struct TapTunDevice {
    WindowsBackend backend;
    TapTunMode mode;
    int emulates_tap;
    HMODULE module;
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    NET_LUID luid;
    NET_IFINDEX if_index;
    char if_name[256];
    HANDLE close_event;
    HANDLE wake_event;
    HANDLE tap_handle;
    HANDLE tap_read_event;
    HANDLE tap_write_event;
    unsigned char tap_mac[6];
    CRITICAL_SECTION state_lock;
    CRITICAL_SECTION write_lock;
    CONDITION_VARIABLE state_condition;
    unsigned int active_operations;
    int active_read;
    int active_send_lease;
    int closing;
    int uses_callbacks;
    TapTunCallbackOptions callbacks;
    BYTE* acquired_receive_packet;
    BYTE* acquired_send_packet;
    char receive_token;
    char send_token;
    TapTunTun2Tap tun2tap;
    unsigned char synthetic_frames[8][TAPTUN_SYNTHETIC_FRAME_SIZE];
    int synthetic_sizes[8];
    unsigned int synthetic_head;
    unsigned int synthetic_count;
    unsigned char* read_packet;
    unsigned char* write_packet;

    WINTUN_CLOSE_ADAPTER_FUNC* close_adapter;
    WINTUN_END_SESSION_FUNC* end_session;
    WINTUN_GET_READ_WAIT_EVENT_FUNC* get_read_wait_event;
    WINTUN_RECEIVE_PACKET_FUNC* receive_packet;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC* release_receive_packet;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC* allocate_send_packet;
    WINTUN_SEND_PACKET_FUNC* send_packet;
};

typedef struct {
    WINTUN_CREATE_ADAPTER_FUNC* create_adapter;
    WINTUN_OPEN_ADAPTER_FUNC* open_adapter;
    WINTUN_CLOSE_ADAPTER_FUNC* close_adapter;
    WINTUN_GET_ADAPTER_LUID_FUNC* get_adapter_luid;
    WINTUN_START_SESSION_FUNC* start_session;
    WINTUN_END_SESSION_FUNC* end_session;
    WINTUN_GET_READ_WAIT_EVENT_FUNC* get_read_wait_event;
    WINTUN_RECEIVE_PACKET_FUNC* receive_packet;
    WINTUN_RELEASE_RECEIVE_PACKET_FUNC* release_receive_packet;
    WINTUN_ALLOCATE_SEND_PACKET_FUNC* allocate_send_packet;
    WINTUN_SEND_PACKET_FUNC* send_packet;
} WintunApi;

static int initialize_device_state(
    TapTunDevice* device,
    TapTunMode mode,
    int emulates_tap,
    const unsigned char interface_mac[6],
    const unsigned char peer_mac[6]) {
    device->mode = mode;
    device->emulates_tap = emulates_tap;
    device->close_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    device->wake_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!device->close_event || !device->wake_event) return TAPTUN_ERROR;
    if (emulates_tap) {
        device->read_packet = (unsigned char*)malloc(TAPTUN_MAX_IP_PACKET_SIZE);
        device->write_packet = (unsigned char*)malloc(TAPTUN_MAX_IP_PACKET_SIZE);
        if (!device->read_packet || !device->write_packet) return TAPTUN_ERROR;
        taptun_tun2tap_init(
            &device->tun2tap,
            interface_mac,
            peer_mac,
            device->if_name,
            device->if_index);
    }
    InitializeCriticalSection(&device->state_lock);
    InitializeCriticalSection(&device->write_lock);
    InitializeConditionVariable(&device->state_condition);
    return TAPTUN_OK;
}

static void free_uninitialized_device(TapTunDevice* device) {
    if (!device) return;
    if (device->close_event) CloseHandle(device->close_event);
    if (device->wake_event) CloseHandle(device->wake_event);
    free(device->read_packet);
    free(device->write_packet);
    free(device);
}

static WCHAR* utf8_to_wide(const char* value) {
    if (!value) return NULL;
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, NULL, 0);
    if (length <= 0) return NULL;
    WCHAR* wide_value = (WCHAR*)calloc((size_t)length, sizeof(WCHAR));
    if (!wide_value) return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value, -1, wide_value, length) == 0) {
        free(wide_value);
        return NULL;
    }
    return wide_value;
}

static int wide_to_utf8(const WCHAR* value, char* buffer, size_t buffer_size) {
    if (!value || !buffer || buffer_size == 0) return TAPTUN_ERROR_INVALID_ARGUMENT;
    int result = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value,
        -1,
        buffer,
        (int)buffer_size,
        NULL,
        NULL);
    return result > 0 ? TAPTUN_OK : TAPTUN_ERROR;
}

static int tap_device_io_control(
    HANDLE handle,
    DWORD control_code,
    void* input,
    DWORD input_size,
    void* output,
    DWORD output_size,
    DWORD* bytes_returned) {
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!event) return TAPTUN_ERROR;
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = event;

    BOOL completed = DeviceIoControl(
        handle,
        control_code,
        input,
        input_size,
        output,
        output_size,
        bytes_returned,
        &overlapped);
    if (!completed && GetLastError() == ERROR_IO_PENDING) {
        completed = GetOverlappedResult(handle, &overlapped, bytes_returned, TRUE);
    }
    DWORD error = completed ? ERROR_SUCCESS : GetLastError();
    CloseHandle(event);
    if (!completed) SetLastError(error);
    return completed ? TAPTUN_OK : TAPTUN_ERROR;
}

static DWORD get_interface_mac(const NET_LUID* luid, unsigned char mac_address[6]) {
    MIB_IF_ROW2 row;
    memset(&row, 0, sizeof(row));
    row.InterfaceLuid = *luid;
    DWORD result = GetIfEntry2(&row);
    if (result != NO_ERROR) return result;
    if (row.PhysicalAddressLength < 6) return ERROR_INVALID_DATA;
    memcpy(mac_address, row.PhysicalAddress, 6);
    return NO_ERROR;
}

static TapTunDevice* open_tap_windows6(const TapTunOptions* options) {
    if (options && options->open_mode == TAPTUN_OPEN_CREATE_ONLY) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }

    WCHAR* requested_name = options && options->name && options->name[0] != '\0'
        ? utf8_to_wide(options->name)
        : NULL;
    if (options && options->name && options->name[0] != '\0' && !requested_name) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return NULL;
    }

    HKEY adapters = NULL;
    LONG registry_result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
        0,
        KEY_READ,
        &adapters);
    if (registry_result != ERROR_SUCCESS) {
        free(requested_name);
        SetLastError((DWORD)registry_result);
        return NULL;
    }

    TapTunDevice* device = NULL;
    DWORD last_error = ERROR_NOT_FOUND;
    for (DWORD index = 0; ; ++index) {
        WCHAR subkey_name[256];
        DWORD subkey_length = (DWORD)(sizeof(subkey_name) / sizeof(subkey_name[0]));
        registry_result = RegEnumKeyExW(
            adapters,
            index,
            subkey_name,
            &subkey_length,
            NULL,
            NULL,
            NULL,
            NULL);
        if (registry_result == ERROR_NO_MORE_ITEMS) break;
        if (registry_result != ERROR_SUCCESS) continue;

        HKEY adapter_key = NULL;
        if (RegOpenKeyExW(adapters, subkey_name, 0, KEY_READ, &adapter_key) != ERROR_SUCCESS) {
            continue;
        }
        WCHAR component_id[256] = { 0 };
        DWORD value_size = sizeof(component_id);
        DWORD value_type = 0;
        if (RegQueryValueExW(
                adapter_key,
                L"ComponentId",
                NULL,
                &value_type,
                (LPBYTE)component_id,
                &value_size) != ERROR_SUCCESS ||
            value_type != REG_SZ || _wcsicmp(component_id, L"tap0901") != 0) {
            RegCloseKey(adapter_key);
            continue;
        }

        WCHAR guid[256] = { 0 };
        value_size = sizeof(guid);
        value_type = 0;
        if (RegQueryValueExW(
                adapter_key,
                L"NetCfgInstanceId",
                NULL,
                &value_type,
                (LPBYTE)guid,
                &value_size) != ERROR_SUCCESS || value_type != REG_SZ) {
            RegCloseKey(adapter_key);
            continue;
        }
        RegCloseKey(adapter_key);

        WCHAR connection_path[768];
        _snwprintf(
            connection_path,
            sizeof(connection_path) / sizeof(connection_path[0]),
            L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%ls\\Connection",
            guid);
        connection_path[(sizeof(connection_path) / sizeof(connection_path[0])) - 1] = L'\0';
        HKEY connection_key = NULL;
        if (RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                connection_path,
                0,
                KEY_READ,
                &connection_key) != ERROR_SUCCESS) {
            continue;
        }
        WCHAR connection_name[256] = { 0 };
        value_size = sizeof(connection_name);
        value_type = 0;
        registry_result = RegQueryValueExW(
            connection_key,
            L"Name",
            NULL,
            &value_type,
            (LPBYTE)connection_name,
            &value_size);
        RegCloseKey(connection_key);
        if (registry_result != ERROR_SUCCESS || value_type != REG_SZ ||
            (requested_name && _wcsicmp(requested_name, connection_name) != 0)) {
            continue;
        }

        WCHAR device_path[512];
        _snwprintf(
            device_path,
            sizeof(device_path) / sizeof(device_path[0]),
            L"\\\\.\\Global\\%ls.tap",
            guid);
        device_path[(sizeof(device_path) / sizeof(device_path[0])) - 1] = L'\0';
        HANDLE handle = CreateFileW(
            device_path,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
            NULL);
        if (handle == INVALID_HANDLE_VALUE) {
            last_error = GetLastError();
            continue;
        }

        device = (TapTunDevice*)calloc(1, sizeof(TapTunDevice));
        if (!device) {
            CloseHandle(handle);
            last_error = ERROR_OUTOFMEMORY;
            break;
        }
        device->backend = WINDOWS_BACKEND_TAP_WINDOWS6;
        device->tap_handle = handle;
        device->tap_read_event = CreateEventW(NULL, TRUE, FALSE, NULL);
        device->tap_write_event = CreateEventW(NULL, TRUE, FALSE, NULL);
        int name_result = wide_to_utf8(connection_name, device->if_name, sizeof(device->if_name));
        DWORD luid_result = name_result == TAPTUN_OK
            ? ConvertInterfaceAliasToLuid(connection_name, &device->luid)
            : ERROR_NO_UNICODE_TRANSLATION;
        DWORD index_result = luid_result == NO_ERROR
            ? ConvertInterfaceLuidToIndex(&device->luid, &device->if_index)
            : luid_result;
        DWORD mac_result = index_result == NO_ERROR
            ? get_interface_mac(&device->luid, device->tap_mac)
            : index_result;
        int state_result = name_result == TAPTUN_OK && luid_result == NO_ERROR &&
            index_result == NO_ERROR && mac_result == NO_ERROR &&
            device->tap_read_event && device->tap_write_event
            ? initialize_device_state(device, TAPTUN_MODE_TAP, 0, NULL, NULL)
            : TAPTUN_ERROR;
        if (state_result != TAPTUN_OK) {
            DWORD error = name_result != TAPTUN_OK ? ERROR_NO_UNICODE_TRANSLATION
                : luid_result != NO_ERROR ? luid_result
                : index_result != NO_ERROR ? index_result
                : (!device->tap_read_event || !device->tap_write_event) ? ERROR_OUTOFMEMORY
                : mac_result != NO_ERROR ? mac_result
                : GetLastError();
            if (error == ERROR_SUCCESS) error = ERROR_OUTOFMEMORY;
            if (device->tap_read_event) CloseHandle(device->tap_read_event);
            if (device->tap_write_event) CloseHandle(device->tap_write_event);
            CloseHandle(handle);
            free_uninitialized_device(device);
            device = NULL;
            last_error = error;
            continue;
        }
        break;
    }

    RegCloseKey(adapters);
    free(requested_name);
    if (!device) SetLastError(last_error);
    return device;
}

static HMODULE load_wintun(const char* runtime_path) {
    if (!runtime_path || runtime_path[0] == '\0') {
        return LoadLibraryExW(
            L"wintun.dll",
            NULL,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    }

    WCHAR* requested_path = utf8_to_wide(runtime_path);
    if (!requested_path) return NULL;
    DWORD full_length = GetFullPathNameW(requested_path, 0, NULL, NULL);
    WCHAR* full_path = full_length ? (WCHAR*)calloc(full_length, sizeof(WCHAR)) : NULL;
    if (!full_path || GetFullPathNameW(requested_path, full_length, full_path, NULL) == 0) {
        free(requested_path);
        free(full_path);
        return NULL;
    }

    HMODULE module = LoadLibraryExW(
        full_path,
        NULL,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    free(requested_path);
    free(full_path);
    return module;
}

static int load_wintun_api(HMODULE module, WintunApi* api) {
#define LOAD_WINTUN_FUNCTION(field, symbol) \
    do { \
        FARPROC address = GetProcAddress(module, symbol); \
        if (!address) return TAPTUN_ERROR; \
        memcpy(&api->field, &address, sizeof(api->field)); \
    } while (0)

    LOAD_WINTUN_FUNCTION(create_adapter, "WintunCreateAdapter");
    LOAD_WINTUN_FUNCTION(open_adapter, "WintunOpenAdapter");
    LOAD_WINTUN_FUNCTION(close_adapter, "WintunCloseAdapter");
    LOAD_WINTUN_FUNCTION(get_adapter_luid, "WintunGetAdapterLUID");
    LOAD_WINTUN_FUNCTION(start_session, "WintunStartSession");
    LOAD_WINTUN_FUNCTION(end_session, "WintunEndSession");
    LOAD_WINTUN_FUNCTION(get_read_wait_event, "WintunGetReadWaitEvent");
    LOAD_WINTUN_FUNCTION(receive_packet, "WintunReceivePacket");
    LOAD_WINTUN_FUNCTION(release_receive_packet, "WintunReleaseReceivePacket");
    LOAD_WINTUN_FUNCTION(allocate_send_packet, "WintunAllocateSendPacket");
    LOAD_WINTUN_FUNCTION(send_packet, "WintunSendPacket");
#undef LOAD_WINTUN_FUNCTION
    return TAPTUN_OK;
}

static int begin_operation(TapTunDevice* device, int is_read) {
    EnterCriticalSection(&device->state_lock);
    if (device->closing) {
        LeaveCriticalSection(&device->state_lock);
        return TAPTUN_ERROR_CLOSED;
    }
    if (is_read && device->active_read) {
        LeaveCriticalSection(&device->state_lock);
        return TAPTUN_ERROR_BUSY;
    }
    ++device->active_operations;
    if (is_read) device->active_read = 1;
    LeaveCriticalSection(&device->state_lock);
    return TAPTUN_OK;
}

static void end_operation_locked(TapTunDevice* device, int is_read) {
    --device->active_operations;
    if (is_read) device->active_read = 0;
    WakeAllConditionVariable(&device->state_condition);
}

static void end_operation(TapTunDevice* device, int is_read) {
    EnterCriticalSection(&device->state_lock);
    end_operation_locked(device, is_read);
    LeaveCriticalSection(&device->state_lock);
}

static TapTunDevice* open_wintun(const TapTunOptions* options, TapTunMode visible_mode) {
    const char* name = options && options->name && options->name[0] != '\0'
        ? options->name
        : "taptun";
    TapTunOpenMode open_mode = options ? options->open_mode : TAPTUN_OPEN_DEFAULT;
    uint32_t ring_capacity = options && options->ring_capacity
        ? options->ring_capacity
        : TAPTUN_DEFAULT_RING_CAPACITY;
    if (ring_capacity < WINTUN_MIN_RING_CAPACITY ||
        ring_capacity > WINTUN_MAX_RING_CAPACITY ||
        (ring_capacity & (ring_capacity - 1)) != 0) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    HMODULE module = load_wintun(options ? options->wintun_dll_path : NULL);
    if (!module) return NULL;

    WintunApi api;
    memset(&api, 0, sizeof(api));
    if (load_wintun_api(module, &api) != TAPTUN_OK) {
        DWORD error = GetLastError();
        if (error == ERROR_SUCCESS) error = ERROR_PROC_NOT_FOUND;
        FreeLibrary(module);
        SetLastError(error);
        return NULL;
    }

    WCHAR* adapter_name = utf8_to_wide(name);
    if (!adapter_name) {
        FreeLibrary(module);
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return NULL;
    }

    WINTUN_ADAPTER_HANDLE adapter = NULL;
    if (open_mode != TAPTUN_OPEN_CREATE_ONLY) {
        adapter = api.open_adapter(adapter_name);
    }
    if (!adapter && open_mode != TAPTUN_OPEN_EXISTING_ONLY) {
        adapter = api.create_adapter(adapter_name, L"taptun-helper", NULL);
    }
    free(adapter_name);
    if (!adapter) {
        DWORD error = GetLastError();
        FreeLibrary(module);
        SetLastError(error);
        return NULL;
    }

    WINTUN_SESSION_HANDLE session = api.start_session(adapter, ring_capacity);
    if (!session) {
        DWORD error = GetLastError();
        api.close_adapter(adapter);
        FreeLibrary(module);
        SetLastError(error);
        return NULL;
    }

    TapTunDevice* device = (TapTunDevice*)calloc(1, sizeof(TapTunDevice));
    if (!device) {
        api.end_session(session);
        api.close_adapter(adapter);
        FreeLibrary(module);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    device->module = module;
    device->backend = WINDOWS_BACKEND_WINTUN;
    device->adapter = adapter;
    device->session = session;
    strncpy(device->if_name, name, sizeof(device->if_name) - 1);
    device->close_adapter = api.close_adapter;
    device->end_session = api.end_session;
    device->get_read_wait_event = api.get_read_wait_event;
    device->receive_packet = api.receive_packet;
    device->release_receive_packet = api.release_receive_packet;
    device->allocate_send_packet = api.allocate_send_packet;
    device->send_packet = api.send_packet;
    api.get_adapter_luid(adapter, &device->luid);
    DWORD index_result = ConvertInterfaceLuidToIndex(&device->luid, &device->if_index);
    if (index_result != NO_ERROR || initialize_device_state(
            device,
            visible_mode,
            visible_mode == TAPTUN_MODE_TAP,
            options ? options->interface_mac : NULL,
            options ? options->peer_mac : NULL) != TAPTUN_OK) {
        DWORD error = index_result != NO_ERROR ? index_result : GetLastError();
        if (error == ERROR_SUCCESS) error = ERROR_OUTOFMEMORY;
        api.end_session(session);
        api.close_adapter(adapter);
        FreeLibrary(module);
        free_uninitialized_device(device);
        SetLastError(error);
        return NULL;
    }
    return device;
}

TapTunDevice* TapTun_Open(const TapTunOptions* options) {
    TapTunMode mode = options ? options->mode : TAPTUN_MODE_TUN;
    TapTunTapBackend tap_backend = options ? options->tap_backend : TAPTUN_TAP_BACKEND_AUTO;
    if ((mode != TAPTUN_MODE_TUN && mode != TAPTUN_MODE_TAP) ||
        tap_backend < TAPTUN_TAP_BACKEND_AUTO ||
        tap_backend > TAPTUN_TAP_BACKEND_EMULATED_ONLY) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (mode == TAPTUN_MODE_TUN) return open_wintun(options, TAPTUN_MODE_TUN);

    if (tap_backend != TAPTUN_TAP_BACKEND_EMULATED_ONLY) {
        TapTunDevice* device = open_tap_windows6(options);
        if (device || tap_backend == TAPTUN_TAP_BACKEND_NATIVE_ONLY) return device;
    }
    return open_wintun(options, TAPTUN_MODE_TAP);
}

TapTunDevice* TapTun_OpenWithPerformance(
    const TapTunOptions* options,
    const TapTunPerformanceOptions* performance_options) {
    if (performance_options) {
        uint32_t requested = performance_options->preferred_features |
            performance_options->required_features;
        if (performance_options->struct_size < sizeof(TapTunPerformanceOptions) ||
            ((requested & TAPTUN_PERF_MULTI_QUEUE) != 0 &&
             performance_options->queue_count < 2)) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return NULL;
        }
        if (performance_options->required_features != 0) {
            SetLastError(ERROR_NOT_SUPPORTED);
            return NULL;
        }
    }
    return TapTun_Open(options);
}

TapTunDevice* TapTun_OpenFromHandle(const TapTunHandleOptions* options) {
    (void)options;
    SetLastError(ERROR_NOT_SUPPORTED);
    return NULL;
}

TapTunDevice* TapTun_OpenFromCallbacks(const TapTunCallbackOptions* options) {
    if (!options || !options->read || !options->write || !options->close) return NULL;
    if ((options->backend_mode != TAPTUN_MODE_TUN && options->backend_mode != TAPTUN_MODE_TAP) ||
        (options->mode != TAPTUN_MODE_TUN && options->mode != TAPTUN_MODE_TAP) ||
        (options->mode == TAPTUN_MODE_TUN && options->backend_mode != TAPTUN_MODE_TUN)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    if (options->mode == TAPTUN_MODE_TAP && options->backend_mode == TAPTUN_MODE_TUN &&
        !options->interrupt_read) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    TapTunDevice* device = (TapTunDevice*)calloc(1, sizeof(TapTunDevice));
    if (!device) return NULL;
    device->backend = WINDOWS_BACKEND_CALLBACKS;
    device->uses_callbacks = 1;
    device->callbacks = *options;
    device->if_index = options->if_index;
    if (options->name) strncpy(device->if_name, options->name, sizeof(device->if_name) - 1);
    if (initialize_device_state(
            device,
            options->mode,
            options->mode == TAPTUN_MODE_TAP && options->backend_mode == TAPTUN_MODE_TUN,
            options->interface_mac,
            options->peer_mac) != TAPTUN_OK) {
        free_uninitialized_device(device);
        return NULL;
    }
    return device;
}

const char* TapTun_GetName(const TapTunDevice* device) {
    return device ? device->if_name : NULL;
}

unsigned int TapTun_GetIndex(const TapTunDevice* device) {
    return device ? device->if_index : 0;
}

uint32_t TapTun_GetQueueCount(const TapTunDevice* device) {
    return device ? 1u : 0u;
}

TapTunMode TapTun_GetMode(const TapTunDevice* device) {
    return device ? device->mode : TAPTUN_MODE_TUN;
}

int TapTun_GetMacAddress(const TapTunDevice* device, unsigned char mac_address[6]) {
    if (!device || !mac_address) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (device->mode != TAPTUN_MODE_TAP) return TAPTUN_ERROR_UNSUPPORTED;
    if (device->emulates_tap) {
        memcpy(mac_address, device->tun2tap.interface_mac, 6);
    } else if (device->backend == WINDOWS_BACKEND_TAP_WINDOWS6) {
        memcpy(mac_address, device->tap_mac, 6);
    } else {
        return TAPTUN_ERROR_UNSUPPORTED;
    }
    return TAPTUN_OK;
}

uint32_t TapTun_GetLastSystemError(void) {
    return (uint32_t)GetLastError();
}

uint32_t TapTun_GetCapabilities(const TapTunDevice* device) {
    if (!device) return 0;
    if (device->mode == TAPTUN_MODE_TAP) {
        return device->emulates_tap ? TAPTUN_CAP_EMULATED_TAP : TAPTUN_CAP_NATIVE_TAP;
    }
    if (device->backend != WINDOWS_BACKEND_WINTUN) return 0;
    return TAPTUN_CAP_ZERO_COPY_RECEIVE | TAPTUN_CAP_ZERO_COPY_SEND;
}

int TapTun_Activate(TapTunDevice* device) {
    if (device && device->uses_callbacks) return TAPTUN_ERROR_UNSUPPORTED;
    if (!device) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (device->backend != WINDOWS_BACKEND_TAP_WINDOWS6) return TAPTUN_OK;
    ULONG media_status = TRUE;
    DWORD bytes_returned = 0;
    return tap_device_io_control(
        device->tap_handle,
        TAP_WIN_IOCTL_SET_MEDIA_STATUS,
        &media_status,
        sizeof(media_status),
        &media_status,
        sizeof(media_status),
        &bytes_returned);
}

static int delete_addresses(TapTunDevice* device, ADDRESS_FAMILY family) {
    PMIB_UNICASTIPADDRESS_TABLE table = NULL;
    DWORD result = GetUnicastIpAddressTable(family, &table);
    if (result != NO_ERROR) {
        SetLastError(result);
        return TAPTUN_ERROR;
    }

    int status = TAPTUN_OK;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        MIB_UNICASTIPADDRESS_ROW* row = &table->Table[i];
        if (row->InterfaceLuid.Value != device->luid.Value) continue;
        result = DeleteUnicastIpAddressEntry(row);
        if (result != NO_ERROR && result != ERROR_NOT_FOUND) {
            SetLastError(result);
            status = TAPTUN_ERROR;
            break;
        }
    }
    FreeMibTable(table);
    return status;
}

int TapTun_SetIPAddressV4(TapTunDevice* device, const char* address, unsigned int prefix_length) {
    if (!device || !address || prefix_length > 32) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (device->uses_callbacks) return TAPTUN_ERROR_UNSUPPORTED;

    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = device->luid;
    row.Address.Ipv4.sin_family = AF_INET;
    row.OnLinkPrefixLength = (UINT8)prefix_length;
    row.ValidLifetime = 0xffffffff;
    row.PreferredLifetime = 0xffffffff;
    if (InetPtonA(AF_INET, address, &row.Address.Ipv4.sin_addr) != 1) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    if (delete_addresses(device, AF_INET) != TAPTUN_OK) return TAPTUN_ERROR;
    DWORD result = CreateUnicastIpAddressEntry(&row);
    if (result == NO_ERROR || result == ERROR_OBJECT_ALREADY_EXISTS) return TAPTUN_OK;
    SetLastError(result);
    return TAPTUN_ERROR;
}

int TapTun_SetIPAddressV6(TapTunDevice* device, const char* address, unsigned int prefix_length) {
    if (!device || !address || prefix_length > 128) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (device->uses_callbacks) return TAPTUN_ERROR_UNSUPPORTED;

    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = device->luid;
    row.Address.Ipv6.sin6_family = AF_INET6;
    row.OnLinkPrefixLength = (UINT8)prefix_length;
    row.ValidLifetime = 0xffffffff;
    row.PreferredLifetime = 0xffffffff;
    if (InetPtonA(AF_INET6, address, &row.Address.Ipv6.sin6_addr) != 1) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    if (delete_addresses(device, AF_INET6) != TAPTUN_OK) return TAPTUN_ERROR;
    DWORD result = CreateUnicastIpAddressEntry(&row);
    if (result == NO_ERROR || result == ERROR_OBJECT_ALREADY_EXISTS) return TAPTUN_OK;
    SetLastError(result);
    return TAPTUN_ERROR;
}

static int dequeue_synthetic_frame(
    TapTunDevice* device,
    unsigned char* buffer,
    int buffer_size) {
    EnterCriticalSection(&device->state_lock);
    if (device->synthetic_count == 0) {
        LeaveCriticalSection(&device->state_lock);
        return 0;
    }
    unsigned int index = device->synthetic_head;
    int frame_size = device->synthetic_sizes[index];
    if (buffer_size < frame_size) {
        LeaveCriticalSection(&device->state_lock);
        return TAPTUN_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer, device->synthetic_frames[index], (size_t)frame_size);
    device->synthetic_head = (index + 1) % 8;
    --device->synthetic_count;
    LeaveCriticalSection(&device->state_lock);
    return frame_size;
}

static int enqueue_synthetic_frame(
    TapTunDevice* device,
    const unsigned char* frame,
    int frame_size) {
    EnterCriticalSection(&device->state_lock);
    if (device->closing) {
        LeaveCriticalSection(&device->state_lock);
        return TAPTUN_ERROR_CLOSED;
    }
    if (device->synthetic_count == 8) {
        LeaveCriticalSection(&device->state_lock);
        return TAPTUN_ERROR_BUSY;
    }
    unsigned int index = (device->synthetic_head + device->synthetic_count) % 8;
    memcpy(device->synthetic_frames[index], frame, (size_t)frame_size);
    device->synthetic_sizes[index] = frame_size;
    ++device->synthetic_count;
    LeaveCriticalSection(&device->state_lock);
    if (device->uses_callbacks) {
        device->callbacks.interrupt_read(device->callbacks.context);
    } else {
        SetEvent(device->wake_event);
    }
    return TAPTUN_OK;
}

static int read_tap_windows6(TapTunDevice* device, unsigned char* buffer, int buffer_size) {
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = device->tap_read_event;
    ResetEvent(overlapped.hEvent);
    DWORD bytes_read = 0;
    if (ReadFile(device->tap_handle, buffer, (DWORD)buffer_size, &bytes_read, &overlapped)) {
        return (int)bytes_read;
    }
    DWORD error = GetLastError();
    if (error != ERROR_IO_PENDING) return TAPTUN_ERROR;
    HANDLE wait_handles[2] = { overlapped.hEvent, device->close_event };
    DWORD wait_result = WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);
    if (wait_result == WAIT_OBJECT_0 + 1) return TAPTUN_ERROR_CLOSED;
    if (wait_result != WAIT_OBJECT_0 ||
        !GetOverlappedResult(device->tap_handle, &overlapped, &bytes_read, FALSE)) {
        return GetLastError() == ERROR_OPERATION_ABORTED ? TAPTUN_ERROR_CLOSED : TAPTUN_ERROR;
    }
    return (int)bytes_read;
}

static int write_tap_windows6(TapTunDevice* device, const unsigned char* data, int data_size) {
    OVERLAPPED overlapped;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = device->tap_write_event;
    ResetEvent(overlapped.hEvent);
    DWORD bytes_written = 0;
    if (WriteFile(device->tap_handle, data, (DWORD)data_size, &bytes_written, &overlapped)) {
        return (int)bytes_written;
    }
    DWORD error = GetLastError();
    if (error != ERROR_IO_PENDING) return TAPTUN_ERROR;
    HANDLE wait_handles[2] = { overlapped.hEvent, device->close_event };
    DWORD wait_result = WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);
    if (wait_result == WAIT_OBJECT_0 + 1) return TAPTUN_ERROR_CLOSED;
    if (wait_result != WAIT_OBJECT_0 ||
        !GetOverlappedResult(device->tap_handle, &overlapped, &bytes_written, FALSE)) {
        return GetLastError() == ERROR_OPERATION_ABORTED ? TAPTUN_ERROR_CLOSED : TAPTUN_ERROR;
    }
    return (int)bytes_written;
}

static int write_wintun_packet(TapTunDevice* device, const unsigned char* data, int data_size) {
    BYTE* packet = device->allocate_send_packet(device->session, (DWORD)data_size);
    if (!packet) {
        DWORD error = GetLastError();
        return error == ERROR_HANDLE_EOF
            ? TAPTUN_ERROR_CLOSED
            : error == ERROR_BUFFER_OVERFLOW ? TAPTUN_ERROR_BUSY : TAPTUN_ERROR;
    }
    memcpy(packet, data, (size_t)data_size);
    device->send_packet(device->session, packet);
    return data_size;
}

int TapTun_Read(TapTunDevice* device, unsigned char* buffer, int buffer_size) {
    if (!device || !buffer || buffer_size <= 0) return TAPTUN_ERROR_INVALID_ARGUMENT;
    int result = begin_operation(device, 1);
    if (result != TAPTUN_OK) return result;
    if (device->backend == WINDOWS_BACKEND_TAP_WINDOWS6) {
        result = read_tap_windows6(device, buffer, buffer_size);
        end_operation(device, 1);
        return result;
    }

    for (;;) {
        if (device->emulates_tap) {
            result = dequeue_synthetic_frame(device, buffer, buffer_size);
            if (result != 0) break;
        }
        EnterCriticalSection(&device->state_lock);
        int closing = device->closing;
        LeaveCriticalSection(&device->state_lock);
        if (closing) {
            result = TAPTUN_ERROR_CLOSED;
            break;
        }
        if (device->uses_callbacks) {
            unsigned char* target = device->emulates_tap ? device->read_packet : buffer;
            int capacity = device->emulates_tap ? TAPTUN_MAX_IP_PACKET_SIZE : buffer_size;
            result = device->callbacks.read(device->callbacks.context, target, capacity);
            if (device->emulates_tap && result == TAPTUN_ERROR_BUSY) continue;
            if (result > 0 && device->emulates_tap) {
                result = taptun_tun2tap_encapsulate(
                    &device->tun2tap,
                    target,
                    result,
                    buffer,
                    buffer_size);
            }
            break;
        }

        DWORD packet_size = 0;
        BYTE* packet = device->receive_packet(device->session, &packet_size);
        if (packet) {
            if (device->emulates_tap) {
                result = taptun_tun2tap_encapsulate(
                    &device->tun2tap,
                    packet,
                    (int)packet_size,
                    buffer,
                    buffer_size);
            } else if (packet_size > (DWORD)buffer_size) {
                 result = TAPTUN_ERROR_BUFFER_TOO_SMALL;
            } else {
                memcpy(buffer, packet, packet_size);
                result = (int)packet_size;
            }
            device->release_receive_packet(device->session, packet);
            break;
        }

        DWORD error = GetLastError();
        if (error != ERROR_NO_MORE_ITEMS) {
            result = error == ERROR_HANDLE_EOF ? TAPTUN_ERROR_CLOSED : TAPTUN_ERROR;
            break;
        }

        HANDLE wait_handles[3] = {
            device->get_read_wait_event(device->session),
            device->close_event,
            device->wake_event
        };
        DWORD wait_result = WaitForMultipleObjects(3, wait_handles, FALSE, INFINITE);
        if (wait_result == WAIT_OBJECT_0 + 1) {
            result = TAPTUN_ERROR_CLOSED;
            break;
        }
        if (wait_result == WAIT_OBJECT_0 + 2) continue;
        if (wait_result != WAIT_OBJECT_0) {
            result = TAPTUN_ERROR;
            break;
        }
    }

    end_operation(device, 1);
    return result;
}

int TapTun_Write(TapTunDevice* device, const unsigned char* data, int data_size) {
    if (!device || !data || data_size <= 0 ||
        (device->mode == TAPTUN_MODE_TUN && data_size > TAPTUN_MAX_IP_PACKET_SIZE) ||
        (device->mode == TAPTUN_MODE_TAP && data_size > TAPTUN_MAX_ETHERNET_FRAME_SIZE)) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    int result = begin_operation(device, 0);
    if (result != TAPTUN_OK) return result;
    if (device->backend == WINDOWS_BACKEND_TAP_WINDOWS6) {
        EnterCriticalSection(&device->write_lock);
        result = write_tap_windows6(device, data, data_size);
        LeaveCriticalSection(&device->write_lock);
        end_operation(device, 0);
        return result;
    }

    if (!device->emulates_tap) {
        if (data_size > WINTUN_MAX_IP_PACKET_SIZE) {
            result = TAPTUN_ERROR_INVALID_ARGUMENT;
        } else if (device->uses_callbacks) {
            result = device->callbacks.write(device->callbacks.context, data, data_size);
        } else {
            result = write_wintun_packet(device, data, data_size);
        }
    } else {
        unsigned char synthetic[TAPTUN_SYNTHETIC_FRAME_SIZE];
        int output_size = 0;
        EnterCriticalSection(&device->write_lock);
        int action = taptun_tun2tap_decapsulate(
            &device->tun2tap,
            data,
            data_size,
            device->write_packet,
            TAPTUN_MAX_IP_PACKET_SIZE,
            synthetic,
            sizeof(synthetic),
            &output_size);
        if (action == TAPTUN_TUN2TAP_PACKET) {
            result = device->uses_callbacks
                ? device->callbacks.write(device->callbacks.context, device->write_packet, output_size)
                : write_wintun_packet(device, device->write_packet, output_size);
            if (result == output_size) result = data_size;
        } else if (action == TAPTUN_TUN2TAP_SYNTHETIC) {
            result = enqueue_synthetic_frame(device, synthetic, output_size);
            if (result == TAPTUN_OK) result = data_size;
        } else if (action == TAPTUN_TUN2TAP_DROP) {
            result = TAPTUN_ERROR_UNSUPPORTED;
        } else {
            result = action;
        }
        LeaveCriticalSection(&device->write_lock);
    }

    end_operation(device, 0);
    return result;
}

int TapTun_ReadBatch(
    TapTunDevice* device,
    TapTunBuffer* buffers,
    uint32_t buffer_count) {
    if (!device || !buffers || buffer_count == 0 || buffer_count > INT_MAX) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    for (uint32_t index = 0; index < buffer_count; ++index) {
        if (!buffers[index].data || buffers[index].capacity == 0 ||
            buffers[index].capacity > INT_MAX) {
            return TAPTUN_ERROR_INVALID_ARGUMENT;
        }
        buffers[index].size = 0;
    }
    int result = TapTun_Read(device, buffers[0].data, (int)buffers[0].capacity);
    if (result <= 0) return result;
    buffers[0].size = (uint32_t)result;
    return 1;
}

int TapTun_WriteBatch(
    TapTunDevice* device,
    const TapTunBuffer* buffers,
    uint32_t buffer_count) {
    if (!device || !buffers || buffer_count == 0 || buffer_count > INT_MAX) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    for (uint32_t index = 0; index < buffer_count; ++index) {
        if (!buffers[index].data || buffers[index].size == 0 ||
            buffers[index].size > INT_MAX) {
            return TAPTUN_ERROR_INVALID_ARGUMENT;
        }
    }
    uint32_t completed = 0;
    for (; completed < buffer_count; ++completed) {
        int result = TapTun_Write(device, buffers[completed].data, (int)buffers[completed].size);
        if (result != (int)buffers[completed].size) {
            return completed != 0 ? (int)completed : result;
        }
    }
    return (int)completed;
}

int TapTun_AcquireReceive(TapTunDevice* device, TapTunPacket* packet) {
    if (!device || !packet) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if ((TapTun_GetCapabilities(device) & TAPTUN_CAP_ZERO_COPY_RECEIVE) == 0) {
        return TAPTUN_ERROR_UNSUPPORTED;
    }

    int result = begin_operation(device, 1);
    if (result != TAPTUN_OK) return result;

    for (;;) {
        DWORD packet_size = 0;
        BYTE* native_packet = device->receive_packet(device->session, &packet_size);
        if (native_packet) {
            EnterCriticalSection(&device->state_lock);
            if (device->closing) {
                LeaveCriticalSection(&device->state_lock);
                device->release_receive_packet(device->session, native_packet);
                result = TAPTUN_ERROR_CLOSED;
                break;
            }
            device->acquired_receive_packet = native_packet;
            packet->data = native_packet;
            packet->size = packet_size;
            packet->backend_token = &device->receive_token;
            LeaveCriticalSection(&device->state_lock);
            return TAPTUN_OK;
        }

        DWORD error = GetLastError();
        if (error != ERROR_NO_MORE_ITEMS) {
            result = error == ERROR_HANDLE_EOF ? TAPTUN_ERROR_CLOSED : TAPTUN_ERROR;
            break;
        }

        HANDLE wait_handles[2] = {
            device->get_read_wait_event(device->session),
            device->close_event
        };
        DWORD wait_result = WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);
        if (wait_result == WAIT_OBJECT_0 + 1) {
            result = TAPTUN_ERROR_CLOSED;
            break;
        }
        if (wait_result != WAIT_OBJECT_0) {
            result = TAPTUN_ERROR;
            break;
        }
    }

    end_operation(device, 1);
    return result;
}

int TapTun_ReleaseReceive(TapTunDevice* device, TapTunPacket* packet) {
    if (!device || !packet) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if ((TapTun_GetCapabilities(device) & TAPTUN_CAP_ZERO_COPY_RECEIVE) == 0) {
        return TAPTUN_ERROR_UNSUPPORTED;
    }

    EnterCriticalSection(&device->state_lock);
    if (packet->backend_token != &device->receive_token ||
        packet->data != device->acquired_receive_packet ||
        !device->active_read) {
        LeaveCriticalSection(&device->state_lock);
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    BYTE* native_packet = device->acquired_receive_packet;
    device->release_receive_packet(device->session, native_packet);
    device->acquired_receive_packet = NULL;
    end_operation_locked(device, 1);
    LeaveCriticalSection(&device->state_lock);

    packet->data = NULL;
    packet->size = 0;
    packet->backend_token = NULL;
    return TAPTUN_OK;
}

int TapTun_AcquireSend(TapTunDevice* device, uint32_t packet_size, TapTunPacket* packet) {
    if (!device || !packet || packet_size == 0 || packet_size > WINTUN_MAX_IP_PACKET_SIZE) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    if ((TapTun_GetCapabilities(device) & TAPTUN_CAP_ZERO_COPY_SEND) == 0) {
        return TAPTUN_ERROR_UNSUPPORTED;
    }

    EnterCriticalSection(&device->state_lock);
    if (device->closing) {
        LeaveCriticalSection(&device->state_lock);
        return TAPTUN_ERROR_CLOSED;
    }
    if (device->active_send_lease) {
        LeaveCriticalSection(&device->state_lock);
        return TAPTUN_ERROR_BUSY;
    }
    BYTE* native_packet = device->allocate_send_packet(device->session, packet_size);
    if (!native_packet) {
        DWORD error = GetLastError();
        LeaveCriticalSection(&device->state_lock);
        return error == ERROR_HANDLE_EOF
            ? TAPTUN_ERROR_CLOSED
            : error == ERROR_BUFFER_OVERFLOW ? TAPTUN_ERROR_BUSY : TAPTUN_ERROR;
    }
    ++device->active_operations;
    device->active_send_lease = 1;
    device->acquired_send_packet = native_packet;
    packet->data = native_packet;
    packet->size = packet_size;
    packet->backend_token = &device->send_token;
    LeaveCriticalSection(&device->state_lock);
    return TAPTUN_OK;
}

int TapTun_CommitSend(TapTunDevice* device, TapTunPacket* packet) {
    if (!device || !packet) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if ((TapTun_GetCapabilities(device) & TAPTUN_CAP_ZERO_COPY_SEND) == 0) {
        return TAPTUN_ERROR_UNSUPPORTED;
    }

    EnterCriticalSection(&device->state_lock);
    if (packet->backend_token != &device->send_token ||
        packet->data != device->acquired_send_packet ||
        !device->active_send_lease) {
        LeaveCriticalSection(&device->state_lock);
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    BYTE* native_packet = device->acquired_send_packet;
    device->send_packet(device->session, native_packet);
    device->acquired_send_packet = NULL;
    device->active_send_lease = 0;
    end_operation_locked(device, 0);
    LeaveCriticalSection(&device->state_lock);

    packet->data = NULL;
    packet->size = 0;
    packet->backend_token = NULL;
    return TAPTUN_OK;
}

void TapTun_Close(TapTunDevice* device) {
    if (!device) return;

    EnterCriticalSection(&device->state_lock);
    device->closing = 1;
    SetEvent(device->close_event);
    SetEvent(device->wake_event);
    // Closing invalidates leases; Wintun session teardown reclaims an
    // allocated send packet because Wintun has no separate cancel operation.
    BYTE* acquired_receive_packet = device->acquired_receive_packet;
    if (acquired_receive_packet) {
        device->acquired_receive_packet = NULL;
        device->active_read = 0;
        --device->active_operations;
    }
    if (device->active_send_lease) {
        device->active_send_lease = 0;
        device->acquired_send_packet = NULL;
        --device->active_operations;
    }
    WakeAllConditionVariable(&device->state_condition);
    LeaveCriticalSection(&device->state_lock);

    if (acquired_receive_packet && device->backend == WINDOWS_BACKEND_WINTUN) {
        device->release_receive_packet(device->session, acquired_receive_packet);
    }
    if (device->uses_callbacks) device->callbacks.close(device->callbacks.context);
    if (device->backend == WINDOWS_BACKEND_TAP_WINDOWS6) {
        CancelIoEx(device->tap_handle, NULL);
    }

    EnterCriticalSection(&device->state_lock);
    while (device->active_operations != 0) {
        SleepConditionVariableCS(&device->state_condition, &device->state_lock, INFINITE);
    }
    LeaveCriticalSection(&device->state_lock);

    if (device->backend == WINDOWS_BACKEND_WINTUN) {
        device->end_session(device->session);
        device->close_adapter(device->adapter);
    } else if (device->backend == WINDOWS_BACKEND_TAP_WINDOWS6) {
        CloseHandle(device->tap_handle);
        CloseHandle(device->tap_read_event);
        CloseHandle(device->tap_write_event);
    }
    CloseHandle(device->close_event);
    CloseHandle(device->wake_event);
    DeleteCriticalSection(&device->write_lock);
    DeleteCriticalSection(&device->state_lock);
    if (device->module) FreeLibrary(device->module);
    free(device->read_packet);
    free(device->write_packet);
    free(device);
}
