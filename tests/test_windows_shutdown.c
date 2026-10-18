#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static int failures, pending, cancelled, drained;
static int synchronous, completion_success;
static DWORD wait_result;
static OVERLAPPED* pending_overlapped;
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "%d: %s\n", __LINE__, #expr); ++failures; } } while (0)

static BOOL WINAPI mock_read(HANDLE handle, LPVOID buffer, DWORD size, LPDWORD count, LPOVERLAPPED overlapped) {
    (void)handle; (void)buffer; (void)size;
    if (synchronous) { *count = 20; return TRUE; }
    pending = 1;
    pending_overlapped = overlapped;
    SetLastError(ERROR_IO_PENDING);
    return FALSE;
}

static BOOL WINAPI mock_write(HANDLE handle, LPCVOID buffer, DWORD size, LPDWORD count, LPOVERLAPPED overlapped) {
    return mock_read(handle, (LPVOID)buffer, size, count, overlapped);
}

static DWORD WINAPI mock_wait(DWORD count, const HANDLE* handles, BOOL all, DWORD timeout) {
    (void)handles; (void)all; (void)timeout;
    CHECK(count == 2 && pending);
    if (wait_result == WAIT_FAILED) SetLastError(ERROR_INVALID_HANDLE);
    return wait_result;
}

static BOOL WINAPI mock_cancel(HANDLE handle, LPOVERLAPPED overlapped) {
    (void)handle;
    if (overlapped) {
        CHECK(pending && overlapped == pending_overlapped);
        cancelled = 1;
    }
    return TRUE;
}

static BOOL WINAPI mock_result(HANDLE handle, LPOVERLAPPED overlapped, LPDWORD count, BOOL wait) {
    (void)handle;
    CHECK(wait && pending && overlapped == pending_overlapped);
    CHECK(wait_result == WAIT_OBJECT_0 || cancelled);
    drained = 1;
    pending = 0;
    *count = 20;
    if (completion_success) return TRUE;
    SetLastError(ERROR_OPERATION_ABORTED);
    return FALSE;
}

#define ReadFile mock_read
#define WriteFile mock_write
#define WaitForMultipleObjects mock_wait
#define CancelIoEx mock_cancel
#define GetOverlappedResult mock_result
#include "../src/taptun_win32.c"
#undef ReadFile
#undef WriteFile
#undef WaitForMultipleObjects
#undef CancelIoEx
#undef GetOverlappedResult

static void test_overlapped(int writing, DWORD waited, int success, int sync) {
    TapTunDevice device = {0};
    device.tap_read_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    device.tap_write_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    device.close_event = CreateEventW(NULL, TRUE, TRUE, NULL);
    unsigned char packet[20] = {0};
    pending = cancelled = drained = 0;
    synchronous = sync;
    completion_success = success;
    wait_result = waited;
    int result = writing ? write_tap_windows6(&device, packet, sizeof(packet))
        : read_tap_windows6(&device, packet, sizeof(packet));
    int expected = sync || (waited == WAIT_OBJECT_0 && success) ? 20
        : waited == WAIT_FAILED && success ? TAPTUN_ERROR : TAPTUN_ERROR_CLOSED;
    CHECK(result == expected);
    CHECK(!pending);
    CHECK(sync ? !drained : drained);
    CHECK(cancelled == (!sync && waited != WAIT_OBJECT_0));
    CloseHandle(device.tap_read_event);
    CloseHandle(device.tap_write_event);
    CloseHandle(device.close_event);
}

static BYTE receive_storage[20], send_storage[20];
static int receive_released, session_ended, send_committed;
static BYTE* WINAPI fake_receive(WINTUN_SESSION_HANDLE session, DWORD* size) {
    (void)session; *size = sizeof(receive_storage); return receive_storage;
}
static void WINAPI fake_release(WINTUN_SESSION_HANDLE session, const BYTE* packet) {
    (void)session; CHECK(packet == receive_storage); ++receive_released;
}
static BYTE* WINAPI fake_allocate(WINTUN_SESSION_HANDLE session, DWORD size) {
    (void)session; CHECK(size == sizeof(send_storage)); return send_storage;
}
static void WINAPI fake_send(WINTUN_SESSION_HANDLE session, const BYTE* packet) {
    (void)session; CHECK(packet == send_storage); ++send_committed;
}
static void WINAPI fake_end(WINTUN_SESSION_HANDLE session) { (void)session; ++session_ended; }
static void WINAPI fake_close(WINTUN_ADAPTER_HANDLE adapter) { (void)adapter; }

static void test_leases(void) {
    TapTunDevice* device = calloc(1, sizeof(*device));
    if (!device || initialize_device_state(device, TAPTUN_MODE_TUN, 0, NULL, NULL) != TAPTUN_OK) abort();
    device->receive_packet = fake_receive;
    device->release_receive_packet = fake_release;
    device->allocate_send_packet = fake_allocate;
    device->send_packet = fake_send;
    device->end_session = fake_end;
    device->close_adapter = fake_close;
    TapTunPacket received = {0}, sent = {0};
    CHECK(TapTun_AcquireReceive(device, &received) == TAPTUN_OK);
    CHECK(TapTun_AcquireSend(device, 20, &sent) == TAPTUN_OK);
    CHECK(TapTun_Shutdown(device) == TAPTUN_OK);
    CHECK(receive_released == 0 && session_ended == 0);
    received.data[0] = 0x45;
    sent.data[0] = 0x45;
    CHECK(TapTun_CommitSend(device, &sent) == TAPTUN_ERROR_CLOSED);
    CHECK(TapTun_ReleaseReceive(device, &received) == TAPTUN_OK);
    CHECK(receive_released == 1 && send_committed == 0);
    CHECK(TapTun_AcquireSend(device, 20, &sent) == TAPTUN_ERROR_CLOSED);
    TapTun_Close(device);
    CHECK(session_ended == 1 && receive_released == 1);
}

int main(void) {
    for (int writing = 0; writing < 2; ++writing) {
        test_overlapped(writing, WAIT_OBJECT_0, 1, 1);
        test_overlapped(writing, WAIT_OBJECT_0, 1, 0);
        test_overlapped(writing, WAIT_OBJECT_0, 0, 0);
        test_overlapped(writing, WAIT_OBJECT_0 + 1, 0, 0);
        test_overlapped(writing, WAIT_OBJECT_0 + 1, 1, 0);
        test_overlapped(writing, WAIT_FAILED, 1, 0);
    }
    test_leases();
    printf("Windows native shutdown: %d failures\n", failures);
    return failures != 0;
}
