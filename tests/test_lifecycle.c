#include "taptun_api.h"
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <windows.h>
typedef CRITICAL_SECTION Mutex;
typedef CONDITION_VARIABLE Condition;
typedef HANDLE Thread;
#define LOCK(m) EnterCriticalSection(m)
#define UNLOCK(m) LeaveCriticalSection(m)
#define WAKE(c) WakeAllConditionVariable(c)
#define WAIT(c, m) SleepConditionVariableCS(c, m, INFINITE)
#define THREAD_RESULT DWORD WINAPI
#else
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
typedef pthread_mutex_t Mutex;
typedef pthread_cond_t Condition;
typedef pthread_t Thread;
#define LOCK(m) pthread_mutex_lock(m)
#define UNLOCK(m) pthread_mutex_unlock(m)
#define WAKE(c) pthread_cond_broadcast(c)
#define WAIT(c, m) pthread_cond_wait(c, m)
#define THREAD_RESULT void*
#endif

static atomic_int failures;
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (0)

typedef struct {
    Mutex lock;
    Condition condition;
    int cancelled, cancel_count, close_count;
    int reads, writes, entered, release, exited;
    int block, block_cancel, cancel_entered, release_cancel, fail_write;
    TapTunDevice* device;
    int result;
    int batch, finish_write;
} Backend;

static void initialize(Backend* backend) {
    memset(backend, 0, sizeof(*backend));
#if defined(_WIN32)
    InitializeCriticalSection(&backend->lock);
    InitializeConditionVariable(&backend->condition);
#else
    pthread_mutex_init(&backend->lock, NULL);
    pthread_cond_init(&backend->condition, NULL);
#endif
}

static void destroy(Backend* backend) {
#if defined(_WIN32)
    DeleteCriticalSection(&backend->lock);
#else
    pthread_cond_destroy(&backend->condition);
    pthread_mutex_destroy(&backend->lock);
#endif
}

static int transfer(Backend* backend, int size, int writing) {
    LOCK(&backend->lock);
    CHECK(backend->close_count == 0);
    if (writing) ++backend->writes; else ++backend->reads;
    ++backend->entered;
    WAKE(&backend->condition);
    while (backend->block && !backend->cancelled) WAIT(&backend->condition, &backend->lock);
    /* Keep this call alive after cancellation to verify Shutdown drains it. */
    while (backend->block && !backend->release) WAIT(&backend->condition, &backend->lock);
    int result = backend->cancelled ? TAPTUN_ERROR_CLOSED : size;
    if (writing && backend->finish_write) result = size;
    if (writing && backend->fail_write == backend->writes) result = TAPTUN_ERROR;
    ++backend->exited;
    UNLOCK(&backend->lock);
    return result;
}

static int read_packet(void* context, unsigned char* data, int capacity) {
    (void)data;
    return transfer(context, capacity, 0);
}

static int write_packet(void* context, const unsigned char* data, int size) {
    (void)data;
    return transfer(context, size, 1);
}

static void cancel_backend(void* context) {
    Backend* backend = context;
    LOCK(&backend->lock);
    ++backend->cancel_count;
    backend->cancelled = 1;
    backend->cancel_entered = 1;
    WAKE(&backend->condition);
    while (backend->block_cancel && !backend->release_cancel) WAIT(&backend->condition, &backend->lock);
    UNLOCK(&backend->lock);
}

static void close_backend(void* context) {
    Backend* backend = context;
    LOCK(&backend->lock);
    ++backend->close_count;
    CHECK(backend->cancel_count == 1);
    CHECK(backend->exited == backend->entered);
    UNLOCK(&backend->lock);
}

static void interrupt_read(void* context) { (void)context; }

static TapTunDevice* open_backend(Backend* backend, TapTunMode mode, int emulated) {
    TapTunCallbackOptions options = {0};
    options.context = backend;
    options.read = read_packet;
    options.write = write_packet;
    options.cancel = cancel_backend;
    options.close = close_backend;
    options.mode = mode;
    options.backend_mode = emulated ? TAPTUN_MODE_TUN : mode;
    options.interrupt_read = interrupt_read;
    backend->device = TapTun_OpenFromCallbacks(&options);
    CHECK(backend->device != NULL);
    return backend->device;
}

static void test_lengths(TapTunMode mode, int emulated) {
    Backend backend;
    initialize(&backend);
    TapTunDevice* device = open_backend(&backend, mode, emulated);
    if (!device) { destroy(&backend); return; }
    unsigned char data[65550] = {0};
    data[12] = 0x08;
    data[14] = 0x45;
    uint32_t maximum = mode == TAPTUN_MODE_TAP ? 65549u : 65535u;
    TapTunBuffer packets[2] = { { data, 0, emulated ? 34u : 1u }, { data, 0, maximum + 1 } };
    CHECK(TapTun_WriteBatch(device, packets, 2) == TAPTUN_ERROR_INVALID_ARGUMENT);
    CHECK(backend.writes == 0);
    packets[1].size = 0;
    CHECK(TapTun_WriteBatch(device, packets, 2) == TAPTUN_ERROR_INVALID_ARGUMENT);
    packets[1].size = 1;
    packets[1].data = NULL;
    CHECK(TapTun_WriteBatch(device, packets, 2) == TAPTUN_ERROR_INVALID_ARGUMENT);
    CHECK(backend.writes == 0);
    CHECK(TapTun_Write(device, data, (int)maximum + 1) == TAPTUN_ERROR_INVALID_ARGUMENT);
    packets[1].data = data;
    packets[1].size = maximum;
    CHECK(TapTun_WriteBatch(device, packets, 2) == 2);
    CHECK(backend.writes == 2);
    backend.fail_write = 4;
    CHECK(TapTun_WriteBatch(device, packets, 2) == 1);
    TapTun_Close(device);
    destroy(&backend);
}

static THREAD_RESULT io_thread(void* argument) {
    Backend* backend = argument;
    unsigned char data[34] = {0x45};
    data[12] = 0x08;
    data[14] = 0x45;
    uint32_t size = TapTun_GetMode(backend->device) == TAPTUN_MODE_TAP ? 34u : 20u;
    TapTunBuffer packets[2] = { { data, 0, size }, { data, 0, size } };
    backend->result = backend->batch ? TapTun_WriteBatch(backend->device, packets, 2)
        : TapTun_Read(backend->device, data, sizeof(data));
    return 0;
}

static THREAD_RESULT shutdown_thread(void* argument) {
    Backend* backend = argument;
    CHECK(TapTun_Shutdown(backend->device) == TAPTUN_OK);
    return 0;
}

static Thread start_thread(THREAD_RESULT (*function)(void*), void* argument) {
    Thread thread;
#if defined(_WIN32)
    thread = CreateThread(NULL, 0, function, argument, 0, NULL);
    if (!thread) abort();
#else
    if (pthread_create(&thread, NULL, function, argument) != 0) abort();
#endif
    return thread;
}

static void join_thread(Thread thread) {
#if defined(_WIN32)
    CHECK(WaitForSingleObject(thread, 10000) == WAIT_OBJECT_0);
    CloseHandle(thread);
#else
    pthread_join(thread, NULL);
#endif
}

static void test_shutdown(int batch, int finish_write, int emulated) {
    Backend backend;
    initialize(&backend);
    backend.block = 1;
    backend.block_cancel = 1;
    backend.batch = batch;
    backend.finish_write = finish_write;
    if (!open_backend(&backend, emulated ? TAPTUN_MODE_TAP : TAPTUN_MODE_TUN, emulated)) {
        destroy(&backend);
        return;
    }
    Thread worker = start_thread(io_thread, &backend);
    LOCK(&backend.lock);
    while (!backend.entered) WAIT(&backend.condition, &backend.lock);
    UNLOCK(&backend.lock);
    Thread shutdown = start_thread(shutdown_thread, &backend);
    LOCK(&backend.lock);
    while (!backend.cancel_entered) WAIT(&backend.condition, &backend.lock);
    CHECK(backend.close_count == 0);
    UNLOCK(&backend.lock);
    unsigned char data = 0;
    CHECK(TapTun_Write(backend.device, &data, 1) == TAPTUN_ERROR_CLOSED);
    CHECK(TapTun_Read(backend.device, &data, 1) == TAPTUN_ERROR_CLOSED);
    Thread second_shutdown = start_thread(shutdown_thread, &backend);
    LOCK(&backend.lock);
    backend.release = 1;
    backend.release_cancel = 1;
    WAKE(&backend.condition);
    UNLOCK(&backend.lock);
    join_thread(worker);
    join_thread(shutdown);
    join_thread(second_shutdown);
    CHECK(backend.result == (finish_write ? 1 : TAPTUN_ERROR_CLOSED));
    CHECK(backend.writes == (batch ? 1 : 0));
    CHECK(backend.cancel_count == 1 && backend.close_count == 0);
    TapTunPacket lease = {0};
    CHECK(TapTun_AcquireSend(backend.device, 20, &lease) == TAPTUN_ERROR_CLOSED);
    CHECK(TapTun_AcquireReceive(backend.device, &lease) == TAPTUN_ERROR_CLOSED);
    CHECK(TapTun_CommitSend(backend.device, &lease) == TAPTUN_ERROR_CLOSED);
    CHECK(TapTun_Shutdown(backend.device) == TAPTUN_OK);
    TapTun_Close(backend.device);
    CHECK(backend.close_count == 1);
    destroy(&backend);
}

static void test_cancel_required(void) {
    TapTunCallbackOptions options = {0};
    options.read = read_packet;
    options.write = write_packet;
    options.close = close_backend;
    TapTunDevice* device = TapTun_OpenFromCallbacks(&options);
    CHECK(device == NULL);
}
int main(void) {
    test_lengths(TAPTUN_MODE_TUN, 0);
    test_lengths(TAPTUN_MODE_TAP, 0);
    test_lengths(TAPTUN_MODE_TAP, 1);
    test_cancel_required();
    for (int round = 0; round < 50; ++round) {
        test_shutdown(0, 0, 0);
        test_shutdown(1, 0, 0);
        test_shutdown(1, 1, 0);
        test_shutdown(1, 0, 1);
        test_shutdown(1, 1, 1);
    }
    printf("lifecycle: %d failures\n", failures);
    return failures != 0;
}
