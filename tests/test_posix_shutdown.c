#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static pthread_mutex_t test_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t test_condition = PTHREAD_COND_INITIALIZER;
static int observed_wait, observed_fd;
static int failures;
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "%d: %s\n", __LINE__, #expr); ++failures; } } while (0)

static int observed_poll(struct pollfd* descriptors, nfds_t count, int timeout) {
    if (count >= 2 && descriptors[0].fd == observed_fd) {
        pthread_mutex_lock(&test_lock);
        observed_wait = 1;
        pthread_cond_broadcast(&test_condition);
        pthread_mutex_unlock(&test_lock);
    }
    return poll(descriptors, count, timeout);
}

#define poll observed_poll
#if defined(TAPTUN_TEST_LINUX)
#include "../src/taptun_linux.c"
#else
#include "../src/taptun_posix.c"
#endif
#undef poll

typedef struct { TapTunDevice* device; int writing, result; } Operation;
static void* run_operation(void* argument) {
    Operation* operation = argument;
    unsigned char packet[20] = {0x45};
    operation->result = operation->writing ? TapTun_Write(operation->device, packet, sizeof(packet))
        : TapTun_Read(operation->device, packet, sizeof(packet));
    return NULL;
}

static void test_native(int writing, int ownership) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0) abort();
    TapTunHandleOptions options = {0};
    options.handle = sockets[0];
    options.take_ownership = ownership;
    int flags = fcntl(sockets[0], F_GETFL);
    errno = 0;
    CHECK(TapTun_OpenFromHandle(&options) == NULL && errno == EINVAL);
    CHECK(fcntl(sockets[0], F_GETFL) == flags);
    if (fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK) < 0) abort();
    flags = fcntl(sockets[0], F_GETFL);
    TapTunDevice* device = TapTun_OpenFromHandle(&options);
    if (!device) abort();
    if (writing) {
        unsigned char packet[20] = {0x45};
        while (write(sockets[0], packet, sizeof(packet)) == (ssize_t)sizeof(packet)) {}
        CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
    }
    Operation operation = { device, writing, 0 };
    observed_wait = 0;
    observed_fd = sockets[0];
    pthread_t worker;
    if (pthread_create(&worker, NULL, run_operation, &operation) != 0) abort();
    pthread_mutex_lock(&test_lock);
    while (!observed_wait) pthread_cond_wait(&test_condition, &test_lock);
    pthread_mutex_unlock(&test_lock);
    CHECK(TapTun_Shutdown(device) == TAPTUN_OK);
    pthread_join(worker, NULL);
    CHECK(operation.result == TAPTUN_ERROR_CLOSED);
    CHECK(fcntl(sockets[0], F_GETFL) == flags);
    unsigned char packet = 0;
    CHECK(TapTun_Write(device, &packet, 1) == TAPTUN_ERROR_CLOSED);
    TapTun_Close(device);
    if (ownership) CHECK(fcntl(sockets[0], F_GETFL) == -1 && errno == EBADF);
    else { CHECK(fcntl(sockets[0], F_GETFL) == flags); close(sockets[0]); }
    close(sockets[1]);
}

int main(void) {
    alarm(20);
    for (int ownership = 0; ownership < 2; ++ownership) {
        test_native(0, ownership);
        test_native(1, ownership);
    }
    printf("POSIX native shutdown: %d failures\n", failures);
    return failures != 0;
}
