#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static long fake_syscall(long number, ...);
#define syscall fake_syscall
#include "../src/linux_uring.c"
#undef syscall

static int failures;
#define CHECK(expr) do { if (!(expr)) { fprintf(stderr, "%d: %s\n", __LINE__, #expr); ++failures; } } while (0)
typedef struct {
    TapTunLinuxUring ring;
    TapTunSendSlot slots[2];
    struct io_uring_sqe sqes[2];
    struct io_uring_cqe cqes[8];
    unsigned int sq_head, sq_tail, sq_mask, sq_entries, sq_array[2];
    unsigned int cq_head, cq_tail, cq_mask;
    unsigned char data[2][64];
    int fail_before, fail_after, cancel_race, cancel_error, cancellations;
} TestRing;
static TestRing* current;

static void complete(uint64_t identity, int result) {
    struct io_uring_cqe* completion = &current->cqes[current->cq_tail++ & current->cq_mask];
    completion->user_data = identity;
    completion->res = result;
}

static long fake_syscall(long number, ...) {
    if (number != __NR_io_uring_enter) { errno = ENOSYS; return -1; }
    va_list arguments;
    va_start(arguments, number);
    (void)va_arg(arguments, int);
    unsigned int submitted = va_arg(arguments, unsigned int);
    (void)va_arg(arguments, unsigned int);
    va_end(arguments);
    if (current->fail_before) { errno = EIO; return -1; }
    if (submitted == 0) { errno = EIO; return -1; }
    while (current->sq_head != current->sq_tail) {
        struct io_uring_sqe* submission = &current->sqes[current->sq_head++ & current->sq_mask];
        if (submission->opcode != IORING_OP_ASYNC_CANCEL) continue;
        ++current->cancellations;
        if (current->cancel_error) complete(UINT64_MAX, -EINVAL);
        else {
            unsigned int index = (unsigned int)submission->addr - 1;
            int result = current->cancel_race ? (int)current->slots[index].expected_size : -ECANCELED;
            complete(submission->addr, result);
            complete(UINT64_MAX, current->cancel_race ? -ENOENT : 0);
        }
    }
    if (current->fail_after) { errno = EIO; return -1; }
    return submitted;
}

static void initialize(TestRing* test) {
    memset(test, 0, sizeof(*test));
    current = test;
    test->sq_mask = 1;
    test->sq_entries = 2;
    test->cq_mask = 7;
    test->ring.sq_head = &test->sq_head;
    test->ring.sq_tail = &test->sq_tail;
    test->ring.sq_ring_mask = &test->sq_mask;
    test->ring.sq_ring_entries = &test->sq_entries;
    test->ring.sq_array = test->sq_array;
    test->ring.cq_head = &test->cq_head;
    test->ring.cq_tail = &test->cq_tail;
    test->ring.cq_ring_mask = &test->cq_mask;
    test->ring.cqes = test->cqes;
    test->ring.sqes = test->sqes;
    test->ring.slots = test->slots;
    test->ring.slot_count = 2;
    test->ring.queue_count = 1;
    test->ring.packet_capacity = 64;
    test->ring.acquired_index = UINT32_MAX;
    for (unsigned int index = 0; index < 2; ++index) test->slots[index].data = test->data[index];
}

static void submit_packet(TestRing* test, int expected) {
    TapTunPacket packet = {0};
    CHECK(taptun_linux_uring_acquire(&test->ring, 20, &packet, -1) == TAPTUN_OK);
    CHECK(taptun_linux_uring_commit(&test->ring, 0, &packet) == expected);
    CHECK(packet.data == NULL && packet.backend_token == NULL);
}

static void test_submit_error(int consumed) {
    TestRing test;
    initialize(&test);
    test.fail_before = !consumed;
    test.fail_after = consumed;
    submit_packet(&test, TAPTUN_ERROR);
    CHECK(test.ring.in_flight == (unsigned int)consumed);
    CHECK(test.sq_head == test.sq_tail);
    test.fail_before = test.fail_after = 0;
    CHECK(taptun_linux_uring_shutdown(&test.ring) == TAPTUN_ERROR && errno == EIO);
    CHECK(test.ring.in_flight == 0 && test.ring.cancel_in_flight == 0);
    CHECK(test.cancellations == consumed);
}

static void test_cancel(int completion_race) {
    TestRing test;
    initialize(&test);
    submit_packet(&test, TAPTUN_OK);
    test.cancel_race = completion_race;
    TapTunPacket uncommitted = {0};
    CHECK(taptun_linux_uring_acquire(&test.ring, 20, &uncommitted, -1) == TAPTUN_OK);
    uncommitted.data[0] = 0x45;
    CHECK(taptun_linux_uring_shutdown(&test.ring) == TAPTUN_OK);
    CHECK(test.ring.in_flight == 0 && test.ring.cancel_in_flight == 0);
    CHECK(test.cancellations == 1);
    CHECK(uncommitted.data[0] == 0x45);
    CHECK(taptun_linux_uring_validate_acquired(&test.ring, &uncommitted) == TAPTUN_OK);
}

static void test_full_queue(void) {
    TestRing test;
    initialize(&test);
    int stop[2], completion[2];
    if (pipe(stop) != 0 || pipe(completion) != 0) abort();
    test.ring.fd = completion[0];
    submit_packet(&test, TAPTUN_OK);
    submit_packet(&test, TAPTUN_OK);
    taptun_signal(stop[1]);
    TapTunPacket packet = {0};
    CHECK(taptun_linux_uring_acquire(&test.ring, 20, &packet, stop[0]) == TAPTUN_ERROR_CLOSED);
    CHECK(taptun_linux_uring_shutdown(&test.ring) == TAPTUN_OK);
    CHECK(test.cancellations == 2 && test.ring.in_flight == 0);
    close(stop[0]); close(stop[1]); close(completion[0]); close(completion[1]);
}

static void test_failed_cancel(void) {
    TestRing test;
    initialize(&test);
    submit_packet(&test, TAPTUN_OK);
    test.cancel_error = 1;
    CHECK(taptun_linux_uring_shutdown(&test.ring) == TAPTUN_ERROR && errno == EINVAL);
    CHECK(test.ring.fatal_error == EINVAL && test.ring.in_flight == 1);
}

int main(void) {
    alarm(20);
    test_submit_error(0);
    test_submit_error(1);
    test_cancel(0);
    test_cancel(1);
    test_full_queue();
    test_failed_cancel();
    printf("io_uring shutdown: %d failures\n", failures);
    return failures != 0;
}
