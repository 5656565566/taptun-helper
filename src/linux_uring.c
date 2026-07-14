#include "linux_uring.h"

#include <errno.h>
#include <limits.h>
#include <linux/io_uring.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

typedef enum {
    TAPTUN_SEND_SLOT_FREE = 0,
    TAPTUN_SEND_SLOT_ACQUIRED = 1,
    TAPTUN_SEND_SLOT_IN_FLIGHT = 2
} TapTunSendSlotState;

typedef struct {
    unsigned char* data;
    uint32_t expected_size;
    TapTunSendSlotState state;
} TapTunSendSlot;

struct TapTunLinuxUring {
    int fd;
    void* sq_ring_mapping;
    size_t sq_ring_mapping_size;
    void* cq_ring_mapping;
    size_t cq_ring_mapping_size;
    struct io_uring_sqe* sqes;
    size_t sqes_mapping_size;

    unsigned int* sq_head;
    unsigned int* sq_tail;
    unsigned int* sq_ring_mask;
    unsigned int* sq_ring_entries;
    unsigned int* sq_array;
    unsigned int* cq_head;
    unsigned int* cq_tail;
    unsigned int* cq_ring_mask;
    struct io_uring_cqe* cqes;

    TapTunSendSlot* slots;
    struct iovec* buffers;
    unsigned char* buffer_storage;
    uint32_t slot_count;
    uint32_t packet_capacity;
    uint32_t packet_prefix_size;
    uint32_t queue_count;
    uint32_t acquired_index;
    uint32_t in_flight;
    int registered_files;
    int registered_buffers;
    int completion_error;
    int fatal_error;
};

static int ring_setup(unsigned int entries, struct io_uring_params* parameters) {
#if defined(__NR_io_uring_setup)
    return (int)syscall(__NR_io_uring_setup, entries, parameters);
#else
    (void)entries;
    (void)parameters;
    errno = ENOSYS;
    return -1;
#endif
}

static int ring_enter(int fd, unsigned int submit_count, unsigned int minimum_complete) {
#if defined(__NR_io_uring_enter)
    unsigned int flags = minimum_complete != 0 ? IORING_ENTER_GETEVENTS : 0;
    return (int)syscall(
        __NR_io_uring_enter,
        fd,
        submit_count,
        minimum_complete,
        flags,
        NULL,
        0u);
#else
    (void)fd;
    (void)submit_count;
    (void)minimum_complete;
    errno = ENOSYS;
    return -1;
#endif
}

static int ring_register(int fd, unsigned int opcode, const void* argument, unsigned int count) {
#if defined(__NR_io_uring_register)
    return (int)syscall(__NR_io_uring_register, fd, opcode, argument, count);
#else
    (void)fd;
    (void)opcode;
    (void)argument;
    (void)count;
    errno = ENOSYS;
    return -1;
#endif
}

static unsigned int load_acquire(const unsigned int* value) {
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

static void store_release(unsigned int* destination, unsigned int value) {
    __atomic_store_n(destination, value, __ATOMIC_RELEASE);
}

static void record_completion_error(TapTunLinuxUring* ring, int result) {
    if (ring->completion_error != 0) return;
    ring->completion_error = result < 0 ? -result : EIO;
}

static uint32_t reap_completions(TapTunLinuxUring* ring) {
    if (!ring->cq_head || !ring->cq_tail || !ring->cq_ring_mask || !ring->cqes) return 0;
    unsigned int head = *ring->cq_head;
    unsigned int tail = load_acquire(ring->cq_tail);
    uint32_t reaped = 0;
    while (head != tail) {
        struct io_uring_cqe* completion = &ring->cqes[head & *ring->cq_ring_mask];
        uint64_t identity = completion->user_data;
        if (identity == 0 || identity > ring->slot_count) {
            record_completion_error(ring, -EIO);
        } else {
            TapTunSendSlot* slot = &ring->slots[identity - 1];
            if (slot->state != TAPTUN_SEND_SLOT_IN_FLIGHT) {
                record_completion_error(ring, -EIO);
            } else {
                if (completion->res !=
                    (int)(slot->expected_size + ring->packet_prefix_size)) {
                    record_completion_error(ring, completion->res);
                }
                slot->expected_size = 0;
                slot->state = TAPTUN_SEND_SLOT_FREE;
                if (ring->in_flight != 0) --ring->in_flight;
            }
        }
        ++head;
        ++reaped;
    }
    if (reaped != 0) store_release(ring->cq_head, head);
    return reaped;
}

static int wait_for_completions(TapTunLinuxUring* ring) {
    if (!ring->cq_head || !ring->cq_tail || !ring->cq_ring_mask || !ring->cqes) {
        return ring->in_flight == 0 ? TAPTUN_OK : TAPTUN_ERROR;
    }
    while (ring->in_flight != 0) {
        if (reap_completions(ring) != 0) continue;
        int result;
        do {
            result = ring_enter(ring->fd, 0, 1);
        } while (result < 0 && errno == EINTR);
        if (result < 0) return TAPTUN_ERROR;
    }
    reap_completions(ring);
    return TAPTUN_OK;
}

static void destroy_ring_resources(TapTunLinuxUring* ring) {
    if (!ring) return;
    if (ring->fd >= 0) {
        int completed = ring->fatal_error == 0 && wait_for_completions(ring) == TAPTUN_OK;
        if (completed) {
            if (ring->registered_buffers) {
                (void)ring_register(ring->fd, IORING_UNREGISTER_BUFFERS, NULL, 0);
            }
            if (ring->registered_files) {
                (void)ring_register(ring->fd, IORING_UNREGISTER_FILES, NULL, 0);
            }
        } else {
            // Closing the ring synchronously cancels or completes requests
            // before their registered storage is released below.
            close(ring->fd);
            ring->fd = -1;
        }
    }
    if (ring->sqes && ring->sqes != MAP_FAILED) {
        munmap(ring->sqes, ring->sqes_mapping_size);
    }
    if (ring->cq_ring_mapping && ring->cq_ring_mapping != MAP_FAILED &&
        ring->cq_ring_mapping != ring->sq_ring_mapping) {
        munmap(ring->cq_ring_mapping, ring->cq_ring_mapping_size);
    }
    if (ring->sq_ring_mapping && ring->sq_ring_mapping != MAP_FAILED) {
        munmap(ring->sq_ring_mapping, ring->sq_ring_mapping_size);
    }
    if (ring->fd >= 0) close(ring->fd);
    free(ring->buffer_storage);
    free(ring->buffers);
    free(ring->slots);
    free(ring);
}

TapTunLinuxUring* taptun_linux_uring_create(
    const int* queue_fds,
    uint32_t queue_count,
    uint32_t queue_depth,
    uint32_t packet_capacity,
    uint32_t packet_prefix_size) {
    if (!queue_fds || queue_count == 0 || queue_depth < 2 || packet_capacity == 0 ||
        packet_prefix_size > UINT32_MAX - packet_capacity) {
        errno = EINVAL;
        return NULL;
    }

    TapTunLinuxUring* ring = (TapTunLinuxUring*)calloc(1, sizeof(TapTunLinuxUring));
    if (!ring) return NULL;
    ring->fd = -1;
    ring->acquired_index = UINT32_MAX;
    ring->slot_count = queue_depth;
    ring->packet_capacity = packet_capacity;
    ring->packet_prefix_size = packet_prefix_size;
    ring->queue_count = queue_count;

    struct io_uring_params parameters;
    memset(&parameters, 0, sizeof(parameters));
    ring->fd = ring_setup(queue_depth, &parameters);
    if (ring->fd < 0) {
        destroy_ring_resources(ring);
        return NULL;
    }

    size_t sq_ring_size = parameters.sq_off.array +
        parameters.sq_entries * sizeof(unsigned int);
    size_t cq_ring_size = parameters.cq_off.cqes +
        parameters.cq_entries * sizeof(struct io_uring_cqe);
    if ((parameters.features & IORING_FEAT_SINGLE_MMAP) != 0) {
        size_t shared_size = sq_ring_size > cq_ring_size ? sq_ring_size : cq_ring_size;
        sq_ring_size = shared_size;
        cq_ring_size = shared_size;
    }

    ring->sq_ring_mapping_size = sq_ring_size;
    ring->sq_ring_mapping = mmap(
        NULL,
        sq_ring_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_POPULATE,
        ring->fd,
        IORING_OFF_SQ_RING);
    if (ring->sq_ring_mapping == MAP_FAILED) {
        destroy_ring_resources(ring);
        return NULL;
    }

    ring->cq_ring_mapping_size = cq_ring_size;
    if ((parameters.features & IORING_FEAT_SINGLE_MMAP) != 0) {
        ring->cq_ring_mapping = ring->sq_ring_mapping;
    } else {
        ring->cq_ring_mapping = mmap(
            NULL,
            cq_ring_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            ring->fd,
            IORING_OFF_CQ_RING);
        if (ring->cq_ring_mapping == MAP_FAILED) {
            destroy_ring_resources(ring);
            return NULL;
        }
    }

    ring->sqes_mapping_size = parameters.sq_entries * sizeof(struct io_uring_sqe);
    ring->sqes = (struct io_uring_sqe*)mmap(
        NULL,
        ring->sqes_mapping_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_POPULATE,
        ring->fd,
        IORING_OFF_SQES);
    if (ring->sqes == MAP_FAILED) {
        destroy_ring_resources(ring);
        return NULL;
    }

    unsigned char* sq_base = (unsigned char*)ring->sq_ring_mapping;
    unsigned char* cq_base = (unsigned char*)ring->cq_ring_mapping;
    ring->sq_head = (unsigned int*)(sq_base + parameters.sq_off.head);
    ring->sq_tail = (unsigned int*)(sq_base + parameters.sq_off.tail);
    ring->sq_ring_mask = (unsigned int*)(sq_base + parameters.sq_off.ring_mask);
    ring->sq_ring_entries = (unsigned int*)(sq_base + parameters.sq_off.ring_entries);
    ring->sq_array = (unsigned int*)(sq_base + parameters.sq_off.array);
    ring->cq_head = (unsigned int*)(cq_base + parameters.cq_off.head);
    ring->cq_tail = (unsigned int*)(cq_base + parameters.cq_off.tail);
    ring->cq_ring_mask = (unsigned int*)(cq_base + parameters.cq_off.ring_mask);
    ring->cqes = (struct io_uring_cqe*)(cq_base + parameters.cq_off.cqes);

    if (queue_depth > *ring->sq_ring_entries) {
        errno = EOVERFLOW;
        destroy_ring_resources(ring);
        return NULL;
    }

    ring->slots = (TapTunSendSlot*)calloc(queue_depth, sizeof(TapTunSendSlot));
    ring->buffers = (struct iovec*)calloc(queue_depth, sizeof(struct iovec));
    size_t registered_capacity = (size_t)packet_capacity + packet_prefix_size;
    size_t stride = (registered_capacity + 63u) & ~(size_t)63u;
    if (stride == 0 || queue_depth > SIZE_MAX / stride ||
        !ring->slots || !ring->buffers) {
        errno = ENOMEM;
        destroy_ring_resources(ring);
        return NULL;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    if (posix_memalign(
            (void**)&ring->buffer_storage,
            (size_t)page_size,
            stride * queue_depth) != 0) {
        errno = ENOMEM;
        destroy_ring_resources(ring);
        return NULL;
    }
    for (uint32_t index = 0; index < queue_depth; ++index) {
        ring->slots[index].data = ring->buffer_storage + stride * index;
        ring->buffers[index].iov_base = ring->slots[index].data;
        ring->buffers[index].iov_len = registered_capacity;
    }

    if (ring_register(ring->fd, IORING_REGISTER_FILES, queue_fds, queue_count) != 0) {
        destroy_ring_resources(ring);
        return NULL;
    }
    ring->registered_files = 1;
    if (ring_register(ring->fd, IORING_REGISTER_BUFFERS, ring->buffers, queue_depth) != 0) {
        destroy_ring_resources(ring);
        return NULL;
    }
    ring->registered_buffers = 1;
    return ring;
}

int taptun_linux_uring_acquire(
    TapTunLinuxUring* ring,
    uint32_t packet_size,
    TapTunPacket* packet) {
    if (!ring || !packet || packet_size == 0 || packet_size > ring->packet_capacity) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    if (ring->fatal_error != 0) {
        errno = ring->fatal_error;
        return TAPTUN_ERROR;
    }
    if (ring->acquired_index != UINT32_MAX) return TAPTUN_ERROR_BUSY;

    for (;;) {
        reap_completions(ring);
        if (ring->completion_error != 0) {
            errno = ring->completion_error;
            ring->completion_error = 0;
            return TAPTUN_ERROR;
        }
        for (uint32_t index = 0; index < ring->slot_count; ++index) {
            TapTunSendSlot* slot = &ring->slots[index];
            if (slot->state != TAPTUN_SEND_SLOT_FREE) continue;
            slot->state = TAPTUN_SEND_SLOT_ACQUIRED;
            slot->expected_size = packet_size;
            ring->acquired_index = index;
            if (ring->packet_prefix_size != 0) {
                memset(slot->data, 0, ring->packet_prefix_size);
            }
            packet->data = slot->data + ring->packet_prefix_size;
            packet->size = packet_size;
            packet->backend_token = slot;
            return TAPTUN_OK;
        }
        if (ring->in_flight == 0) return TAPTUN_ERROR_BUSY;

        // Backpressure waits for one CQE instead of forcing callers to spin
        // when every registered buffer is owned by the kernel.
        int result;
        do {
            result = ring_enter(ring->fd, 0, 1);
        } while (result < 0 && errno == EINTR);
        if (result < 0) return TAPTUN_ERROR;
    }
}

int taptun_linux_uring_validate_acquired(
    const TapTunLinuxUring* ring,
    const TapTunPacket* packet) {
    if (!ring || !packet || ring->acquired_index == UINT32_MAX) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    const TapTunSendSlot* slot = &ring->slots[ring->acquired_index];
    return slot->state == TAPTUN_SEND_SLOT_ACQUIRED &&
        packet->backend_token == slot &&
        packet->data == slot->data + ring->packet_prefix_size &&
        packet->size == slot->expected_size
        ? TAPTUN_OK
        : TAPTUN_ERROR_INVALID_ARGUMENT;
}

int taptun_linux_uring_commit(
    TapTunLinuxUring* ring,
    uint32_t queue_index,
    TapTunPacket* packet) {
    if (!ring || !packet || queue_index >= ring->queue_count ||
        ring->acquired_index == UINT32_MAX) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    if (taptun_linux_uring_validate_acquired(ring, packet) != TAPTUN_OK) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    TapTunSendSlot* slot = &ring->slots[ring->acquired_index];

    unsigned int head = load_acquire(ring->sq_head);
    unsigned int tail = *ring->sq_tail;
    if (tail - head >= *ring->sq_ring_entries) return TAPTUN_ERROR_BUSY;

    unsigned int sqe_index = tail & *ring->sq_ring_mask;
    struct io_uring_sqe* submission = &ring->sqes[sqe_index];
    memset(submission, 0, sizeof(*submission));
    submission->opcode = IORING_OP_WRITE_FIXED;
    submission->flags = IOSQE_FIXED_FILE;
    submission->fd = (int)queue_index;
    submission->off = (uint64_t)-1;
    submission->addr = (uint64_t)(uintptr_t)slot->data;
    submission->len = slot->expected_size + ring->packet_prefix_size;
    submission->buf_index = (uint16_t)ring->acquired_index;
    submission->user_data = (uint64_t)ring->acquired_index + 1u;
    ring->sq_array[sqe_index] = sqe_index;
    store_release(ring->sq_tail, tail + 1);

    slot->state = TAPTUN_SEND_SLOT_IN_FLIGHT;
    ++ring->in_flight;
    ring->acquired_index = UINT32_MAX;
    packet->data = NULL;
    packet->size = 0;
    packet->backend_token = NULL;

    int result;
    do {
        result = ring_enter(ring->fd, 1, 0);
    } while (result < 0 && errno == EINTR);
    if (result <= 0) {
        ring->fatal_error = result < 0 ? errno : EIO;
        errno = ring->fatal_error;
        return TAPTUN_ERROR;
    }
    return TAPTUN_OK;
}

void taptun_linux_uring_cancel_acquired(TapTunLinuxUring* ring) {
    if (!ring || ring->acquired_index == UINT32_MAX) return;
    TapTunSendSlot* slot = &ring->slots[ring->acquired_index];
    slot->expected_size = 0;
    slot->state = TAPTUN_SEND_SLOT_FREE;
    ring->acquired_index = UINT32_MAX;
}

void taptun_linux_uring_destroy(TapTunLinuxUring* ring) {
    if (!ring) return;
    taptun_linux_uring_cancel_acquired(ring);
    destroy_ring_resources(ring);
}
