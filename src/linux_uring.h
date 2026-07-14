#ifndef TAPTUN_LINUX_URING_H
#define TAPTUN_LINUX_URING_H

#include "taptun_api.h"

#include <stdint.h>

typedef struct TapTunLinuxUring TapTunLinuxUring;

TapTunLinuxUring* taptun_linux_uring_create(
    const int* queue_fds,
    uint32_t queue_count,
    uint32_t queue_depth,
    uint32_t packet_capacity,
    uint32_t packet_prefix_size);

int taptun_linux_uring_acquire(
    TapTunLinuxUring* ring,
    uint32_t packet_size,
    TapTunPacket* packet);

int taptun_linux_uring_validate_acquired(
    const TapTunLinuxUring* ring,
    const TapTunPacket* packet);

int taptun_linux_uring_commit(
    TapTunLinuxUring* ring,
    uint32_t queue_index,
    TapTunPacket* packet);

void taptun_linux_uring_cancel_acquired(TapTunLinuxUring* ring);
void taptun_linux_uring_destroy(TapTunLinuxUring* ring);

#endif
