#ifndef TAPTUN_INTERNAL_H
#define TAPTUN_INTERNAL_H

#include "taptun_api.h"
#include "tun2tap.h"
#include <limits.h>

static inline int taptun_valid_packet_size(TapTunMode mode, uint32_t size) {
    return size != 0 && size <= (mode == TAPTUN_MODE_TAP
        ? TAPTUN_MAX_ETHERNET_FRAME_SIZE : TAPTUN_MAX_IP_PACKET_SIZE);
}

static inline int taptun_valid_write_batch(
    TapTunMode mode, const TapTunBuffer* buffers, uint32_t count) {
    if (!buffers || count == 0 || count > INT_MAX) return 0;
    for (uint32_t index = 0; index < count; ++index) {
        if (!buffers[index].data || !taptun_valid_packet_size(mode, buffers[index].size)) return 0;
    }
    return 1;
}

#endif
