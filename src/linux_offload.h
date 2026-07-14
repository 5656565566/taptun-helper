#ifndef TAPTUN_LINUX_OFFLOAD_H
#define TAPTUN_LINUX_OFFLOAD_H

#include "taptun_api.h"

#include <linux/virtio_net.h>
#include <stdint.h>

enum {
    TAPTUN_LINUX_OFFLOAD_NORMAL = 0,
    TAPTUN_LINUX_OFFLOAD_GSO = 1
};

typedef struct {
    const unsigned char* packet;
    uint32_t packet_size;
    uint32_t next_payload_offset;
    uint32_t segment_index;
    uint16_t header_size;
    uint16_t segment_size;
    uint16_t checksum_start;
    uint16_t checksum_offset;
    uint8_t gso_type;
} TapTunLinuxGsoCursor;

/** Decodes a virtio-net header and prepares either a normal packet or GSO cursor. */
int taptun_linux_offload_prepare_read(
    unsigned char* input,
    uint32_t input_size,
    TapTunLinuxGsoCursor* cursor,
    unsigned char** normal_packet,
    uint32_t* normal_size);

/** Emits the next ordinary packet from a prepared GSO cursor. */
int taptun_linux_gso_next(
    TapTunLinuxGsoCursor* cursor,
    unsigned char* output,
    uint32_t output_capacity);

/**
 * Coalesces the compatible TCP prefix of a batch into output, including its
 * virtio-net header. Zero means the first packet cannot be coalesced.
 */
int taptun_linux_gro_coalesce(
    const TapTunBuffer* buffers,
    uint32_t buffer_count,
    unsigned char* output,
    uint32_t output_capacity,
    uint32_t* consumed_packets);

#endif
