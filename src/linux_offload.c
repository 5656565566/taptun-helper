#include "linux_offload.h"

#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <string.h>

#define TAPTUN_TCP_MIN_HEADER_SIZE 20u
#define TAPTUN_TCP_FLAGS_OFFSET 13u
#define TAPTUN_TCP_FLAG_FIN 0x01u
#define TAPTUN_TCP_FLAG_PSH 0x08u
#define TAPTUN_TCP_FLAG_ACK 0x10u
#define TAPTUN_IPV4_MORE_FRAGMENTS 0x2000u
#define TAPTUN_IPV4_FRAGMENT_OFFSET 0x1fffu

_Static_assert(sizeof(struct virtio_net_hdr) == 10, "Unexpected virtio_net_hdr ABI");

typedef struct {
    const unsigned char* packet;
    uint32_t packet_size;
    uint16_t ip_header_size;
    uint16_t tcp_header_size;
    uint16_t payload_size;
    uint16_t ip_id;
    uint32_t sequence;
    uint32_t acknowledgement;
    uint8_t version;
    uint8_t flags;
} TapTunTcpPacket;

static uint16_t read_be16(const unsigned char* data) {
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static uint32_t read_be32(const unsigned char* data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
        ((uint32_t)data[2] << 8) | data[3];
}

static void write_be16(unsigned char* data, uint16_t value) {
    data[0] = (unsigned char)(value >> 8);
    data[1] = (unsigned char)value;
}

static void write_be32(unsigned char* data, uint32_t value) {
    data[0] = (unsigned char)(value >> 24);
    data[1] = (unsigned char)(value >> 16);
    data[2] = (unsigned char)(value >> 8);
    data[3] = (unsigned char)value;
}

static uint64_t checksum_add(uint64_t sum, const unsigned char* data, uint32_t size) {
    while (size >= 2) {
        sum += read_be16(data);
        data += 2;
        size -= 2;
    }
    if (size != 0) sum += (uint16_t)data[0] << 8;
    return sum;
}

static uint16_t checksum_fold(uint64_t sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)sum;
}

static uint16_t checksum_finish(uint64_t sum) {
    return (uint16_t)~checksum_fold(sum);
}

static uint64_t tcp_pseudo_header_sum(
    const unsigned char* packet,
    uint8_t version,
    uint16_t tcp_size) {
    uint64_t sum = 0;
    if (version == 4) {
        sum = checksum_add(sum, packet + 12, 8);
        sum += IPPROTO_TCP;
        sum += tcp_size;
    } else {
        sum = checksum_add(sum, packet + 8, 32);
        sum += tcp_size;
        sum += IPPROTO_TCP;
    }
    return sum;
}

static uint16_t ipv4_checksum(const unsigned char* packet, uint16_t header_size) {
    return checksum_finish(checksum_add(0, packet, header_size));
}

static int tcp_checksum_is_valid(const TapTunTcpPacket* parsed) {
    uint16_t tcp_size = (uint16_t)(parsed->packet_size - parsed->ip_header_size);
    uint64_t sum = tcp_pseudo_header_sum(parsed->packet, parsed->version, tcp_size);
    sum = checksum_add(sum, parsed->packet + parsed->ip_header_size, tcp_size);
    return checksum_fold(sum) == 0xffffu;
}

static void write_tcp_checksum(
    unsigned char* packet,
    uint8_t version,
    uint16_t ip_header_size,
    uint16_t packet_size) {
    uint16_t tcp_size = (uint16_t)(packet_size - ip_header_size);
    unsigned char* checksum = packet + ip_header_size + 16;
    checksum[0] = 0;
    checksum[1] = 0;
    uint64_t sum = tcp_pseudo_header_sum(packet, version, tcp_size);
    sum = checksum_add(sum, packet + ip_header_size, tcp_size);
    write_be16(checksum, checksum_finish(sum));
}

static int complete_partial_checksum(
    unsigned char* packet,
    uint32_t packet_size,
    uint16_t checksum_start,
    uint16_t checksum_offset) {
    uint32_t checksum_at = (uint32_t)checksum_start + checksum_offset;
    if (checksum_start >= packet_size || checksum_at + 2 > packet_size) {
        errno = EPROTO;
        return TAPTUN_ERROR;
    }
    uint16_t initial = read_be16(packet + checksum_at);
    packet[checksum_at] = 0;
    packet[checksum_at + 1] = 0;
    uint64_t sum = checksum_add(initial, packet + checksum_start, packet_size - checksum_start);
    write_be16(packet + checksum_at, checksum_finish(sum));
    return TAPTUN_OK;
}

static int parse_tcp_packet(
    const unsigned char* packet,
    uint32_t packet_size,
    int validate_lengths,
    TapTunTcpPacket* parsed) {
    if (!packet || !parsed || packet_size < 20 || packet_size > UINT16_MAX) return 0;
    memset(parsed, 0, sizeof(*parsed));
    parsed->packet = packet;
    parsed->packet_size = packet_size;
    parsed->version = packet[0] >> 4;

    if (parsed->version == 4) {
        parsed->ip_header_size = (uint16_t)(packet[0] & 0x0fu) * 4u;
        if (parsed->ip_header_size < 20 ||
            packet_size < (uint32_t)parsed->ip_header_size + 20u ||
            packet[9] != IPPROTO_TCP) {
            return 0;
        }
        uint16_t fragments = read_be16(packet + 6);
        if ((fragments & (TAPTUN_IPV4_MORE_FRAGMENTS | TAPTUN_IPV4_FRAGMENT_OFFSET)) != 0) {
            return 0;
        }
        if (validate_lengths &&
            (read_be16(packet + 2) != packet_size ||
             checksum_fold(checksum_add(0, packet, parsed->ip_header_size)) != 0xffffu)) {
            return 0;
        }
        parsed->ip_id = read_be16(packet + 4);
    } else if (parsed->version == 6) {
        parsed->ip_header_size = 40;
        if (packet_size < 60 || packet[6] != IPPROTO_TCP) return 0;
        if (validate_lengths && (uint32_t)read_be16(packet + 4) + 40u != packet_size) return 0;
    } else {
        return 0;
    }

    const unsigned char* tcp = packet + parsed->ip_header_size;
    parsed->tcp_header_size = (uint16_t)(tcp[12] >> 4) * 4u;
    if (parsed->tcp_header_size < TAPTUN_TCP_MIN_HEADER_SIZE ||
        parsed->tcp_header_size > 60 ||
        packet_size < (uint32_t)parsed->ip_header_size + parsed->tcp_header_size) {
        return 0;
    }
    parsed->payload_size = (uint16_t)(
        packet_size - parsed->ip_header_size - parsed->tcp_header_size);
    parsed->sequence = read_be32(tcp + 4);
    parsed->acknowledgement = read_be32(tcp + 8);
    parsed->flags = tcp[TAPTUN_TCP_FLAGS_OFFSET];
    return 1;
}

static int tcp_headers_compatible(
    const TapTunTcpPacket* first,
    const TapTunTcpPacket* next,
    uint32_t segment_index) {
    if (first->version != next->version ||
        first->ip_header_size != next->ip_header_size ||
        first->tcp_header_size != next->tcp_header_size ||
        first->acknowledgement != next->acknowledgement ||
        next->payload_size == 0 || next->payload_size > first->payload_size) {
        return 0;
    }
    if (first->flags != TAPTUN_TCP_FLAG_ACK ||
        (next->flags != TAPTUN_TCP_FLAG_ACK &&
         next->flags != (TAPTUN_TCP_FLAG_ACK | TAPTUN_TCP_FLAG_PSH))) {
        return 0;
    }

    const unsigned char* first_tcp = first->packet + first->ip_header_size;
    const unsigned char* next_tcp = next->packet + next->ip_header_size;
    if (memcmp(first_tcp, next_tcp, 4) != 0 ||
        memcmp(first_tcp + 8, next_tcp + 8, 5) != 0 ||
        (first_tcp[13] & (uint8_t)~TAPTUN_TCP_FLAG_PSH) !=
            (next_tcp[13] & (uint8_t)~TAPTUN_TCP_FLAG_PSH) ||
        memcmp(first_tcp + 14, next_tcp + 14, 2) != 0 ||
        memcmp(first_tcp + 18, next_tcp + 18, 2) != 0 ||
        (first->tcp_header_size > 20 &&
         memcmp(first_tcp + 20, next_tcp + 20, first->tcp_header_size - 20) != 0)) {
        return 0;
    }

    if (first->version == 4) {
        if (first->packet[0] != next->packet[0] || first->packet[1] != next->packet[1] ||
            memcmp(first->packet + 6, next->packet + 6, 4) != 0 ||
            memcmp(first->packet + 12, next->packet + 12, first->ip_header_size - 12) != 0) {
            return 0;
        }
        uint16_t fragments = read_be16(first->packet + 6);
        if ((fragments & 0x4000u) == 0 &&
            next->ip_id != (uint16_t)(first->ip_id + segment_index)) {
            return 0;
        }
    } else {
        if (memcmp(first->packet, next->packet, 4) != 0 ||
            memcmp(first->packet + 6, next->packet + 6, 34) != 0) {
            return 0;
        }
    }
    return 1;
}

int taptun_linux_offload_prepare_read(
    unsigned char* input,
    uint32_t input_size,
    TapTunLinuxGsoCursor* cursor,
    unsigned char** normal_packet,
    uint32_t* normal_size) {
    if (!input || !cursor || !normal_packet || !normal_size ||
        input_size <= sizeof(struct virtio_net_hdr)) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }

    struct virtio_net_hdr header;
    memcpy(&header, input, sizeof(header));
    unsigned char* packet = input + sizeof(header);
    uint32_t packet_size = input_size - (uint32_t)sizeof(header);
    *normal_packet = NULL;
    *normal_size = 0;
    memset(cursor, 0, sizeof(*cursor));

    if ((header.gso_type & VIRTIO_NET_HDR_GSO_ECN) != 0) {
        errno = EPROTONOSUPPORT;
        return TAPTUN_ERROR_UNSUPPORTED;
    }
    uint8_t gso_type = header.gso_type;
    if (gso_type == VIRTIO_NET_HDR_GSO_NONE) {
        if ((header.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) != 0 &&
            complete_partial_checksum(
                packet,
                packet_size,
                header.csum_start,
                header.csum_offset) != TAPTUN_OK) {
            return TAPTUN_ERROR;
        }
        *normal_packet = packet;
        *normal_size = packet_size;
        return TAPTUN_LINUX_OFFLOAD_NORMAL;
    }

    if ((gso_type != VIRTIO_NET_HDR_GSO_TCPV4 &&
         gso_type != VIRTIO_NET_HDR_GSO_TCPV6) ||
        header.gso_size == 0) {
        errno = EPROTONOSUPPORT;
        return TAPTUN_ERROR_UNSUPPORTED;
    }

    uint8_t version = packet[0] >> 4;
    uint16_t ip_header_size = header.csum_start;
    if ((gso_type == VIRTIO_NET_HDR_GSO_TCPV4 && version != 4) ||
        (gso_type == VIRTIO_NET_HDR_GSO_TCPV6 && version != 6) ||
        (version == 4 &&
         (ip_header_size < 20 || ip_header_size != (uint16_t)(packet[0] & 0x0fu) * 4u ||
          packet[9] != IPPROTO_TCP)) ||
        (version == 6 && ip_header_size < 40) ||
        packet_size < (uint32_t)ip_header_size + TAPTUN_TCP_MIN_HEADER_SIZE ||
        header.csum_offset != 16) {
        errno = EPROTO;
        return TAPTUN_ERROR;
    }
    uint16_t tcp_header_size =
        (uint16_t)(packet[ip_header_size + 12] >> 4) * 4u;
    if (tcp_header_size < TAPTUN_TCP_MIN_HEADER_SIZE || tcp_header_size > 60 ||
        packet_size < (uint32_t)ip_header_size + tcp_header_size) {
        errno = EPROTO;
        return TAPTUN_ERROR;
    }
    uint16_t header_size = header.hdr_len;
    if (header_size == 0) {
        header_size = (uint16_t)(ip_header_size + tcp_header_size);
    }
    if (header_size != ip_header_size + tcp_header_size ||
        header_size >= packet_size) {
        errno = EPROTO;
        return TAPTUN_ERROR;
    }

    cursor->packet = packet;
    cursor->packet_size = packet_size;
    cursor->next_payload_offset = header_size;
    cursor->header_size = header_size;
    cursor->segment_size = header.gso_size;
    cursor->checksum_start = header.csum_start;
    cursor->checksum_offset = header.csum_offset;
    cursor->gso_type = gso_type;
    return TAPTUN_LINUX_OFFLOAD_GSO;
}

int taptun_linux_gso_next(
    TapTunLinuxGsoCursor* cursor,
    unsigned char* output,
    uint32_t output_capacity) {
    if (!cursor || !output || !cursor->packet) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (cursor->next_payload_offset >= cursor->packet_size) return 0;

    uint32_t payload_end = cursor->next_payload_offset + cursor->segment_size;
    if (payload_end > cursor->packet_size) payload_end = cursor->packet_size;
    uint32_t payload_size = payload_end - cursor->next_payload_offset;
    uint32_t output_size = cursor->header_size + payload_size;
    if (output_size > output_capacity) return TAPTUN_ERROR_BUFFER_TOO_SMALL;

    memcpy(output, cursor->packet, cursor->header_size);
    memcpy(
        output + cursor->header_size,
        cursor->packet + cursor->next_payload_offset,
        payload_size);

    uint8_t version = output[0] >> 4;
    if (version == 4) {
        write_be16(output + 2, (uint16_t)output_size);
        write_be16(output + 4, (uint16_t)(read_be16(cursor->packet + 4) + cursor->segment_index));
        output[10] = 0;
        output[11] = 0;
        write_be16(output + 10, ipv4_checksum(output, cursor->checksum_start));
    } else {
        write_be16(output + 4, (uint16_t)(output_size - 40));
    }

    unsigned char* tcp = output + cursor->checksum_start;
    write_be32(
        tcp + 4,
        read_be32(cursor->packet + cursor->checksum_start + 4) +
            cursor->segment_index * cursor->segment_size);
    if (payload_end != cursor->packet_size) {
        tcp[TAPTUN_TCP_FLAGS_OFFSET] &= (uint8_t)~(TAPTUN_TCP_FLAG_FIN | TAPTUN_TCP_FLAG_PSH);
    }
    write_tcp_checksum(
        output,
        version,
        cursor->checksum_start,
        (uint16_t)output_size);

    cursor->next_payload_offset = payload_end;
    ++cursor->segment_index;
    return (int)output_size;
}

int taptun_linux_gro_coalesce(
    const TapTunBuffer* buffers,
    uint32_t buffer_count,
    unsigned char* output,
    uint32_t output_capacity,
    uint32_t* consumed_packets) {
    if (!buffers || buffer_count == 0 || !output || !consumed_packets ||
        output_capacity <= sizeof(struct virtio_net_hdr)) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    *consumed_packets = 1;

    TapTunTcpPacket first;
    if (!buffers[0].data || !parse_tcp_packet(buffers[0].data, buffers[0].size, 1, &first) ||
        first.payload_size == 0 || first.flags != TAPTUN_TCP_FLAG_ACK ||
        !tcp_checksum_is_valid(&first)) {
        return 0;
    }

    uint32_t packet_capacity = output_capacity - (uint32_t)sizeof(struct virtio_net_hdr);
    if (first.packet_size > packet_capacity) return 0;
    unsigned char* packet = output + sizeof(struct virtio_net_hdr);
    memcpy(packet, first.packet, first.packet_size);
    uint32_t coalesced_size = first.packet_size;
    uint32_t expected_sequence = first.sequence + first.payload_size;

    for (uint32_t index = 1; index < buffer_count; ++index) {
        TapTunTcpPacket next;
        if (!buffers[index].data ||
            !parse_tcp_packet(buffers[index].data, buffers[index].size, 1, &next) ||
            next.sequence != expected_sequence ||
            !tcp_headers_compatible(&first, &next, index) ||
            !tcp_checksum_is_valid(&next) ||
            coalesced_size + next.payload_size > packet_capacity ||
            (first.version == 6 && coalesced_size + next.payload_size - 40u > UINT16_MAX)) {
            break;
        }
        memcpy(
            packet + coalesced_size,
            next.packet + next.ip_header_size + next.tcp_header_size,
            next.payload_size);
        coalesced_size += next.payload_size;
        expected_sequence += next.payload_size;
        *consumed_packets = index + 1;
        if ((next.flags & TAPTUN_TCP_FLAG_PSH) != 0 || next.payload_size < first.payload_size) break;
    }

    if (*consumed_packets == 1) return 0;
    unsigned char* tcp = packet + first.ip_header_size;
    if ((buffers[*consumed_packets - 1].data[first.ip_header_size + TAPTUN_TCP_FLAGS_OFFSET] &
         TAPTUN_TCP_FLAG_PSH) != 0) {
        tcp[TAPTUN_TCP_FLAGS_OFFSET] |= TAPTUN_TCP_FLAG_PSH;
    }
    if (first.version == 4) {
        write_be16(packet + 2, (uint16_t)coalesced_size);
        packet[10] = 0;
        packet[11] = 0;
        write_be16(packet + 10, ipv4_checksum(packet, first.ip_header_size));
    } else {
        write_be16(packet + 4, (uint16_t)(coalesced_size - 40));
    }

    // CHECKSUM_PARTIAL expects the folded pseudo-header sum in the TCP field.
    tcp[16] = 0;
    tcp[17] = 0;
    uint16_t tcp_size = (uint16_t)(coalesced_size - first.ip_header_size);
    write_be16(
        tcp + 16,
        checksum_fold(tcp_pseudo_header_sum(packet, first.version, tcp_size)));

    struct virtio_net_hdr header;
    memset(&header, 0, sizeof(header));
    header.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    header.gso_type = first.version == 4
        ? VIRTIO_NET_HDR_GSO_TCPV4
        : VIRTIO_NET_HDR_GSO_TCPV6;
    header.hdr_len = (uint16_t)(first.ip_header_size + first.tcp_header_size);
    header.gso_size = first.payload_size;
    header.csum_start = first.ip_header_size;
    header.csum_offset = 16;
    memcpy(output, &header, sizeof(header));
    return (int)(sizeof(header) + coalesced_size);
}
