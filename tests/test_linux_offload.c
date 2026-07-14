#include "../src/linux_offload.h"

#include <linux/virtio_net.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define IP_HEADER_SIZE 20u
#define TCP_HEADER_SIZE 20u

static uint16_t read_be16(const unsigned char* data) {
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
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

static uint32_t checksum_add(uint32_t sum, const unsigned char* data, uint32_t size) {
    while (size >= 2) {
        sum += read_be16(data);
        data += 2;
        size -= 2;
    }
    if (size != 0) sum += (uint16_t)data[0] << 8;
    return sum;
}

static uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t checksum_fold(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)sum;
}

static void prepare_tcp_packet(
    unsigned char* packet,
    uint16_t payload_size,
    uint16_t ip_id,
    uint32_t sequence,
    uint8_t flags,
    uint8_t payload_seed) {
    uint16_t packet_size = IP_HEADER_SIZE + TCP_HEADER_SIZE + payload_size;
    memset(packet, 0, packet_size);
    packet[0] = 0x45;
    write_be16(packet + 2, packet_size);
    write_be16(packet + 4, ip_id);
    write_be16(packet + 6, 0x4000);
    packet[8] = 64;
    packet[9] = 6;
    packet[12] = 192;
    packet[13] = 0;
    packet[14] = 2;
    packet[15] = 1;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 2;

    unsigned char* tcp = packet + IP_HEADER_SIZE;
    write_be16(tcp, 40000);
    write_be16(tcp + 2, 40001);
    write_be32(tcp + 4, sequence);
    write_be32(tcp + 8, 7000);
    tcp[12] = 5u << 4;
    tcp[13] = flags;
    write_be16(tcp + 14, 32768);
    for (uint16_t index = 0; index < payload_size; ++index) {
        packet[IP_HEADER_SIZE + TCP_HEADER_SIZE + index] = (unsigned char)(payload_seed + index);
    }

    write_be16(packet + 10, checksum_finish(checksum_add(0, packet, IP_HEADER_SIZE)));
    uint32_t tcp_sum = checksum_add(0, packet + 12, 8);
    tcp_sum += 6;
    tcp_sum += TCP_HEADER_SIZE + payload_size;
    tcp_sum = checksum_add(tcp_sum, tcp, TCP_HEADER_SIZE + payload_size);
    write_be16(tcp + 16, checksum_finish(tcp_sum));
}

static void prepare_ipv6_tcp_packet(
    unsigned char* packet,
    uint16_t payload_size,
    uint32_t sequence,
    uint8_t flags,
    uint8_t payload_seed) {
    uint16_t packet_size = 40 + TCP_HEADER_SIZE + payload_size;
    memset(packet, 0, packet_size);
    packet[0] = 0x60;
    write_be16(packet + 4, (uint16_t)(TCP_HEADER_SIZE + payload_size));
    packet[6] = 6;
    packet[7] = 64;
    packet[8] = 0x20;
    packet[9] = 0x01;
    packet[10] = 0x0d;
    packet[11] = 0xb8;
    packet[23] = 1;
    packet[24] = 0x20;
    packet[25] = 0x01;
    packet[26] = 0x0d;
    packet[27] = 0xb8;
    packet[39] = 2;

    unsigned char* tcp = packet + 40;
    write_be16(tcp, 40000);
    write_be16(tcp + 2, 40001);
    write_be32(tcp + 4, sequence);
    write_be32(tcp + 8, 7000);
    tcp[12] = 5u << 4;
    tcp[13] = flags;
    write_be16(tcp + 14, 32768);
    for (uint16_t index = 0; index < payload_size; ++index) {
        packet[60 + index] = (unsigned char)(payload_seed + index);
    }

    uint32_t tcp_sum = checksum_add(0, packet + 8, 32);
    tcp_sum += 6;
    tcp_sum += TCP_HEADER_SIZE + payload_size;
    tcp_sum = checksum_add(tcp_sum, tcp, TCP_HEADER_SIZE + payload_size);
    write_be16(tcp + 16, checksum_finish(tcp_sum));
}

static int test_tcp_gro_gso_round_trip(void) {
    unsigned char packet0[140];
    unsigned char packet1[140];
    unsigned char packet2[77];
    prepare_tcp_packet(packet0, 100, 10, 1000, 0x10, 1);
    prepare_tcp_packet(packet1, 100, 11, 1100, 0x10, 101);
    prepare_tcp_packet(packet2, 37, 12, 1200, 0x18, 201);

    TapTunBuffer input[3] = {
        { packet0, sizeof(packet0), sizeof(packet0) },
        { packet1, sizeof(packet1), sizeof(packet1) },
        { packet2, sizeof(packet2), sizeof(packet2) }
    };
    unsigned char coalesced[65545];
    uint32_t consumed = 0;
    int coalesced_size = taptun_linux_gro_coalesce(
        input,
        3,
        coalesced,
        sizeof(coalesced),
        &consumed);
    if (coalesced_size <= 0 || consumed != 3) return 1;

    struct virtio_net_hdr header;
    memcpy(&header, coalesced, sizeof(header));
    if (header.gso_type != VIRTIO_NET_HDR_GSO_TCPV4 ||
        header.gso_size != 100 || header.hdr_len != 40 ||
        header.csum_start != 20 || header.csum_offset != 16) {
        return 1;
    }

    TapTunLinuxGsoCursor cursor;
    unsigned char* normal_packet = NULL;
    uint32_t normal_size = 0;
    if (taptun_linux_offload_prepare_read(
            coalesced,
            (uint32_t)coalesced_size,
            &cursor,
            &normal_packet,
            &normal_size) != TAPTUN_LINUX_OFFLOAD_GSO) {
        return 1;
    }

    unsigned char output[160];
    if (taptun_linux_gso_next(&cursor, output, 20) != TAPTUN_ERROR_BUFFER_TOO_SMALL) return 1;
    int size = taptun_linux_gso_next(&cursor, output, sizeof(output));
    if (size != (int)sizeof(packet0) || memcmp(output, packet0, sizeof(packet0)) != 0) return 1;
    size = taptun_linux_gso_next(&cursor, output, sizeof(output));
    if (size != (int)sizeof(packet1) || memcmp(output, packet1, sizeof(packet1)) != 0) return 1;
    size = taptun_linux_gso_next(&cursor, output, sizeof(output));
    if (size != (int)sizeof(packet2) || memcmp(output, packet2, sizeof(packet2)) != 0) return 1;
    return taptun_linux_gso_next(&cursor, output, sizeof(output)) == 0 ? 0 : 1;
}

static int test_incompatible_sequence_is_not_coalesced(void) {
    unsigned char first[104];
    unsigned char second[104];
    prepare_tcp_packet(first, 64, 1, 100, 0x10, 1);
    prepare_tcp_packet(second, 64, 2, 999, 0x10, 2);
    TapTunBuffer input[2] = {
        { first, sizeof(first), sizeof(first) },
        { second, sizeof(second), sizeof(second) }
    };
    unsigned char output[512];
    uint32_t consumed = 0;
    int result = taptun_linux_gro_coalesce(input, 2, output, sizeof(output), &consumed);
    return result == 0 && consumed == 1 ? 0 : 1;
}

static int test_ipv6_tcp_gro_gso_round_trip(void) {
    unsigned char packet0[140];
    unsigned char packet1[140];
    unsigned char packet2[91];
    prepare_ipv6_tcp_packet(packet0, 80, 2000, 0x10, 1);
    prepare_ipv6_tcp_packet(packet1, 80, 2080, 0x10, 81);
    prepare_ipv6_tcp_packet(packet2, 31, 2160, 0x18, 161);
    TapTunBuffer input[3] = {
        { packet0, sizeof(packet0), sizeof(packet0) },
        { packet1, sizeof(packet1), sizeof(packet1) },
        { packet2, sizeof(packet2), sizeof(packet2) }
    };
    unsigned char coalesced[65545];
    uint32_t consumed = 0;
    int coalesced_size = taptun_linux_gro_coalesce(
        input, 3, coalesced, sizeof(coalesced), &consumed);
    if (coalesced_size <= 0 || consumed != 3) return 1;

    struct virtio_net_hdr header;
    memcpy(&header, coalesced, sizeof(header));
    if (header.gso_type != VIRTIO_NET_HDR_GSO_TCPV6 || header.gso_size != 80 ||
        header.hdr_len != 60 || header.csum_start != 40) {
        return 1;
    }
    TapTunLinuxGsoCursor cursor;
    unsigned char* normal_packet = NULL;
    uint32_t normal_size = 0;
    if (taptun_linux_offload_prepare_read(
            coalesced,
            (uint32_t)coalesced_size,
            &cursor,
            &normal_packet,
            &normal_size) != TAPTUN_LINUX_OFFLOAD_GSO) {
        return 1;
    }
    unsigned char output[160];
    int size = taptun_linux_gso_next(&cursor, output, sizeof(output));
    if (size != (int)sizeof(packet0) || memcmp(output, packet0, sizeof(packet0)) != 0) return 1;
    size = taptun_linux_gso_next(&cursor, output, sizeof(output));
    if (size != (int)sizeof(packet1) || memcmp(output, packet1, sizeof(packet1)) != 0) return 1;
    size = taptun_linux_gso_next(&cursor, output, sizeof(output));
    return size == (int)sizeof(packet2) && memcmp(output, packet2, sizeof(packet2)) == 0
        ? 0
        : 1;
}

static int test_partial_checksum_completion(void) {
    unsigned char original[104];
    prepare_tcp_packet(original, 64, 1, 100, 0x10, 7);
    unsigned char input[sizeof(struct virtio_net_hdr) + sizeof(original)];
    struct virtio_net_hdr header;
    memset(&header, 0, sizeof(header));
    header.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
    header.csum_start = 20;
    header.csum_offset = 16;
    memcpy(input, &header, sizeof(header));
    memcpy(input + sizeof(header), original, sizeof(original));

    unsigned char* tcp = input + sizeof(header) + 20;
    tcp[16] = 0;
    tcp[17] = 0;
    uint32_t pseudo_sum = checksum_add(0, original + 12, 8);
    pseudo_sum += 6 + sizeof(original) - 20;
    write_be16(tcp + 16, checksum_fold(pseudo_sum));

    TapTunLinuxGsoCursor cursor;
    unsigned char* normal_packet = NULL;
    uint32_t normal_size = 0;
    int result = taptun_linux_offload_prepare_read(
        input,
        sizeof(input),
        &cursor,
        &normal_packet,
        &normal_size);
    return result == TAPTUN_LINUX_OFFLOAD_NORMAL && normal_size == sizeof(original) &&
        memcmp(normal_packet, original, sizeof(original)) == 0
        ? 0
        : 1;
}

int main(void) {
    if (test_tcp_gro_gso_round_trip() != 0) {
        fprintf(stderr, "TCP GSO/GRO round-trip test failed.\n");
        return 1;
    }
    if (test_incompatible_sequence_is_not_coalesced() != 0) {
        fprintf(stderr, "Incompatible TCP sequence test failed.\n");
        return 1;
    }
    if (test_ipv6_tcp_gro_gso_round_trip() != 0) {
        fprintf(stderr, "IPv6 TCP GSO/GRO round-trip test failed.\n");
        return 1;
    }
    if (test_partial_checksum_completion() != 0) {
        fprintf(stderr, "Partial checksum completion test failed.\n");
        return 1;
    }
    printf("Linux GSO/GRO protocol tests passed.\n");
    return 0;
}
