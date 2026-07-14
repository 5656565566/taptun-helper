#include "tun2tap.h"

#include "taptun_api.h"

#include <stddef.h>
#include <string.h>

#define ETHERTYPE_IPV4 0x0800u
#define ETHERTYPE_ARP 0x0806u
#define ETHERTYPE_IPV6 0x86ddu

static uint16_t read_u16(const unsigned char* value) {
    return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static void write_u16(unsigned char* value, uint16_t number) {
    value[0] = (unsigned char)(number >> 8);
    value[1] = (unsigned char)number;
}

static void write_u32(unsigned char* value, uint32_t number) {
    value[0] = (unsigned char)(number >> 24);
    value[1] = (unsigned char)(number >> 16);
    value[2] = (unsigned char)(number >> 8);
    value[3] = (unsigned char)number;
}

static int is_zero_mac(const unsigned char mac[6]) {
    static const unsigned char zero[6] = { 0 };
    return !mac || memcmp(mac, zero, sizeof(zero)) == 0;
}

static uint32_t hash_device(const char* name, unsigned int if_index) {
    uint32_t hash = 2166136261u;
    if (name) {
        while (*name) {
            hash ^= (unsigned char)*name++;
            hash *= 16777619u;
        }
    }
    hash ^= if_index;
    hash *= 16777619u;
    return hash;
}

static void make_default_mac(unsigned char mac[6], uint32_t hash, unsigned char role) {
    mac[0] = 0x02;
    mac[1] = 0x54;
    mac[2] = role;
    mac[3] = (unsigned char)(hash >> 16);
    mac[4] = (unsigned char)(hash >> 8);
    mac[5] = (unsigned char)hash;
}

void taptun_tun2tap_init(
    TapTunTun2Tap* state,
    const unsigned char interface_mac[6],
    const unsigned char peer_mac[6],
    const char* device_name,
    unsigned int if_index) {
    uint32_t hash = hash_device(device_name, if_index);
    if (is_zero_mac(interface_mac)) {
        make_default_mac(state->interface_mac, hash, 0x00);
    } else {
        memcpy(state->interface_mac, interface_mac, 6);
    }
    if (is_zero_mac(peer_mac)) {
        make_default_mac(state->peer_mac, hash, 0x01);
    } else {
        memcpy(state->peer_mac, peer_mac, 6);
    }
}

static void ipv4_destination_mac(
    const TapTunTun2Tap* state,
    const unsigned char* packet,
    unsigned char destination[6]) {
    const unsigned char* address = packet + 16;
    if (address[0] == 255 && address[1] == 255 && address[2] == 255 && address[3] == 255) {
        memset(destination, 0xff, 6);
    } else if ((address[0] & 0xf0) == 0xe0) {
        destination[0] = 0x01;
        destination[1] = 0x00;
        destination[2] = 0x5e;
        destination[3] = (unsigned char)(address[1] & 0x7f);
        destination[4] = address[2];
        destination[5] = address[3];
    } else {
        memcpy(destination, state->peer_mac, 6);
    }
}

static void ipv6_destination_mac(
    const TapTunTun2Tap* state,
    const unsigned char* packet,
    unsigned char destination[6]) {
    const unsigned char* address = packet + 24;
    if (address[0] == 0xff) {
        destination[0] = 0x33;
        destination[1] = 0x33;
        memcpy(destination + 2, address + 12, 4);
    } else {
        memcpy(destination, state->peer_mac, 6);
    }
}

int taptun_tun2tap_encapsulate(
    const TapTunTun2Tap* state,
    const unsigned char* packet,
    int packet_size,
    unsigned char* frame,
    int frame_capacity) {
    if (!state || !packet || !frame || packet_size <= 0) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (frame_capacity < packet_size + TAPTUN_ETHERNET_HEADER_SIZE) {
        return TAPTUN_ERROR_BUFFER_TOO_SMALL;
    }

    unsigned int version = packet[0] >> 4;
    if (version == 4 && packet_size >= 20) {
        ipv4_destination_mac(state, packet, frame);
        write_u16(frame + 12, ETHERTYPE_IPV4);
    } else if (version == 6 && packet_size >= 40) {
        ipv6_destination_mac(state, packet, frame);
        write_u16(frame + 12, ETHERTYPE_IPV6);
    } else {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    memcpy(frame + 6, state->interface_mac, 6);
    memcpy(frame + TAPTUN_ETHERNET_HEADER_SIZE, packet, (size_t)packet_size);
    return packet_size + TAPTUN_ETHERNET_HEADER_SIZE;
}

static int build_arp_reply(
    const TapTunTun2Tap* state,
    const unsigned char* request,
    unsigned char* reply,
    int capacity) {
    const int arp_frame_size = 42;
    if (capacity < arp_frame_size) return TAPTUN_ERROR_BUFFER_TOO_SMALL;
    const unsigned char* arp = request + TAPTUN_ETHERNET_HEADER_SIZE;
    if (read_u16(arp) != 1 || read_u16(arp + 2) != ETHERTYPE_IPV4 ||
        arp[4] != 6 || arp[5] != 4 || read_u16(arp + 6) != 1) {
        return TAPTUN_TUN2TAP_DROP;
    }

    memcpy(reply, arp + 8, 6);
    memcpy(reply + 6, state->interface_mac, 6);
    write_u16(reply + 12, ETHERTYPE_ARP);
    write_u16(reply + 14, 1);
    write_u16(reply + 16, ETHERTYPE_IPV4);
    reply[18] = 6;
    reply[19] = 4;
    write_u16(reply + 20, 2);
    memcpy(reply + 22, state->interface_mac, 6);
    memcpy(reply + 28, arp + 24, 4);
    memcpy(reply + 32, arp + 8, 6);
    memcpy(reply + 38, arp + 14, 4);
    return arp_frame_size;
}

static uint32_t checksum_add(uint32_t sum, const unsigned char* data, size_t size) {
    while (size >= 2) {
        sum += read_u16(data);
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

static uint16_t icmpv6_checksum(
    const unsigned char source[16],
    const unsigned char destination[16],
    const unsigned char* payload,
    uint32_t payload_size) {
    uint32_t sum = checksum_add(0, source, 16);
    sum = checksum_add(sum, destination, 16);
    unsigned char length_and_protocol[8] = { 0 };
    write_u32(length_and_protocol, payload_size);
    length_and_protocol[7] = 58;
    sum = checksum_add(sum, length_and_protocol, sizeof(length_and_protocol));
    sum = checksum_add(sum, payload, payload_size);
    return checksum_finish(sum);
}

static int is_unspecified_ipv6(const unsigned char address[16]) {
    static const unsigned char zero[16] = { 0 };
    return memcmp(address, zero, sizeof(zero)) == 0;
}

static int build_neighbor_advertisement(
    const TapTunTun2Tap* state,
    const unsigned char* request,
    int request_size,
    unsigned char* reply,
    int capacity) {
    const int reply_size = 14 + 40 + 32;
    if (request_size < 14 + 40 + 24) return TAPTUN_TUN2TAP_DROP;
    if (capacity < reply_size) return TAPTUN_ERROR_BUFFER_TOO_SMALL;
    const unsigned char* ipv6 = request + 14;
    const unsigned char* solicitation = ipv6 + 40;
    if ((ipv6[0] >> 4) != 6 || ipv6[6] != 58 || ipv6[7] != 255 || solicitation[0] != 135) {
        return TAPTUN_TUN2TAP_DROP;
    }

    int unspecified_source = is_unspecified_ipv6(ipv6 + 8);
    if (unspecified_source) {
        static const unsigned char all_nodes_mac[6] = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 };
        memcpy(reply, all_nodes_mac, 6);
    } else {
        memcpy(reply, request + 6, 6);
    }
    memcpy(reply + 6, state->interface_mac, 6);
    write_u16(reply + 12, ETHERTYPE_IPV6);

    unsigned char* out_ipv6 = reply + 14;
    memset(out_ipv6, 0, 40 + 32);
    out_ipv6[0] = 0x60;
    write_u16(out_ipv6 + 4, 32);
    out_ipv6[6] = 58;
    out_ipv6[7] = 255;
    memcpy(out_ipv6 + 8, solicitation + 8, 16);
    if (unspecified_source) {
        static const unsigned char all_nodes[16] = {
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        };
        memcpy(out_ipv6 + 24, all_nodes, 16);
    } else {
        memcpy(out_ipv6 + 24, ipv6 + 8, 16);
    }

    unsigned char* advertisement = out_ipv6 + 40;
    advertisement[0] = 136;
    advertisement[4] = unspecified_source ? 0x20 : 0x60;
    memcpy(advertisement + 8, solicitation + 8, 16);
    advertisement[24] = 2;
    advertisement[25] = 1;
    memcpy(advertisement + 26, state->interface_mac, 6);
    write_u16(advertisement + 2, icmpv6_checksum(
        out_ipv6 + 8,
        out_ipv6 + 24,
        advertisement,
        32));
    return reply_size;
}

int taptun_tun2tap_decapsulate(
    const TapTunTun2Tap* state,
    const unsigned char* frame,
    int frame_size,
    unsigned char* packet,
    int packet_capacity,
    unsigned char* synthetic_frame,
    int synthetic_capacity,
    int* output_size) {
    if (!state || !frame || !output_size || frame_size < TAPTUN_ETHERNET_HEADER_SIZE) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    *output_size = 0;
    uint16_t ether_type = read_u16(frame + 12);
    if (ether_type == ETHERTYPE_IPV6 && frame_size >= 14 + 40 + 24 &&
        frame[14 + 6] == 58 && frame[14 + 7] == 255 && frame[14 + 40] == 135) {
        if (!synthetic_frame) return TAPTUN_TUN2TAP_DROP;
        int result = build_neighbor_advertisement(
            state,
            frame,
            frame_size,
            synthetic_frame,
            synthetic_capacity);
        if (result < 0 || result == TAPTUN_TUN2TAP_DROP) return result;
        *output_size = result;
        return TAPTUN_TUN2TAP_SYNTHETIC;
    }
    if (ether_type == ETHERTYPE_IPV4 || ether_type == ETHERTYPE_IPV6) {
        int payload_size = frame_size - TAPTUN_ETHERNET_HEADER_SIZE;
        if (!packet) return TAPTUN_ERROR_INVALID_ARGUMENT;
        if (packet_capacity < payload_size) return TAPTUN_ERROR_BUFFER_TOO_SMALL;
        unsigned int expected_version = ether_type == ETHERTYPE_IPV4 ? 4u : 6u;
        if (payload_size <= 0 || (frame[14] >> 4) != expected_version) {
            return TAPTUN_ERROR_INVALID_ARGUMENT;
        }
        memcpy(packet, frame + TAPTUN_ETHERNET_HEADER_SIZE, (size_t)payload_size);
        *output_size = payload_size;
        return TAPTUN_TUN2TAP_PACKET;
    }
    if (ether_type == ETHERTYPE_ARP) {
        if (frame_size < 42 || !synthetic_frame) return TAPTUN_TUN2TAP_DROP;
        int result = build_arp_reply(state, frame, synthetic_frame, synthetic_capacity);
        if (result < 0 || result == TAPTUN_TUN2TAP_DROP) return result;
        *output_size = result;
        return TAPTUN_TUN2TAP_SYNTHETIC;
    }
    return TAPTUN_TUN2TAP_DROP;
}
