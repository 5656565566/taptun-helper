#include <stdio.h>
#include <string.h>

#include "../src/tun2tap.h"
#include "../include/taptun_api.h"

static void write_u16(unsigned char* value, unsigned int number) {
    value[0] = (unsigned char)(number >> 8);
    value[1] = (unsigned char)number;
}

static int test_ipv4_round_trip(const TapTunTun2Tap* state) {
    unsigned char packet[20] = { 0x45, 0, 0, 20 };
    packet[16] = 10;
    packet[17] = 0;
    packet[18] = 0;
    packet[19] = 2;
    unsigned char frame[64];
    int frame_size = taptun_tun2tap_encapsulate(
        state,
        packet,
        sizeof(packet),
        frame,
        sizeof(frame));
    if (frame_size != 34 || memcmp(frame, state->peer_mac, 6) != 0 ||
        memcmp(frame + 6, state->interface_mac, 6) != 0 ||
        frame[12] != 0x08 || frame[13] != 0x00) {
        return 1;
    }

    unsigned char decoded[32];
    unsigned char synthetic[128];
    int output_size = 0;
    int action = taptun_tun2tap_decapsulate(
        state,
        frame,
        frame_size,
        decoded,
        sizeof(decoded),
        synthetic,
        sizeof(synthetic),
        &output_size);
    return action == TAPTUN_TUN2TAP_PACKET && output_size == (int)sizeof(packet) &&
        memcmp(packet, decoded, sizeof(packet)) == 0 ? 0 : 1;
}

static int test_multicast_mapping(const TapTunTun2Tap* state) {
    unsigned char ipv4[20] = { 0x45 };
    ipv4[16] = 239;
    ipv4[17] = 1;
    ipv4[18] = 2;
    ipv4[19] = 3;
    unsigned char frame[64];
    if (taptun_tun2tap_encapsulate(state, ipv4, sizeof(ipv4), frame, sizeof(frame)) != 34) {
        return 1;
    }
    const unsigned char expected_ipv4[6] = { 0x01, 0x00, 0x5e, 0x01, 0x02, 0x03 };
    if (memcmp(frame, expected_ipv4, 6) != 0) return 1;

    unsigned char ipv6[40] = { 0x60 };
    ipv6[24] = 0xff;
    ipv6[36] = 0x12;
    ipv6[37] = 0x34;
    ipv6[38] = 0x56;
    ipv6[39] = 0x78;
    if (taptun_tun2tap_encapsulate(state, ipv6, sizeof(ipv6), frame, sizeof(frame)) != 54) {
        return 1;
    }
    const unsigned char expected_ipv6[6] = { 0x33, 0x33, 0x12, 0x34, 0x56, 0x78 };
    return memcmp(frame, expected_ipv6, 6) == 0 ? 0 : 1;
}

static int test_proxy_arp(const TapTunTun2Tap* state) {
    unsigned char request[42] = { 0 };
    const unsigned char requester_mac[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    memset(request, 0xff, 6);
    memcpy(request + 6, requester_mac, 6);
    write_u16(request + 12, 0x0806);
    write_u16(request + 14, 1);
    write_u16(request + 16, 0x0800);
    request[18] = 6;
    request[19] = 4;
    write_u16(request + 20, 1);
    memcpy(request + 22, requester_mac, 6);
    request[28] = 10;
    request[29] = 0;
    request[30] = 0;
    request[31] = 1;
    request[38] = 10;
    request[39] = 0;
    request[40] = 0;
    request[41] = 2;

    unsigned char packet[64];
    unsigned char reply[128];
    int output_size = 0;
    int action = taptun_tun2tap_decapsulate(
        state,
        request,
        sizeof(request),
        packet,
        sizeof(packet),
        reply,
        sizeof(reply),
        &output_size);
    if (action != TAPTUN_TUN2TAP_SYNTHETIC || output_size != 42) return 1;
    return memcmp(reply, requester_mac, 6) == 0 &&
        memcmp(reply + 6, state->interface_mac, 6) == 0 &&
        reply[20] == 0 && reply[21] == 2 &&
        memcmp(reply + 22, state->interface_mac, 6) == 0 &&
        memcmp(reply + 28, request + 38, 4) == 0 &&
        memcmp(reply + 32, requester_mac, 6) == 0 &&
        memcmp(reply + 38, request + 28, 4) == 0 ? 0 : 1;
}

static int test_neighbor_discovery(const TapTunTun2Tap* state) {
    unsigned char request[14 + 40 + 24] = { 0 };
    const unsigned char requester_mac[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    const unsigned char source[16] = {
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    };
    const unsigned char target[16] = {
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
    };
    request[0] = 0x33;
    request[1] = 0x33;
    request[2] = 0xff;
    request[5] = 0x02;
    memcpy(request + 6, requester_mac, 6);
    write_u16(request + 12, 0x86dd);
    request[14] = 0x60;
    write_u16(request + 18, 24);
    request[20] = 58;
    request[21] = 255;
    memcpy(request + 22, source, 16);
    request[38] = 0xff;
    request[39] = 0x02;
    request[49] = 0x01;
    request[50] = 0xff;
    request[53] = 0x02;
    request[54] = 135;
    memcpy(request + 62, target, 16);

    unsigned char packet[128];
    unsigned char reply[128];
    int output_size = 0;
    int action = taptun_tun2tap_decapsulate(
        state,
        request,
        sizeof(request),
        packet,
        sizeof(packet),
        reply,
        sizeof(reply),
        &output_size);
    if (action != TAPTUN_TUN2TAP_SYNTHETIC || output_size != 86) return 1;
    return memcmp(reply, requester_mac, 6) == 0 &&
        memcmp(reply + 6, state->interface_mac, 6) == 0 &&
        reply[54] == 136 && reply[58] == 0x60 &&
        memcmp(reply + 22, target, 16) == 0 &&
        memcmp(reply + 38, source, 16) == 0 &&
        memcmp(reply + 62, target, 16) == 0 &&
        reply[78] == 2 && reply[79] == 1 &&
        memcmp(reply + 80, state->interface_mac, 6) == 0 &&
        (reply[56] != 0 || reply[57] != 0) ? 0 : 1;
}

int main(void) {
    const unsigned char interface_mac[6] = { 0x02, 0x54, 0, 0, 0, 1 };
    const unsigned char peer_mac[6] = { 0x02, 0x54, 0, 0, 0, 2 };
    TapTunTun2Tap state;
    taptun_tun2tap_init(&state, interface_mac, peer_mac, "test", 7);

    if (test_ipv4_round_trip(&state) != 0 ||
        test_multicast_mapping(&state) != 0 ||
        test_proxy_arp(&state) != 0 ||
        test_neighbor_discovery(&state) != 0) {
        fprintf(stderr, "tun2tap protocol test failed.\n");
        return 1;
    }
    printf("tun2tap protocol test passed.\n");
    return 0;
}
