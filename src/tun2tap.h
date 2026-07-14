#ifndef TAPTUN_TUN2TAP_H
#define TAPTUN_TUN2TAP_H

#include <stdint.h>

#define TAPTUN_ETHERNET_HEADER_SIZE 14
#define TAPTUN_MAX_IP_PACKET_SIZE 65535
#define TAPTUN_MAX_ETHERNET_FRAME_SIZE \
    (TAPTUN_ETHERNET_HEADER_SIZE + TAPTUN_MAX_IP_PACKET_SIZE)
#define TAPTUN_SYNTHETIC_FRAME_SIZE 128

typedef struct {
    unsigned char interface_mac[6];
    unsigned char peer_mac[6];
} TapTunTun2Tap;

typedef enum {
    TAPTUN_TUN2TAP_PACKET = 1,
    TAPTUN_TUN2TAP_SYNTHETIC = 2,
    TAPTUN_TUN2TAP_DROP = 3
} TapTunTun2TapAction;

void taptun_tun2tap_init(
    TapTunTun2Tap* state,
    const unsigned char interface_mac[6],
    const unsigned char peer_mac[6],
    const char* device_name,
    unsigned int if_index);

int taptun_tun2tap_encapsulate(
    const TapTunTun2Tap* state,
    const unsigned char* packet,
    int packet_size,
    unsigned char* frame,
    int frame_capacity);

int taptun_tun2tap_decapsulate(
    const TapTunTun2Tap* state,
    const unsigned char* frame,
    int frame_size,
    unsigned char* packet,
    int packet_capacity,
    unsigned char* synthetic_frame,
    int synthetic_capacity,
    int* output_size);

#endif
