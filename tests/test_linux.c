#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../include/taptun_api.h"

static void* delayed_close_thread(void* argument) {
    struct timespec delay = { 0, 10000000 };
    nanosleep(&delay, NULL);
    TapTun_Close((TapTunDevice*)argument);
    return NULL;
}

static int test_external_handle(void) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0) return 1;

    TapTunHandleOptions handle_options;
    memset(&handle_options, 0, sizeof(handle_options));
    handle_options.handle = sockets[0];
    handle_options.name = "host-tun";
    handle_options.if_index = 7;
    handle_options.take_ownership = 1;
    TapTunDevice* device = TapTun_OpenFromHandle(&handle_options);
    if (!device || strcmp(TapTun_GetName(device), "host-tun") != 0 || TapTun_GetIndex(device) != 7) {
        close(sockets[0]);
        close(sockets[1]);
        return 1;
    }

    TapTunPacket zero_copy_packet;
    memset(&zero_copy_packet, 0, sizeof(zero_copy_packet));
    if (TapTun_GetCapabilities(device) != 0 || TapTun_GetQueueCount(device) != 1 ||
        TapTun_AcquireReceive(device, &zero_copy_packet) != TAPTUN_ERROR_UNSUPPORTED ||
        TapTun_ReleaseReceive(device, &zero_copy_packet) != TAPTUN_ERROR_UNSUPPORTED ||
        TapTun_AcquireSend(device, 20, &zero_copy_packet) != TAPTUN_ERROR_UNSUPPORTED ||
        TapTun_CommitSend(device, &zero_copy_packet) != TAPTUN_ERROR_UNSUPPORTED) {
        TapTun_Close(device);
        close(sockets[1]);
        return 1;
    }

    const unsigned char inbound[] = { 0x45, 0x00, 0x00, 0x14 };
    unsigned char buffer[64];
    if (write(sockets[1], inbound, sizeof(inbound)) != (ssize_t)sizeof(inbound) ||
        TapTun_Read(device, buffer, sizeof(buffer)) != (int)sizeof(inbound) ||
        memcmp(buffer, inbound, sizeof(inbound)) != 0) {
        TapTun_Close(device);
        close(sockets[1]);
        return 1;
    }

    const unsigned char outbound[] = { 0x60, 0x00, 0x00, 0x00 };
    if (TapTun_Write(device, outbound, sizeof(outbound)) != (int)sizeof(outbound) ||
        read(sockets[1], buffer, sizeof(buffer)) != (ssize_t)sizeof(outbound) ||
        memcmp(buffer, outbound, sizeof(outbound)) != 0) {
        TapTun_Close(device);
        close(sockets[1]);
        return 1;
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, delayed_close_thread, device) != 0) {
        TapTun_Close(device);
        close(sockets[1]);
        return 1;
    }
    int close_result = TapTun_Read(device, buffer, sizeof(buffer));
    pthread_join(thread, NULL);
    close(sockets[1]);
    return close_result == TAPTUN_ERROR_CLOSED ? 0 : 1;
}

static int test_native_device(TapTunMode mode) {
    TapTunOptions options;
    memset(&options, 0, sizeof(options));
    options.name = mode == TAPTUN_MODE_TAP ? "taptap0" : "taptun0";
    options.mode = mode;
    TapTunDevice* device = TapTun_Open(&options);
    if (!device) {
        fprintf(stderr, "Failed to create native %s. Run as root and verify /dev/net/tun.\n",
            mode == TAPTUN_MODE_TAP ? "TAP" : "TUN");
        return 1;
    }
    int result = TapTun_SetIPAddressV4(device, "10.10.0.1", 24);
    if (result == TAPTUN_OK) result = TapTun_SetIPAddressV6(device, "fd10::1", 64);
    if (result == TAPTUN_OK) result = TapTun_Activate(device);
    if (result == TAPTUN_OK && TapTun_GetMode(device) != mode) result = TAPTUN_ERROR;
    if (result == TAPTUN_OK && mode == TAPTUN_MODE_TAP &&
        (TapTun_GetCapabilities(device) & TAPTUN_CAP_NATIVE_TAP) == 0) {
        result = TAPTUN_ERROR;
    }
    printf("Native %s name=%s index=%u\n",
        mode == TAPTUN_MODE_TAP ? "TAP" : "TUN",
        TapTun_GetName(device),
        TapTun_GetIndex(device));
    TapTun_Close(device);
    return result == TAPTUN_OK ? 0 : 1;
}

static uint16_t ipv4_checksum(const unsigned char* packet, size_t size) {
    uint32_t sum = 0;
    for (size_t index = 0; index + 1 < size; index += 2) {
        sum += ((uint32_t)packet[index] << 8) | packet[index + 1];
    }
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t checksum_add(uint32_t sum, const unsigned char* packet, size_t size) {
    for (size_t index = 0; index + 1 < size; index += 2) {
        sum += ((uint32_t)packet[index] << 8) | packet[index + 1];
    }
    if ((size & 1u) != 0) sum += (uint32_t)packet[size - 1] << 8;
    return sum;
}

static uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t read_be32(const unsigned char* data) {
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
        ((uint32_t)data[2] << 8) | data[3];
}

static void write_be32(unsigned char* data, uint32_t value) {
    data[0] = (unsigned char)(value >> 24);
    data[1] = (unsigned char)(value >> 16);
    data[2] = (unsigned char)(value >> 8);
    data[3] = (unsigned char)value;
}

static void prepare_udp_packet(unsigned char* packet, uint32_t size, uint16_t sequence) {
    memset(packet, 0, size);
    packet[0] = 0x45;
    packet[2] = (unsigned char)(size >> 8);
    packet[3] = (unsigned char)size;
    packet[4] = (unsigned char)(sequence >> 8);
    packet[5] = (unsigned char)sequence;
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = 192;
    packet[13] = 0;
    packet[14] = 2;
    packet[15] = 2;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 2;
    packet[20] = 0x9c;
    packet[21] = 0x40;
    packet[22] = 0x9c;
    packet[23] = 0x41;
    uint16_t udp_size = (uint16_t)(size - 20);
    packet[24] = (unsigned char)(udp_size >> 8);
    packet[25] = (unsigned char)udp_size;
    uint16_t checksum = ipv4_checksum(packet, 20);
    packet[10] = (unsigned char)(checksum >> 8);
    packet[11] = (unsigned char)checksum;
}

static void prepare_tcp_packet(
    unsigned char* packet,
    uint32_t size,
    uint16_t ip_id,
    uint32_t sequence) {
    memset(packet, 0, size);
    packet[0] = 0x45;
    packet[2] = (unsigned char)(size >> 8);
    packet[3] = (unsigned char)size;
    packet[4] = (unsigned char)(ip_id >> 8);
    packet[5] = (unsigned char)ip_id;
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 6;
    packet[12] = 192;
    packet[13] = 0;
    packet[14] = 2;
    packet[15] = 2;
    packet[16] = 198;
    packet[17] = 51;
    packet[18] = 100;
    packet[19] = 2;

    unsigned char* tcp = packet + 20;
    tcp[0] = 0x9c;
    tcp[1] = 0x40;
    tcp[2] = 0x9c;
    tcp[3] = 0x41;
    tcp[4] = (unsigned char)(sequence >> 24);
    tcp[5] = (unsigned char)(sequence >> 16);
    tcp[6] = (unsigned char)(sequence >> 8);
    tcp[7] = (unsigned char)sequence;
    tcp[11] = 1;
    tcp[12] = 5u << 4;
    tcp[13] = 0x10;
    tcp[14] = 0x80;
    for (uint32_t index = 40; index < size; ++index) {
        packet[index] = (unsigned char)(sequence + index);
    }

    uint16_t checksum = ipv4_checksum(packet, 20);
    packet[10] = (unsigned char)(checksum >> 8);
    packet[11] = (unsigned char)checksum;
    uint32_t tcp_size = size - 20;
    uint32_t tcp_sum = checksum_add(0, packet + 12, 8);
    tcp_sum += 6;
    tcp_sum += tcp_size;
    tcp_sum = checksum_add(tcp_sum, tcp, tcp_size);
    checksum = checksum_finish(tcp_sum);
    tcp[16] = (unsigned char)(checksum >> 8);
    tcp[17] = (unsigned char)checksum;
}

static int prepare_syn_ack(
    const unsigned char* syn,
    uint32_t syn_size,
    unsigned char response[40]) {
    if (syn_size < 40 || syn[0] >> 4 != 4 || syn[9] != 6 ||
        (syn[33] & 0x02) == 0) {
        return 0;
    }
    memset(response, 0, 40);
    response[0] = 0x45;
    response[3] = 40;
    response[4] = 0x12;
    response[5] = 0x34;
    response[6] = 0x40;
    response[8] = 64;
    response[9] = 6;
    memcpy(response + 12, syn + 16, 4);
    memcpy(response + 16, syn + 12, 4);

    unsigned char* tcp = response + 20;
    memcpy(tcp, syn + 22, 2);
    memcpy(tcp + 2, syn + 20, 2);
    write_be32(tcp + 4, 5000);
    write_be32(tcp + 8, read_be32(syn + 24) + 1);
    tcp[12] = 5u << 4;
    tcp[13] = 0x12;
    tcp[14] = 0x80;

    uint16_t checksum = ipv4_checksum(response, 20);
    response[10] = (unsigned char)(checksum >> 8);
    response[11] = (unsigned char)checksum;
    uint32_t tcp_sum = checksum_add(0, response + 12, 8);
    tcp_sum += 6 + 20;
    tcp_sum = checksum_add(tcp_sum, tcp, 20);
    checksum = checksum_finish(tcp_sum);
    tcp[16] = (unsigned char)(checksum >> 8);
    tcp[17] = (unsigned char)checksum;
    return 1;
}

static int prepare_peer_tcp_data(
    const unsigned char* syn,
    uint32_t syn_size,
    unsigned char* packet,
    uint32_t packet_size,
    uint16_t ip_id,
    uint32_t sequence,
    unsigned char payload_value) {
    if (syn_size < 40 || packet_size <= 40 || packet_size > UINT16_MAX) return 0;
    memset(packet, 0, packet_size);
    packet[0] = 0x45;
    packet[2] = (unsigned char)(packet_size >> 8);
    packet[3] = (unsigned char)packet_size;
    packet[4] = (unsigned char)(ip_id >> 8);
    packet[5] = (unsigned char)ip_id;
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 6;
    memcpy(packet + 12, syn + 16, 4);
    memcpy(packet + 16, syn + 12, 4);

    unsigned char* tcp = packet + 20;
    memcpy(tcp, syn + 22, 2);
    memcpy(tcp + 2, syn + 20, 2);
    write_be32(tcp + 4, sequence);
    write_be32(tcp + 8, read_be32(syn + 24) + 1);
    tcp[12] = 5u << 4;
    tcp[13] = 0x10;
    tcp[14] = 0x80;
    memset(packet + 40, payload_value, packet_size - 40);

    uint16_t checksum = ipv4_checksum(packet, 20);
    packet[10] = (unsigned char)(checksum >> 8);
    packet[11] = (unsigned char)checksum;
    uint32_t tcp_size = packet_size - 20;
    uint32_t tcp_sum = checksum_add(0, packet + 12, 8);
    tcp_sum += 6 + tcp_size;
    tcp_sum = checksum_add(tcp_sum, tcp, tcp_size);
    checksum = checksum_finish(tcp_sum);
    tcp[16] = (unsigned char)(checksum >> 8);
    tcp[17] = (unsigned char)checksum;
    return 1;
}

static int test_native_gso_read(void) {
    TapTunOptions options;
    memset(&options, 0, sizeof(options));
    options.name = "tungso0";
    options.mode = TAPTUN_MODE_TUN;
    TapTunPerformanceOptions performance;
    memset(&performance, 0, sizeof(performance));
    performance.struct_size = sizeof(performance);
    performance.required_features = TAPTUN_PERF_GSO;

    TapTunDevice* device = TapTun_OpenWithPerformance(&options, &performance);
    if (!device) return 1;
    int result = TapTun_SetIPAddressV4(device, "10.77.0.1", 24);
    if (result == TAPTUN_OK) result = TapTun_Activate(device);
    if (result != TAPTUN_OK ||
        (TapTun_GetCapabilities(device) & TAPTUN_CAP_GSO) == 0) {
        TapTun_Close(device);
        return 1;
    }

    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client < 0 || fcntl(client, F_SETFL, O_NONBLOCK) != 0) {
        if (client >= 0) close(client);
        TapTun_Close(device);
        return 1;
    }
    struct sockaddr_in peer;
    memset(&peer, 0, sizeof(peer));
    peer.sin_family = AF_INET;
    peer.sin_port = htons(19000);
    inet_pton(AF_INET, "10.77.0.2", &peer.sin_addr);
    if (connect(client, (struct sockaddr*)&peer, sizeof(peer)) == 0 || errno != EINPROGRESS) {
        close(client);
        TapTun_Close(device);
        return 1;
    }

    unsigned char handshake_packet[2048];
    TapTunBuffer handshake = { handshake_packet, sizeof(handshake_packet), 0 };
    int packet_count = TapTun_ReadBatch(device, &handshake, 1);
    unsigned char saved_syn[128];
    uint32_t saved_syn_size = handshake.size < sizeof(saved_syn)
        ? handshake.size
        : sizeof(saved_syn);
    memcpy(saved_syn, handshake.data, saved_syn_size);
    unsigned char syn_ack[40];
    if (packet_count != 1 ||
        !prepare_syn_ack(handshake.data, handshake.size, syn_ack) ||
        TapTun_Write(device, syn_ack, sizeof(syn_ack)) != (int)sizeof(syn_ack)) {
        close(client);
        TapTun_Close(device);
        return 1;
    }

    struct pollfd client_poll = { client, POLLOUT, 0 };
    int socket_error = 0;
    socklen_t socket_error_size = sizeof(socket_error);
    if (poll(&client_poll, 1, 1000) != 1 ||
        getsockopt(client, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_size) != 0 ||
        socket_error != 0) {
        close(client);
        TapTun_Close(device);
        return 1;
    }

    // Drain the final handshake ACK before measuring the first data burst.
    handshake.size = 0;
    if (TapTun_ReadBatch(device, &handshake, 1) != 1) {
        close(client);
        TapTun_Close(device);
        return 1;
    }
    unsigned char application_data[65536];
    memset(application_data, 0x5a, sizeof(application_data));
    if (send(client, application_data, sizeof(application_data), 0) < 4096) {
        close(client);
        TapTun_Close(device);
        return 1;
    }

    unsigned char packet_storage[64][2048];
    TapTunBuffer packets[64];
    for (uint32_t index = 0; index < 64; ++index) {
        packets[index].data = packet_storage[index];
        packets[index].capacity = sizeof(packet_storage[index]);
        packets[index].size = 0;
    }
    packet_count = TapTun_ReadBatch(device, packets, 64);
    if (packet_count <= 1) {
        close(client);
        TapTun_Close(device);
        fprintf(stderr, "Expected a GSO burst, got %d packet(s).\n", packet_count);
        return 1;
    }

    unsigned char peer_packets[4][1400];
    TapTunBuffer peer_batch[4];
    for (uint32_t index = 0; index < 4; ++index) {
        if (!prepare_peer_tcp_data(
                saved_syn,
                saved_syn_size,
                peer_packets[index],
                sizeof(peer_packets[index]),
                (uint16_t)(200 + index),
                5001 + index * 1360,
                (unsigned char)(0x40 + index))) {
            close(client);
            TapTun_Close(device);
            return 1;
        }
        peer_batch[index].data = peer_packets[index];
        peer_batch[index].capacity = sizeof(peer_packets[index]);
        peer_batch[index].size = sizeof(peer_packets[index]);
    }
    if (TapTun_WriteBatch(device, peer_batch, 4) != 4) {
        close(client);
        TapTun_Close(device);
        return 1;
    }

    client_poll.events = POLLIN;
    client_poll.revents = 0;
    unsigned char received[4 * 1360];
    size_t received_size = 0;
    while (received_size < sizeof(received)) {
        if (poll(&client_poll, 1, 1000) != 1) break;
        ssize_t bytes = recv(
            client,
            received + received_size,
            sizeof(received) - received_size,
            0);
        if (bytes <= 0) break;
        received_size += (size_t)bytes;
    }
    close(client);
    TapTun_Close(device);
    if (received_size != sizeof(received)) {
        fprintf(stderr, "TCP socket received %zu of %zu GRO bytes.\n",
            received_size, sizeof(received));
        return 1;
    }
    for (uint32_t index = 0; index < 4; ++index) {
        for (uint32_t offset = 0; offset < 1360; ++offset) {
            if (received[index * 1360 + offset] != (unsigned char)(0x40 + index)) return 1;
        }
    }
    printf(
        "Native GSO read split one kernel super-packet into %d TCP packets; GRO delivered %zu bytes.\n",
        packet_count,
        received_size);
    return 0;
}

static int test_native_performance(void) {
    TapTunOptions options;
    memset(&options, 0, sizeof(options));
    options.name = "tunperf0";
    options.mode = TAPTUN_MODE_TUN;

    TapTunPerformanceOptions performance;
    memset(&performance, 0, sizeof(performance));
    performance.struct_size = sizeof(performance);
    performance.required_features =
        TAPTUN_PERF_IO_URING_SEND | TAPTUN_PERF_MULTI_QUEUE | TAPTUN_PERF_GSO;
    performance.queue_count = 4;
    performance.send_queue_depth = 32;

    TapTunDevice* device = TapTun_OpenWithPerformance(&options, &performance);
    if (!device) {
        fprintf(stderr,
            "Failed to create performance TUN: system_error=%u.\n",
            TapTun_GetLastSystemError());
        return 1;
    }
    uint32_t expected_capabilities = TAPTUN_CAP_ZERO_COPY_SEND |
        TAPTUN_CAP_IO_URING_SEND | TAPTUN_CAP_MULTI_QUEUE | TAPTUN_CAP_GSO;
    if ((TapTun_GetCapabilities(device) & expected_capabilities) != expected_capabilities ||
        TapTun_GetQueueCount(device) != 4) {
        fprintf(stderr,
            "Unexpected performance capabilities=0x%08x queues=%u.\n",
            TapTun_GetCapabilities(device),
            TapTun_GetQueueCount(device));
        TapTun_Close(device);
        return 1;
    }
    if (TapTun_Activate(device) != TAPTUN_OK) {
        fprintf(stderr,
            "Failed to activate performance TUN: system_error=%u.\n",
            TapTun_GetLastSystemError());
        TapTun_Close(device);
        return 1;
    }

    unsigned char tcp_packets[4][1400];
    TapTunBuffer tcp_batch[4];
    for (uint32_t index = 0; index < 4; ++index) {
        prepare_tcp_packet(tcp_packets[index], sizeof(tcp_packets[index]),
            (uint16_t)(100 + index), 1000 + index * 1360);
        tcp_batch[index].data = tcp_packets[index];
        tcp_batch[index].capacity = sizeof(tcp_packets[index]);
        tcp_batch[index].size = sizeof(tcp_packets[index]);
    }
    if (TapTun_WriteBatch(device, tcp_batch, 4) != 4) {
        fprintf(stderr,
            "GSO batch write failed: system_error=%u.\n",
            TapTun_GetLastSystemError());
        TapTun_Close(device);
        return 1;
    }

    for (uint32_t index = 0; index < 256; ++index) {
        TapTunPacket packet;
        memset(&packet, 0, sizeof(packet));
        int result;
        do {
            result = TapTun_AcquireSend(device, 1400, &packet);
            if (result == TAPTUN_ERROR_BUSY) sched_yield();
        } while (result == TAPTUN_ERROR_BUSY);
        if (result != TAPTUN_OK || !packet.data || packet.size != 1400) {
            fprintf(stderr,
                "AcquireSend failed at packet %u: result=%d system_error=%u.\n",
                index,
                result,
                TapTun_GetLastSystemError());
            TapTun_Close(device);
            return 1;
        }

        prepare_udp_packet(packet.data, packet.size, (uint16_t)index);
        if (index == 0) {
            TapTunPacket invalid = packet;
            ++invalid.data;
            if (TapTun_CommitSend(device, &invalid) != TAPTUN_ERROR_INVALID_ARGUMENT) {
                fprintf(stderr, "CommitSend accepted an invalid lease.\n");
                TapTun_Close(device);
                return 1;
            }
        }
        result = TapTun_CommitSend(device, &packet);
        if (result != TAPTUN_OK ||
            packet.data != NULL || packet.size != 0 || packet.backend_token != NULL) {
            fprintf(stderr,
                "CommitSend failed at packet %u: result=%d system_error=%u.\n",
                index,
                result,
                TapTun_GetLastSystemError());
            TapTun_Close(device);
            return 1;
        }
    }

    // An acquired but uncommitted slot is intentionally reclaimed by Close.
    TapTunPacket final_packet;
    memset(&final_packet, 0, sizeof(final_packet));
    int result;
    do {
        result = TapTun_AcquireSend(device, 1400, &final_packet);
        if (result == TAPTUN_ERROR_BUSY) sched_yield();
    } while (result == TAPTUN_ERROR_BUSY);
    TapTun_Close(device);
    if (result != TAPTUN_OK) {
        fprintf(stderr,
            "Final AcquireSend failed: result=%d system_error=%u.\n",
            result,
            TapTun_GetLastSystemError());
        return 1;
    }
    printf("Native performance TUN queues=4 io_uring=fixed-buffer gso=tcp\n");
    return 0;
}

static int test_emulated_tap(void) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0) return 1;
    TapTunHandleOptions options;
    memset(&options, 0, sizeof(options));
    options.handle = sockets[0];
    options.name = "host-tap";
    options.take_ownership = 1;
    options.backend_mode = TAPTUN_MODE_TUN;
    options.mode = TAPTUN_MODE_TAP;
    TapTunDevice* device = TapTun_OpenFromHandle(&options);
    if (!device || TapTun_GetMode(device) != TAPTUN_MODE_TAP ||
        TapTun_GetCapabilities(device) != TAPTUN_CAP_EMULATED_TAP) {
        if (device) TapTun_Close(device);
        close(sockets[1]);
        return 1;
    }

    const unsigned char ip_packet[20] = { 0x45, 0, 0, 20 };
    unsigned char frame[64];
    if (write(sockets[1], ip_packet, sizeof(ip_packet)) != (ssize_t)sizeof(ip_packet) ||
        TapTun_Read(device, frame, sizeof(frame)) != 34 ||
        frame[12] != 0x08 || frame[13] != 0x00 ||
        memcmp(frame + 14, ip_packet, sizeof(ip_packet)) != 0 ||
        TapTun_Write(device, frame, 34) != 34) {
        TapTun_Close(device);
        close(sockets[1]);
        return 1;
    }
    unsigned char decoded[32];
    int result = read(sockets[1], decoded, sizeof(decoded)) == (ssize_t)sizeof(ip_packet) &&
        memcmp(decoded, ip_packet, sizeof(ip_packet)) == 0;
    unsigned char arp_request[42] = { 0 };
    memset(arp_request, 0xff, 6);
    const unsigned char requester_mac[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    memcpy(arp_request + 6, requester_mac, 6);
    arp_request[12] = 0x08;
    arp_request[13] = 0x06;
    arp_request[15] = 0x01;
    arp_request[16] = 0x08;
    arp_request[18] = 6;
    arp_request[19] = 4;
    arp_request[21] = 1;
    memcpy(arp_request + 22, requester_mac, 6);
    arp_request[28] = 10;
    arp_request[31] = 1;
    arp_request[38] = 10;
    arp_request[41] = 2;
    result = result && TapTun_Write(device, arp_request, sizeof(arp_request)) ==
        (int)sizeof(arp_request) && TapTun_Read(device, frame, sizeof(frame)) == 42 &&
        frame[20] == 0 && frame[21] == 2 && memcmp(frame, requester_mac, 6) == 0;
    TapTun_Close(device);
    close(sockets[1]);
    return result ? 0 : 1;
}

int main(int argc, char** argv) {
    TapTunPerformanceOptions invalid_performance;
    memset(&invalid_performance, 0, sizeof(invalid_performance));
    if (TapTun_OpenWithPerformance(NULL, &invalid_performance) != NULL || errno != EINVAL) {
        fprintf(stderr, "Invalid performance options were accepted.\n");
        return 1;
    }
    if (test_external_handle() != 0) {
        fprintf(stderr, "External-handle TUN test failed.\n");
        return 1;
    }
    if (test_emulated_tap() != 0) {
        fprintf(stderr, "External-handle emulated TAP test failed.\n");
        return 1;
    }
    if (argc > 1 && strcmp(argv[1], "--native") == 0) {
        return test_native_device(TAPTUN_MODE_TUN);
    }
    if (argc > 1 && strcmp(argv[1], "--native-tap") == 0) {
        return test_native_device(TAPTUN_MODE_TAP);
    }
    if (argc > 1 && strcmp(argv[1], "--native-performance") == 0) {
        return test_native_performance();
    }
    if (argc > 1 && strcmp(argv[1], "--native-gso-read") == 0) {
        return test_native_gso_read();
    }
    printf("External-handle TUN test passed.\n");
    return 0;
}
