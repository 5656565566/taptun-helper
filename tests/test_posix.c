#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/taptun_api.h"

typedef struct {
    unsigned char written[32];
    int written_size;
    int closed;
    int interrupted;
} CallbackContext;

static int callback_read(void* context, unsigned char* buffer, int buffer_size) {
    (void)context;
    const unsigned char packet[] = { 0x60, 0x00, 0x00, 0x00 };
    if (buffer_size < (int)sizeof(packet)) return TAPTUN_ERROR_BUFFER_TOO_SMALL;
    memcpy(buffer, packet, sizeof(packet));
    return sizeof(packet);
}

static int callback_write(void* context, const unsigned char* data, int data_size) {
    CallbackContext* callback_context = (CallbackContext*)context;
    if (data_size > (int)sizeof(callback_context->written)) return TAPTUN_ERROR_BUFFER_TOO_SMALL;
    memcpy(callback_context->written, data, (size_t)data_size);
    callback_context->written_size = data_size;
    return data_size;
}

static void callback_close(void* context) {
    ((CallbackContext*)context)->closed = 1;
}

static void callback_interrupt_read(void* context) {
    ((CallbackContext*)context)->interrupted = 1;
}

int main(void) {
    TapTunPerformanceOptions performance;
    memset(&performance, 0, sizeof(performance));
    performance.struct_size = sizeof(performance);
    performance.required_features = TAPTUN_PERF_IO_URING_SEND;
    if (TapTun_OpenWithPerformance(NULL, &performance) != NULL) return 1;

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0) return 1;
    TapTunHandleOptions handle_options;
    memset(&handle_options, 0, sizeof(handle_options));
    handle_options.handle = sockets[0];
    handle_options.name = "external-tun";
    handle_options.take_ownership = 1;
    TapTunDevice* device = TapTun_OpenFromHandle(&handle_options);
    if (!device) return 1;

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

    const unsigned char packet[] = { 0x45, 0x00, 0x00, 0x14 };
    unsigned char received[32];
    int result = write(sockets[1], packet, sizeof(packet)) == (ssize_t)sizeof(packet) &&
                 TapTun_Read(device, received, sizeof(received)) == (int)sizeof(packet) &&
                 memcmp(packet, received, sizeof(packet)) == 0;
    TapTun_Close(device);
    close(sockets[1]);

    CallbackContext context;
    memset(&context, 0, sizeof(context));
    TapTunCallbackOptions options;
    memset(&options, 0, sizeof(options));
    options.context = &context;
    options.read = callback_read;
    options.write = callback_write;
    options.close = callback_close;
    options.name = "callback-tun";
    device = TapTun_OpenFromCallbacks(&options);
    if (!device || TapTun_Read(device, received, sizeof(received)) != 4 ||
        TapTun_Write(device, packet, sizeof(packet)) != (int)sizeof(packet)) {
        if (device) TapTun_Close(device);
        return 1;
    }
    TapTunBuffer callback_batch[2] = {
        { received, sizeof(received), sizeof(packet) },
        { received, sizeof(received), sizeof(packet) }
    };
    if (TapTun_ReadBatch(device, callback_batch, 2) != 1 ||
        callback_batch[0].size != sizeof(packet)) {
        TapTun_Close(device);
        return 1;
    }
    callback_batch[0].size = sizeof(packet);
    callback_batch[1].size = sizeof(packet);
    if (TapTun_WriteBatch(device, callback_batch, 2) != 2) {
        TapTun_Close(device);
        return 1;
    }
    TapTun_Close(device);
    result = result && context.closed && context.written_size == (int)sizeof(packet);

    memset(&context, 0, sizeof(context));
    memset(&options, 0, sizeof(options));
    options.context = &context;
    options.read = callback_read;
    options.write = callback_write;
    options.close = callback_close;
    options.interrupt_read = callback_interrupt_read;
    options.name = "callback-tap";
    options.backend_mode = TAPTUN_MODE_TUN;
    options.mode = TAPTUN_MODE_TAP;
    device = TapTun_OpenFromCallbacks(&options);
    if (!device) return 1;
    unsigned char arp_request[42] = { 0 };
    const unsigned char requester_mac[6] = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };
    memset(arp_request, 0xff, 6);
    memcpy(arp_request + 6, requester_mac, 6);
    arp_request[12] = 0x08;
    arp_request[13] = 0x06;
    arp_request[15] = 1;
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
        (int)sizeof(arp_request) && context.interrupted &&
        TapTun_Read(device, received, sizeof(received)) == TAPTUN_ERROR_BUFFER_TOO_SMALL;
    unsigned char arp_reply[64];
    result = result && TapTun_Read(device, arp_reply, sizeof(arp_reply)) == 42 &&
        memcmp(arp_reply, requester_mac, 6) == 0 && arp_reply[20] == 0 && arp_reply[21] == 2;
    TapTun_Close(device);
    result = result && context.closed;
    printf("External TUN tests %s.\n", result ? "passed" : "failed");
    return result ? 0 : 1;
}
