#include "taptun_api.h"
#include "tun2tap.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct TapTunDevice {
    int fd;
    int owns_fd;
    int uses_callbacks;
    TapTunCallbackOptions callbacks;
    int cancel_pipe[2];
    unsigned int if_index;
    char if_name[256];
    TapTunMode mode;
    TapTunMode backend_mode;
    int emulates_tap;
    TapTunTun2Tap tun2tap;
    unsigned char synthetic_frames[8][TAPTUN_SYNTHETIC_FRAME_SIZE];
    int synthetic_sizes[8];
    unsigned int synthetic_head;
    unsigned int synthetic_count;
    unsigned char* read_packet;
    unsigned char* write_packet;
    pthread_mutex_t state_lock;
    pthread_mutex_t write_lock;
    pthread_cond_t state_condition;
    unsigned int active_operations;
    int active_read;
    int closing;
};

static int begin_operation(TapTunDevice* device) {
    pthread_mutex_lock(&device->state_lock);
    if (device->closing) {
        pthread_mutex_unlock(&device->state_lock);
        return TAPTUN_ERROR_CLOSED;
    }
    ++device->active_operations;
    pthread_mutex_unlock(&device->state_lock);
    return TAPTUN_OK;
}

static void end_operation(TapTunDevice* device) {
    pthread_mutex_lock(&device->state_lock);
    --device->active_operations;
    pthread_cond_broadcast(&device->state_condition);
    pthread_mutex_unlock(&device->state_lock);
}

static int begin_read_operation(TapTunDevice* device) {
    pthread_mutex_lock(&device->state_lock);
    if (device->closing) {
        pthread_mutex_unlock(&device->state_lock);
        return TAPTUN_ERROR_CLOSED;
    }
    if (device->active_read) {
        pthread_mutex_unlock(&device->state_lock);
        return TAPTUN_ERROR_BUSY;
    }
    device->active_read = 1;
    ++device->active_operations;
    pthread_mutex_unlock(&device->state_lock);
    return TAPTUN_OK;
}

static void end_read_operation(TapTunDevice* device) {
    pthread_mutex_lock(&device->state_lock);
    device->active_read = 0;
    --device->active_operations;
    pthread_cond_broadcast(&device->state_condition);
    pthread_mutex_unlock(&device->state_lock);
}

TapTunDevice* TapTun_Open(const TapTunOptions* options) {
    (void)options;
    return NULL;
}

TapTunDevice* TapTun_OpenWithPerformance(
    const TapTunOptions* options,
    const TapTunPerformanceOptions* performance_options) {
    if (performance_options) {
        uint32_t requested = performance_options->preferred_features |
            performance_options->required_features;
        if (performance_options->struct_size < sizeof(TapTunPerformanceOptions) ||
            ((requested & TAPTUN_PERF_MULTI_QUEUE) != 0 &&
             performance_options->queue_count < 2)) {
            errno = EINVAL;
            return NULL;
        }
        if (performance_options->required_features != 0) {
            errno = ENOTSUP;
            return NULL;
        }
    }
    return TapTun_Open(options);
}

TapTunDevice* TapTun_OpenFromHandle(const TapTunHandleOptions* options) {
    if (!options || options->handle < 0 ||
        (options->backend_mode != TAPTUN_MODE_TUN && options->backend_mode != TAPTUN_MODE_TAP) ||
        (options->mode != TAPTUN_MODE_TUN && options->mode != TAPTUN_MODE_TAP) ||
        (options->mode == TAPTUN_MODE_TUN && options->backend_mode != TAPTUN_MODE_TUN)) {
        errno = EINVAL;
        return NULL;
    }
    TapTunDevice* device = (TapTunDevice*)calloc(1, sizeof(TapTunDevice));
    if (!device) return NULL;
    device->fd = (int)options->handle;
    device->cancel_pipe[0] = -1;
    device->cancel_pipe[1] = -1;
    device->owns_fd = options->take_ownership != 0;
    device->if_index = options->if_index;
    device->backend_mode = options->backend_mode;
    device->mode = options->mode;
    device->emulates_tap = options->mode == TAPTUN_MODE_TAP &&
        options->backend_mode == TAPTUN_MODE_TUN;
    if (options->name) strncpy(device->if_name, options->name, sizeof(device->if_name) - 1);
    if (device->emulates_tap) {
        device->read_packet = (unsigned char*)malloc(TAPTUN_MAX_IP_PACKET_SIZE);
        device->write_packet = (unsigned char*)malloc(TAPTUN_MAX_IP_PACKET_SIZE);
        if (!device->read_packet || !device->write_packet) {
            free(device->read_packet);
            free(device->write_packet);
            free(device);
            return NULL;
        }
        taptun_tun2tap_init(
            &device->tun2tap,
            options->interface_mac,
            options->peer_mac,
            options->name,
            options->if_index);
    }
    if (pipe(device->cancel_pipe) != 0) {
        free(device->read_packet);
        free(device->write_packet);
        free(device);
        return NULL;
    }
    if (pthread_mutex_init(&device->state_lock, NULL) != 0) {
        close(device->cancel_pipe[0]);
        close(device->cancel_pipe[1]);
        free(device->read_packet);
        free(device->write_packet);
        free(device);
        return NULL;
    }
    if (pthread_mutex_init(&device->write_lock, NULL) != 0) {
        pthread_mutex_destroy(&device->state_lock);
        close(device->cancel_pipe[0]);
        close(device->cancel_pipe[1]);
        free(device->read_packet);
        free(device->write_packet);
        free(device);
        return NULL;
    }
    if (pthread_cond_init(&device->state_condition, NULL) != 0) {
        pthread_mutex_destroy(&device->write_lock);
        pthread_mutex_destroy(&device->state_lock);
        close(device->cancel_pipe[0]);
        close(device->cancel_pipe[1]);
        free(device->read_packet);
        free(device->write_packet);
        free(device);
        return NULL;
    }
    return device;
}

TapTunDevice* TapTun_OpenFromCallbacks(const TapTunCallbackOptions* options) {
    if (!options || !options->read || !options->write || !options->close) return NULL;
    if ((options->backend_mode != TAPTUN_MODE_TUN && options->backend_mode != TAPTUN_MODE_TAP) ||
        (options->mode != TAPTUN_MODE_TUN && options->mode != TAPTUN_MODE_TAP) ||
        (options->mode == TAPTUN_MODE_TUN && options->backend_mode != TAPTUN_MODE_TUN) ||
        (options->mode == TAPTUN_MODE_TAP && options->backend_mode == TAPTUN_MODE_TUN &&
         !options->interrupt_read)) {
        errno = EINVAL;
        return NULL;
    }
    TapTunHandleOptions handle_options;
    memset(&handle_options, 0, sizeof(handle_options));
    handle_options.handle = 0;
    handle_options.name = options->name;
    handle_options.if_index = options->if_index;
    handle_options.backend_mode = options->backend_mode;
    handle_options.mode = options->mode;
    memcpy(handle_options.interface_mac, options->interface_mac, 6);
    memcpy(handle_options.peer_mac, options->peer_mac, 6);
    TapTunDevice* device = TapTun_OpenFromHandle(&handle_options);
    if (!device) return NULL;
    device->fd = -1;
    device->uses_callbacks = 1;
    device->callbacks = *options;
    return device;
}

const char* TapTun_GetName(const TapTunDevice* device) {
    return device ? device->if_name : NULL;
}

unsigned int TapTun_GetIndex(const TapTunDevice* device) {
    return device ? device->if_index : 0;
}

uint32_t TapTun_GetQueueCount(const TapTunDevice* device) {
    return device ? 1u : 0u;
}

TapTunMode TapTun_GetMode(const TapTunDevice* device) {
    return device ? device->mode : TAPTUN_MODE_TUN;
}

int TapTun_GetMacAddress(const TapTunDevice* device, unsigned char mac_address[6]) {
    if (!device || !mac_address) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (!device->emulates_tap) return TAPTUN_ERROR_UNSUPPORTED;
    memcpy(mac_address, device->tun2tap.interface_mac, 6);
    return TAPTUN_OK;
}

uint32_t TapTun_GetLastSystemError(void) {
    return (uint32_t)errno;
}

uint32_t TapTun_GetCapabilities(const TapTunDevice* device) {
    if (!device || device->mode != TAPTUN_MODE_TAP) return 0;
    return device->emulates_tap ? TAPTUN_CAP_EMULATED_TAP : TAPTUN_CAP_NATIVE_TAP;
}

int TapTun_AcquireReceive(TapTunDevice* device, TapTunPacket* packet) {
    if (!device || !packet) return TAPTUN_ERROR_INVALID_ARGUMENT;
    return TAPTUN_ERROR_UNSUPPORTED;
}

int TapTun_ReleaseReceive(TapTunDevice* device, TapTunPacket* packet) {
    return device && packet ? TAPTUN_ERROR_UNSUPPORTED : TAPTUN_ERROR_INVALID_ARGUMENT;
}

int TapTun_AcquireSend(TapTunDevice* device, uint32_t packet_size, TapTunPacket* packet) {
    if (!device || !packet || packet_size == 0) return TAPTUN_ERROR_INVALID_ARGUMENT;
    return TAPTUN_ERROR_UNSUPPORTED;
}

int TapTun_CommitSend(TapTunDevice* device, TapTunPacket* packet) {
    return device && packet ? TAPTUN_ERROR_UNSUPPORTED : TAPTUN_ERROR_INVALID_ARGUMENT;
}

int TapTun_Activate(TapTunDevice* device) {
    return device ? TAPTUN_ERROR_UNSUPPORTED : TAPTUN_ERROR_INVALID_ARGUMENT;
}

int TapTun_SetIPAddressV4(TapTunDevice* device, const char* address, unsigned int prefix_length) {
    if (!device || !address || prefix_length > 32) return TAPTUN_ERROR_INVALID_ARGUMENT;
    return TAPTUN_ERROR_UNSUPPORTED;
}

int TapTun_SetIPAddressV6(TapTunDevice* device, const char* address, unsigned int prefix_length) {
    if (!device || !address || prefix_length > 128) return TAPTUN_ERROR_INVALID_ARGUMENT;
    return TAPTUN_ERROR_UNSUPPORTED;
}

static int dequeue_synthetic_frame(
    TapTunDevice* device,
    unsigned char* buffer,
    int buffer_size) {
    pthread_mutex_lock(&device->state_lock);
    if (device->synthetic_count == 0) {
        pthread_mutex_unlock(&device->state_lock);
        return 0;
    }
    unsigned int index = device->synthetic_head;
    int frame_size = device->synthetic_sizes[index];
    if (buffer_size < frame_size) {
        pthread_mutex_unlock(&device->state_lock);
        return TAPTUN_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer, device->synthetic_frames[index], (size_t)frame_size);
    device->synthetic_head = (index + 1) % 8;
    --device->synthetic_count;
    pthread_mutex_unlock(&device->state_lock);
    return frame_size;
}

static int enqueue_synthetic_frame(
    TapTunDevice* device,
    const unsigned char* frame,
    int frame_size) {
    pthread_mutex_lock(&device->state_lock);
    if (device->closing) {
        pthread_mutex_unlock(&device->state_lock);
        return TAPTUN_ERROR_CLOSED;
    }
    if (device->synthetic_count == 8) {
        pthread_mutex_unlock(&device->state_lock);
        return TAPTUN_ERROR_BUSY;
    }
    unsigned int index = (device->synthetic_head + device->synthetic_count) % 8;
    memcpy(device->synthetic_frames[index], frame, (size_t)frame_size);
    device->synthetic_sizes[index] = frame_size;
    ++device->synthetic_count;
    pthread_mutex_unlock(&device->state_lock);
    if (device->uses_callbacks) {
        device->callbacks.interrupt_read(device->callbacks.context);
    } else {
        (void)write(device->cancel_pipe[1], "w", 1);
    }
    return TAPTUN_OK;
}

static int read_backend_packet(
    TapTunDevice* device,
    unsigned char* buffer,
    int buffer_size) {
    if (device->uses_callbacks) {
        return device->callbacks.read(device->callbacks.context, buffer, buffer_size);
    }
    ssize_t bytes_read = read(device->fd, buffer, (size_t)buffer_size);
    return bytes_read >= 0 ? (int)bytes_read : TAPTUN_ERROR;
}

static int write_backend_packet(
    TapTunDevice* device,
    const unsigned char* data,
    int data_size) {
    if (device->uses_callbacks) {
        return device->callbacks.write(device->callbacks.context, data, data_size);
    }
    ssize_t bytes_written = write(device->fd, data, (size_t)data_size);
    return bytes_written >= 0 ? (int)bytes_written : TAPTUN_ERROR;
}

int TapTun_Read(TapTunDevice* device, unsigned char* buffer, int buffer_size) {
    if (!device || !buffer || buffer_size <= 0) return TAPTUN_ERROR_INVALID_ARGUMENT;
    int result = begin_read_operation(device);
    if (result != TAPTUN_OK) return result;
    for (;;) {
        if (device->emulates_tap) {
            result = dequeue_synthetic_frame(device, buffer, buffer_size);
            if (result != 0) break;
        }
        pthread_mutex_lock(&device->state_lock);
        int closing = device->closing;
        pthread_mutex_unlock(&device->state_lock);
        if (closing) {
            result = TAPTUN_ERROR_CLOSED;
            break;
        }
        if (!device->uses_callbacks) {
            struct pollfd poll_fds[2] = {
                { device->fd, POLLIN, 0 },
                { device->cancel_pipe[0], POLLIN, 0 }
            };
            do {
                result = poll(poll_fds, 2, -1);
            } while (result < 0 && errno == EINTR);
            if (result <= 0) {
                result = TAPTUN_ERROR;
                break;
            }
            if ((poll_fds[1].revents & POLLIN) != 0) {
                char signal;
                (void)read(device->cancel_pipe[0], &signal, 1);
                pthread_mutex_lock(&device->state_lock);
                closing = device->closing;
                pthread_mutex_unlock(&device->state_lock);
                if (closing) {
                    result = TAPTUN_ERROR_CLOSED;
                    break;
                }
                continue;
            }
            if ((poll_fds[0].revents & POLLIN) == 0) {
                result = TAPTUN_ERROR;
                break;
            }
        }
        unsigned char* target = device->emulates_tap ? device->read_packet : buffer;
        int capacity = device->emulates_tap ? TAPTUN_MAX_IP_PACKET_SIZE : buffer_size;
        result = read_backend_packet(device, target, capacity);
        if (device->emulates_tap && result == TAPTUN_ERROR_BUSY) continue;
        if (result <= 0 || !device->emulates_tap) break;
        result = taptun_tun2tap_encapsulate(
            &device->tun2tap,
            target,
            result,
            buffer,
            buffer_size);
        break;
    }
    end_read_operation(device);
    return result;
}

int TapTun_Write(TapTunDevice* device, const unsigned char* data, int data_size) {
    if (!device || !data || data_size <= 0 ||
        (device->mode == TAPTUN_MODE_TUN && data_size > TAPTUN_MAX_IP_PACKET_SIZE) ||
        (device->mode == TAPTUN_MODE_TAP && data_size > TAPTUN_MAX_ETHERNET_FRAME_SIZE)) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    int result = begin_operation(device);
    if (result != TAPTUN_OK) return result;
    if (!device->emulates_tap) {
        result = write_backend_packet(device, data, data_size);
        end_operation(device);
        return result;
    }
    unsigned char synthetic[TAPTUN_SYNTHETIC_FRAME_SIZE];
    int output_size = 0;
    pthread_mutex_lock(&device->write_lock);
    int action = taptun_tun2tap_decapsulate(
        &device->tun2tap,
        data,
        data_size,
        device->write_packet,
        TAPTUN_MAX_IP_PACKET_SIZE,
        synthetic,
        sizeof(synthetic),
        &output_size);
    if (action == TAPTUN_TUN2TAP_PACKET) {
        result = write_backend_packet(device, device->write_packet, output_size);
        if (result == output_size) result = data_size;
    } else if (action == TAPTUN_TUN2TAP_SYNTHETIC) {
        result = enqueue_synthetic_frame(device, synthetic, output_size);
        if (result == TAPTUN_OK) result = data_size;
    } else if (action == TAPTUN_TUN2TAP_DROP) {
        result = TAPTUN_ERROR_UNSUPPORTED;
    } else {
        result = action;
    }
    pthread_mutex_unlock(&device->write_lock);
    end_operation(device);
    return result;
}

int TapTun_ReadBatch(
    TapTunDevice* device,
    TapTunBuffer* buffers,
    uint32_t buffer_count) {
    if (!device || !buffers || buffer_count == 0 || buffer_count > INT_MAX) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    for (uint32_t index = 0; index < buffer_count; ++index) {
        if (!buffers[index].data || buffers[index].capacity == 0 ||
            buffers[index].capacity > INT_MAX) {
            return TAPTUN_ERROR_INVALID_ARGUMENT;
        }
        buffers[index].size = 0;
    }
    int result = TapTun_Read(device, buffers[0].data, (int)buffers[0].capacity);
    if (result <= 0) return result;
    buffers[0].size = (uint32_t)result;
    return 1;
}

int TapTun_WriteBatch(
    TapTunDevice* device,
    const TapTunBuffer* buffers,
    uint32_t buffer_count) {
    if (!device || !buffers || buffer_count == 0 || buffer_count > INT_MAX) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    for (uint32_t index = 0; index < buffer_count; ++index) {
        if (!buffers[index].data || buffers[index].size == 0 ||
            buffers[index].size > INT_MAX) {
            return TAPTUN_ERROR_INVALID_ARGUMENT;
        }
    }
    uint32_t completed = 0;
    for (; completed < buffer_count; ++completed) {
        int result = TapTun_Write(device, buffers[completed].data, (int)buffers[completed].size);
        if (result != (int)buffers[completed].size) {
            return completed != 0 ? (int)completed : result;
        }
    }
    return (int)completed;
}

void TapTun_Close(TapTunDevice* device) {
    if (!device) return;
    pthread_mutex_lock(&device->state_lock);
    device->closing = 1;
    pthread_mutex_unlock(&device->state_lock);
    if (device->uses_callbacks) {
        device->callbacks.close(device->callbacks.context);
    } else {
        (void)write(device->cancel_pipe[1], "x", 1);
    }
    pthread_mutex_lock(&device->state_lock);
    while (device->active_operations != 0) {
        pthread_cond_wait(&device->state_condition, &device->state_lock);
    }
    pthread_mutex_unlock(&device->state_lock);
    if (device->owns_fd) close(device->fd);
    close(device->cancel_pipe[0]);
    close(device->cancel_pipe[1]);
    free(device->read_packet);
    free(device->write_packet);
    pthread_cond_destroy(&device->state_condition);
    pthread_mutex_destroy(&device->write_lock);
    pthread_mutex_destroy(&device->state_lock);
    free(device);
}
