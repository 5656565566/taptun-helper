#include "taptun_api.h"
#include "linux_offload.h"
#include "linux_uring.h"
#include "tun2tap.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#define TAPTUN_VNET_BUFFER_SIZE (sizeof(struct virtio_net_hdr) + TAPTUN_MAX_IP_PACKET_SIZE)

struct TapTunDevice {
    int* queue_fds;
    uint32_t queue_count;
    struct pollfd* read_poll_fds;
    uint32_t next_read_queue;
    int owns_fd;
    int uses_callbacks;
    TapTunCallbackOptions callbacks;
    int cancel_pipe[2];
    unsigned int if_index;
    char if_name[IFNAMSIZ];
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
    int active_send_lease;
    int closing;
    TapTunLinuxUring* send_ring;
    int vnet_hdr;
    unsigned char* offload_read_buffer;
    unsigned char* offload_write_buffer;
    TapTunLinuxGsoCursor pending_gso;
    int has_pending_gso;
};

typedef struct {
    int* fds;
    uint32_t count;
    char if_name[IFNAMSIZ];
} LinuxQueueSet;

static void copy_interface_name(char* destination, size_t destination_size, const char* source) {
    if (destination_size == 0) return;
    size_t length = 0;
    while (source && length + 1 < destination_size && source[length] != '\0') ++length;
    if (length != 0) memcpy(destination, source, length);
    destination[length] = '\0';
}

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

static TapTunDevice* allocate_device(
    const int* queue_fds,
    uint32_t queue_count,
    const char* name,
    unsigned int if_index,
    int owns_fd,
    TapTunMode backend_mode,
    TapTunMode mode,
    int vnet_hdr,
    const unsigned char interface_mac[6],
    const unsigned char peer_mac[6]) {
    if (!queue_fds || queue_count == 0) return NULL;
    TapTunDevice* device = (TapTunDevice*)calloc(1, sizeof(TapTunDevice));
    if (!device) return NULL;

    device->queue_fds = (int*)malloc(sizeof(int) * queue_count);
    device->read_poll_fds = (struct pollfd*)calloc(queue_count + 1, sizeof(struct pollfd));
    if (!device->queue_fds || !device->read_poll_fds) {
        free(device->queue_fds);
        free(device->read_poll_fds);
        free(device);
        return NULL;
    }
    memcpy(device->queue_fds, queue_fds, sizeof(int) * queue_count);
    device->queue_count = queue_count;
    device->owns_fd = owns_fd;
    device->cancel_pipe[0] = -1;
    device->cancel_pipe[1] = -1;
    device->if_index = if_index;
    device->mode = mode;
    device->backend_mode = backend_mode;
    device->emulates_tap = mode == TAPTUN_MODE_TAP && backend_mode == TAPTUN_MODE_TUN;
    device->vnet_hdr = vnet_hdr;
    copy_interface_name(device->if_name, sizeof(device->if_name), name);

    if (device->vnet_hdr) {
        device->offload_read_buffer = (unsigned char*)malloc(TAPTUN_VNET_BUFFER_SIZE);
        device->offload_write_buffer = (unsigned char*)malloc(TAPTUN_VNET_BUFFER_SIZE);
        if (!device->offload_read_buffer || !device->offload_write_buffer) {
            free(device->offload_read_buffer);
            free(device->offload_write_buffer);
            free(device->queue_fds);
            free(device->read_poll_fds);
            free(device);
            return NULL;
        }
    }

    if (device->emulates_tap) {
        device->read_packet = (unsigned char*)malloc(TAPTUN_MAX_IP_PACKET_SIZE);
        device->write_packet = (unsigned char*)malloc(TAPTUN_MAX_IP_PACKET_SIZE);
        if (!device->read_packet || !device->write_packet) {
            free(device->read_packet);
            free(device->write_packet);
            free(device->offload_read_buffer);
            free(device->offload_write_buffer);
            free(device->queue_fds);
            free(device->read_poll_fds);
            free(device);
            return NULL;
        }
        taptun_tun2tap_init(
            &device->tun2tap,
            interface_mac,
            peer_mac,
            name,
            if_index);
    }

    if (pipe(device->cancel_pipe) != 0) {
        free(device->read_packet);
        free(device->write_packet);
        free(device->offload_read_buffer);
        free(device->offload_write_buffer);
        free(device->queue_fds);
        free(device->read_poll_fds);
        free(device);
        return NULL;
    }
    if (pthread_mutex_init(&device->state_lock, NULL) != 0) {
        close(device->cancel_pipe[0]);
        close(device->cancel_pipe[1]);
        free(device->read_packet);
        free(device->write_packet);
        free(device->offload_read_buffer);
        free(device->offload_write_buffer);
        free(device->queue_fds);
        free(device->read_poll_fds);
        free(device);
        return NULL;
    }
    if (pthread_mutex_init(&device->write_lock, NULL) != 0) {
        pthread_mutex_destroy(&device->state_lock);
        close(device->cancel_pipe[0]);
        close(device->cancel_pipe[1]);
        free(device->read_packet);
        free(device->write_packet);
        free(device->offload_read_buffer);
        free(device->offload_write_buffer);
        free(device->queue_fds);
        free(device->read_poll_fds);
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
        free(device->offload_read_buffer);
        free(device->offload_write_buffer);
        free(device->queue_fds);
        free(device->read_poll_fds);
        free(device);
        return NULL;
    }
    return device;
}

static void close_queue_set(LinuxQueueSet* queue_set) {
    if (!queue_set) return;
    for (uint32_t index = 0; index < queue_set->count; ++index) {
        close(queue_set->fds[index]);
    }
    free(queue_set->fds);
    memset(queue_set, 0, sizeof(*queue_set));
}

static int open_native_queues(
    TapTunMode backend_mode,
    const char* requested_name,
    uint32_t desired_count,
    int require_exact_count,
    int enable_gso,
    LinuxQueueSet* queue_set) {
    memset(queue_set, 0, sizeof(*queue_set));
    queue_set->fds = (int*)malloc(sizeof(int) * desired_count);
    if (!queue_set->fds) return TAPTUN_ERROR;

    for (uint32_t index = 0; index < desired_count; ++index) {
        int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            if (require_exact_count || queue_set->count == 0) {
                int native_error = errno;
                close_queue_set(queue_set);
                errno = native_error;
                return TAPTUN_ERROR;
            }
            break;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = (backend_mode == TAPTUN_MODE_TAP ? IFF_TAP : IFF_TUN) | IFF_NO_PI;
        if (enable_gso) ifr.ifr_flags |= IFF_VNET_HDR;
        if (desired_count > 1) ifr.ifr_flags |= IFF_MULTI_QUEUE;
        const char* queue_name = index == 0 ? requested_name : queue_set->if_name;
        if (queue_name && queue_name[0] != '\0') {
            copy_interface_name(ifr.ifr_name, sizeof(ifr.ifr_name), queue_name);
        }
        if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
            int native_error = errno;
            close(fd);
            if (require_exact_count || queue_set->count == 0) {
                close_queue_set(queue_set);
                errno = native_error;
                return TAPTUN_ERROR;
            }
            break;
        }

        if (enable_gso) {
            unsigned int offloads = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
            if (ioctl(fd, TUNSETOFFLOAD, offloads) < 0) {
                int native_error = errno;
                close(fd);
                close_queue_set(queue_set);
                errno = native_error;
                return TAPTUN_ERROR;
            }
        }

        queue_set->fds[queue_set->count++] = fd;
        if (index == 0) {
            copy_interface_name(queue_set->if_name, sizeof(queue_set->if_name), ifr.ifr_name);
        }
    }
    return TAPTUN_OK;
}

static int open_configured_queues(
    TapTunMode backend_mode,
    const char* requested_name,
    uint32_t desired_count,
    int require_multi_queue,
    int enable_gso,
    LinuxQueueSet* queue_set) {
    if (open_native_queues(
            backend_mode,
            requested_name,
            desired_count,
            require_multi_queue,
            enable_gso,
            queue_set) == TAPTUN_OK) {
        return TAPTUN_OK;
    }
    if (desired_count == 1 || require_multi_queue) return TAPTUN_ERROR;
    return open_native_queues(backend_mode, requested_name, 1, 1, enable_gso, queue_set);
}

TapTunDevice* TapTun_Open(const TapTunOptions* options) {
    return TapTun_OpenWithPerformance(options, NULL);
}

TapTunDevice* TapTun_OpenWithPerformance(
    const TapTunOptions* options,
    const TapTunPerformanceOptions* performance_options) {
    const uint32_t known_features = TAPTUN_PERF_IO_URING_SEND |
        TAPTUN_PERF_MULTI_QUEUE | TAPTUN_PERF_GSO;
    uint32_t preferred_features = 0;
    uint32_t required_features = 0;
    uint32_t requested_features = 0;
    uint32_t desired_queue_count = 1;
    uint32_t send_queue_depth = 64;
    if (performance_options) {
        if (performance_options->struct_size < sizeof(TapTunPerformanceOptions)) {
            errno = EINVAL;
            return NULL;
        }
        preferred_features = performance_options->preferred_features & known_features;
        required_features = performance_options->required_features;
        if ((required_features & ~known_features) != 0) {
            errno = ENOTSUP;
            return NULL;
        }
        requested_features = preferred_features | required_features;
        if ((requested_features & TAPTUN_PERF_MULTI_QUEUE) != 0) {
            if (performance_options->queue_count < 2 || performance_options->queue_count > 1024) {
                errno = EINVAL;
                return NULL;
            }
            desired_queue_count = performance_options->queue_count;
        } else if (performance_options->queue_count > 1) {
            errno = EINVAL;
            return NULL;
        }
        if ((requested_features & TAPTUN_PERF_IO_URING_SEND) != 0) {
            if (performance_options->send_queue_depth != 0) {
                if (performance_options->send_queue_depth < 2 ||
                    performance_options->send_queue_depth > 1024) {
                    errno = EINVAL;
                    return NULL;
                }
                send_queue_depth = performance_options->send_queue_depth;
            }
        } else if (performance_options->send_queue_depth != 0) {
            errno = EINVAL;
            return NULL;
        }
    }

    const char* requested_name = options ? options->name : NULL;
    unsigned int existing_index = requested_name && requested_name[0] != '\0'
        ? if_nametoindex(requested_name)
        : 0;
    if (options && options->open_mode == TAPTUN_OPEN_EXISTING_ONLY && existing_index == 0) return NULL;
    if (options && options->open_mode == TAPTUN_OPEN_CREATE_ONLY && existing_index != 0) return NULL;

    TapTunMode mode = options ? options->mode : TAPTUN_MODE_TUN;
    TapTunTapBackend tap_backend = options ? options->tap_backend : TAPTUN_TAP_BACKEND_AUTO;
    if ((mode != TAPTUN_MODE_TUN && mode != TAPTUN_MODE_TAP) ||
        tap_backend < TAPTUN_TAP_BACKEND_AUTO ||
        tap_backend > TAPTUN_TAP_BACKEND_EMULATED_ONLY) {
        errno = EINVAL;
        return NULL;
    }

    TapTunMode backend_mode = mode == TAPTUN_MODE_TAP &&
        tap_backend != TAPTUN_TAP_BACKEND_EMULATED_ONLY ? TAPTUN_MODE_TAP : TAPTUN_MODE_TUN;
    int enable_gso = (requested_features & TAPTUN_PERF_GSO) != 0;
    if (enable_gso && mode != TAPTUN_MODE_TUN) {
        if ((required_features & TAPTUN_PERF_GSO) != 0) {
            errno = ENOTSUP;
            return NULL;
        }
        enable_gso = 0;
        requested_features &= ~TAPTUN_PERF_GSO;
    }
    LinuxQueueSet queue_set;
    int require_multi_queue = (required_features & TAPTUN_PERF_MULTI_QUEUE) != 0;
    if (open_configured_queues(
            backend_mode,
            requested_name,
            desired_queue_count,
            require_multi_queue,
            enable_gso,
            &queue_set) != TAPTUN_OK) {
        int native_error = errno;
        if (enable_gso && (required_features & TAPTUN_PERF_GSO) == 0 &&
            open_configured_queues(
                backend_mode,
                requested_name,
                desired_queue_count,
                require_multi_queue,
                0,
                &queue_set) == TAPTUN_OK) {
            enable_gso = 0;
            requested_features &= ~TAPTUN_PERF_GSO;
        } else if (mode != TAPTUN_MODE_TAP || tap_backend != TAPTUN_TAP_BACKEND_AUTO) {
            errno = native_error;
            return NULL;
        } else if (open_configured_queues(
                TAPTUN_MODE_TUN,
                requested_name,
                desired_queue_count,
                require_multi_queue,
                0,
                &queue_set) != TAPTUN_OK) {
            errno = native_error;
            return NULL;
        } else {
            backend_mode = TAPTUN_MODE_TUN;
        }
    }

    TapTunDevice* device = allocate_device(
        queue_set.fds,
        queue_set.count,
        queue_set.if_name,
        if_nametoindex(queue_set.if_name),
        1,
        backend_mode,
        mode,
        enable_gso,
        options ? options->interface_mac : NULL,
        options ? options->peer_mac : NULL);
    if (!device) {
        close_queue_set(&queue_set);
        return NULL;
    }
    free(queue_set.fds);

    if ((requested_features & TAPTUN_PERF_IO_URING_SEND) != 0) {
        if (!device->emulates_tap) {
            uint32_t packet_capacity = device->mode == TAPTUN_MODE_TUN
                ? TAPTUN_MAX_IP_PACKET_SIZE
                : TAPTUN_MAX_ETHERNET_FRAME_SIZE;
            device->send_ring = taptun_linux_uring_create(
                device->queue_fds,
                device->queue_count,
                send_queue_depth,
                packet_capacity,
                device->vnet_hdr ? (uint32_t)sizeof(struct virtio_net_hdr) : 0);
        }
        if (!device->send_ring &&
            (required_features & TAPTUN_PERF_IO_URING_SEND) != 0) {
            int native_error = device->emulates_tap ? ENOTSUP : errno;
            TapTun_Close(device);
            errno = native_error;
            return NULL;
        }
    }
    return device;
}

TapTunDevice* TapTun_OpenFromHandle(const TapTunHandleOptions* options) {
    if (!options || options->handle < 0 ||
        (options->backend_mode != TAPTUN_MODE_TUN && options->backend_mode != TAPTUN_MODE_TAP) ||
        (options->mode != TAPTUN_MODE_TUN && options->mode != TAPTUN_MODE_TAP) ||
        (options->mode == TAPTUN_MODE_TUN && options->backend_mode != TAPTUN_MODE_TUN)) {
        errno = EINVAL;
        return NULL;
    }
    int fd = (int)options->handle;
    return allocate_device(
        &fd,
        1,
        options->name,
        options->if_index,
        options->take_ownership != 0,
        options->backend_mode,
        options->mode,
        0,
        options->interface_mac,
        options->peer_mac);
}

TapTunDevice* TapTun_OpenFromCallbacks(const TapTunCallbackOptions* options) {
    if (!options || !options->read || !options->write || !options->close) return NULL;
    if ((options->backend_mode != TAPTUN_MODE_TUN && options->backend_mode != TAPTUN_MODE_TAP) ||
        (options->mode != TAPTUN_MODE_TUN && options->mode != TAPTUN_MODE_TAP) ||
        (options->mode == TAPTUN_MODE_TUN && options->backend_mode != TAPTUN_MODE_TUN)) {
        errno = EINVAL;
        return NULL;
    }
    if (options->mode == TAPTUN_MODE_TAP && options->backend_mode == TAPTUN_MODE_TUN &&
        !options->interrupt_read) {
        errno = EINVAL;
        return NULL;
    }
    int callback_fd = -1;
    TapTunDevice* device = allocate_device(
        &callback_fd,
        1,
        options->name,
        options->if_index,
        0,
        options->backend_mode,
        options->mode,
        0,
        options->interface_mac,
        options->peer_mac);
    if (!device) return NULL;
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
    return device ? device->queue_count : 0;
}

TapTunMode TapTun_GetMode(const TapTunDevice* device) {
    return device ? device->mode : TAPTUN_MODE_TUN;
}

int TapTun_GetMacAddress(const TapTunDevice* device, unsigned char mac_address[6]) {
    if (!device || !mac_address) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (device->mode != TAPTUN_MODE_TAP) return TAPTUN_ERROR_UNSUPPORTED;
    if (device->emulates_tap) {
        memcpy(mac_address, device->tun2tap.interface_mac, 6);
        return TAPTUN_OK;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    copy_interface_name(ifr.ifr_name, sizeof(ifr.ifr_name), device->if_name);
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return TAPTUN_ERROR;
    int result = ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    if (result != 0) return TAPTUN_ERROR;
    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
    return TAPTUN_OK;
}

uint32_t TapTun_GetLastSystemError(void) {
    return (uint32_t)errno;
}

uint32_t TapTun_GetCapabilities(const TapTunDevice* device) {
    if (!device) return 0;
    uint32_t capabilities = 0;
    if (device->send_ring) {
        capabilities |= TAPTUN_CAP_ZERO_COPY_SEND | TAPTUN_CAP_IO_URING_SEND;
    }
    if (device->queue_count > 1) capabilities |= TAPTUN_CAP_MULTI_QUEUE;
    if (device->vnet_hdr) capabilities |= TAPTUN_CAP_GSO;
    if (device->mode == TAPTUN_MODE_TAP) {
        capabilities |= device->emulates_tap
            ? TAPTUN_CAP_EMULATED_TAP
            : TAPTUN_CAP_NATIVE_TAP;
    }
    return capabilities;
}

int TapTun_AcquireReceive(TapTunDevice* device, TapTunPacket* packet) {
    if (!device || !packet) return TAPTUN_ERROR_INVALID_ARGUMENT;
    return TAPTUN_ERROR_UNSUPPORTED;
}

int TapTun_ReleaseReceive(TapTunDevice* device, TapTunPacket* packet) {
    return device && packet ? TAPTUN_ERROR_UNSUPPORTED : TAPTUN_ERROR_INVALID_ARGUMENT;
}

static uint16_t read_big_endian_u16(const unsigned char* data) {
    return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static uint32_t append_flow_hash(uint32_t hash, const unsigned char* data, size_t size) {
    for (size_t index = 0; index < size; ++index) {
        hash ^= data[index];
        hash *= 16777619u;
    }
    return hash;
}

static uint32_t packet_flow_hash(
    const TapTunDevice* device,
    const unsigned char* packet,
    uint32_t packet_size) {
    const unsigned char* network_packet = packet;
    uint32_t network_size = packet_size;
    uint16_t ethernet_type = 0;
    uint32_t hash = 2166136261u;

    if (device->backend_mode == TAPTUN_MODE_TAP) {
        if (packet_size < 14) return append_flow_hash(hash, packet, packet_size);
        hash = append_flow_hash(hash, packet, 12);
        ethernet_type = read_big_endian_u16(packet + 12);
        uint32_t offset = 14;
        for (unsigned int vlan = 0; vlan < 2 &&
             (ethernet_type == 0x8100 || ethernet_type == 0x88a8); ++vlan) {
            if (packet_size < offset + 4) return hash;
            ethernet_type = read_big_endian_u16(packet + offset + 2);
            offset += 4;
        }
        if (packet_size < offset) return hash;
        network_packet = packet + offset;
        network_size = packet_size - offset;
    }

    unsigned int version = network_size != 0 ? network_packet[0] >> 4 : 0;
    if (version == 4 && network_size >= 20 &&
        (ethernet_type == 0 || ethernet_type == 0x0800)) {
        uint32_t header_size = (uint32_t)(network_packet[0] & 0x0f) * 4;
        if (header_size < 20 || network_size < header_size) return hash;
        hash = append_flow_hash(hash, network_packet + 12, 8);
        hash = append_flow_hash(hash, network_packet + 9, 1);
        uint16_t fragment = read_big_endian_u16(network_packet + 6);
        if ((fragment & 0x3fffu) != 0) {
            return append_flow_hash(hash, network_packet + 4, 2);
        }
        if ((network_packet[9] == IPPROTO_TCP || network_packet[9] == IPPROTO_UDP) &&
            network_size >= header_size + 4) {
            hash = append_flow_hash(hash, network_packet + header_size, 4);
        }
        return hash;
    }

    if (version == 6 && network_size >= 40 &&
        (ethernet_type == 0 || ethernet_type == 0x86dd)) {
        hash = append_flow_hash(hash, network_packet + 8, 32);
        hash = append_flow_hash(hash, network_packet + 6, 1);
        if ((network_packet[6] == IPPROTO_TCP || network_packet[6] == IPPROTO_UDP) &&
            network_size >= 44) {
            hash = append_flow_hash(hash, network_packet + 40, 4);
        }
        return hash;
    }

    size_t fallback_size = packet_size < 32 ? packet_size : 32;
    return append_flow_hash(hash, packet, fallback_size);
}

static uint32_t select_write_queue(
    const TapTunDevice* device,
    const unsigned char* packet,
    uint32_t packet_size) {
    if (device->queue_count <= 1) return 0;
    return packet_flow_hash(device, packet, packet_size) % device->queue_count;
}

int TapTun_AcquireSend(TapTunDevice* device, uint32_t packet_size, TapTunPacket* packet) {
    if (!device || !packet || packet_size == 0 ||
        (device->mode == TAPTUN_MODE_TUN && packet_size > TAPTUN_MAX_IP_PACKET_SIZE) ||
        (device->mode == TAPTUN_MODE_TAP && packet_size > TAPTUN_MAX_ETHERNET_FRAME_SIZE)) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    if (!device->send_ring) return TAPTUN_ERROR_UNSUPPORTED;

    pthread_mutex_lock(&device->state_lock);
    if (device->closing) {
        pthread_mutex_unlock(&device->state_lock);
        return TAPTUN_ERROR_CLOSED;
    }
    if (device->active_send_lease) {
        pthread_mutex_unlock(&device->state_lock);
        return TAPTUN_ERROR_BUSY;
    }
    int result = taptun_linux_uring_acquire(device->send_ring, packet_size, packet);
    if (result == TAPTUN_OK) {
        device->active_send_lease = 1;
        ++device->active_operations;
    }
    pthread_mutex_unlock(&device->state_lock);
    return result;
}

int TapTun_CommitSend(TapTunDevice* device, TapTunPacket* packet) {
    if (!device || !packet) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (!device->send_ring) return TAPTUN_ERROR_UNSUPPORTED;

    pthread_mutex_lock(&device->state_lock);
    if (!device->active_send_lease) {
        pthread_mutex_unlock(&device->state_lock);
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    if (taptun_linux_uring_validate_acquired(device->send_ring, packet) != TAPTUN_OK) {
        pthread_mutex_unlock(&device->state_lock);
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    uint32_t queue_index = select_write_queue(device, packet->data, packet->size);
    int result = taptun_linux_uring_commit(device->send_ring, queue_index, packet);
    if (result == TAPTUN_OK || result == TAPTUN_ERROR) {
        device->active_send_lease = 0;
        --device->active_operations;
        pthread_cond_broadcast(&device->state_condition);
    }
    pthread_mutex_unlock(&device->state_lock);
    return result;
}

int TapTun_Activate(TapTunDevice* device) {
    if (!device) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (device->uses_callbacks) return TAPTUN_ERROR_UNSUPPORTED;
    if (device->if_name[0] == '\0') return TAPTUN_ERROR_UNSUPPORTED;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    copy_interface_name(ifr.ifr_name, sizeof(ifr.ifr_name), device->if_name);

    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return TAPTUN_ERROR;
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        close(sock);
        return TAPTUN_ERROR;
    }
    ifr.ifr_flags |= IFF_UP;
    int result = ioctl(sock, SIOCSIFFLAGS, &ifr) == 0 ? TAPTUN_OK : TAPTUN_ERROR;
    close(sock);
    return result;
}

int TapTun_SetIPAddressV4(TapTunDevice* device, const char* address, unsigned int prefix_length) {
    if (!device || !address || prefix_length > 32) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (device->uses_callbacks) return TAPTUN_ERROR_UNSUPPORTED;
    if (device->if_name[0] == '\0') return TAPTUN_ERROR_UNSUPPORTED;

    struct sockaddr_in ip_address;
    struct sockaddr_in netmask;
    memset(&ip_address, 0, sizeof(ip_address));
    memset(&netmask, 0, sizeof(netmask));
    ip_address.sin_family = AF_INET;
    netmask.sin_family = AF_INET;
    if (inet_pton(AF_INET, address, &ip_address.sin_addr) != 1) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    netmask.sin_addr.s_addr = prefix_length == 0
        ? 0
        : htonl(UINT32_MAX << (32 - prefix_length));

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    copy_interface_name(ifr.ifr_name, sizeof(ifr.ifr_name), device->if_name);

    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return TAPTUN_ERROR;
    memcpy(&ifr.ifr_addr, &ip_address, sizeof(ip_address));
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        close(sock);
        return TAPTUN_ERROR;
    }
    memcpy(&ifr.ifr_netmask, &netmask, sizeof(netmask));
    int result = ioctl(sock, SIOCSIFNETMASK, &ifr) == 0 ? TAPTUN_OK : TAPTUN_ERROR;
    close(sock);
    return result;
}

int TapTun_SetIPAddressV6(TapTunDevice* device, const char* address, unsigned int prefix_length) {
    if (!device || !address || prefix_length > 128) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (device->uses_callbacks) return TAPTUN_ERROR_UNSUPPORTED;
    if (device->if_index == 0) return TAPTUN_ERROR_UNSUPPORTED;

    struct in6_ifreq {
        struct in6_addr ifr6_addr;
        uint32_t ifr6_prefixlen;
        unsigned int ifr6_ifindex;
    } ifr6;

    memset(&ifr6, 0, sizeof(ifr6));
    ifr6.ifr6_ifindex = device->if_index;
    ifr6.ifr6_prefixlen = prefix_length;
    if (inet_pton(AF_INET6, address, &ifr6.ifr6_addr) != 1) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }

    int sock = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) return TAPTUN_ERROR;
    int result = ioctl(sock, SIOCSIFADDR, &ifr6) == 0 ? TAPTUN_OK : TAPTUN_ERROR;
    close(sock);
    return result;
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

    // The same pipe wakes a blocked read for queued protocol replies and close.
    if (device->uses_callbacks) {
        device->callbacks.interrupt_read(device->callbacks.context);
    } else {
        (void)write(device->cancel_pipe[1], "w", 1);
    }
    return TAPTUN_OK;
}

static int read_backend_packet(
    TapTunDevice* device,
    uint32_t queue_index,
    unsigned char* buffer,
    int buffer_size) {
    if (device->uses_callbacks) {
        return device->callbacks.read(device->callbacks.context, buffer, buffer_size);
    }
    ssize_t bytes_read = read(device->queue_fds[queue_index], buffer, (size_t)buffer_size);
    return bytes_read >= 0 ? (int)bytes_read : TAPTUN_ERROR;
}

static int write_backend_packet(
    TapTunDevice* device,
    const unsigned char* data,
    int data_size) {
    if (device->uses_callbacks) {
        return device->callbacks.write(device->callbacks.context, data, data_size);
    }
    uint32_t queue_index = select_write_queue(device, data, (uint32_t)data_size);
    if (!device->vnet_hdr) {
        ssize_t bytes_written = write(device->queue_fds[queue_index], data, (size_t)data_size);
        return bytes_written >= 0 ? (int)bytes_written : TAPTUN_ERROR;
    }

    struct virtio_net_hdr header;
    memset(&header, 0, sizeof(header));
    struct iovec vectors[2] = {
        { &header, sizeof(header) },
        { (void*)data, (size_t)data_size }
    };
    ssize_t bytes_written = writev(device->queue_fds[queue_index], vectors, 2);
    if (bytes_written == (ssize_t)(sizeof(header) + (size_t)data_size)) return data_size;
    if (bytes_written >= 0) errno = EIO;
    return TAPTUN_ERROR;
}

static int write_backend_offload_packet(
    TapTunDevice* device,
    const unsigned char* data,
    int data_size,
    const unsigned char* flow_packet,
    uint32_t flow_packet_size) {
    uint32_t queue_index = select_write_queue(device, flow_packet, flow_packet_size);
    ssize_t bytes_written = write(device->queue_fds[queue_index], data, (size_t)data_size);
    if (bytes_written == data_size) return TAPTUN_OK;
    if (bytes_written >= 0) errno = EIO;
    return TAPTUN_ERROR;
}

static int wait_for_read_queue(TapTunDevice* device) {
    for (uint32_t index = 0; index < device->queue_count; ++index) {
        device->read_poll_fds[index].fd = device->queue_fds[index];
        device->read_poll_fds[index].events = POLLIN;
        device->read_poll_fds[index].revents = 0;
    }
    uint32_t cancel_index = device->queue_count;
    device->read_poll_fds[cancel_index].fd = device->cancel_pipe[0];
    device->read_poll_fds[cancel_index].events = POLLIN;
    device->read_poll_fds[cancel_index].revents = 0;

    int result;
    do {
        result = poll(device->read_poll_fds, device->queue_count + 1, -1);
    } while (result < 0 && errno == EINTR);
    if (result <= 0) return TAPTUN_ERROR;
    if ((device->read_poll_fds[cancel_index].revents & POLLIN) != 0) return TAPTUN_ERROR_BUSY;

    // Rotate the scan start so continuously busy queues cannot starve peers.
    for (uint32_t offset = 0; offset < device->queue_count; ++offset) {
        uint32_t queue_index = (device->next_read_queue + offset) % device->queue_count;
        if ((device->read_poll_fds[queue_index].revents & POLLIN) == 0) continue;
        device->next_read_queue = (queue_index + 1) % device->queue_count;
        return (int)queue_index;
    }
    return TAPTUN_ERROR;
}

static int read_single_packet(TapTunDevice* device, unsigned char* buffer, int buffer_size) {
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

        uint32_t read_queue = 0;
        if (!device->uses_callbacks) {
            result = wait_for_read_queue(device);
            if (result == TAPTUN_ERROR_BUSY) {
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
            if (result < 0) {
                result = TAPTUN_ERROR;
                break;
            }
            read_queue = (uint32_t)result;
        }

        unsigned char* target = device->emulates_tap ? device->read_packet : buffer;
        int capacity = device->emulates_tap ? TAPTUN_MAX_IP_PACKET_SIZE : buffer_size;
        result = read_backend_packet(device, read_queue, target, capacity);
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

    if (!device->vnet_hdr) {
        int result = read_single_packet(device, buffers[0].data, (int)buffers[0].capacity);
        if (result <= 0) return result;
        buffers[0].size = (uint32_t)result;
        return 1;
    }

    int result = begin_read_operation(device);
    if (result != TAPTUN_OK) return result;
    uint32_t output_count = 0;
    for (;;) {
        while (device->has_pending_gso && output_count < buffer_count) {
            int packet_size = taptun_linux_gso_next(
                &device->pending_gso,
                buffers[output_count].data,
                buffers[output_count].capacity);
            if (packet_size == 0) {
                device->has_pending_gso = 0;
                memset(&device->pending_gso, 0, sizeof(device->pending_gso));
                break;
            }
            if (packet_size < 0) {
                result = output_count != 0 ? (int)output_count : packet_size;
                goto complete;
            }
            buffers[output_count].size = (uint32_t)packet_size;
            ++output_count;
        }
        if (output_count != 0) {
            result = (int)output_count;
            break;
        }

        pthread_mutex_lock(&device->state_lock);
        int closing = device->closing;
        pthread_mutex_unlock(&device->state_lock);
        if (closing) {
            result = TAPTUN_ERROR_CLOSED;
            break;
        }

        result = wait_for_read_queue(device);
        if (result == TAPTUN_ERROR_BUSY) {
            char signal;
            (void)read(device->cancel_pipe[0], &signal, 1);
            continue;
        }
        if (result < 0) {
            result = TAPTUN_ERROR;
            break;
        }

        ssize_t bytes_read = read(
            device->queue_fds[(uint32_t)result],
            device->offload_read_buffer,
            TAPTUN_VNET_BUFFER_SIZE);
        if (bytes_read < 0) {
            result = TAPTUN_ERROR;
            break;
        }

        unsigned char* normal_packet = NULL;
        uint32_t normal_size = 0;
        result = taptun_linux_offload_prepare_read(
            device->offload_read_buffer,
            (uint32_t)bytes_read,
            &device->pending_gso,
            &normal_packet,
            &normal_size);
        if (result < 0) break;
        if (result == TAPTUN_LINUX_OFFLOAD_NORMAL) {
            if (normal_size > buffers[0].capacity) {
                result = TAPTUN_ERROR_BUFFER_TOO_SMALL;
                break;
            }
            memcpy(buffers[0].data, normal_packet, normal_size);
            buffers[0].size = normal_size;
            result = 1;
            break;
        }
        device->has_pending_gso = 1;
    }

complete:
    end_read_operation(device);
    return result;
}

int TapTun_Read(TapTunDevice* device, unsigned char* buffer, int buffer_size) {
    if (!device || !buffer || buffer_size <= 0) return TAPTUN_ERROR_INVALID_ARGUMENT;
    if (!device->vnet_hdr) return read_single_packet(device, buffer, buffer_size);
    TapTunBuffer packet = { buffer, (uint32_t)buffer_size, 0 };
    int result = TapTun_ReadBatch(device, &packet, 1);
    return result == 1 ? (int)packet.size : result;
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

int TapTun_WriteBatch(
    TapTunDevice* device,
    const TapTunBuffer* buffers,
    uint32_t buffer_count) {
    if (!device || !buffers || buffer_count == 0 || buffer_count > INT_MAX) {
        return TAPTUN_ERROR_INVALID_ARGUMENT;
    }
    uint32_t maximum_size = device->mode == TAPTUN_MODE_TUN
        ? TAPTUN_MAX_IP_PACKET_SIZE
        : TAPTUN_MAX_ETHERNET_FRAME_SIZE;
    for (uint32_t index = 0; index < buffer_count; ++index) {
        if (!buffers[index].data || buffers[index].size == 0 ||
            buffers[index].size > maximum_size) {
            return TAPTUN_ERROR_INVALID_ARGUMENT;
        }
    }

    if (!device->vnet_hdr) {
        uint32_t completed = 0;
        for (; completed < buffer_count; ++completed) {
            int result = TapTun_Write(
                device,
                buffers[completed].data,
                (int)buffers[completed].size);
            if (result != (int)buffers[completed].size) {
                return completed != 0 ? (int)completed : result;
            }
        }
        return (int)completed;
    }

    int result = begin_operation(device);
    if (result != TAPTUN_OK) return result;
    uint32_t completed = 0;
    pthread_mutex_lock(&device->write_lock);
    while (completed < buffer_count) {
        uint32_t consumed = 1;
        int offload_size = taptun_linux_gro_coalesce(
            buffers + completed,
            buffer_count - completed,
            device->offload_write_buffer,
            TAPTUN_VNET_BUFFER_SIZE,
            &consumed);
        if (offload_size < 0) {
            result = offload_size;
            break;
        }
        if (offload_size != 0) {
            result = write_backend_offload_packet(
                device,
                device->offload_write_buffer,
                offload_size,
                buffers[completed].data,
                buffers[completed].size);
            if (result != TAPTUN_OK) break;
            completed += consumed;
            continue;
        }

        result = write_backend_packet(
            device,
            buffers[completed].data,
            (int)buffers[completed].size);
        if (result != (int)buffers[completed].size) break;
        ++completed;
    }
    pthread_mutex_unlock(&device->write_lock);
    end_operation(device);
    return completed != 0 ? (int)completed : result;
}

void TapTun_Close(TapTunDevice* device) {
    if (!device) return;

    pthread_mutex_lock(&device->state_lock);
    device->closing = 1;
    if (device->active_send_lease) {
        taptun_linux_uring_cancel_acquired(device->send_ring);
        device->active_send_lease = 0;
        --device->active_operations;
    }
    pthread_cond_broadcast(&device->state_condition);
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

    taptun_linux_uring_destroy(device->send_ring);
    if (device->owns_fd) {
        for (uint32_t index = 0; index < device->queue_count; ++index) {
            close(device->queue_fds[index]);
        }
    }
    close(device->cancel_pipe[0]);
    close(device->cancel_pipe[1]);
    free(device->read_packet);
    free(device->write_packet);
    free(device->offload_read_buffer);
    free(device->offload_write_buffer);
    free(device->queue_fds);
    free(device->read_poll_fds);
    pthread_cond_destroy(&device->state_condition);
    pthread_mutex_destroy(&device->write_lock);
    pthread_mutex_destroy(&device->state_lock);
    free(device);
}
