#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../include/taptun_api.h"

#define DEFAULT_PACKET_SIZE 1400u
#define DEFAULT_ITERATIONS 100000u
#define DEFAULT_ROUNDS 4u
#define DEFAULT_BATCH_SIZE 32u
#define WARMUP_ITERATIONS 5000u
#define ETHERNET_HEADER_SIZE 14u
#define IPV4_UDP_HEADER_SIZE 28u
#define MAX_IP_PACKET_SIZE 65535u
#define MAX_ETHERNET_FRAME_SIZE (ETHERNET_HEADER_SIZE + MAX_IP_PACKET_SIZE)

#if defined(__OPTIMIZE__)
#define BENCHMARK_OPTIMIZATION "enabled"
#else
#define BENCHMARK_OPTIMIZATION "disabled"
#endif

typedef struct {
    double seconds;
} BenchmarkResult;

typedef struct {
    int peer_fd;
    uint32_t expected_packets;
    uint32_t received_packets;
    int error_number;
} DrainContext;

typedef struct {
    TapTunDevice* device;
    int peer_fd;
    pthread_t drain_thread;
    DrainContext drain_context;
    int has_drain_thread;
} BenchmarkTarget;

static uint16_t ipv4_checksum(const unsigned char* data, size_t size) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < size; i += 2) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t checksum_add(uint32_t sum, const unsigned char* data, size_t size) {
    for (size_t i = 0; i + 1 < size; i += 2) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
    }
    if ((size & 1u) != 0) sum += (uint32_t)data[size - 1] << 8;
    return sum;
}

static uint16_t checksum_finish(uint32_t sum) {
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static void prepare_ipv4_udp(
    unsigned char* packet,
    uint32_t packet_size,
    uint32_t sequence) {
    memset(packet, 0, IPV4_UDP_HEADER_SIZE);
    packet[0] = 0x45;
    packet[2] = (unsigned char)(packet_size >> 8);
    packet[3] = (unsigned char)packet_size;
    packet[4] = (unsigned char)(sequence >> 8);
    packet[5] = (unsigned char)sequence;
    packet[8] = 64;
    packet[9] = 17;
    packet[12] = 198;
    packet[13] = 18;
    packet[15] = 1;
    packet[16] = 198;
    packet[17] = 18;
    packet[19] = 2;

    uint32_t udp_size = packet_size - 20;
    packet[20] = 0x9c;
    packet[21] = 0x40;
    packet[22] = 0x9c;
    packet[23] = 0x41;
    packet[24] = (unsigned char)(udp_size >> 8);
    packet[25] = (unsigned char)udp_size;
    for (uint32_t i = IPV4_UDP_HEADER_SIZE; i < packet_size; ++i) {
        packet[i] = (unsigned char)(sequence + i);
    }

    uint16_t checksum = ipv4_checksum(packet, 20);
    packet[10] = (unsigned char)(checksum >> 8);
    packet[11] = (unsigned char)checksum;
}

static void prepare_ipv4_tcp(
    unsigned char* packet,
    uint32_t packet_size,
    uint32_t sequence) {
    memset(packet, 0, packet_size);
    packet[0] = 0x45;
    packet[2] = (unsigned char)(packet_size >> 8);
    packet[3] = (unsigned char)packet_size;
    uint32_t payload_size = packet_size > 40 ? packet_size - 40 : 1;
    uint16_t ip_id = (uint16_t)(sequence / payload_size);
    packet[4] = (unsigned char)(ip_id >> 8);
    packet[5] = (unsigned char)ip_id;
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = 6;
    packet[12] = 198;
    packet[13] = 18;
    packet[15] = 1;
    packet[16] = 198;
    packet[17] = 18;
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
    for (uint32_t i = 40; i < packet_size; ++i) {
        packet[i] = (unsigned char)(sequence + i);
    }

    uint16_t checksum = ipv4_checksum(packet, 20);
    packet[10] = (unsigned char)(checksum >> 8);
    packet[11] = (unsigned char)checksum;
    uint32_t tcp_size = packet_size - 20;
    uint32_t tcp_sum = checksum_add(0, packet + 12, 8);
    tcp_sum += 6;
    tcp_sum += tcp_size;
    tcp_sum = checksum_add(tcp_sum, tcp, tcp_size);
    checksum = checksum_finish(tcp_sum);
    tcp[16] = (unsigned char)(checksum >> 8);
    tcp[17] = (unsigned char)checksum;
}

static void prepare_packet(
    unsigned char* packet,
    uint32_t packet_size,
    TapTunMode mode,
    uint32_t sequence,
    int use_tcp) {
    if (mode == TAPTUN_MODE_TUN) {
        if (use_tcp) {
            prepare_ipv4_tcp(packet, packet_size, sequence);
        } else {
            prepare_ipv4_udp(packet, packet_size, sequence);
        }
        return;
    }

    // Use unicast Ethernet II frames so emulated TAP exercises its normal
    // decapsulation path without generating synthetic ARP/NDP replies.
    const unsigned char destination[6] = { 0x02, 0, 0, 0, 0, 2 };
    const unsigned char source[6] = { 0x02, 0, 0, 0, 0, 1 };
    memcpy(packet, destination, sizeof(destination));
    memcpy(packet + 6, source, sizeof(source));
    packet[12] = 0x08;
    packet[13] = 0x00;
    if (use_tcp) {
        prepare_ipv4_tcp(
            packet + ETHERNET_HEADER_SIZE,
            packet_size - ETHERNET_HEADER_SIZE,
            sequence);
    } else {
        prepare_ipv4_udp(
            packet + ETHERNET_HEADER_SIZE,
            packet_size - ETHERNET_HEADER_SIZE,
            sequence);
    }
}

static double elapsed_seconds(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) +
        (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

static void* drain_packets(void* argument) {
    DrainContext* context = (DrainContext*)argument;
    unsigned char packet[MAX_IP_PACKET_SIZE];
    while (context->received_packets < context->expected_packets) {
        ssize_t result = recv(context->peer_fd, packet, sizeof(packet), 0);
        if (result >= 0) {
            ++context->received_packets;
            continue;
        }
        if (errno == EINTR) continue;
        context->error_number = errno;
        break;
    }
    return NULL;
}

static void close_target(BenchmarkTarget* target, int abort_drain) {
    if (target->has_drain_thread) {
        if (abort_drain) shutdown(target->peer_fd, SHUT_RDWR);
        pthread_join(target->drain_thread, NULL);
        target->has_drain_thread = 0;
    }
    if (target->device) {
        TapTun_Close(target->device);
        target->device = NULL;
    }
    if (target->peer_fd >= 0) {
        close(target->peer_fd);
        target->peer_fd = -1;
    }
}

static int open_target(
    BenchmarkTarget* target,
    int use_native,
    TapTunMode mode,
    int use_io_uring,
    int use_gso,
    uint32_t queue_count,
    uint32_t send_queue_depth,
    uint32_t expected_packets) {
    memset(target, 0, sizeof(*target));
    target->peer_fd = -1;

    if (use_native) {
        TapTunOptions options;
        memset(&options, 0, sizeof(options));
        // Keep explicit names within Linux IFNAMSIZ - 1 as well as the more
        // permissive platform limits used by the other POSIX backends.
        options.name = mode == TAPTUN_MODE_TAP ? "tapbench0" : "tunbench0";
        options.mode = mode;
        TapTunPerformanceOptions performance;
        memset(&performance, 0, sizeof(performance));
        performance.struct_size = sizeof(performance);
        if (use_io_uring) {
            performance.required_features |= TAPTUN_PERF_IO_URING_SEND;
            performance.send_queue_depth = send_queue_depth;
        }
        if (use_gso) performance.required_features |= TAPTUN_PERF_GSO;
        if (queue_count > 1) {
            performance.required_features |= TAPTUN_PERF_MULTI_QUEUE;
            performance.queue_count = queue_count;
        }
        target->device = performance.required_features != 0
            ? TapTun_OpenWithPerformance(&options, &performance)
            : TapTun_Open(&options);
        if (!target->device) {
            fprintf(stderr, "Failed to open the native benchmark device: system_error=%d (%s).\n",
                errno, strerror(errno));
            return TAPTUN_ERROR;
        }
        // Follow the platform's normal configuration lifecycle before timing.
        // A documentation-only /32 creates no peer subnet route, so generated
        // benchmark packets cannot loop back into the device queue.
        int configure_result = TapTun_SetIPAddressV4(target->device, "192.0.2.1", 32);
        if (configure_result != TAPTUN_OK) {
            fprintf(stderr, "Failed to configure native device %s: system_error=%d (%s).\n",
                TapTun_GetName(target->device), errno, strerror(errno));
        } else {
            configure_result = TapTun_Activate(target->device);
            if (configure_result != TAPTUN_OK) {
                fprintf(stderr, "Failed to activate native device %s: system_error=%d (%s).\n",
                    TapTun_GetName(target->device), errno, strerror(errno));
            }
        }
        if (configure_result != TAPTUN_OK) {
            int native_error = errno;
            close_target(target, 0);
            errno = native_error;
            return configure_result;
        }
        return TAPTUN_OK;
    }

    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) != 0) return TAPTUN_ERROR;
    TapTunHandleOptions options;
    memset(&options, 0, sizeof(options));
    options.handle = sockets[0];
    options.name = mode == TAPTUN_MODE_TAP ? "external-tap" : "external-tun";
    options.take_ownership = 1;
    options.backend_mode = TAPTUN_MODE_TUN;
    options.mode = mode;
    target->device = TapTun_OpenFromHandle(&options);
    if (!target->device) {
        close(sockets[0]);
        close(sockets[1]);
        return TAPTUN_ERROR;
    }

    target->peer_fd = sockets[1];
    target->drain_context.peer_fd = sockets[1];
    target->drain_context.expected_packets = expected_packets;
    if (pthread_create(&target->drain_thread, NULL, drain_packets, &target->drain_context) != 0) {
        close_target(target, 1);
        return TAPTUN_ERROR;
    }
    target->has_drain_thread = 1;
    return TAPTUN_OK;
}

static int run_benchmark(
    int use_native,
    TapTunMode mode,
    int use_io_uring,
    int use_tcp,
    int use_gso,
    uint32_t queue_count,
    uint32_t send_queue_depth,
    uint32_t batch_size,
    uint32_t packet_size,
    uint32_t iterations,
    BenchmarkResult* result,
    uint32_t* capabilities) {
    BenchmarkTarget target;
    int open_result = open_target(
        &target,
        use_native,
        mode,
        use_io_uring,
        use_gso,
        queue_count,
        send_queue_depth,
        iterations);
    if (open_result != TAPTUN_OK) return open_result;
    if (capabilities) *capabilities = TapTun_GetCapabilities(target.device);

    uint32_t allocation_count = use_gso ? batch_size : 1;
    unsigned char* packet = use_io_uring
        ? NULL
        : (unsigned char*)malloc((size_t)packet_size * allocation_count);
    TapTunBuffer* batch = use_gso
        ? (TapTunBuffer*)calloc(batch_size, sizeof(TapTunBuffer))
        : NULL;
    if ((!use_io_uring && !packet) || (use_gso && !batch)) {
        free(packet);
        free(batch);
        close_target(&target, 1);
        return TAPTUN_ERROR;
    }

    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int write_result = TAPTUN_OK;
    uint32_t completed = 0;
    for (uint32_t i = 0; i < iterations;) {
        if (use_io_uring) {
            TapTunPacket send_packet;
            memset(&send_packet, 0, sizeof(send_packet));
            write_result = TapTun_AcquireSend(target.device, packet_size, &send_packet);
            if (write_result != TAPTUN_OK) break;
            uint32_t header_size = mode == TAPTUN_MODE_TAP ? ETHERNET_HEADER_SIZE + 40u : 40u;
            uint32_t sequence = use_tcp ? i * (packet_size - header_size) : i;
            prepare_packet(send_packet.data, packet_size, mode, sequence, use_tcp);
            write_result = TapTun_CommitSend(target.device, &send_packet);
            if (write_result != TAPTUN_OK) break;
            ++i;
            ++completed;
        } else if (use_gso) {
            uint32_t current_batch = iterations - i;
            if (current_batch > batch_size) current_batch = batch_size;
            uint32_t payload_size = packet_size - 40;
            for (uint32_t index = 0; index < current_batch; ++index) {
                unsigned char* current = packet + (size_t)index * packet_size;
                prepare_packet(
                    current,
                    packet_size,
                    mode,
                    (i + index) * payload_size,
                    1);
                batch[index].data = current;
                batch[index].capacity = packet_size;
                batch[index].size = packet_size;
            }
            write_result = TapTun_WriteBatch(target.device, batch, current_batch);
            if (write_result != (int)current_batch) break;
            i += current_batch;
            completed += current_batch;
        } else {
            uint32_t header_size = mode == TAPTUN_MODE_TAP ? ETHERNET_HEADER_SIZE + 40u : 40u;
            uint32_t sequence = use_tcp ? i * (packet_size - header_size) : i;
            prepare_packet(packet, packet_size, mode, sequence, use_tcp);
            write_result = TapTun_Write(target.device, packet, (int)packet_size);
            if (write_result != (int)packet_size) break;
            ++i;
            ++completed;
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    result->seconds = elapsed_seconds(start, end);
    free(packet);
    free(batch);

    int failed = use_io_uring
        ? write_result != TAPTUN_OK
        : use_gso ? completed != iterations : write_result != (int)packet_size;
    int used_drain_thread = target.has_drain_thread;
    int native_error = errno;
    if (failed) {
        fprintf(stderr,
            "Packet write failed after %u packets: result=%d system_error=%d (%s).\n",
            completed, write_result, native_error, strerror(native_error));
    }
    close_target(&target, failed);
    errno = native_error;
    if (failed) return write_result;
    if (used_drain_thread &&
        (target.drain_context.error_number != 0 ||
         target.drain_context.received_packets != iterations)) {
        errno = target.drain_context.error_number != 0
            ? target.drain_context.error_number
            : EIO;
        return TAPTUN_ERROR;
    }
    return TAPTUN_OK;
}

static void print_result(
    const char* name,
    uint32_t packet_size,
    uint32_t packet_count,
    const BenchmarkResult* result) {
    double packets_per_second = (double)packet_count / result->seconds;
    double gigabits_per_second = packets_per_second * packet_size * 8.0 / 1000000000.0;
    double nanoseconds_per_packet = result->seconds * 1000000000.0 / packet_count;
    printf(
        "%-18s %8.3f Mpps  %8.3f Gbps  %8.1f ns/packet\n",
        name,
        packets_per_second / 1000000.0,
        gigabits_per_second,
        nanoseconds_per_packet);
}

static int compare_doubles(const void* left, const void* right) {
    double left_value = *(const double*)left;
    double right_value = *(const double*)right;
    return left_value < right_value ? -1 : left_value > right_value ? 1 : 0;
}

static double median_seconds(const BenchmarkResult* results, uint32_t count) {
    double* values = (double*)malloc(sizeof(double) * count);
    if (!values) return 0.0;
    for (uint32_t i = 0; i < count; ++i) values[i] = results[i].seconds;
    qsort(values, count, sizeof(double), compare_doubles);
    double median = count & 1u
        ? values[count / 2]
        : (values[count / 2 - 1] + values[count / 2]) / 2.0;
    free(values);
    return median;
}

static int parse_uint32(const char* value, uint32_t minimum, uint32_t* parsed) {
    char* end = NULL;
    unsigned long number = strtoul(value, &end, 10);
    if (!value[0] || !end || *end != '\0' || number < minimum || number > UINT32_MAX) return 0;
    *parsed = (uint32_t)number;
    return 1;
}

static void print_usage(const char* executable) {
    printf(
        "Usage: %s [--native] [--tap] [--size BYTES] [--iterations COUNT]\n"
        "          [--rounds COUNT] [--io-uring] [--queues COUNT]\n"
        "          [--send-depth COUNT] [--tcp] [--gso] [--batch COUNT]\n"
        "Default mode uses a drained Unix datagram socket to measure the external-handle path.\n"
        "Use --native to measure the platform TUN/TAP backend (usually requires root).\n",
        executable);
}

static const char* backend_name(int use_native, TapTunMode mode, uint32_t capabilities) {
    if (!use_native) return mode == TAPTUN_MODE_TAP ? "external/emulated-tap" : "external/tun";
    if (mode == TAPTUN_MODE_TUN) return "native/tun";
    if (capabilities & TAPTUN_CAP_NATIVE_TAP) return "native/native-tap";
    if (capabilities & TAPTUN_CAP_EMULATED_TAP) return "native/emulated-tap";
    return "native/tap";
}

int main(int argc, char** argv) {
    int use_native = 0;
    TapTunMode mode = TAPTUN_MODE_TUN;
    uint32_t packet_size = DEFAULT_PACKET_SIZE;
    uint32_t iterations = DEFAULT_ITERATIONS;
    uint32_t rounds = DEFAULT_ROUNDS;
    int use_io_uring = 0;
    int use_tcp = 0;
    int use_gso = 0;
    int batch_size_set = 0;
    uint32_t queue_count = 1;
    uint32_t send_queue_depth = 0;
    uint32_t batch_size = DEFAULT_BATCH_SIZE;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--native") == 0) {
            use_native = 1;
            continue;
        }
        if (strcmp(argv[i], "--tap") == 0) {
            mode = TAPTUN_MODE_TAP;
            continue;
        }
        if (strcmp(argv[i], "--io-uring") == 0) {
            use_io_uring = 1;
            continue;
        }
        if (strcmp(argv[i], "--tcp") == 0) {
            use_tcp = 1;
            continue;
        }
        if (strcmp(argv[i], "--gso") == 0) {
            use_gso = 1;
            use_tcp = 1;
            continue;
        }
        if (i + 1 >= argc) {
            print_usage(argv[0]);
            return 2;
        }
        if (strcmp(argv[i], "--size") == 0) {
            if (!parse_uint32(argv[++i], 1, &packet_size)) return 2;
        } else if (strcmp(argv[i], "--iterations") == 0) {
            if (!parse_uint32(argv[++i], 1, &iterations)) return 2;
        } else if (strcmp(argv[i], "--rounds") == 0) {
            if (!parse_uint32(argv[++i], 1, &rounds)) return 2;
        } else if (strcmp(argv[i], "--queues") == 0) {
            if (!parse_uint32(argv[++i], 1, &queue_count)) return 2;
        } else if (strcmp(argv[i], "--send-depth") == 0) {
            if (!parse_uint32(argv[++i], 2, &send_queue_depth)) return 2;
        } else if (strcmp(argv[i], "--batch") == 0) {
            if (!parse_uint32(argv[++i], 2, &batch_size)) return 2;
            batch_size_set = 1;
        } else {
            print_usage(argv[0]);
            return 2;
        }
    }

    uint32_t network_header_size = use_tcp ? 40u : IPV4_UDP_HEADER_SIZE;
    uint32_t minimum_size = mode == TAPTUN_MODE_TAP
        ? ETHERNET_HEADER_SIZE + network_header_size
        : network_header_size;
    if (use_gso) ++minimum_size;
    uint32_t maximum_size = mode == TAPTUN_MODE_TAP
        ? MAX_ETHERNET_FRAME_SIZE
        : MAX_IP_PACKET_SIZE;
    if (packet_size < minimum_size || packet_size > maximum_size) {
        fprintf(stderr, "Packet size must be between %u and %u bytes in this mode.\n",
            minimum_size, maximum_size);
        return 2;
    }
    if (!use_native && (use_io_uring || use_gso || queue_count > 1 || send_queue_depth != 0)) {
        fprintf(stderr, "io_uring, GSO, and multi-queue options require --native.\n");
        return 2;
    }
    if (!use_io_uring && send_queue_depth != 0) {
        fprintf(stderr, "--send-depth requires --io-uring.\n");
        return 2;
    }
    if (use_gso && (mode != TAPTUN_MODE_TUN || use_io_uring)) {
        fprintf(stderr, "--gso currently requires TUN mode and cannot be combined with --io-uring.\n");
        return 2;
    }
    if (!use_gso && batch_size_set) {
        fprintf(stderr, "--batch requires --gso.\n");
        return 2;
    }

    printf("Benchmark build: optimization=%s\n", BENCHMARK_OPTIMIZATION);
    if (strcmp(BENCHMARK_OPTIMIZATION, "disabled") == 0) {
        fprintf(stderr, "Warning: compiler optimization is disabled; performance results are invalid.\n");
    }

    BenchmarkResult warmup;
    uint32_t capabilities = 0;
    int result = run_benchmark(
        use_native,
        mode,
        use_io_uring,
        use_tcp,
        use_gso,
        queue_count,
        send_queue_depth,
        batch_size,
        packet_size,
        WARMUP_ITERATIONS,
        &warmup,
        &capabilities);
    if (result != TAPTUN_OK) {
        fprintf(stderr,
            "Benchmark warmup failed: result=%d system_error=%u (%s).%s\n",
            result,
            TapTun_GetLastSystemError(),
            strerror((int)TapTun_GetLastSystemError()),
            use_native ? " Check privileges and native TUN/TAP availability." : "");
        return 1;
    }

    const char* selected_backend = backend_name(use_native, mode, capabilities);
    printf(
        "POSIX send benchmark: backend=%s packet=%u bytes protocol=%s iterations/round=%u rounds=%u queues=%u send=%s batch=%u\n",
        selected_backend,
        packet_size,
        use_tcp ? "tcp" : "udp",
        iterations,
        rounds,
        use_native ? queue_count : 1,
        use_io_uring ? "io_uring/fixed-buffer" : use_gso ? "gso/write-batch" : "write",
        use_gso ? batch_size : 1);
    if (!use_native) {
        printf("External mode includes socketpair send and concurrent drain costs.\n");
    }

    BenchmarkResult* results = (BenchmarkResult*)calloc(rounds, sizeof(BenchmarkResult));
    if (!results) return 1;
    for (uint32_t round = 0; round < rounds; ++round) {
        result = run_benchmark(
            use_native,
            mode,
            use_io_uring,
            use_tcp,
            use_gso,
            queue_count,
            send_queue_depth,
            batch_size,
            packet_size,
            iterations,
            &results[round],
            NULL);
        if (result != TAPTUN_OK) break;
        char round_name[32];
        snprintf(round_name, sizeof(round_name), "  round %u", round + 1);
        print_result(round_name, packet_size, iterations, &results[round]);
    }
    if (result != TAPTUN_OK) {
        fprintf(stderr,
            "Benchmark failed: result=%d system_error=%u (%s).\n",
            result,
            TapTun_GetLastSystemError(),
            strerror((int)TapTun_GetLastSystemError()));
        free(results);
        return 1;
    }

    BenchmarkResult median = { median_seconds(results, rounds) };
    free(results);
    if (median.seconds == 0.0) {
        fprintf(stderr, "Failed to calculate benchmark median.\n");
        return 1;
    }
    printf("Median of %u rounds\n", rounds);
    print_result("  send", packet_size, iterations, &median);
    return 0;
}
