#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "../include/taptun_api.h"

#define DEFAULT_PACKET_SIZE 1400u
#define DEFAULT_ITERATIONS 100000u
#define DEFAULT_ROUNDS 4u
#define DEFAULT_BURST_SIZE 10000u
#define DEFAULT_DRAIN_MS 25u
#define WARMUP_ITERATIONS 5000u
#define WINTUN_BENCHMARK_RING_CAPACITY 0x4000000u

#if defined(__OPTIMIZE__)
#define BENCHMARK_OPTIMIZATION "enabled"
#else
#define BENCHMARK_OPTIMIZATION "disabled"
#endif

typedef struct {
    double seconds;
    unsigned long long retries;
} BenchmarkResult;

static uint16_t ipv4_checksum(const unsigned char* data, size_t size) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < size; i += 2) {
        sum += ((uint32_t)data[i] << 8) | data[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static void prepare_ipv4_udp(unsigned char* packet, uint32_t packet_size, uint32_t sequence) {
    // Write each packet region once so packet construction does not hide the
    // additional copy performed by TapTun_Write.
    memset(packet, 0, 28);
    memset(packet + 28, (unsigned char)sequence, packet_size - 28);
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
    for (uint32_t i = 28; i < packet_size; ++i) {
        packet[i] = (unsigned char)(sequence + i);
    }

    uint16_t checksum = ipv4_checksum(packet, 20);
    packet[10] = (unsigned char)(checksum >> 8);
    packet[11] = (unsigned char)checksum;
}

static double elapsed_seconds(LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER frequency) {
    return (double)(end.QuadPart - start.QuadPart) / (double)frequency.QuadPart;
}

static int run_copy_benchmark(
    TapTunDevice* device,
    uint32_t packet_size,
    uint32_t iterations,
    uint32_t burst_size,
    uint32_t drain_ms,
    BenchmarkResult* result) {
    result->seconds = 0.0;
    result->retries = 0;
    unsigned char* packet = (unsigned char*)malloc(packet_size);
    if (!packet) return TAPTUN_ERROR;

    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    QueryPerformanceFrequency(&frequency);
    uint32_t completed = 0;
    while (completed < iterations) {
        uint32_t chunk_size = burst_size == 0 || burst_size > iterations - completed
            ? iterations - completed
            : burst_size;
        QueryPerformanceCounter(&start);
        for (uint32_t i = 0; i < chunk_size; ++i) {
            prepare_ipv4_udp(packet, packet_size, completed + i);
            int write_result;
            do {
                write_result = TapTun_Write(device, packet, (int)packet_size);
                if (write_result == TAPTUN_ERROR_BUSY) {
                    ++result->retries;
                    SwitchToThread();
                }
            } while (write_result == TAPTUN_ERROR_BUSY);
            if (write_result != (int)packet_size) {
                free(packet);
                return write_result;
            }
        }
        QueryPerformanceCounter(&end);
        result->seconds += elapsed_seconds(start, end, frequency);
        completed += chunk_size;
        if (completed < iterations && burst_size != 0 && drain_ms != 0) Sleep(drain_ms);
    }
    free(packet);
    return TAPTUN_OK;
}

static int run_zero_copy_benchmark(
    TapTunDevice* device,
    uint32_t packet_size,
    uint32_t iterations,
    uint32_t burst_size,
    uint32_t drain_ms,
    BenchmarkResult* result) {
    result->seconds = 0.0;
    result->retries = 0;
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    QueryPerformanceFrequency(&frequency);
    uint32_t completed = 0;
    while (completed < iterations) {
        uint32_t chunk_size = burst_size == 0 || burst_size > iterations - completed
            ? iterations - completed
            : burst_size;
        QueryPerformanceCounter(&start);
        for (uint32_t i = 0; i < chunk_size; ++i) {
            TapTunPacket packet;
            int acquire_result;
            do {
                acquire_result = TapTun_AcquireSend(device, packet_size, &packet);
                if (acquire_result == TAPTUN_ERROR_BUSY) {
                    ++result->retries;
                    SwitchToThread();
                }
            } while (acquire_result == TAPTUN_ERROR_BUSY);
            if (acquire_result != TAPTUN_OK) return acquire_result;

            // Construct directly in Wintun's send ring to avoid an extra memcpy.
            prepare_ipv4_udp(packet.data, packet.size, completed + i);
            int commit_result = TapTun_CommitSend(device, &packet);
            if (commit_result != TAPTUN_OK) return commit_result;
        }
        QueryPerformanceCounter(&end);
        result->seconds += elapsed_seconds(start, end, frequency);
        completed += chunk_size;
        if (completed < iterations && burst_size != 0 && drain_ms != 0) Sleep(drain_ms);
    }
    return TAPTUN_OK;
}

static void print_result(
    const char* name,
    uint32_t packet_size,
    unsigned long long packet_count,
    const BenchmarkResult* result) {
    double packets_per_second = (double)packet_count / result->seconds;
    double gigabits_per_second = packets_per_second * packet_size * 8.0 / 1000000000.0;
    double nanoseconds_per_packet = result->seconds * 1000000000.0 / packet_count;
    printf(
        "%-18s %8.3f Mpps  %8.3f Gbps  %8.1f ns/packet  retries=%llu\n",
        name,
        packets_per_second / 1000000.0,
        gigabits_per_second,
        nanoseconds_per_packet,
        result->retries);
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

static unsigned long long total_retries(const BenchmarkResult* results, uint32_t count) {
    unsigned long long retries = 0;
    for (uint32_t i = 0; i < count; ++i) retries += results[i].retries;
    return retries;
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
        "Usage: %s [--dll PATH] [--size BYTES] [--iterations COUNT] [--rounds COUNT]\n"
        "          [--burst COUNT] [--drain-ms MILLISECONDS] [--saturated]\n"
        "Run from an elevated shell. Packet size must be 28..65535 bytes.\n",
        executable);
}

static void configure_benchmark_priority(void) {
    if (!SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
        fprintf(
            stderr,
            "Warning: failed to set high process priority. Win32 error=%lu.\n",
            (unsigned long)GetLastError());
    }
    if (!SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST)) {
        fprintf(
            stderr,
            "Warning: failed to set high thread priority. Win32 error=%lu.\n",
            (unsigned long)GetLastError());
    }
}

int main(int argc, char** argv) {
    const char* dll_path = NULL;
    uint32_t packet_size = DEFAULT_PACKET_SIZE;
    uint32_t iterations = DEFAULT_ITERATIONS;
    uint32_t rounds = DEFAULT_ROUNDS;
    uint32_t burst_size = DEFAULT_BURST_SIZE;
    uint32_t drain_ms = DEFAULT_DRAIN_MS;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--saturated") == 0) {
            burst_size = 0;
            drain_ms = 0;
            continue;
        }
        if (i + 1 >= argc) {
            print_usage(argv[0]);
            return 2;
        }
        if (strcmp(argv[i], "--dll") == 0) {
            dll_path = argv[++i];
        } else if (strcmp(argv[i], "--size") == 0) {
            if (!parse_uint32(argv[++i], 1, &packet_size)) return 2;
        } else if (strcmp(argv[i], "--iterations") == 0) {
            if (!parse_uint32(argv[++i], 1, &iterations)) return 2;
        } else if (strcmp(argv[i], "--rounds") == 0) {
            if (!parse_uint32(argv[++i], 1, &rounds)) return 2;
        } else if (strcmp(argv[i], "--burst") == 0) {
            if (!parse_uint32(argv[++i], 1, &burst_size)) return 2;
        } else if (strcmp(argv[i], "--drain-ms") == 0) {
            if (!parse_uint32(argv[++i], 0, &drain_ms)) return 2;
        } else {
            print_usage(argv[0]);
            return 2;
        }
    }
    if (packet_size < 28 || packet_size > 65535) {
        fprintf(stderr, "Packet size must be between 28 and 65535 bytes.\n");
        return 2;
    }
    printf("Benchmark build: optimization=%s\n", BENCHMARK_OPTIMIZATION);
    if (strcmp(BENCHMARK_OPTIMIZATION, "disabled") == 0) {
        fprintf(stderr, "Warning: compiler optimization is disabled; performance results are invalid.\n");
    }
    configure_benchmark_priority();

    TapTunOptions options;
    memset(&options, 0, sizeof(options));
    options.name = "taptun-benchmark";
    options.wintun_dll_path = dll_path;
    options.ring_capacity = WINTUN_BENCHMARK_RING_CAPACITY;
    TapTunDevice* device = TapTun_Open(&options);
    if (!device) {
        fprintf(
            stderr,
            "Failed to open Wintun. Win32 error: %lu. Run as Administrator and verify wintun.dll.\n",
            (unsigned long)TapTun_GetLastSystemError());
        return 1;
    }
    if ((TapTun_GetCapabilities(device) & TAPTUN_CAP_ZERO_COPY_SEND) == 0) {
        fprintf(stderr, "The selected backend does not support zero-copy send.\n");
        TapTun_Close(device);
        return 1;
    }

    BenchmarkResult warmup = { 0.0, 0 };
    int result = run_copy_benchmark(device, packet_size, WARMUP_ITERATIONS, 0, 0, &warmup);
    if (result == TAPTUN_OK) {
        memset(&warmup, 0, sizeof(warmup));
        result = run_zero_copy_benchmark(device, packet_size, WARMUP_ITERATIONS, 0, 0, &warmup);
    }
    if (result != TAPTUN_OK) {
        fprintf(stderr, "Benchmark warmup failed: result=%d Win32 error=%lu.\n",
            result, (unsigned long)TapTun_GetLastSystemError());
        TapTun_Close(device);
        return 1;
    }

    if (burst_size == 0) {
        printf(
            "Wintun send benchmark: packet=%u bytes iterations/round=%u rounds=%u "
            "ring=64 MiB mode=saturated\n",
            packet_size,
            iterations,
            rounds);
    } else {
        printf(
            "Wintun send benchmark: packet=%u bytes iterations/round=%u rounds=%u "
            "ring=64 MiB burst=%u drain=%u ms\n",
            packet_size,
            iterations,
            rounds,
            burst_size,
            drain_ms);
    }

    BenchmarkResult* copy_results = (BenchmarkResult*)calloc(rounds, sizeof(BenchmarkResult));
    BenchmarkResult* zero_copy_results = (BenchmarkResult*)calloc(rounds, sizeof(BenchmarkResult));
    if (!copy_results || !zero_copy_results) {
        free(copy_results);
        free(zero_copy_results);
        TapTun_Close(device);
        return 1;
    }

    for (uint32_t round = 0; round < rounds && result == TAPTUN_OK; ++round) {
        if ((round & 1u) == 0) {
            result = run_copy_benchmark(
                device,
                packet_size,
                iterations,
                burst_size,
                drain_ms,
                &copy_results[round]);
            if (result == TAPTUN_OK) {
                Sleep(50);
                result = run_zero_copy_benchmark(
                    device,
                    packet_size,
                    iterations,
                    burst_size,
                    drain_ms,
                    &zero_copy_results[round]);
            }
        } else {
            result = run_zero_copy_benchmark(
                device,
                packet_size,
                iterations,
                burst_size,
                drain_ms,
                &zero_copy_results[round]);
            if (result == TAPTUN_OK) {
                Sleep(50);
                result = run_copy_benchmark(
                    device,
                    packet_size,
                    iterations,
                    burst_size,
                    drain_ms,
                    &copy_results[round]);
            }
        }
        if (result == TAPTUN_OK) {
            printf("Round %u\n", round + 1);
            print_result("  copy write", packet_size, iterations, &copy_results[round]);
            print_result("  zero-copy", packet_size, iterations, &zero_copy_results[round]);
            printf(
                "  ratio             %.3fx\n",
                copy_results[round].seconds / zero_copy_results[round].seconds);
        }
        Sleep(50);
    }
    if (result != TAPTUN_OK) {
        fprintf(
            stderr,
            "Benchmark failed: result=%d Win32 error=%lu.\n",
            result,
            (unsigned long)TapTun_GetLastSystemError());
        free(copy_results);
        free(zero_copy_results);
        TapTun_Close(device);
        return 1;
    }

    unsigned long long copy_retries = total_retries(copy_results, rounds);
    unsigned long long zero_copy_retries = total_retries(zero_copy_results, rounds);
    BenchmarkResult copy_median = { median_seconds(copy_results, rounds), 0 };
    BenchmarkResult zero_copy_median = { median_seconds(zero_copy_results, rounds), 0 };
    if (copy_median.seconds == 0.0 || zero_copy_median.seconds == 0.0) {
        fprintf(stderr, "Failed to calculate benchmark medians.\n");
        free(copy_results);
        free(zero_copy_results);
        TapTun_Close(device);
        return 1;
    }

    printf("Median of %u rounds\n", rounds);
    print_result("  copy write", packet_size, iterations, &copy_median);
    print_result("  zero-copy", packet_size, iterations, &zero_copy_median);
    printf("  ratio             %.3fx\n", copy_median.seconds / zero_copy_median.seconds);
    printf(
        "Total ring-full retries: copy=%llu zero-copy=%llu\n",
        copy_retries,
        zero_copy_retries);
    free(copy_results);
    free(zero_copy_results);
    TapTun_Close(device);
    return 0;
}
