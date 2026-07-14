[简体中文](README.md)

## Introduction

taptun-helper provides a unified API for creating, configuring, reading, and writing TUN and TAP devices.

The project's own code is licensed under MIT. This repository does not distribute Wintun or any other third-party binary.

## Platform Support

| Platform | TUN | TAP |
|-|-|-|
| Windows | Wintun | Prefers installed tap-windows6; can fall back to Wintun + tun2tap |
| Linux | Native `IFF_TUN` | Native `IFF_TAP`, or forced TUN + tun2tap |
| Android | `VpnService` TUN fd | tun2tap over the host TUN fd |
| macOS | utun | utun + tun2tap |
| iOS and other restricted platforms | Platform VPN callbacks | tun2tap over layer-3 callbacks |
| Other POSIX platforms | Caller-provided TUN/TAP handle | Native TAP handle or TUN + tun2tap |

Emulated TAP is a routed Ethernet compatibility layer supporting Ethernet II, IPv4, IPv6, proxy ARP, IPv6 NDP, and IP multicast MAC mapping. It is not a layer-2 switch and does not support arbitrary non-IP EtherTypes, VLANs, or layer-2 broadcast protocols. Select native TAP when full layer-2 behavior is required.

## Building

```bash
make all
make test
```

`BUILD=release` is the default and compiles with `-O3 -DNDEBUG`. Use the following for a debug build:

```bash
make BUILD=debug all test
```

Object files for different platforms, build configurations, and compilers are stored separately, so changing `TARGET`, `BUILD`, or `CC` cannot reuse incompatible stale objects.

Set `TARGET` to `windows`, `linux`, `macos`, or `posix` to select a backend explicitly. MinGW64 or Clang64 is recommended on Windows.

The native Linux TUN/TAP tests require root privileges:

```bash
sudo ./bin/test_linux --native
sudo ./bin/test_linux --native-tap
sudo ./bin/test_linux --native-performance
sudo ./bin/test_linux --native-gso-read
```

Without `--native`, Linux and generic POSIX tests only exercise externally supplied handles and do not require root access.

## Windows Backends

This repository includes only `wintun.h`, selected under its MIT option. It does not provide, download, or install `wintun.dll`. The caller must obtain the correct DLL architecture from the [official Wintun website](https://www.wintun.net/) and pass its path through `TapTunOptions.wintun_dll_path`, or place it in the application directory.

The library uses Wintun through `LoadLibraryExW` and `GetProcAddress`. It does not copy the GPLv2 Wintun example implementation.

Native TAP uses an installed tap-windows6 adapter. The repository contains only its MIT-licensed IOCTL header and integration code; it does not provide, download, or install the tap-windows6 driver. TAP backend policies are:

- `TAPTUN_TAP_BACKEND_AUTO`: try tap-windows6 first, then Wintun + tun2tap.
- `TAPTUN_TAP_BACKEND_NATIVE_ONLY`: accept tap-windows6 only.
- `TAPTUN_TAP_BACKEND_EMULATED_ONLY`: use Wintun + tun2tap only.

Run these from an elevated shell:

```powershell
.\bin\test_windows.exe --tap-native
.\bin\test_windows.exe --tap-auto
.\bin\test_windows.exe --tap-emulated
```

The cross-platform callback and batch API test does not create an adapter and can run without elevation: `.\bin\test_windows.exe --callbacks-only`.

## Basic Usage

```c
TapTunOptions options = {0};
options.name = "taptun0";

TapTunDevice* device = TapTun_Open(&options);
if (!device) return 1;

TapTun_SetIPAddressV4(device, "10.0.0.1", 24);
TapTun_Activate(device);

unsigned char packet[65535];
int packet_size = TapTun_Read(device, packet, sizeof(packet));

TapTun_Close(device);
```

Set the mode and backend policy to create TAP:

```c
TapTunOptions options = {0};
options.name = "taptap0";
options.mode = TAPTUN_MODE_TAP;
options.tap_backend = TAPTUN_TAP_BACKEND_AUTO;

TapTunDevice* device = TapTun_Open(&options);
uint32_t capabilities = TapTun_GetCapabilities(device);
```

Use `TAPTUN_CAP_NATIVE_TAP` and `TAPTUN_CAP_EMULATED_TAP` to identify the selected backend. `TapTun_Read` and `TapTun_Write` exchange complete Ethernet II frames in TAP mode.

On Android and similar platforms, create the TUN through the platform API and wrap it with:

```c
TapTunHandleOptions options = {0};
options.handle = tun_fd;
options.take_ownership = 0;
options.backend_mode = TAPTUN_MODE_TUN;
options.mode = TAPTUN_MODE_TAP; // Expose emulated TAP to the caller.

TapTunDevice* device = TapTun_OpenFromHandle(&options);
```

Address, route, and DNS configuration is normally owned by the host VPN API in this mode.

Platforms that do not expose an fd can use `TapTun_OpenFromCallbacks`. Callbacks are synchronous from the library's point of view, and `close` must unblock a pending `read`. Emulated TAP additionally requires `interrupt_read`; when the library queues an ARP/NDP reply it calls this callback, after which `read` should return `TAPTUN_ERROR_BUSY` so the internal reply queue can be read.

## Linux Performance Configuration

The native Linux backend can explicitly request io_uring send, multi-queue, and GSO through a separate versioned configuration. `TapTun_Open` retains its single-queue synchronous behavior and does not silently change latency or buffer lifetime for existing callers:

```c
TapTunOptions options = {0};
options.name = "taptun0";
options.mode = TAPTUN_MODE_TUN;

TapTunPerformanceOptions performance = {0};
performance.struct_size = sizeof(performance);
performance.preferred_features = TAPTUN_PERF_IO_URING_SEND | TAPTUN_PERF_GSO;
performance.required_features = TAPTUN_PERF_MULTI_QUEUE;
performance.queue_count = 4;
performance.send_queue_depth = 64;

TapTunDevice* device = TapTun_OpenWithPerformance(&options, &performance);
```

An unavailable preferred feature falls back, while opening fails when a required feature cannot be enabled. Multi-queue requires an explicit `queue_count` greater than one. Its queue fds attach to one network interface and share its name, ifindex, addresses, routes, and MTU; they are not independent TUN devices. `TapTun_GetQueueCount` and `TapTun_GetCapabilities` report the effective result. Synchronous and io_uring writes use flow-affine queue selection to avoid reordering one flow across queues, while reads poll every queue.

io_uring is used only by `TapTun_AcquireSend`/`TapTun_CommitSend`. The backend registers the TUN/TAP queue fds and a fixed buffer pool once during open. The caller builds directly in acquired storage, and `TapTun_CommitSend` transfers ownership and submits asynchronously. A later acquire waits for a CQE when the pool is exhausted. `TapTun_Write` always remains a direct synchronous write and does not add an internal copy merely to use io_uring. Zero-copy here means no additional user-space buffer copy; the kernel still constructs a network packet from the data.

Per-packet io_uring submission is not guaranteed to outperform direct `write` in a single producer. Enable it only when the caller can build directly in leased storage, maintain multiple in-flight submissions, and has measured its real workload. `TapTun_Close` discards an uncommitted lease and waits for submitted requests before releasing registered storage.

`TAPTUN_PERF_GSO` currently supports TCP/IPv4 and TCP/IPv6 on native Linux TUN only. A successfully enabled device reports `TAPTUN_CAP_GSO`. The backend uses `IFF_VNET_HDR` and `TUNSETOFFLOAD` while keeping Linux virtio-net metadata private:

- `TapTun_ReadBatch` segments one kernel GSO super-packet into ordinary IP packets in caller-provided buffers.
- `TapTun_WriteBatch` only coalesces packets with a matching TCP flow, contiguous sequence numbers, compatible headers, and valid checksums. Incompatible, reordered, or invalid packets retain ordinary write behavior.
- `TapTun_Read` still returns one ordinary packet and retains remaining segments for later calls. `TapTun_Write` still writes one ordinary packet. Existing callers remain correct, but the batch API is required for the full throughput benefit.
- `TapTun_AcquireSend`/`TapTun_CommitSend` still submit one ordinary packet. GSO and io_uring can be enabled together, but the lease API does not delay or implicitly aggregate future packets.

```c
unsigned char storage[32][2048];
TapTunBuffer packets[32] = {0};
for (uint32_t i = 0; i < 32; ++i) {
    packets[i].data = storage[i];
    packets[i].capacity = sizeof(storage[i]);
}

int count = TapTun_ReadBatch(device, packets, 32);
if (count > 0) {
    encrypt_and_send_normal_mtu_packets(packets, (uint32_t)count);
}
```

The batch API exists on every platform. Other backends process ordinary packets, so cross-platform callers need neither preprocessor guards nor hot-path calls that only return `UNSUPPORTED`. GSO/GRO is local batching at the TUN boundary: the public network still carries independent ordinary-MTU tunnel packets, and the receiver never waits to reconstruct the sender's original 64 KiB boundary. Configure the virtual interface MTU as the public Path MTU minus tunnel, encryption, UDP, and IP overhead.

## Zero-Copy I/O

Use `TapTun_GetCapabilities` to check whether the current device supports zero-copy I/O. Native Wintun TUN supports zero-copy receive and send. Native Linux TUN/TAP supports asynchronous zero-copy send when io_uring was explicitly enabled. Emulated TAP does not expose this API because it must add or remove an Ethernet header and cannot preserve the contiguous-buffer lease semantics.

```c
if (TapTun_GetCapabilities(device) & TAPTUN_CAP_ZERO_COPY_SEND) {
    TapTunPacket packet;
    if (TapTun_AcquireSend(device, packet_size, &packet) == TAPTUN_OK) {
        build_ip_packet(packet.data, packet.size);
        TapTun_CommitSend(device, &packet);
    }
}
```

Received data remains valid until `TapTun_ReleaseReceive`; send storage remains valid until `TapTun_CommitSend`. Each device allows one receive lease and one uncommitted send lease at a time, while Linux can retain multiple committed buffers in flight. A later `TapTun_AcquireSend` reports asynchronous completion errors. `TapTun_Close` immediately invalidates outstanding leases, so callers must not access a `TapTunPacket` after close.

## Performance Benchmark Example

Always use `BUILD=release` for benchmarks. Linux, macOS, and generic POSIX backends share one send benchmark:

```bash
make TARGET=linux BUILD=release benchmark
./bin/benchmark_linux --iterations 100000 --rounds 4
```

The default mode uses a continuously drained Unix datagram `socketpair` to measure the external TUN handle wrapper. It requires no root privileges and is suitable for CI and Android/host VPN integration regressions. It includes per-packet construction, local socket send, and concurrent drain costs and does not represent native TUN performance. Native mode also includes per-packet construction to match the Windows benchmark methodology. Use root privileges to measure the real kernel TUN write path on Linux or WSL:

```bash
sudo ./bin/benchmark_linux --native --size 1400 --iterations 100000 --rounds 4
```

Linux can measure fixed-buffer io_uring, an explicit queue count, and single-flow TCP GSO batch writes separately:

```bash
sudo ./bin/benchmark_linux --native --io-uring --size 1400
sudo ./bin/benchmark_linux --native --io-uring --queues 4 --send-depth 64 --size 1400
sudo ./bin/benchmark_linux --native --tcp --size 1400
sudo ./bin/benchmark_linux --native --gso --batch 32 --size 1400
```

The current benchmark uses one send thread. `--queues` primarily verifies configuration and queue-selection overhead; it does not represent the parallel throughput ceiling of multi-queue, which requires independent flows and concurrent producers. `--gso` supplies checksum-valid packets with contiguous TCP sequence numbers to `TapTun_WriteBatch`; it measures the GRO/GSO path used to inject packets received from the public network into local TUN, excluding encryption and public-network transport.

Add `--tap` to measure TAP. Linux `--native --tap` uses native `IFF_TAP`; native TAP mode on macOS uses utun + tun2tap. The generic POSIX target cannot create a native device, so it only supports external-handle mode:

```bash
make TARGET=posix BUILD=release benchmark
./bin/benchmark_posix --tap
```

On macOS, `make TARGET=macos BUILD=release benchmark` produces `bin/benchmark_macos`. The entry point is provided, but this repository currently has no macOS execution environment, so it still requires verification on a real macOS host.

The Windows benchmark additionally compares the copying write path with constructing packets directly in Wintun's send ring:

```bash
make TARGET=windows BUILD=release benchmark
./bin/benchmark_windows.exe --size 1400 --iterations 100000 --rounds 4
```

Run it from an elevated shell. Add `--dll PATH` when `wintun.dll` is not beside the executable in `bin`. The program verifies compiler optimization, warms up both modes, alternates their execution order, prints every round, and calculates the final ratio from median times. Packet generation writes each byte once so an unoptimized test loop cannot hide the copy cost. It measures local packet injection into the Windows network stack, not encrypted, forwarded, or end-to-end VPN throughput.

By default, each round is split into 10000-packet bursts with a 25 ms drain interval between them. Drain time is excluded from the result. This keeps 100000 measured packets per round while avoiding ring-full retries and very short samples dominated by Windows scheduling. Use `--burst COUNT` and `--drain-ms MILLISECONDS` to tune this behavior. To measure sustained saturation of the Windows network stack, run:

```bash
./bin/benchmark_windows.exe --size 1400 --iterations 100000 --rounds 4 --saturated
```

## Third-Party Files

| Component | File | License |
|-|-|-|
| [Wintun API](https://git.zx2c4.com/wintun/) | [include/wintun.h](include/wintun.h) | GPL-2.0 OR MIT; this project selects MIT. The full license is in the file header. |
| [tap-windows6 header](https://github.com/OpenVPN/tap-windows6/) | [include/tap-windows6.h](include/tap-windows6.h) | MIT. The full license is in the file header. |
