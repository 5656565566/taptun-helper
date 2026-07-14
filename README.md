[English](README_EN.md)

## 介绍

taptun-helper 提供统一的 TUN/TAP 设备创建、配置和数据包读写接口。

项目自有代码使用 MIT 许可证。仓库不提供 Wintun 或其他第三方项目的二进制文件。

## 平台支持

| 平台 | TUN | TAP |
|-|-|-|
| Windows | Wintun | 优先使用已安装的 tap-windows6；可回退到 Wintun + tun2tap |
| Linux | 原生 `IFF_TUN` | 原生 `IFF_TAP`，也可强制 TUN + tun2tap |
| Android | `VpnService` TUN fd | 在宿主 TUN fd 上进行 tun2tap |
| macOS（未经测试） | utun | utun + tun2tap |
| iOS 及其他受限平台（未经测试） | 平台 VPN API 回调 | 在三层回调上进行 tun2tap |
| 其他 POSIX 平台 | 调用方提供的 TUN/TAP 句柄 | 原生 TAP 句柄或 TUN + tun2tap |

模拟 TAP 提供路由型 Ethernet 兼容层，支持 Ethernet II、IPv4、IPv6、代理 ARP、IPv6 NDP 和 IP 组播 MAC 映射。它不是二层交换机，不支持任意非 IP EtherType、VLAN 或二层广播协议；需要完整二层语义时应选择原生 TAP。

## 编译

```bash
make all
make test
```

默认使用 `BUILD=release`，并以 `-O3 -DNDEBUG` 编译。调试构建使用：

```bash
make BUILD=debug all test
```

不同平台、构建配置和编译器的对象文件保存在独立目录中，切换 `TARGET`、`BUILD` 或 `CC` 不会复用不兼容的旧对象。

可以通过 `TARGET` 显式选择 `windows`、`linux`、`macos` 或 `posix`。Windows 推荐在 MinGW64/Clang64 环境编译。

Linux 原生 TUN/TAP 测试需要 root 权限：

```bash
sudo ./bin/test_linux --native
sudo ./bin/test_linux --native-tap
sudo ./bin/test_linux --native-performance
sudo ./bin/test_linux --native-gso-read
```

不带 `--native` 的 Linux/通用 POSIX 测试只验证外部句柄接入，不需要 root 权限。

## Windows 后端

本仓库只包含采用 MIT 选项使用的 `wintun.h`，不提供、下载或安装 `wintun.dll`。调用方应从 [Wintun 官方网站](https://www.wintun.net/)获取与目标架构匹配的 DLL，并通过 `TapTunOptions.wintun_dll_path` 显式传入路径，或将其放在应用程序目录中。

库通过 `LoadLibraryExW` 和 `GetProcAddress` 使用 Wintun，不复制 Wintun GPLv2 示例代码。

原生 TAP 使用系统中已安装的 tap-windows6 适配器。仓库只保留 MIT 许可的 IOCTL 头文件和调用代码，不提供、下载或安装 tap-windows6 驱动。TAP 后端策略如下：

- `TAPTUN_TAP_BACKEND_AUTO`：Windows 先查找 tap-windows6，找不到时使用 Wintun + tun2tap。
- `TAPTUN_TAP_BACKEND_NATIVE_ONLY`：只接受 tap-windows6。
- `TAPTUN_TAP_BACKEND_EMULATED_ONLY`：只使用 Wintun + tun2tap。

管理员终端中的测试命令：

```powershell
.\bin\test_windows.exe --tap-native
.\bin\test_windows.exe --tap-auto
.\bin\test_windows.exe --tap-emulated
```

不创建适配器的跨平台回调与批量 API 测试可在普通终端运行：`.\bin\test_windows.exe --callbacks-only`。

## 基本用法

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

创建 TAP 时设置模式和后端策略：

```c
TapTunOptions options = {0};
options.name = "taptap0";
options.mode = TAPTUN_MODE_TAP;
options.tap_backend = TAPTUN_TAP_BACKEND_AUTO;

TapTunDevice* device = TapTun_Open(&options);
uint32_t capabilities = TapTun_GetCapabilities(device);
```

通过 `TAPTUN_CAP_NATIVE_TAP` 与 `TAPTUN_CAP_EMULATED_TAP` 判断实际后端。`TapTun_Read`/`TapTun_Write` 在 TAP 模式下读写完整 Ethernet II 帧。

Android 等平台由系统创建 TUN 后，使用：

```c
TapTunHandleOptions options = {0};
options.handle = tun_fd;
options.take_ownership = 0;
options.backend_mode = TAPTUN_MODE_TUN;
options.mode = TAPTUN_MODE_TAP; // 对调用方暴露模拟 TAP

TapTunDevice* device = TapTun_OpenFromHandle(&options);
```

此时地址、路由和 DNS 通常由宿主平台 VPN API 配置。

不提供 fd 的平台使用 `TapTun_OpenFromCallbacks`。回调从本库视角是同步的，`close` 必须唤醒正在阻塞的 `read`。模拟 TAP 还要求提供 `interrupt_read`；库生成 ARP/NDP 回复时会调用它，随后 `read` 应返回 `TAPTUN_ERROR_BUSY`，使库从内部回复队列继续读取。

## Linux 性能配置

Linux 原生后端可通过独立的版本化配置显式请求 io_uring 发送、multi-queue 和 GSO。`TapTun_Open` 保持单队列同步行为，不会自动改变已有调用方的延迟或缓冲区生命周期：

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

preferred 功能不受平台或内核支持时会回退，required 功能无法启用时打开失败。multi-queue 必须显式设置大于 1 的 `queue_count`；多个队列 fd 挂到同一个网络接口，共享接口名、ifindex、IP、路由和 MTU，并不是多个独立 TUN。`TapTun_GetQueueCount` 与 `TapTun_GetCapabilities` 返回实际结果。同步和 io_uring 写入都按 IP 流固定选择队列，避免同一流跨队列乱序；读操作轮询全部队列。

io_uring 只用于 `TapTun_AcquireSend`/`TapTun_CommitSend`。打开时一次注册 TUN/TAP 队列 fd 和固定缓冲池，调用方直接在取得的缓冲区中构造包；`TapTun_CommitSend` 转移所有权并异步提交，缓冲池耗尽时下一次 acquire 会等待 CQE 回收。`TapTun_Write` 始终保持直接同步写，不会为了使用 io_uring 增加一次内部复制。这里的零拷贝指不发生额外的用户态缓冲区复制，内核仍需把数据构造成网络包。

io_uring 不保证单线程逐包提交比直接 `write` 更快，因此只应在调用方可以直接构造发送缓冲区、维持多个在途提交并经过实际负载测试后启用。`TapTun_Close` 会丢弃尚未 commit 的租约，并等待已提交请求完成后再释放注册缓冲区。

`TAPTUN_PERF_GSO` 当前只支持 Linux 原生 TUN 的 TCP/IPv4 和 TCP/IPv6。成功启用后返回 `TAPTUN_CAP_GSO`，后端通过 `IFF_VNET_HDR`、`TUNSETOFFLOAD` 隐藏 Linux virtio-net 元数据：

- `TapTun_ReadBatch` 把内核交付的一个 GSO 大包分段到调用方提供的多个普通 IP 包缓冲区。
- `TapTun_WriteBatch` 只合并同一 TCP 流中序号连续、头部兼容且校验和有效的包，然后用一个 GSO 写入交给内核；不兼容、乱序或校验和无效的包保持普通写入。
- `TapTun_Read` 在启用 GSO 后仍返回一个普通包，剩余分段由后续调用读取；`TapTun_Write` 仍写一个普通包。因此旧调用保持正确，但只有批量 API 能获得完整收益。
- `TapTun_AcquireSend`/`TapTun_CommitSend` 仍提交一个普通包。GSO 与 io_uring 可以同时启用，但现有租约接口不会隐式等待或聚合后续包。

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

批量 API 在所有平台都存在，其他后端按普通包处理，因此跨平台调用方不需要宏定义，也不会触发仅返回 `UNSUPPORTED` 的热路径。GSO/GRO 只是本机 TUN 边界的批处理：公网仍传输独立的普通 MTU 隧道包，接收端不会等待恢复发送端原来的 64 KiB 边界。调用方应把虚拟网卡 MTU 设置为公网 Path MTU 减去隧道、加密、UDP 和 IP 头开销。

## 零拷贝收发

通过 `TapTun_GetCapabilities` 检查当前设备是否支持零拷贝。原生 Wintun TUN 支持零拷贝收发；显式启用 io_uring 的 Linux 原生 TUN/TAP 支持零拷贝异步发送。模拟 TAP 不暴露该接口，因为它必须增删 Ethernet 头，无法满足现有连续缓冲区的租约语义。

```c
if (TapTun_GetCapabilities(device) & TAPTUN_CAP_ZERO_COPY_SEND) {
    TapTunPacket packet;
    if (TapTun_AcquireSend(device, packet_size, &packet) == TAPTUN_OK) {
        build_ip_packet(packet.data, packet.size);
        TapTun_CommitSend(device, &packet);
    }
}
```

接收数据在 `TapTun_ReleaseReceive` 前有效；发送缓冲区在 `TapTun_CommitSend` 前有效。每个设备同时只允许一个接收租约和一个尚未提交的发送租约，但 Linux 可以保留多个已经 commit 的在途缓冲区。异步完成错误会由后续 `TapTun_AcquireSend` 返回。`TapTun_Close` 会使尚未归还的租约立即失效，因此调用方不应在关闭后再访问 `TapTunPacket`。

## 性能测试示范

所有平台都应使用 `BUILD=release` 构建基准程序。Linux、macOS 和通用 POSIX 后端共用一套发送基准：

```bash
make TARGET=linux BUILD=release benchmark
./bin/benchmark_linux --iterations 100000 --rounds 4
```

默认模式使用持续排空的 Unix 数据报 `socketpair`，测量外部 TUN 句柄包装路径，不需要 root 权限，适合 CI 以及 Android/宿主 VPN 集成的回归比较。它包含逐包构造、本机 socket 发送和并发排空开销，不代表原生 TUN 性能。原生模式同样包含逐包构造成本，以便与 Windows 基准保持一致。Linux/WSL 上测量真实内核 TUN 写入路径需要 root：

```bash
sudo ./bin/benchmark_linux --native --size 1400 --iterations 100000 --rounds 4
```

Linux 可分别测量固定缓冲区 io_uring、显式队列数量和单 TCP 流 GSO 批量写入：

```bash
sudo ./bin/benchmark_linux --native --io-uring --size 1400
sudo ./bin/benchmark_linux --native --io-uring --queues 4 --send-depth 64 --size 1400
sudo ./bin/benchmark_linux --native --tcp --size 1400
sudo ./bin/benchmark_linux --native --gso --batch 32 --size 1400
```

当前基准是单发送线程，`--queues` 主要验证配置与队列选择开销，不代表 multi-queue 的并行吞吐上限。multi-queue 的收益需要多个独立流和并行生产者。`--gso` 使用校验和有效、TCP sequence 连续的同一条流调用 `TapTun_WriteBatch`；它衡量公网接收包写入本机 TUN 的 GRO/GSO 路径，不包含加密或公网传输。

增加 `--tap` 可测试 TAP。Linux 的 `--native --tap` 使用原生 `IFF_TAP`；macOS 原生 TAP 模式使用 utun + tun2tap。通用 POSIX 目标没有原生设备创建能力，因此只运行外部句柄模式：

```bash
make TARGET=posix BUILD=release benchmark
./bin/benchmark_posix --tap
```

macOS 使用 `make TARGET=macos BUILD=release benchmark` 生成 `bin/benchmark_macos`。该入口已提供但当前仓库没有 macOS 执行环境，结果仍需在真实 macOS 主机验证。

Windows 基准程序另外比较普通复制写入与直接在 Wintun 发送环中构造数据包：

```bash
make TARGET=windows BUILD=release benchmark
./bin/benchmark_windows.exe --size 1400 --iterations 100000 --rounds 4
```

需要从管理员终端运行。未把 `wintun.dll` 放在 `bin` 目录时，可增加 `--dll PATH`。程序会检查编译器优化状态，预热后交错执行两种模式，逐轮输出 Mpps、Gbps、ns/packet，并以各轮中位数计算最终比例。报文构造只写入每个字节一次，避免未优化的测试循环掩盖复制成本。该结果衡量本机向 Windows 网络栈注入数据包的发送路径，不等同于加密、转发或真实链路上的端到端 VPN 吞吐。

默认每轮按 10000 包分段，分段间等待 25 ms 让 Wintun 环排空，等待时间不计入结果。这既保留 100000 包的有效采样量，也避免环满重试和过短采样受 Windows 调度影响。可通过 `--burst COUNT` 和 `--drain-ms MILLISECONDS` 调整。需要测量持续压满 Windows 网络栈的吞吐时使用：

```bash
./bin/benchmark_windows.exe --size 1400 --iterations 100000 --rounds 4 --saturated
```

## 第三方文件

| 组件 | 文件 | 许可证 |
|-|-|-|
| [Wintun API](https://git.zx2c4.com/wintun/) | [include/wintun.h](include/wintun.h) | GPL-2.0 OR MIT，本项目选择 MIT，完整许可证位于文件头 |
| [tap-windows6 header](https://github.com/OpenVPN/tap-windows6/) | [include/tap-windows6.h](include/tap-windows6.h) | MIT，完整许可证位于文件头 |
