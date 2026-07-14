#ifndef TAPTUN_API_H
#define TAPTUN_API_H

#include <stdint.h>

#if defined(_WIN32)
    #ifdef TUNTAP_EXPORTS
        #define TAPTUN_API __declspec(dllexport)
    #else
        #define TAPTUN_API __declspec(dllimport)
    #endif
#else
    #define TAPTUN_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TapTunDevice TapTunDevice;

/**
 * @brief Defines operation result codes
 *        定义操作结果码
 */
typedef enum {
    TAPTUN_OK = 0,
    TAPTUN_ERROR = -1,
    TAPTUN_ERROR_INVALID_ARGUMENT = -2,
    TAPTUN_ERROR_UNSUPPORTED = -3,
    TAPTUN_ERROR_CLOSED = -4,
    TAPTUN_ERROR_BUSY = -5,
    TAPTUN_ERROR_BUFFER_TOO_SMALL = -6
} TapTunResult;

/**
 * @brief Defines how an existing device is opened or created
 *        定义现有设备的打开或创建方式
 */
typedef enum {
    TAPTUN_OPEN_DEFAULT = 0,
    TAPTUN_OPEN_EXISTING_ONLY = 1,
    TAPTUN_OPEN_CREATE_ONLY = 2
} TapTunOpenMode;

/**
 * @brief Defines the packet layer exposed by a device
 *        定义设备公开的数据包层级
 */
typedef enum {
    TAPTUN_MODE_TUN = 0,
    TAPTUN_MODE_TAP = 1
} TapTunMode;

/**
 * @brief Defines how TAP mode selects its backend
 *        定义 TAP 模式选择后端的方式
 */
typedef enum {
    TAPTUN_TAP_BACKEND_AUTO = 0,
    TAPTUN_TAP_BACKEND_NATIVE_ONLY = 1,
    TAPTUN_TAP_BACKEND_EMULATED_ONLY = 2
} TapTunTapBackend;

/**
 * @brief Defines capabilities enabled by the selected backend
 *        定义所选后端启用的能力
 */
typedef enum {
    TAPTUN_CAP_ZERO_COPY_RECEIVE = 1u << 0,
    TAPTUN_CAP_ZERO_COPY_SEND = 1u << 1,
    TAPTUN_CAP_NATIVE_TAP = 1u << 2,
    TAPTUN_CAP_EMULATED_TAP = 1u << 3,
    TAPTUN_CAP_IO_URING_SEND = 1u << 4,
    TAPTUN_CAP_MULTI_QUEUE = 1u << 5,
    TAPTUN_CAP_GSO = 1u << 6
} TapTunCapability;

/**
 * @brief Defines optional Linux performance features
 *        定义可选的 Linux 性能特性
 */
typedef enum {
    TAPTUN_PERF_IO_URING_SEND = 1u << 0,
    TAPTUN_PERF_MULTI_QUEUE = 1u << 1,
    TAPTUN_PERF_GSO = 1u << 2
} TapTunPerformanceFeature;

/**
 * @brief Describes a packet borrowed from a native backend
 *        描述从原生后端借用的数据包
 */
typedef struct {
    unsigned char* data;
    uint32_t size;
    // Opaque lease identity
    // 不透明租约标识
    // Callers must not inspect or modify this value
    // 调用方不得检查或修改此值
    void* backend_token;
} TapTunPacket;

/**
 * @brief Describes caller owned storage for batch packet operations
 *        描述批量数据包操作使用的调用方缓冲区
 */
typedef struct {
    unsigned char* data;
    // ReadBatch treats this as writable capacity
    // WriteBatch ignores this value
    // ReadBatch 将此值作为可写容量
    // WriteBatch 忽略此值
    uint32_t capacity;
    // ReadBatch writes the packet size
    // WriteBatch reads the packet size
    // ReadBatch 写入数据包大小
    // WriteBatch 读取数据包大小
    uint32_t size;
} TapTunBuffer;

/**
 * @brief Configures device creation and backend selection
 *        配置设备创建和后端选择
 */
typedef struct {
    const char* name;
    // Zero keeps the historical layer 3 TUN behavior
    // 零值保持原有的三层 TUN 行为
    TapTunMode mode;
    // Used only when mode is TAP
    // AUTO prefers a native TAP backend
    // 仅在 mode 为 TAP 时使用
    // AUTO 优先选择原生 TAP 后端
    TapTunTapBackend tap_backend;
    TapTunOpenMode open_mode;
    // Windows only UTF 8 path to a caller provided wintun library
    // 仅用于 Windows 指向调用方提供的 wintun 库的 UTF 8 路径
    const char* wintun_dll_path;
    // Windows only Wintun ring capacity
    // Zero selects the default value
    // 仅用于 Windows 的 Wintun 环形缓冲区容量
    // 零值选择默认容量
    uint32_t ring_capacity;
    // Optional locally administered MAC addresses for emulated TAP mode
    // All zero values select deterministic defaults for each device
    // 模拟 TAP 模式使用的可选本地管理 MAC 地址
    // 全零值为每个设备选择确定性默认地址
    unsigned char interface_mac[6];
    unsigned char peer_mac[6];
} TapTunOptions;

/**
 * @brief Configures optional backend performance features
 *        配置可选的后端性能特性
 */
typedef struct {
    // Must be initialized to sizeof(TapTunPerformanceOptions)
    // 必须初始化为 sizeof(TapTunPerformanceOptions)
    uint32_t struct_size;
    // Unsupported preferred features are ignored and can be queried afterward
    // 不支持的首选特性会被忽略并可在打开后查询
    uint32_t preferred_features;
    // Opening fails when any required feature cannot be enabled
    // 任一必需特性无法启用时打开失败
    uint32_t required_features;
    // MULTI_QUEUE requires an explicit value greater than one
    // MULTI_QUEUE 要求显式设置大于一的值
    uint32_t queue_count;
    // Zero selects the backend default
    // Linux currently accepts values from 2 to 1024
    // 零值选择后端默认值
    // Linux 当前接受 2 到 1024
    uint32_t send_queue_depth;
    uint32_t reserved[3];
} TapTunPerformanceOptions;

/**
 * @brief Configures a device created from a host handle
 *        配置从宿主句柄创建的设备
 */
typedef struct {
    intptr_t handle;
    const char* name;
    unsigned int if_index;
    int take_ownership;
    // Describes packets carried by the supplied handle
    // 描述所提供句柄承载的数据包
    TapTunMode backend_mode;
    // TAP over a TUN handle enables tun2tap emulation
    // 在 TUN 句柄上使用 TAP 会启用 tun2tap 模拟
    TapTunMode mode;
    unsigned char interface_mac[6];
    unsigned char peer_mac[6];
} TapTunHandleOptions;

/**
 * @brief Reads one packet through a host callback
 *        通过宿主回调读取一个数据包
 */
typedef int (*TapTunReadCallback)(void* context, unsigned char* buffer, int buffer_size);

/**
 * @brief Writes one packet through a host callback
 *        通过宿主回调写入一个数据包
 */
typedef int (*TapTunWriteCallback)(void* context, const unsigned char* data, int data_size);

/**
 * @brief Closes resources owned by a host callback backend
 *        关闭宿主回调后端拥有的资源
 */
typedef void (*TapTunCloseCallback)(void* context);

/**
 * @brief Interrupts a pending host read callback
 *        中断等待中的宿主读取回调
 */
typedef void (*TapTunInterruptReadCallback)(void* context);

/**
 * @brief Configures a device created from host callbacks
 *        配置从宿主回调创建的设备
 */
typedef struct {
    void* context;
    TapTunReadCallback read;
    TapTunWriteCallback write;
    // Must unblock a pending read callback when TapTun_Close is called
    // 调用 TapTun_Close 时必须解除等待中的读取回调
    TapTunCloseCallback close;
    // Required for emulated TAP
    // Must make a pending read callback return
    // 模拟 TAP 模式必须提供此回调
    // 必须使等待中的读取回调返回
    TapTunInterruptReadCallback interrupt_read;
    const char* name;
    unsigned int if_index;
    // Describes packets exchanged by read and write callbacks
    // 描述读取和写入回调交换的数据包
    TapTunMode backend_mode;
    TapTunMode mode;
    unsigned char interface_mac[6];
    unsigned char peer_mac[6];
} TapTunCallbackOptions;

/**
 * @brief Opens or creates a TUN or TAP device
 *        打开或创建 TUN/TAP 设备
 *
 * The backend is selected according to the requested mode and platform
 * 后端实现根据请求的设备模式和当前平台自动选择
 *
 * @param options Device options NULL selects the defaults
 *                设备配置 传入 NULL 时使用默认配置
 *
 * @return A device handle on success or NULL on failure
 *         成功时返回设备句柄 失败时返回 NULL
 *
 * @note Call TapTun_GetLastSystemError() to obtain the native error code
 *       可调用 TapTun_GetLastSystemError() 获取系统原生错误码
 */
TAPTUN_API TapTunDevice* TapTun_Open(const TapTunOptions* options);

/**
 * @brief Opens a device with optional performance features
 *        使用可选性能特性打开设备
 *
 * TapTun_Open is equivalent to passing NULL as performance_options
 * TapTun_Open 等同于将 performance_options 设置为 NULL
 *
 * @param options Device options NULL selects the defaults
 *                设备配置 传入 NULL 时使用默认配置
 *
 * @param performance_options Performance options NULL disables optional features
 *                            性能配置 传入 NULL 时不启用可选特性
 *
 * @return A device handle on success or NULL on failure
 *         成功时返回设备句柄 失败时返回 NULL
 *
 * @note Call TapTun_GetLastSystemError() to obtain the native error code
 *       可调用 TapTun_GetLastSystemError() 获取系统原生错误码
 */
TAPTUN_API TapTunDevice* TapTun_OpenWithPerformance(
    const TapTunOptions* options,
    const TapTunPerformanceOptions* performance_options);

/**
 * @brief Wraps a TUN or TAP handle created by the host platform
 *        包装由宿主平台创建的 TUN 或 TAP 句柄
 *
 * TapTun_Close closes the handle only when take_ownership is nonzero
 * 仅当 take_ownership 非零时 TapTun_Close 才会关闭句柄
 *
 * @param options Host handle options
 *                宿主句柄配置
 *
 * @return A device handle on success or NULL on failure
 *         成功时返回设备句柄 失败时返回 NULL
 */
TAPTUN_API TapTunDevice* TapTun_OpenFromHandle(const TapTunHandleOptions* options);

/**
 * @brief Wraps a host VPN API through synchronous callbacks
 *        通过同步回调包装宿主 VPN API
 *
 * This supports host APIs that do not expose a file descriptor
 * 此方式支持不公开文件描述符的宿主 API
 *
 * @param options Host callback options
 *                宿主回调配置
 *
 * @return A device handle on success or NULL on failure
 *         成功时返回设备句柄 失败时返回 NULL
 */
TAPTUN_API TapTunDevice* TapTun_OpenFromCallbacks(const TapTunCallbackOptions* options);

/**
 * @brief Returns the device name
 *        返回设备名称
 *
 * @param device Device handle
 *               设备句柄
 *
 * @return The device name or NULL for an invalid handle
 *         返回设备名称 句柄无效时返回 NULL
 */
TAPTUN_API const char* TapTun_GetName(const TapTunDevice* device);

/**
 * @brief Returns the native interface index
 *        返回原生网络接口索引
 *
 * @param device Device handle
 *               设备句柄
 *
 * @return The interface index or zero when unavailable
 *         返回网络接口索引 无法获取时返回零
 */
TAPTUN_API unsigned int TapTun_GetIndex(const TapTunDevice* device);

/**
 * @brief Returns the packet mode exposed by the device
 *        返回设备公开的数据包模式
 *
 * @param device Device handle
 *               设备句柄
 *
 * @return The configured TUN or TAP mode
 *         返回配置的 TUN 或 TAP 模式
 */
TAPTUN_API TapTunMode TapTun_GetMode(const TapTunDevice* device);

/**
 * @brief Returns the number of native queues attached to the device
 *        返回设备关联的原生队列数量
 *
 * @param device Device handle
 *               设备句柄
 *
 * @return The native queue count
 *         返回原生队列数量
 */
TAPTUN_API uint32_t TapTun_GetQueueCount(const TapTunDevice* device);

/**
 * @brief Returns the visible TAP MAC address
 *        返回可见的 TAP MAC 地址
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param mac_address Receives the six byte MAC address
 *                    接收六字节 MAC 地址
 *
 * @return TAPTUN_OK on success or a negative TapTunResult on failure
 *         成功时返回 TAPTUN_OK 失败时返回负数 TapTunResult
 *
 * @note TUN devices return TAPTUN_ERROR_UNSUPPORTED
 *       TUN 设备返回 TAPTUN_ERROR_UNSUPPORTED
 */
TAPTUN_API int TapTun_GetMacAddress(const TapTunDevice* device, unsigned char mac_address[6]);

/**
 * @brief Returns the current thread native system error
 *        返回当前线程的系统原生错误
 *
 * @return A Win32 error code or POSIX errno value
 *         返回 Win32 错误码或 POSIX errno 值
 */
TAPTUN_API uint32_t TapTun_GetLastSystemError(void);

/**
 * @brief Returns capabilities enabled for the device
 *        返回设备已启用的能力
 *
 * @param device Device handle
 *               设备句柄
 *
 * @return A bitmask of TapTunCapability values
 *         返回 TapTunCapability 位掩码
 */
TAPTUN_API uint32_t TapTun_GetCapabilities(const TapTunDevice* device);

/**
 * @brief Sets the native interface state to up
 *        将原生网络接口状态设置为启用
 *
 * @param device Device handle
 *               设备句柄
 *
 * @return TAPTUN_OK on success or a negative TapTunResult on failure
 *         成功时返回 TAPTUN_OK 失败时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_Activate(TapTunDevice* device);

/**
 * @brief Configures an IPv4 address and CIDR prefix
 *        配置 IPv4 地址和 CIDR 前缀
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param address IPv4 address text
 *                IPv4 地址文本
 *
 * @param prefix_length CIDR prefix length from 0 to 32
 *                      范围为 0 到 32 的 CIDR 前缀长度
 *
 * @return TAPTUN_OK on success or a negative TapTunResult on failure
 *         成功时返回 TAPTUN_OK 失败时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_SetIPAddressV4(
    TapTunDevice* device,
    const char* address,
    unsigned int prefix_length);

/**
 * @brief Configures an IPv6 address and prefix
 *        配置 IPv6 地址和前缀
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param address IPv6 address text
 *                IPv6 地址文本
 *
 * @param prefix_length Prefix length from 0 to 128
 *                      范围为 0 到 128 的前缀长度
 *
 * @return TAPTUN_OK on success or a negative TapTunResult on failure
 *         成功时返回 TAPTUN_OK 失败时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_SetIPAddressV6(
    TapTunDevice* device,
    const char* address,
    unsigned int prefix_length);

/**
 * @brief Reads one packet from the device
 *        从设备读取一个数据包
 *
 * TUN mode reads one layer 3 packet
 * TUN 模式读取一个三层数据包
 *
 * TAP mode reads one Ethernet II frame
 * TAP 模式读取一个 Ethernet II 帧
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param buffer Receives packet data
 *               接收数据包内容
 *
 * @param buffer_size Writable buffer size in bytes
 *                    缓冲区可写字节数
 *
 * @return The packet size or a negative TapTunResult on failure
 *         成功时返回数据包大小 失败时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_Read(TapTunDevice* device, unsigned char* buffer, int buffer_size);

/**
 * @brief Writes one packet to the device
 *        向设备写入一个数据包
 *
 * TUN mode writes one layer 3 packet
 * TUN 模式写入一个三层数据包
 *
 * TAP mode writes one Ethernet II frame
 * TAP 模式写入一个 Ethernet II 帧
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param data Packet data
 *             数据包内容
 *
 * @param data_size Packet size in bytes
 *                  数据包字节数
 *
 * @return The written packet size or a negative TapTunResult on failure
 *         成功时返回写入的数据包大小 失败时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_Write(TapTunDevice* device, const unsigned char* data, int data_size);

/**
 * @brief Reads packets into caller owned buffers
 *        将数据包读取到调用方缓冲区
 *
 * Linux GSO may split one native super packet across several buffers
 * Linux GSO 可将一个原生大包拆分到多个缓冲区
 *
 * Other backends may return one packet with the same API contract
 * 其他后端可能按照相同 API 约定返回一个数据包
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param buffers Caller owned packet buffers
 *                调用方拥有的数据包缓冲区
 *
 * @param buffer_count Number of available buffers
 *                     可用缓冲区数量
 *
 * @return The populated buffer count or a negative TapTunResult on failure
 *         成功时返回已填充缓冲区数量 失败时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_ReadBatch(
    TapTunDevice* device,
    TapTunBuffer* buffers,
    uint32_t buffer_count);

/**
 * @brief Writes a batch of packets to the device
 *        向设备批量写入数据包
 *
 * Linux GSO may coalesce compatible TCP packets before entering the kernel
 * Linux GSO 可在进入内核前合并兼容的 TCP 数据包
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param buffers Packet buffers to write
 *                要写入的数据包缓冲区
 *
 * @param buffer_count Number of packet buffers
 *                     数据包缓冲区数量
 *
 * @return The accepted packet count or a negative TapTunResult when none were accepted
 *         成功时返回已接受数据包数量 未接受任何数据包时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_WriteBatch(
    TapTunDevice* device,
    const TapTunBuffer* buffers,
    uint32_t buffer_count);

/**
 * @brief Borrows the next received packet from the native backend
 *        从原生后端借用下一个接收数据包
 *
 * The packet remains valid until TapTun_ReleaseReceive is called
 * 数据包在调用 TapTun_ReleaseReceive 前保持有效
 *
 * Only one receive lease may be active for each device
 * 每个设备只能存在一个接收租约
 *
 * TapTun_Read cannot run while the lease is active
 * 租约有效期间不能调用 TapTun_Read
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param packet Receives the borrowed packet
 *               接收借用的数据包
 *
 * @return TAPTUN_OK on success or a negative TapTunResult on failure
 *         成功时返回 TAPTUN_OK 失败时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_AcquireReceive(TapTunDevice* device, TapTunPacket* packet);

/**
 * @brief Releases a borrowed receive packet
 *        释放借用的接收数据包
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param packet Packet returned by TapTun_AcquireReceive
 *               TapTun_AcquireReceive 返回的数据包
 *
 * @return TAPTUN_OK on success or a negative TapTunResult on failure
 *         成功时返回 TAPTUN_OK 失败时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_ReleaseReceive(TapTunDevice* device, TapTunPacket* packet);

/**
 * @brief Borrows native storage for one send packet
 *        为一个发送数据包借用原生存储
 *
 * A successful acquisition must be completed by TapTun_CommitSend
 * 成功借用后必须调用 TapTun_CommitSend 完成提交
 *
 * Only one send lease may be active for each device
 * 每个设备只能存在一个发送租约
 *
 * Later sends may wait behind the active lease
 * 后续发送可能等待当前租约完成
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param packet_size Required packet size in bytes
 *                    所需数据包字节数
 *
 * @param packet Receives the borrowed send storage
 *               接收借用的发送存储
 *
 * @return TAPTUN_OK on success or a negative TapTunResult on failure
 *         成功时返回 TAPTUN_OK 失败时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_AcquireSend(
    TapTunDevice* device,
    uint32_t packet_size,
    TapTunPacket* packet);

/**
 * @brief Commits a packet borrowed for sending
 *        提交借用于发送的数据包
 *
 * @param device Device handle
 *               设备句柄
 *
 * @param packet Packet returned by TapTun_AcquireSend
 *               TapTun_AcquireSend 返回的数据包
 *
 * @return TAPTUN_OK on success or a negative TapTunResult on failure
 *         成功时返回 TAPTUN_OK 失败时返回负数 TapTunResult
 */
TAPTUN_API int TapTun_CommitSend(TapTunDevice* device, TapTunPacket* packet);

/**
 * @brief Cancels pending reads and destroys the device
 *        取消等待中的读取并销毁设备
 *
 * Native resources and outstanding leases are released
 * 原生资源和未完成租约会被释放
 *
 * @param device Device handle NULL is accepted
 *               设备句柄 可以传入 NULL
 */
TAPTUN_API void TapTun_Close(TapTunDevice* device);

#ifdef __cplusplus
}
#endif

#endif
