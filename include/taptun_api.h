#ifndef TAPTUN_API_H
#define TAPTUN_API_H

#if defined(_WIN32)
    #include <winsock2.h>
    #include <windows.h>
    #include <ifdef.h>
    #ifdef TUNTAP_EXPORTS
        #define TAPTUN_API __declspec(dllexport)
    #else
        #define TAPTUN_API __declspec(dllimport)
    #endif
#else // Linux, macOS, ....
    #include <stdint.h>
    #define TAPTUN_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// 平台无关的设备信息结构体
typedef struct {
#if defined(_WIN32)
    HANDLE handle;
    NET_LUID luid;
    char guid_str[256];
    OVERLAPPED overlap_read;
    OVERLAPPED overlap_write;
#else
    intptr_t handle;
#endif
    unsigned int if_index; 
    char if_name[256];
} TapTunDevice;

/**
 * @brief Opens a TAP device.
 * @param name The desired name of the network interface. 
 *             On Windows, this will search for a TAP adapter with a matching connection name.
 *             On Linux, this will attempt to create a TAP device with the specified name.
 *             If NULL or empty, the function opens the first available device.
 * @return A pointer to a TapTunDevice structure on success, NULL on failure.
 *         The caller is responsible for freeing this structure using TapTun_Close.
 */
TAPTUN_API TapTunDevice* TapTun_Open(const char* name);

/**
 * @brief Retrieves the MAC address of the TAP device.
 * @param device A pointer to the TapTunDevice structure.
 * @param mac_address A buffer of at least 6 bytes to store the MAC address.
 * @return 0 on success, -1 on failure.
 */
TAPTUN_API int TapTun_GetMacAddress(TapTunDevice* device, unsigned char* mac_address);

/**
 * @brief Reads a packet from the TAP device. This is a blocking call.
 * @param device A pointer to the TapTunDevice structure.
 * @param buffer The buffer to store the packet data.
 * @param bufferSize The size of the buffer.
 * @return The number of bytes read on success, or -1 on failure.
 */
TAPTUN_API int TapTun_Read(TapTunDevice* device, unsigned char* buffer, int bufferSize);

/**
 * @brief Writes a packet to the TAP device.
 * @param device A pointer to the TapTunDevice structure.
 * @param data The packet data to write.
 * @param dataSize The size of the packet data.
 * @return The number of bytes written on success, or -1 on failure.
 */
TAPTUN_API int TapTun_Write(TapTunDevice* device, const unsigned char* data, int dataSize);

/**
 * @brief Sets the IPv4 address and subnet mask for the TAP device.
 * @param device A pointer to the TapTunDevice structure.
 * @param ip The IPv4 address in string format (e.g., "10.0.0.1").
 * @param mask The subnet mask in string format (e.g., "255.255.255.0").
 * @return 0 on success, -1 on failure.
 */
TAPTUN_API int TapTun_SetIPAddress(TapTunDevice* device, const char* ip, const char* mask);

/**
 * @brief Sets the IPv6 address for the TAP device.
 * @param device A pointer to the TapTunDevice structure.
 * @param ipv6 The IPv6 address in string format (e.g., "fd00::1").
 * @param prefixLength The prefix length of the subnet (e.g., 64).
 * @return 0 on success, -1 on failure.
 */
TAPTUN_API int TapTun_SetIPAddressV6(TapTunDevice* device, const char* ipv6, int prefixLength);

/**
 * @brief Activates the TAP device (sets the link to 'up').
 * @param device A pointer to the TapTunDevice structure.
 * @return 0 on success, -1 on failure.
 */
TAPTUN_API int TapTun_Activate(TapTunDevice* device);

/**
 * @brief Closes the TAP device and frees associated resources.
 * @param device A pointer to the TapTunDevice structure to be closed.
 */
TAPTUN_API void TapTun_Close(TapTunDevice* device);

#ifdef __cplusplus
}
#endif

#endif