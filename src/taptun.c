#include "taptun_api.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// windows
#if defined(_WIN32)

#include <ws2tcpip.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include "tap-windows6.h"


TapTunDevice* TapTun_Open() {
    HKEY adapter_key;
    LONG status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapter_key);
    if (status != ERROR_SUCCESS) return NULL;

    for (int i = 0; ; ++i) {
        char enum_name[256], unit_key_name[512], component_id[256], guid_str[256], device_path[512];
        HKEY unit_key, connection_key;
        DWORD len = sizeof(enum_name);

        if (RegEnumKeyExA(adapter_key, i, enum_name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        
        snprintf(unit_key_name, sizeof(unit_key_name), "%s\\%s", ADAPTER_KEY, enum_name);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, unit_key_name, 0, KEY_READ, &unit_key) != ERROR_SUCCESS) continue;

        len = sizeof(component_id);
        if (RegQueryValueExA(unit_key, "ComponentId", NULL, NULL, (LPBYTE)component_id, &len) == ERROR_SUCCESS &&
            strcmp(component_id, "tap0901") == 0) {
            
            len = sizeof(guid_str);
            if (RegQueryValueExA(unit_key, "NetCfgInstanceId", NULL, NULL, (LPBYTE)guid_str, &len) != ERROR_SUCCESS) {
                RegCloseKey(unit_key);
                continue;
            }

            snprintf(device_path, sizeof(device_path), "%s%s%s", USERMODEDEVICEDIR, guid_str, TAP_WIN_SUFFIX);
            HANDLE hDevice = CreateFileA(device_path, GENERIC_READ 
                | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM 
                | FILE_FLAG_OVERLAPPED, 0);
            // 必须使用 FILE_FLAG_OVERLAPPED 否则有严重性能问题

            if (hDevice != INVALID_HANDLE_VALUE) {
                TapTunDevice* device = (TapTunDevice*)calloc(1, sizeof(TapTunDevice));
                if (!device) { CloseHandle(hDevice); RegCloseKey(unit_key); continue; }
                
                device->handle = hDevice;
                // 仅保存 GUID 和 Name 字符串，不进行转换
                strncpy(device->guid_str, guid_str, sizeof(device->guid_str) - 1);
                
                device->overlap_read.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
                device->overlap_write.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

                if (!device->overlap_read.hEvent || !device->overlap_write.hEvent) {
                    CloseHandle(hDevice);
                    free(device);
                }

                snprintf(unit_key_name, sizeof(unit_key_name), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, guid_str);
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, unit_key_name, 0, KEY_READ, &connection_key) == ERROR_SUCCESS) {
                    len = sizeof(device->if_name);
                    RegQueryValueExA(connection_key, "Name", NULL, NULL, (LPBYTE)device->if_name, &len);
                    RegCloseKey(connection_key);
                }

                RegCloseKey(unit_key);
                RegCloseKey(adapter_key);
                return device;
            }
        }
        RegCloseKey(unit_key);
    }
    RegCloseKey(adapter_key);
    return NULL;
}

int TapTun_GetMacAddress(TapTunDevice* device, unsigned char* mac_address) {
    if (!device || !mac_address || device->if_index == 0) {
        fprintf(stderr, "ERROR: GetMacAddress called on a device that is not properly activated or initialized.\n");
        return -1;
    }

    IP_ADAPTER_ADDRESSES* adapter_addresses = NULL;
    // 初始缓冲区大小，可以设置得小一点
    ULONG buffer_size = sizeof(IP_ADAPTER_ADDRESSES); 
    DWORD result = 0;
    int ret = -1;
    int attempts = 0;
    const int MAX_ATTEMPTS = 3; // 设置最大重试次数，防止无限循环

    // 使用循环来处理缓冲区大小问题
    do {
        adapter_addresses = (IP_ADAPTER_ADDRESSES*)malloc(buffer_size);
        if (!adapter_addresses) {
            fprintf(stderr, "ERROR: Failed to allocate memory for GetAdaptersAddresses.\n");
            return -1;
        }

        result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, adapter_addresses, &buffer_size);

        if (result == ERROR_BUFFER_OVERFLOW) {
            // 如果缓冲区太小，释放当前内存，循环会使用新的 buffer_size 重新分配
            free(adapter_addresses);
            adapter_addresses = NULL;
        } else if (result != NO_ERROR) {
            fprintf(stderr, "ERROR: GetAdaptersAddresses failed with error other than buffer overflow. Error: %lu\n", result);
            free(adapter_addresses);
            return -1;
        }

        attempts++;
    } while (result == ERROR_BUFFER_OVERFLOW && attempts < MAX_ATTEMPTS);

    if (result != NO_ERROR) {
        fprintf(stderr, "ERROR: GetAdaptersAddresses failed after %d attempts.\n", attempts);
        return -1;
    }

    IP_ADAPTER_ADDRESSES* current_adapter = adapter_addresses;
    while (current_adapter) {
        if (current_adapter->IfIndex == device->if_index) {
            if (current_adapter->PhysicalAddressLength == 6) {
                memcpy(mac_address, current_adapter->PhysicalAddress, 6);
                ret = 0; // 成功找到
            }
            break;
        }
        current_adapter = current_adapter->Next;
    }

    if (adapter_addresses) {
        free(adapter_addresses);
    }
    
    return ret;
}

int TapTun_Activate(TapTunDevice* device) {
    if (!device) return -1;

    ULONG status = TRUE;
    DWORD len;
    if (!DeviceIoControl(device->handle, TAP_WIN_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status), &status, sizeof(status), &len, NULL)) {
        fprintf(stderr, "ERROR: TAP_WIN_IOCTL_SET_MEDIA_STATUS failed. Error: %lu\n", GetLastError());
        return -1;
    }

    Sleep(2000);

    GUID guid;
    WCHAR guid_w[256];
    MultiByteToWideChar(CP_ACP, 0, device->guid_str, -1, guid_w, 256);
    if (CLSIDFromString(guid_w, &guid) != S_OK) {
        fprintf(stderr, "ERROR: Failed to parse GUID string after activation.\n");
        return -1;
    }

    DWORD result = ConvertInterfaceGuidToLuid(&guid, &device->luid);
    if (result != NO_ERROR) {
        fprintf(stderr, "ERROR: ConvertInterfaceGuidToLuid failed after activation. Error: %lu\n", result);
        return -1;
    }

    result = ConvertInterfaceLuidToIndex(&device->luid, (PNET_IFINDEX)&device->if_index);
    if (result != NO_ERROR) {
        fprintf(stderr, "ERROR: ConvertInterfaceLuidToIndex failed after activation. Error: %lu\n", result);
        return -1;
    }
    
    printf("  [INFO] Interface activated and identifiers refreshed. Index: %u\n", device->if_index);
    return 0;
}


int TapTun_SetIPAddress(TapTunDevice* device, const char* ip, const char* mask) {
    if (!device || device->if_index == 0) {
        fprintf(stderr, "ERROR: SetIPAddress called on a device that is not properly activated or initialized.\n");
        return -1;
    }
    
    // Clean up existing addresses on the interface first
    MIB_IPADDRTABLE* ipAddrTable = NULL;
    DWORD tableSize = 0;
    if (GetIpAddrTable(NULL, &tableSize, 0) == ERROR_INSUFFICIENT_BUFFER) {
        ipAddrTable = (MIB_IPADDRTABLE*)malloc(tableSize);
        if (ipAddrTable && GetIpAddrTable(ipAddrTable, &tableSize, 0) == NO_ERROR) {
            for (DWORD i = 0; i < ipAddrTable->dwNumEntries; i++) {
                if (ipAddrTable->table[i].dwIndex == device->if_index) {
                    DeleteIPAddress(ipAddrTable->table[i].dwAddr);
                }
            }
        }
        if (ipAddrTable) free(ipAddrTable);
    }
    
    ULONG nteContext = 0, nteInstance = 0;
    IN_ADDR ip_addr, mask_addr;
    InetPton(AF_INET, ip, &ip_addr);
    InetPton(AF_INET, mask, &mask_addr);

    DWORD result = AddIPAddress(ip_addr.S_un.S_addr, mask_addr.S_un.S_addr, device->if_index, &nteContext, &nteInstance);
    if (result != NO_ERROR) {
        fprintf(stderr, "Failed to add IPv4 address. Error: %lu\n", result);
        return -1;
    }
    return 0;
}


int TapTun_SetIPAddressV6(TapTunDevice* device, const char* ipv6, int prefixLength) {
    if (!device || device->if_index == 0) {
        fprintf(stderr, "ERROR: SetIPAddressV6 called on a device that is not properly activated or initialized.\n");
        return -1;
    }

    MIB_UNICASTIPADDRESS_ROW addrRow;
    InitializeUnicastIpAddressEntry(&addrRow);
    
    addrRow.InterfaceLuid = device->luid;
    addrRow.Address.Ipv6.sin6_family = AF_INET6;
    if (InetPton(AF_INET6, ipv6, &addrRow.Address.Ipv6.sin6_addr) != 1) return -1;

    addrRow.OnLinkPrefixLength = (UINT8)prefixLength;
    addrRow.ValidLifetime = 0xFFFFFFFF;
    addrRow.PreferredLifetime = 0xFFFFFFFF;
    
    DeleteUnicastIpAddressEntry(&addrRow);

    DWORD result = CreateUnicastIpAddressEntry(&addrRow);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
        fprintf(stderr, "Failed to create IPv6 address. Error: %lu\n", result);
        return -1;
    }
    return 0;
}

int TapTun_Read(TapTunDevice* device, unsigned char* buffer, int bufferSize) {
    if (!device) return -1;
    DWORD bytesRead;

    ResetEvent(device->overlap_read.hEvent);

    if (!ReadFile(device->handle, buffer, bufferSize, &bytesRead, &device->overlap_read)) {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_IO_PENDING) {
            if (GetOverlappedResult(device->handle, &device->overlap_read, &bytesRead, TRUE)) {
                return (int)bytesRead;
            } else {
                return -1;
            }
        } else {
            return -1;
        }
    }
    
    // 如果 ReadFile 立即成功返回 TRUE，bytesRead 已经包含了读取的字节数
    return (int)bytesRead;
}

int TapTun_Write(TapTunDevice* device, const unsigned char* data, int dataSize) {
    if (!device) return -1;
    DWORD bytesWritten;

    ResetEvent(device->overlap_write.hEvent);
    
    if (!WriteFile(device->handle, data, dataSize, &bytesWritten, &device->overlap_write)) {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_IO_PENDING) {
            if (GetOverlappedResult(device->handle, &device->overlap_write, &bytesWritten, TRUE)) {
                return (int)bytesWritten;
            } else {
                return -1;
            }
        } else {
            return -1;
        }
    }

    return (int)bytesWritten;
}

void TapTun_Close(TapTunDevice* device) {
    if (device) {
        if (device->overlap_read.hEvent) CloseHandle(device->overlap_read.hEvent);
        if (device->overlap_write.hEvent) CloseHandle(device->overlap_write.hEvent);
        
        CloseHandle(device->handle);
        free(device);
    }
}

// Linux
#elif defined(__linux__)

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/in.h>

TapTunDevice* TapTun_Open() {
    struct ifreq ifr;
    int fd;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) return NULL;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) {
        close(fd);
        return NULL;
    }

    TapTunDevice* device = (TapTunDevice*)calloc(1, sizeof(TapTunDevice));
    if (!device) { close(fd); return NULL; }

    device->handle = (intptr_t)fd;
    strncpy(device->if_name, ifr.ifr_name, sizeof(device->if_name) - 1);
    
    // On Linux, if_index can be retrieved via ioctl
    struct ifreq ifr_idx;
    memset(&ifr_idx, 0, sizeof(ifr_idx));
    strncpy(ifr_idx.ifr_name, device->if_name, IFNAMSIZ -1);
    // Need a socket to perform this ioctl
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        if (ioctl(sock, SIOCGIFINDEX, &ifr_idx) == 0) {
            device->if_index = ifr_idx.ifr_ifindex;
        }
        close(sock);
    }
    
    return device;
}

int TapTun_GetMacAddress(TapTunDevice* device, unsigned char* mac_address) {
    if (!device || !mac_address) return -1;

    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device->if_name, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl(SIOCGIFHWADDR) failed");
        close(sock);
        return -1;
    }

    close(sock);
    memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

int TapTun_Activate(TapTunDevice* device) {
    if (!device) return -1;

    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    // 复制接口名称到 ifreq 结构体
    strncpy(ifr.ifr_name, device->if_name, IFNAMSIZ);

    // 获取当前的接口标志 (flags)
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCGIFFLAGS) failed");
        close(sock);
        return -1;
    }

    // 添加 IFF_UP 标志来激活接口
    ifr.ifr_flags |= IFF_UP;

    // 设置新的接口标志
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCSIFFLAGS) failed");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}


int TapTun_SetIPAddress(TapTunDevice* device, const char* ip, const char* mask) {
    if (!device) return -1;

    struct ifreq ifr;
    struct sockaddr_in* addr_in;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    strncpy(ifr.ifr_name, device->if_name, IFNAMSIZ);

    addr_in = (struct sockaddr_in*)&ifr.ifr_addr;
    addr_in->sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &addr_in->sin_addr) <= 0) {
        perror("inet_pton(ip) failed");
        close(sock);
        return -1;
    }
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR) failed for IP");
        close(sock);
        return -1;
    }

    addr_in = (struct sockaddr_in*)&ifr.ifr_netmask;
    addr_in->sin_family = AF_INET;
    if (inet_pton(AF_INET, mask, &addr_in->sin_addr) <= 0) {
        perror("inet_pton(mask) failed");
        close(sock);
        return -1;
    }
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl(SIOCSIFNETMASK) failed for mask");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}


int TapTun_SetIPAddressV6(TapTunDevice* device, const char* ipv6, int prefixLength) {
    if (!device) return -1;

    struct in6_ifreq {
        struct in6_addr ifr6_addr;
        uint32_t        ifr6_prefixlen;
        unsigned int    ifr6_ifindex;
    };

    struct in6_ifreq ifr6;
    int sock = socket(AF_INET6, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    // 填充 in6_ifreq 结构体
    memset(&ifr6, 0, sizeof(ifr6));
    ifr6.ifr6_ifindex = device->if_index;
    ifr6.ifr6_prefixlen = prefixLength;
    if (inet_pton(AF_INET6, ipv6, &ifr6.ifr6_addr) <= 0) {
        perror("inet_pton(ipv6) failed");
        close(sock);
        return -1;
    }

    // 使用 ioctl 添加 IPv6 地址
    // SIOCSIFADDR 是一个通用命令，内核会根据 socket 的 family (AF_INET6)
    // 和传入的结构体来决定是设置 v4 还是 v6 地址。
    if (ioctl(sock, SIOCSIFADDR, &ifr6) < 0) {
        perror("ioctl(SIOCSIFADDR) failed for IPv6");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

int TapTun_Read(TapTunDevice* device, unsigned char* buffer, int bufferSize) {
    if (!device) return -1;
    return read((int)device->handle, buffer, bufferSize);
}

int TapTun_Write(TapTunDevice* device, const unsigned char* data, int dataSize) {
    if (!device) return -1;
    return write((int)device->handle, data, dataSize);
}

void TapTun_Close(TapTunDevice* device) {
    if (device) {
        close((int)device->handle);
        free(device);
    }
}

#endif