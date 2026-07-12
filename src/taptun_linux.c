#include "taptun_api.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/in.h>

TapTunDevice* TapTun_Open(const char* name) {
    struct ifreq ifr;
    int fd;
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) return NULL;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    // 如果提供了名称 则使用它
    if (name && name[0] != '\0') {
        strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    }

    if (ioctl(fd, TUNSETIFF, (void*)&ifr) < 0) {
        close(fd);
        return NULL;
    }

    TapTunDevice* device = (TapTunDevice*)calloc(1, sizeof(TapTunDevice));
    if (!device) { close(fd); return NULL; }

    device->handle = (intptr_t)fd;
    strncpy(device->if_name, ifr.ifr_name, sizeof(device->if_name) - 1);
    
    struct ifreq ifr_idx;
    memset(&ifr_idx, 0, sizeof(ifr_idx));
    strncpy(ifr_idx.ifr_name, device->if_name, IFNAMSIZ -1);
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
    if (!device || !ip || !mask) return -1;

    struct ifreq ifr;
    struct sockaddr_in ip_addr;
    struct sockaddr_in mask_addr;

    // 在修改接口状态前完成全部参数校验，避免留下半配置状态
    memset(&ip_addr, 0, sizeof(ip_addr));
    ip_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &ip_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", ip);
        return -1;
    }

    memset(&mask_addr, 0, sizeof(mask_addr));
    mask_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, mask, &mask_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 subnet mask: %s\n", mask);
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, device->if_name, IFNAMSIZ - 1);
    memcpy(&ifr.ifr_addr, &ip_addr, sizeof(ip_addr));
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR) failed for IP");
        close(sock);
        return -1;
    }

    memcpy(&ifr.ifr_netmask, &mask_addr, sizeof(mask_addr));
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
    // 和传入的结构体来决定是设置 v4 还是 v6 地址
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
