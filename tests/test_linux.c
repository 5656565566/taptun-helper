// tests/test_linux.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "../include/taptun_api.h"

// --- 测试参数 ---
const char* TEST_IPV4 = "10.10.0.1";
const char* TEST_MASK = "255.255.255.0";
const char* TEST_IPV6 = "fd10::1";
const int   TEST_IPV6_PREFIX = 64;


void* PingThread(void* arg) {
    const char* ip_address = (const char*)arg;
    char command[128];

    printf("  [THREAD] Ping thread started. Pinging %s...\n", ip_address);
    
    snprintf(command, sizeof(command), "ping -c 1 %s", ip_address);
    
    int result = system(command);
    
    if (result == 0) {
        printf("  [THREAD] Ping command finished successfully.\n");
    } else {
        fprintf(stderr, "  [THREAD] Ping command failed. (Is 'ping' installed?)\n");
    }
    
    return NULL;
}

int main() {
    printf("--- TAP-Linux DLL Automated Functional Test ---\n");
    printf("[INFO] This test must be run with root privileges (e.g., using 'sudo').\n\n");

    printf("[1] Opening TAP device...\n");
    TapTunDevice* device = TapTun_Open(NULL);
    
    unsigned char mac[6]; 

    if (TapTun_GetMacAddress(device, mac) == 0) {
        printf("[INFO] MacAddress: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        printf("[ERROR] Failed to get MAC address.\n");
    }

    if (device == NULL) {
        fprintf(stderr, "  [ERROR] Failed to open TAP device. Do you have permissions for /dev/net/tun?\n");
        return 1;
    }
    printf("  [SUCCESS] Device opened successfully.\n");
    printf("  [INFO] Handle: %ld, Index: %u, Name: \"%s\"\n", (long)device->handle, device->if_index, device->if_name);

    printf("\n[2] Activating device...\n");
    if (TapTun_Activate(device) != 0) {
        fprintf(stderr, "  [ERROR] Failed to activate device.\n");
        TapTun_Close(device);
        return 1;
    }
    printf("  [SUCCESS] Device activated.\n");
    
    sleep(2); // 保险起见还是等一下

    // 配置 IP 地址
    printf("\n[3] Configuring IP addresses...\n");
    if (TapTun_SetIPAddress(device, TEST_IPV4, TEST_MASK) != 0) {
        fprintf(stderr, "  [ERROR] Failed to set IPv4 address.\n");
    } else {
        printf("  [SUCCESS] IPv4 address set to %s\n", TEST_IPV4);
    }
    
    if (TapTun_SetIPAddressV6(device, TEST_IPV6, TEST_IPV6_PREFIX) != 0) {
        fprintf(stderr, "  [ERROR] Failed to set IPv6 address.\n");
    } else {
        printf("  [SUCCESS] IPv6 address set to %s/%d\n", TEST_IPV6, TEST_IPV6_PREFIX);
    }

    printf("\n[4] Starting background ping thread and waiting for packet...\n");
    pthread_t ping_thread_id;
    int ret = pthread_create(&ping_thread_id, NULL, PingThread, (void*)TEST_IPV4);
    if (ret != 0) {
        fprintf(stderr, "  [ERROR] Failed to create ping thread. Error code: %d\n", ret);
        TapTun_Close(device);
        return 1;
    }
    
    // 主线程在这里阻塞，等待 TAP 设备接收到数据，其实更有可能收到 ARP 数据包
    unsigned char buffer[2048];
    int bytesRead = TapTun_Read(device, buffer, sizeof(buffer));

    if (bytesRead <= 0) {
        fprintf(stderr, "  [ERROR] Failed to read from device.\n");
    } else {
        printf("  [SUCCESS] Read %d bytes from the TAP device!\n", bytesRead);
        printf("  [INFO] This is likely the ICMP (ping) request packet.\n");

        int bytesToPrint = bytesRead < 128 ? bytesRead : 128;
        printf("  [INFO] Packet hex dump (first %d bytes): ", bytesToPrint);

        for (int i = 0; i < bytesRead && i < bytesToPrint; ++i) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");
    }
    
    printf("\n[5] Waiting for ping thread to finish...\n");
    pthread_join(ping_thread_id, NULL);
    printf("  [SUCCESS] Ping thread finished.\n");

    printf("\n[6] Closing device...\n");
    TapTun_Close(device);
    printf("  [SUCCESS] Device closed.\n");

    printf("\n--- Test Finished ---\n");

    return 0;
}