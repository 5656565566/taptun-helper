#include <stdio.h>

#include "../include/taptun_api.h"

// 测试参数
const char* TEST_IPV4 = "10.10.0.1";
const char* TEST_MASK = "255.255.255.0";
const char* TEST_IPV6 = "fd10::1";
const int   TEST_IPV6_PREFIX = 64;


DWORD WINAPI PingThread(LPVOID lpParam) {
    const char* ip_address = (const char*)lpParam;
    char command[128];

    printf("  [THREAD] Ping thread started. Pinging %s...\n", ip_address);
    
    snprintf(command, sizeof(command), "ping %s -n 1", ip_address);
    
    // 使用 system() 执行命令。它会阻塞这个线程，直到 ping 完成
    int result = system(command);
    
    if (result == 0) {
        printf("  [THREAD] Ping command finished successfully.\n");
    } else {
        fprintf(stderr, "  [THREAD] Ping command failed with exit code %d.\n", result);
    }
    
    return (DWORD)result;
}

int main() {
    printf("--- TAP-Windows DLL Automated Functional Test ---\n");
    
    // 打开 TAP 设备
    printf("[1] Opening TAP device...\n");
    TapTunDevice* device = TapTun_Open();
    
    unsigned char mac[6]; 

    if (device == NULL) {
        fprintf(stderr, "  [ERROR] Failed to open TAP device. Is tap-windows6 installed and enabled?\n");
        return 1;
    }
    printf("  [SUCCESS] Device opened successfully.\n");
    printf("  [INFO] Handle: %p, Index: %u, Name: \"%s\"\n", device->handle, device->if_index, device->if_name);

    // 激活设备
    printf("\n[2] Activating device...\n");
    if (TapTun_Activate(device) != 0) {
        fprintf(stderr, "  [ERROR] Failed to activate device.\n");
        TapTun_Close(device);
        return 1;
    }
    printf("  [SUCCESS] Device activated.\n");
    
    if (TapTun_GetMacAddress(device, mac) == 0) {
        printf("[INFO] MacAddress: %02x:%02x:%02x:%02x:%02x:%02x\n",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        printf("[ERROR] Failed to get MAC address.\n");
    }

    Sleep(3000); // 不等会导致 ip 未成功分配

    // 测试程序必须以管理员权限运行!
    printf("\n[3] Configuring IP addresses (requires Administrator privileges)...\n");
    if (TapTun_SetIPAddress(device, TEST_IPV4, TEST_MASK) != 0) {
        fprintf(stderr, "  [ERROR] Failed to set IPv4 address. Did you run this as Administrator?\n");
    } else {
        printf("  [SUCCESS] IPv4 address set to %s\n", TEST_IPV4);
    }
    
    if (TapTun_SetIPAddressV6(device, TEST_IPV6, TEST_IPV6_PREFIX) != 0) {
        fprintf(stderr, "  [ERROR] Failed to set IPv6 address.\n");
    } else {
        printf("  [SUCCESS] IPv6 address set to %s/%d\n", TEST_IPV6, TEST_IPV6_PREFIX);
    }

    printf("\n[4] Starting background ping thread and waiting for packet...\n");
    HANDLE hPingThread = CreateThread(NULL, 0, PingThread, (LPVOID)TEST_IPV4, 0, NULL);
    if (hPingThread == NULL) {
        fprintf(stderr, "  [ERROR] Failed to create ping thread. Error: %lu\n", GetLastError());
        TapTun_Close(device);
        return 1;
    }
    
    // 主线程在这里阻塞，等待 TAP 设备接收到数据，windows 也可能收到系统发起的各种广播数据包，ping 仅为了防止意外情况
    unsigned char buffer[2048];
    int bytesRead = TapTun_Read(device, buffer, sizeof(buffer));

    if (bytesRead <= 0) {
        fprintf(stderr, "  [ERROR] Failed to read from device. Error: %lu\n", GetLastError());
    } else {
        printf("  [SUCCESS] Read %d bytes from the TAP device!\n", bytesRead);
        printf("  [INFO] This is likely the ICMP (ping) request packet.\n");
        
        int bytesToPrint = bytesRead < 128 ? bytesRead : 128;
        
        printf("  [INFO] Packet hex dump (first %d bytes): ", bytesToPrint);
        for (int i = 0; i < bytesToPrint; ++i) {
            printf("%02X ", buffer[i]);
        }
        printf("\n");
    }

    printf("\n[5] Waiting for ping thread to finish...\n");
    WaitForSingleObject(hPingThread, INFINITE);
    CloseHandle(hPingThread); // 关闭线程句柄
    printf("  [SUCCESS] Ping thread finished.\n");
    
    printf("\n[6] Closing device...\n");
    TapTun_Close(device);
    printf("  [SUCCESS] Device closed.\n");

    printf("\n--- Test Finished ---\n");
    printf("Press Enter to exit.\n");
    getchar();

    return 0;
}