#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "../include/taptun_api.h"

#pragma comment(lib, "ws2_32.lib") // 链接 Winsock 库

// 用于在线程间传递数据的结构体
typedef struct {
    TapTunDevice* tap_device;
    SOCKET udp_socket;
    struct sockaddr_in remote_addr;
} ThreadArgs;

// 从 TAP 读取并发送到 UDP
DWORD WINAPI TapToUdpThread(LPVOID lpParam) {
    ThreadArgs* args = (ThreadArgs*)lpParam;
    unsigned char buffer[4096];
    int bytes_read;
    printf("[THREAD Tap->UDP] Started.\n");

    while (1) { // 简单起见，使用无限循环
        bytes_read = TapTun_Read(args->tap_device, buffer, sizeof(buffer));
        if (bytes_read > 0) {
            sendto(args->udp_socket, (const char*)buffer, bytes_read, 0, 
                   (struct sockaddr*)&args->remote_addr, sizeof(args->remote_addr));
        } else {
            fprintf(stderr, "[THREAD Tap->UDP] TapTun_Read failed.\n");
            break;
        }
    }
    return 0;
}

// 线程 2: 从 UDP 接收并写入 TAP
DWORD WINAPI UdpToTapThread(LPVOID lpParam) {
    ThreadArgs* args = (ThreadArgs*)lpParam;
    unsigned char buffer[4096];
    int bytes_received;
    struct sockaddr_in sender_addr;
    int sender_addr_len = sizeof(sender_addr);
    printf("[THREAD UDP->TAP] Started.\n");

    while (1) {
        bytes_received = recvfrom(args->udp_socket, (char*)buffer, sizeof(buffer), 0,
                                  (struct sockaddr*)&sender_addr, &sender_addr_len);
        if (bytes_received > 0) {
            TapTun_Write(args->tap_device, buffer, bytes_received);
        } else {
            fprintf(stderr, "[THREAD UDP->TAP] recvfrom failed with error: %d\n", WSAGetLastError());
            break;
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <test1|test2> <remote_ip:port>\n", argv[0]);
        return 1;
    }

    const char* local_ip;
    int local_port;
    if (strcmp(argv[1], "test1") == 0) {
        local_ip = "10.0.0.1";
        local_port = 8001;
    } else if (strcmp(argv[1], "test2") == 0) {
        local_ip = "10.0.0.2";
        local_port = 8002;
    } else {
        printf("Invalid first argument. Use 'test1' or 'test2'.\n");
        return 1;
    }

    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed.\n");
        return 1;
    }

    printf("Initializing TAP device...\n");
    TapTunDevice* tap = TapTun_Open(NULL);
    if (!tap) { printf("TapTun_Open failed.\n"); return 1; }
    if (TapTun_Activate(tap) != 0) { printf("TapTun_Activate failed.\n"); return 1; }
    if (TapTun_SetIPAddress(tap, local_ip, "255.255.255.0") != 0) {
        printf("TapTun_SetIPAddress failed. Run as Administrator.\n");
        return 1;
    }
    printf("TAP device configured with IP %s\n", local_ip);

    SOCKET udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return 1;
    }

    struct sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(udp_sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        return 1;
    }
    printf("UDP socket bound to port %d\n", local_port);
    
    // 解析远程地址
    struct sockaddr_in remote_addr;
    char* remote_ip_str = strtok(argv[2], ":");
    char* remote_port_str = strtok(NULL, ":");
    if (!remote_ip_str || !remote_port_str) {
        printf("Invalid remote address format.\n");
        return 1;
    }
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(atoi(remote_port_str));
    inet_pton(AF_INET, remote_ip_str, &remote_addr.sin_addr);

    ThreadArgs args = { tap, udp_sock, remote_addr };
    HANDLE hTapToUdp = CreateThread(NULL, 0, TapToUdpThread, &args, 0, NULL);
    HANDLE hUdpToTap = CreateThread(NULL, 0, UdpToTapThread, &args, 0, NULL);

    printf("Bridge is running. Press Enter to exit...\n");
    getchar();

    printf("Shutting down...\n");
    TerminateThread(hTapToUdp, 0); // 简单粗暴地终止线程
    TerminateThread(hUdpToTap, 0);
    CloseHandle(hTapToUdp);
    CloseHandle(hUdpToTap);
    closesocket(udp_sock);
    TapTun_Close(tap);
    WSACleanup();

    return 0;
}