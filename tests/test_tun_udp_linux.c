#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../include/taptun_api.h"

typedef struct {
    TapTunDevice* tun_device;
    int udp_socket_fd;
    struct sockaddr_in remote_addr;
} ThreadArgs;

void* tap_to_udp_thread(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    unsigned char buffer[4096];
    int bytes_read;
    printf("[THREAD TUN->UDP] Started.\n");

    while (1) {
        bytes_read = TapTun_Read(args->tun_device, buffer, sizeof(buffer));
        if (bytes_read > 0) {
            sendto(args->udp_socket_fd, buffer, bytes_read, 0,
                   (struct sockaddr*)&args->remote_addr, sizeof(args->remote_addr));
        } else {
            perror("[THREAD TUN->UDP] TapTun_Read failed");
            break;
        }
    }
    return NULL;
}

void* udp_to_tap_thread(void* arg) {
    ThreadArgs* args = (ThreadArgs*)arg;
    unsigned char buffer[4096];
    int bytes_received;
    printf("[THREAD UDP->TUN] Started.\n");

    while (1) {
        bytes_received = recvfrom(args->udp_socket_fd, buffer, sizeof(buffer), 0, NULL, NULL);
        if (bytes_received > 0) {
            TapTun_Write(args->tun_device, buffer, bytes_received);
        } else {
            perror("[THREAD UDP->TUN] recvfrom failed");
            break;
        }
    }
    return NULL;
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

    // 需要 root 权限
    printf("Initializing TUN device...\n");
    TapTunDevice* tun = TapTun_Open(NULL);
    if (!tun) { printf("TapTun_Open failed.\n"); return 1; }
    if (TapTun_Activate(tun) != 0) { printf("TapTun_Activate failed.\n"); return 1; }
    if (TapTun_SetIPAddressV4(tun, local_ip, 24) != 0) {
        printf("TapTun_SetIPAddressV4 failed.\n");
        return 1;
    }
    printf("TUN device '%s' configured with IP %s\n", TapTun_GetName(tun), local_ip);

    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock_fd < 0) { perror("socket() failed"); return 1; }

    struct sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    local_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(udp_sock_fd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind() failed");
        return 1;
    }
    printf("UDP socket bound to port %d\n", local_port);

    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    char* remote_ip_str = strtok(argv[2], ":");
    char* remote_port_str = strtok(NULL, ":");
    if (!remote_ip_str || !remote_port_str) { printf("Invalid remote address format.\n"); return 1; }
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(atoi(remote_port_str));
    inet_pton(AF_INET, remote_ip_str, &remote_addr.sin_addr);

    ThreadArgs args = { tun, udp_sock_fd, remote_addr };
    pthread_t tid1, tid2;
    pthread_create(&tid1, NULL, tap_to_udp_thread, &args);
    pthread_create(&tid2, NULL, udp_to_tap_thread, &args);

    printf("Bridge is running. Press Enter to exit...\n");
    getchar();

    printf("Shutting down...\n");
    pthread_cancel(tid1);
    pthread_cancel(tid2);
    pthread_join(tid1, NULL);
    pthread_join(tid2, NULL);
    close(udp_sock_fd);
    TapTun_Close(tun);

    return 0;
}
