#include "taptun_api.h"
#include "tap-windows6.h"

#include <ws2tcpip.h>
#include <winioctl.h>
#include <iphlpapi.h>

TapTunDevice* TapTun_Open(const char* name) {
    HKEY adapter_key;
    LONG status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &adapter_key);
    if (status != ERROR_SUCCESS) return NULL;

    for (int i = 0; ; ++i) {
        char enum_name[256], unit_key_name[512], component_id[256], guid_str[256];
        HKEY unit_key;
        DWORD len = sizeof(enum_name);

        if (RegEnumKeyExA(adapter_key, i, enum_name, &len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
            break; // 没有更多适配器
        }
        
        snprintf(unit_key_name, sizeof(unit_key_name), "%s\\%s", ADAPTER_KEY, enum_name);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, unit_key_name, 0, KEY_READ, &unit_key) != ERROR_SUCCESS) {
            continue;
        }

        len = sizeof(component_id);
        if (RegQueryValueExA(unit_key, "ComponentId", NULL, NULL, (LPBYTE)component_id, &len) == ERROR_SUCCESS &&
            strcmp(component_id, "tap0901") == 0) {
            
            len = sizeof(guid_str);
            if (RegQueryValueExA(unit_key, "NetCfgInstanceId", NULL, NULL, (LPBYTE)guid_str, &len) != ERROR_SUCCESS) {
                RegCloseKey(unit_key);
                continue;
            }

            // 如果指定了名称 请检查是否匹配
            if (name && name[0] != '\0') {
                HKEY connection_key;
                char connection_name[256];
                char connection_key_name[512];
                snprintf(connection_key_name, sizeof(connection_key_name), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, guid_str);
                
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, connection_key_name, 0, KEY_READ, &connection_key) == ERROR_SUCCESS) {
                    len = sizeof(connection_name);
                    // 只有成功读取到名称时才进行比较
                    if (RegQueryValueExA(connection_key, "Name", NULL, NULL, (LPBYTE)connection_name, &len) == ERROR_SUCCESS) {
                        if (strcmp(name, connection_name) != 0) {
                            RegCloseKey(connection_key);
                            RegCloseKey(unit_key);
                            continue; // 不是我们正在寻找的适配器
                        }
                    } else { // 读取名称失败 无法确认
                        RegCloseKey(connection_key);
                        RegCloseKey(unit_key);
                        continue;
                    }
                    RegCloseKey(connection_key);
                } else {
                    // 无法检查名称 因此不能确定它是正确的
                    RegCloseKey(unit_key);
                    continue;
                }
            }

            // 找到了匹配的适配器（或者如果 name 为 NULL 则为任何 TAP 适配器）尝试打开它
            char device_path[512];
            snprintf(device_path, sizeof(device_path), "%s%s%s", USERMODEDEVICEDIR, guid_str, TAP_WIN_SUFFIX);
            HANDLE hDevice = CreateFileA(device_path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);

            if (hDevice != INVALID_HANDLE_VALUE) {
                TapTunDevice* device = (TapTunDevice*)calloc(1, sizeof(TapTunDevice));
                if (!device) {
                    CloseHandle(hDevice);
                    RegCloseKey(unit_key);
                    continue; 
                }
                
                device->handle = hDevice;
                strncpy(device->guid_str, guid_str, sizeof(device->guid_str) - 1);
                
                device->overlap_read.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
                device->overlap_write.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

                if (!device->overlap_read.hEvent || !device->overlap_write.hEvent) {
                    if (device->overlap_read.hEvent) CloseHandle(device->overlap_read.hEvent);
                    if (device->overlap_write.hEvent) CloseHandle(device->overlap_write.hEvent);
                    CloseHandle(hDevice);
                    free(device);
                    RegCloseKey(unit_key);
                    continue; // 无法创建事件 尝试下一个适配器
                }

                InitializeCriticalSection(&device->io_lock);
                InitializeConditionVariable(&device->io_condition);

                // 获取接口名称并存储
                HKEY connection_key;
                char connection_key_name[512];
                snprintf(connection_key_name, sizeof(connection_key_name), "%s\\%s\\Connection", NETWORK_CONNECTIONS_KEY, guid_str);
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, connection_key_name, 0, KEY_READ, &connection_key) == ERROR_SUCCESS) {
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
    // 初始缓冲区大小 可以设置得小一点
    ULONG buffer_size = sizeof(IP_ADAPTER_ADDRESSES); 
    DWORD result = 0;
    int ret = -1;
    int attempts = 0;
    const int MAX_ATTEMPTS = 3; // 设置最大重试次数 防止无限循环

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
    if (!device || device->if_index == 0 || !ip || !mask) {
        fprintf(stderr, "ERROR: SetIPAddress called on a device that is not properly activated or initialized.\n");
        return -1;
    }

    IN_ADDR ip_addr, mask_addr;
    // 在删除现有地址前验证全部输入，失败时不得改变接口状态
    if (InetPtonA(AF_INET, ip, &ip_addr) != 1 || InetPtonA(AF_INET, mask, &mask_addr) != 1) {
        fprintf(stderr, "ERROR: Invalid IPv4 address or subnet mask.\n");
        return -1;
    }
    
    PMIB_UNICASTIPADDRESS_TABLE address_table = NULL;
    if (GetUnicastIpAddressTable(AF_INET, &address_table) == NO_ERROR) {
        for (ULONG i = 0; i < address_table->NumEntries; ++i) {
            MIB_UNICASTIPADDRESS_ROW* row = &address_table->Table[i];
            if (row->InterfaceIndex == device->if_index) {
                DWORD delete_result = DeleteUnicastIpAddressEntry(row);
                if (delete_result != NO_ERROR && delete_result != ERROR_NOT_FOUND) {
                    fprintf(stderr, "Failed to delete existing IPv4 address. Error: %lu\n", delete_result);
                    FreeMibTable(address_table);
                    return -1;
                }
            }
        }
        FreeMibTable(address_table);
    }
    
    ULONG nteContext = 0, nteInstance = 0;
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
    if (!device || !buffer || bufferSize <= 0) return -1;
    DWORD bytesRead;
    int result = -1;

    EnterCriticalSection(&device->io_lock);
    if (device->closing || device->active_read) {
        LeaveCriticalSection(&device->io_lock);
        return -1;
    }
    device->active_read = 1;
    ResetEvent(device->overlap_read.hEvent);
    BOOL completed = ReadFile(device->handle, buffer, bufferSize, &bytesRead, &device->overlap_read);
    DWORD lastError = completed ? ERROR_SUCCESS : GetLastError();
    LeaveCriticalSection(&device->io_lock);

    if (!completed) {
        if (lastError == ERROR_IO_PENDING) {
            if (GetOverlappedResult(device->handle, &device->overlap_read, &bytesRead, TRUE)) {
                result = (int)bytesRead;
            }
        }
    } else {
        // 如果 ReadFile 立即成功返回 TRUE bytesRead 已经包含了读取的字节数
        result = (int)bytesRead;
    }

    EnterCriticalSection(&device->io_lock);
    device->active_read = 0;
    WakeAllConditionVariable(&device->io_condition);
    LeaveCriticalSection(&device->io_lock);
    return result;
}

int TapTun_Write(TapTunDevice* device, const unsigned char* data, int dataSize) {
    if (!device || !data || dataSize <= 0) return -1;
    DWORD bytesWritten;
    int result = -1;

    EnterCriticalSection(&device->io_lock);
    if (device->closing || device->active_write) {
        LeaveCriticalSection(&device->io_lock);
        return -1;
    }
    device->active_write = 1;
    ResetEvent(device->overlap_write.hEvent);
    BOOL completed = WriteFile(device->handle, data, dataSize, &bytesWritten, &device->overlap_write);
    DWORD lastError = completed ? ERROR_SUCCESS : GetLastError();
    LeaveCriticalSection(&device->io_lock);

    if (!completed) {
        if (lastError == ERROR_IO_PENDING) {
            if (GetOverlappedResult(device->handle, &device->overlap_write, &bytesWritten, TRUE)) {
                result = (int)bytesWritten;
            }
        }
    } else {
        result = (int)bytesWritten;
    }

    EnterCriticalSection(&device->io_lock);
    device->active_write = 0;
    WakeAllConditionVariable(&device->io_condition);
    LeaveCriticalSection(&device->io_lock);
    return result;
}

void TapTun_Close(TapTunDevice* device) {
    if (device) {
        EnterCriticalSection(&device->io_lock);
        device->closing = 1;
        LeaveCriticalSection(&device->io_lock);

        // 先取消挂起操作，并等待所有 I/O 调用离开设备对象后再释放资源
        CancelIoEx(device->handle, NULL);

        EnterCriticalSection(&device->io_lock);
        while (device->active_read || device->active_write) {
            SleepConditionVariableCS(&device->io_condition, &device->io_lock, INFINITE);
        }
        LeaveCriticalSection(&device->io_lock);

        if (device->overlap_read.hEvent) CloseHandle(device->overlap_read.hEvent);
        if (device->overlap_write.hEvent) CloseHandle(device->overlap_write.hEvent);
        
        CloseHandle(device->handle);
        DeleteCriticalSection(&device->io_lock);
        free(device);
    }
}
