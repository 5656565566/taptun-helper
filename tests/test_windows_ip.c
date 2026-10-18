#include <winsock2.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static MIB_UNICASTIPADDRESS_ROW rows[4];
static ULONG row_count;
static DWORD create_error;
static DWORD get_error;
static DWORD set_error;
static DWORD table_error;
static DWORD delete_error;

static int find_row(const MIB_UNICASTIPADDRESS_ROW* key) {
    for (ULONG index = 0; index < row_count; ++index) {
        if (rows[index].InterfaceLuid.Value != key->InterfaceLuid.Value ||
            rows[index].Address.si_family != key->Address.si_family) continue;
        if (key->Address.si_family == AF_INET) {
            if (memcmp(&rows[index].Address.Ipv4.sin_addr,
                    &key->Address.Ipv4.sin_addr, sizeof(IN_ADDR)) == 0) return (int)index;
        } else if (memcmp(&rows[index].Address.Ipv6.sin6_addr,
                       &key->Address.Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0) {
            return (int)index;
        }
    }
    return -1;
}

static DWORD WINAPI mock_create(const MIB_UNICASTIPADDRESS_ROW* row) {
    if (create_error != NO_ERROR) return create_error;
    if (find_row(row) >= 0) return ERROR_OBJECT_ALREADY_EXISTS;
    if (row_count == sizeof(rows) / sizeof(rows[0])) return ERROR_NOT_ENOUGH_MEMORY;
    rows[row_count++] = *row;
    return NO_ERROR;
}

static DWORD WINAPI mock_get(MIB_UNICASTIPADDRESS_ROW* row) {
    if (get_error != NO_ERROR) return get_error;
    int index = find_row(row);
    if (index < 0) return ERROR_NOT_FOUND;
    *row = rows[index];
    return NO_ERROR;
}

static DWORD WINAPI mock_set(const MIB_UNICASTIPADDRESS_ROW* row) {
    if (set_error != NO_ERROR) return set_error;
    int index = find_row(row);
    if (index < 0) return ERROR_NOT_FOUND;
    rows[index] = *row;
    return NO_ERROR;
}

static DWORD WINAPI mock_table(ADDRESS_FAMILY family, PMIB_UNICASTIPADDRESS_TABLE* table) {
    if (table_error != NO_ERROR) return table_error;
    *table = calloc(1, sizeof(**table) + row_count * sizeof(rows[0]));
    if (!*table) return ERROR_NOT_ENOUGH_MEMORY;
    for (ULONG index = 0; index < row_count; ++index) {
        if (rows[index].Address.si_family == family) {
            (*table)->Table[(*table)->NumEntries++] = rows[index];
        }
    }
    return NO_ERROR;
}

static DWORD WINAPI mock_delete(const MIB_UNICASTIPADDRESS_ROW* row) {
    if (delete_error != NO_ERROR) return delete_error;
    int index = find_row(row);
    if (index < 0) return ERROR_NOT_FOUND;
    memmove(rows + index, rows + index + 1,
        (row_count - (ULONG)index - 1) * sizeof(rows[0]));
    --row_count;
    return NO_ERROR;
}

static void WINAPI mock_free(void* table) {
    free(table);
}

/* Keep IP Helper substitution local to this test; no host interface is changed. */
#define CreateUnicastIpAddressEntry mock_create
#define GetUnicastIpAddressEntry mock_get
#define SetUnicastIpAddressEntry mock_set
#define GetUnicastIpAddressTable mock_table
#define DeleteUnicastIpAddressEntry mock_delete
#define FreeMibTable mock_free
#include "../src/taptun_win32.c"

typedef enum {
    UPDATE_PREFIX,
    SAME_PREFIX,
    CREATE_NEW_ADDRESS,
    CREATE_FAILURE,
    GET_FAILURE,
    SET_FAILURE,
    TABLE_FAILURE,
    DELETE_FAILURE
} Scenario;

static int prepare_row(
    MIB_UNICASTIPADDRESS_ROW* row,
    ADDRESS_FAMILY family,
    const char* address,
    unsigned int prefix_length,
    ULONG64 luid) {
    memset(row, 0, sizeof(*row));
    row->InterfaceLuid.Value = luid;
    row->Address.si_family = family;
    row->OnLinkPrefixLength = (UINT8)prefix_length;
    row->ValidLifetime = 3600;
    row->PreferredLifetime = 1800;
    row->PrefixOrigin = IpPrefixOriginManual;
    row->SuffixOrigin = IpSuffixOriginManual;
    row->SkipAsSource = TRUE;
    void* target = family == AF_INET
        ? (void*)&row->Address.Ipv4.sin_addr
        : (void*)&row->Address.Ipv6.sin6_addr;
    return InetPtonA(family, address, target) == 1;
}

static int test_address(ADDRESS_FAMILY family, Scenario scenario) {
    const char* old_address = family == AF_INET ? "10.1.2.3" : "fd00::1";
    const char* other_address = family == AF_INET ? "10.8.9.10" : "fd00::2";
    const char* new_address = family == AF_INET ? "10.9.8.7" : "fd01::1";
    unsigned int old_prefix = family == AF_INET ? 24 : 64;
    unsigned int requested_prefix = family == AF_INET ? 16 : 48;
    TapTunDevice device;
    memset(&device, 0, sizeof(device));
    device.luid.Value = 123;
    memset(rows, 0, sizeof(rows));
    if (!prepare_row(&rows[0], family, old_address, old_prefix, device.luid.Value) ||
        !prepare_row(&rows[1], family, other_address, old_prefix, device.luid.Value) ||
        !prepare_row(&rows[2], family, old_address, old_prefix, 456)) return 1;
    row_count = 3;
    create_error = get_error = set_error = table_error = delete_error = NO_ERROR;
    const char* requested_address = old_address;
    DWORD expected_error = NO_ERROR;
    switch (scenario) {
        case SAME_PREFIX: requested_prefix = old_prefix; break;
        case CREATE_NEW_ADDRESS: requested_address = new_address; break;
        case CREATE_FAILURE:
            requested_address = new_address;
            expected_error = create_error = ERROR_ACCESS_DENIED;
            break;
        case GET_FAILURE: expected_error = get_error = ERROR_NOT_FOUND; break;
        case SET_FAILURE: expected_error = set_error = ERROR_INVALID_PARAMETER; break;
        case TABLE_FAILURE:
            requested_address = new_address;
            expected_error = table_error = ERROR_NOT_ENOUGH_MEMORY;
            break;
        case DELETE_FAILURE:
            requested_address = new_address;
            expected_error = delete_error = ERROR_ACCESS_DENIED;
            break;
        case UPDATE_PREFIX: break;
    }
    MIB_UNICASTIPADDRESS_ROW before[3];
    memcpy(before, rows, sizeof(before));
    SetLastError(NO_ERROR);
    int result = family == AF_INET
        ? TapTun_SetIPAddressV4(&device, requested_address, requested_prefix)
        : TapTun_SetIPAddressV6(&device, requested_address, requested_prefix);
    DWORD native_error = GetLastError();
    if (expected_error != NO_ERROR) {
        if (result != TAPTUN_ERROR || native_error != expected_error) return 1;
        if (scenario == CREATE_FAILURE || scenario == GET_FAILURE || scenario == SET_FAILURE) {
            return row_count != 3 || memcmp(before, rows, sizeof(before)) != 0;
        }
        if (row_count != 4 || memcmp(before, rows, sizeof(before)) != 0) return 1;
    } else if (result != TAPTUN_OK || row_count != 2) {
        return 1;
    }

    MIB_UNICASTIPADDRESS_ROW key;
    if (!prepare_row(&key, family, requested_address, requested_prefix,
            device.luid.Value)) return 1;
    int configured = find_row(&key);
    int foreign = find_row(&before[2]);
    if (configured < 0 || rows[configured].OnLinkPrefixLength != requested_prefix ||
        foreign < 0 || memcmp(&rows[foreign], &before[2], sizeof(before[2])) != 0) return 1;
    if (scenario == UPDATE_PREFIX || scenario == SAME_PREFIX) {
        MIB_UNICASTIPADDRESS_ROW expected = before[0];
        expected.OnLinkPrefixLength = (UINT8)requested_prefix;
        if (memcmp(&rows[configured], &expected, sizeof(expected)) != 0) return 1;
    }
    return 0;
}

int main(void) {
    unsigned int failures = 0;
    for (unsigned int version = 0; version < 2; ++version) {
        ADDRESS_FAMILY family = version == 0 ? AF_INET : AF_INET6;
        for (int scenario = UPDATE_PREFIX; scenario <= DELETE_FAILURE; ++scenario) {
            if (test_address(family, (Scenario)scenario) != 0) {
                fprintf(stderr, "IPv%u address scenario %d failed.\n", version == 0 ? 4 : 6, scenario);
                ++failures;
            }
        }
    }
    if (failures != 0) return 1;
    printf("Windows IP configuration tests passed (16 scenarios).\n");
    return 0;
}
