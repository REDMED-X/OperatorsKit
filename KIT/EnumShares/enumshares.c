#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Lm.h>
#include "enumshares.h"
#include "beacon.h"

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Ws2_32.lib")

// --- Output Buffering ---
#ifndef bufsize
#define bufsize 8192
#endif
char *output = 0;  
WORD currentoutsize = 0;

void printoutput(BOOL done) {
    if (currentoutsize > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
        currentoutsize = 0;
        MSVCRT$memset(output, 0, bufsize);
    }
    if(done && output) { MSVCRT$free(output); output=NULL; }
}

void internal_printf(const char* format, ...){
    va_list args;
    va_start(args, format);
    int size = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);
    if (size < 0) return;
    char* temp = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1);
    va_start(args, format);
    MSVCRT$vsnprintf(temp, size + 1, format, args);
    va_end(args);
    if(size + currentoutsize < bufsize) {
        MSVCRT$memcpy(output+currentoutsize, temp, size);
        currentoutsize += size;
    } else {
        printoutput(FALSE);
        MSVCRT$memcpy(output, temp, size);
        currentoutsize = size;
    }
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, temp);
}

// --- Suggestions Logic ---

void secure_sleep(int base_seconds, int jitter_percent) {
    if (base_seconds <= 0) return;
    int sleep_ms = base_seconds * 1000;
    if (jitter_percent > 0) {
        MSVCRT$srand(KERNEL32$GetTickCount());
        int range = (sleep_ms * jitter_percent) / 100;
        if (range > 0) {
            int jitter = (MSVCRT$rand() % (range * 2)) - range;
            sleep_ms += jitter;
        }
    }
    if (sleep_ms > 0) KERNEL32$Sleep(sleep_ms);
}

// Check if port 445 is actually listening before wasting time on NetAPI32
int is_smb_open(const char* host, int timeout_ms) {
    struct addrinfo hints, *res;
    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (WS2_32$getaddrinfo(host, "445", &hints, &res) != 0) return 0;

    SOCKET s = WS2_32$socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    u_long nonblocking = 1;
    WS2_32$ioctlsocket(s, FIONBIO, &nonblocking);

    int rc = WS2_32$connect(s, res->ai_addr, (int)res->ai_addrlen);
    int active = 0;

    if (rc == SOCKET_ERROR && WS2_32$WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set wfds;
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        FD_ZERO(&wfds);
        FD_SET(s, &wfds);
        if (WS2_32$select(0, NULL, &wfds, NULL, &tv) > 0) active = 1;
    } else if (rc == 0) {
        active = 1;
    }

    WS2_32$closesocket(s);
    WS2_32$freeaddrinfo(res);
    return active;
}

void listShares(wchar_t *servername) {
    PSHARE_INFO_1 pShareInfo = NULL;
    DWORD dwEntriesRead = 0, dwTotalEntries = 0, dwResumeHandle = 0;
    NET_API_STATUS nStatus;

    internal_printf("\n--- Host: %ls ---\n", servername);
    
    do {
        nStatus = NETAPI32$NetShareEnum(servername, 1, (LPBYTE*)&pShareInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                if (KERNEL32$lstrcmpW(pShareInfo[i].shi1_netname, L"IPC$") == 0) continue;

                wchar_t fullPath[MAX_PATH];
                MSVCRT$_snwprintf(fullPath, MAX_PATH, L"\\\\%s\\%s", servername, pShareInfo[i].shi1_netname);

                // Stealth check: Check attributes instead of NetUseAdd
                DWORD attr = KERNEL32$GetFileAttributesW(fullPath);
                if (attr != INVALID_FILE_ATTRIBUTES) {
                    internal_printf("[+] READABLE: %ls\n", pShareInfo[i].shi1_netname);
                } else {
                    internal_printf("[-] DENIED:   %ls\n", pShareInfo[i].shi1_netname);
                }
            }
            NETAPI32$NetApiBufferFree(pShareInfo);
        } else {
            internal_printf("[!] NetShareEnum failed: %d\n", nStatus);
        }
    } while (nStatus == ERROR_MORE_DATA);
}

int go(char *args, int len) {
    datap parser;
    int iBytesLen, sleep_sec, jitter_pct, timeout_ms;
    char *hostFileBytes, *hostname;
    WSADATA wsa;

    BeaconDataParse(&parser, args, len);
    hostFileBytes = BeaconDataExtract(&parser, &iBytesLen);
    sleep_sec = BeaconDataInt(&parser);
    jitter_pct = BeaconDataInt(&parser);
    timeout_ms = BeaconDataInt(&parser);
    if (timeout_ms <= 0) timeout_ms = 300; // Safety default

    output = (char*)MSVCRT$calloc(bufsize, 1);
    WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa);

    hostname = MSVCRT$strtok(hostFileBytes, "\r\n");
    while (hostname != NULL) {
        if (is_smb_open(hostname, timeout_ms)) {
            WCHAR wHostname[MAX_PATH];
            KERNEL32$MultiByteToWideChar(CP_ACP, 0, hostname, -1, wHostname, MAX_PATH);
            listShares(wHostname);
        } else {
            // Optional: internal_printf("[*] Skipping %s (Port 445 closed/timeout)\n", hostname);
        }

        hostname = MSVCRT$strtok(NULL, "\r\n");
        if (hostname) secure_sleep(sleep_sec, jitter_pct);
    }

    printoutput(TRUE);
    WS2_32$WSACleanup();
    return 0;
}