#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "beacon.h"
#include "enumactivehosts.h"

#pragma comment(lib, "Ws2_32.lib")

// ============================================================================
// TrustedSec BOF output buffering logic
// Purpose: Batch up printed output into a buffer to avoid Beacon print spam.
// ============================================================================
#ifndef bufsize
#define bufsize 8192
#endif
char *output = 0;                 
WORD currentoutsize = 0;          
HANDLE trash = NULL;              

int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);

// Initializes output buffer for this BOF run
int bofstart() {
    output = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

// Formats text like printf, appends to output buffer, flushes if full
void internal_printf(const char* format, ...){
    int buffersize = 0;
    int transfersize = 0;
    char * curloc = NULL;
    char* intBuffer = NULL;
    va_list args;

    // First pass: measure formatted string size
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (buffersize == -1) return;

    // Allocate temp buffers
    char* transferBuffer = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, bufsize);
    intBuffer = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, buffersize);

    // Second pass: actually format string into intBuffer
    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args);
    va_end(args);

    // Append to output buffer (with flush logic)
    if(buffersize + currentoutsize < bufsize) {
        MSVCRT$memcpy(output+currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    } else {
        curloc = intBuffer;
        while(buffersize > 0) {
            transfersize = bufsize - currentoutsize;
            if(buffersize < transfersize) {
                transfersize = buffersize;
            }
            MSVCRT$memcpy(output+currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;

            // Flush if buffer is full
            if(currentoutsize == bufsize) {
                printoutput(FALSE);
            }
            MSVCRT$memset(transferBuffer, 0, transfersize);
            curloc += transfersize;
            buffersize -= transfersize;
        }
    }

    // Free temp buffers
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, intBuffer);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, transferBuffer);
}

// Sends buffer to Beacon and optionally frees it
void printoutput(BOOL done) {
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    MSVCRT$memset(output, 0, bufsize);
    if(done) {MSVCRT$free(output); output=NULL;}
}




static int is_host_active(const char *host, const char *port, int timeout_ms) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    struct addrinfo *rp = NULL;
    int rc;

    MSVCRT$memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    rc = WS2_32$getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        return 0;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        SOCKET s;
        u_long nonblocking = 1;
        fd_set wfds;
        fd_set efds;
        struct timeval tv;
        int sel_rc;
        int so_error = 0;
        int so_error_len = (int)sizeof(so_error);

        s = WS2_32$socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == INVALID_SOCKET) {
            continue;
        }

        if (WS2_32$ioctlsocket(s, FIONBIO, &nonblocking) != 0) {
            WS2_32$closesocket(s);
            continue;
        }

        rc = WS2_32$connect(s, rp->ai_addr, (int)rp->ai_addrlen);
        if (rc == 0) {
            WS2_32$closesocket(s);
            WS2_32$freeaddrinfo(res);
            return 1;
        }

        rc = WS2_32$WSAGetLastError();
        if (rc != WSAEWOULDBLOCK && rc != WSAEINPROGRESS && rc != WSAEINVAL) {
            if (rc == WSAECONNREFUSED) {
                WS2_32$closesocket(s);
                WS2_32$freeaddrinfo(res);
                return 1;
            }

            WS2_32$closesocket(s);
            continue;
        }

        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        FD_SET(s, &wfds);
        FD_SET(s, &efds);

        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        sel_rc = WS2_32$select(0, NULL, &wfds, &efds, &tv);
        if (sel_rc > 0) {
            if (WS2_32$getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&so_error, &so_error_len) == 0) {
                WS2_32$closesocket(s);

                if (so_error == 0 || so_error == WSAECONNREFUSED) {
                    WS2_32$freeaddrinfo(res);
                    return 1;
                }

                continue;
            }
        }

        WS2_32$closesocket(s);
    }

    WS2_32$freeaddrinfo(res);
    return 0;
}



// ============================================================================
// Entry point
// ============================================================================
int go(char *args, int len) {
	WSADATA wsaData;
    int active;
    CHAR *port = "";
	int *timeout_ms = 300;
	
    char* hostname;
	char* nextHostname;
    int iBytesLen = 0;
    CHAR *hostFileBytes;
    datap parser;

    BeaconDataParse(&parser, args, len);
    hostFileBytes = BeaconDataExtract(&parser, &iBytesLen);
	port = (CHAR*)BeaconDataExtract(&parser, NULL);
	timeout_ms = BeaconDataInt(&parser);
	
	if(!bofstart()) return;
	
    if(iBytesLen != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Loaded file in memory with a size of %d bytes\n", iBytesLen); 
		
		internal_printf("\nActive host(s) based on validated port:\n");
		internal_printf("==============================================\n");
	
		if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
			return 1;
		}

        hostname = MSVCRT$strtok(hostFileBytes, "\r\n");
		while (hostname != NULL) {
			active = is_host_active(hostname, port, timeout_ms);

			if (active) {
				//internal_printf("[+] Active: %s\n", hostname);
				internal_printf("%s\n", hostname);
			} else {
				//internal_printf("[-] Inactive or Unknown: %s\n", hostname);
			}

			nextHostname = MSVCRT$strtok(NULL, "\r\n");
			if (nextHostname == NULL) {
				break;
			}

			hostname = nextHostname;
		}
		
		printoutput(TRUE);
		WS2_32$WSACleanup();

    } else {
		BeaconPrintf(CALLBACK_ERROR, "Failed to load file in memory or file is empty.\n"); 
        return -1;
    }
	
    return 0;
}

