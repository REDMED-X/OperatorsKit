#include <stdio.h>
#include <Windows.h>
#include <Lm.h>
#include "enumshares.h"
#include "beacon.h"

#pragma comment(lib, "Netapi32.lib")


//START TrustedSec BOF print code: https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/common/base.c
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
    char * msg = NULL;
    BeaconOutput(CALLBACK_OUTPUT, output, currentoutsize);
    currentoutsize = 0;
    MSVCRT$memset(output, 0, bufsize);
    if(done) {MSVCRT$free(output); output=NULL;}
}
//END TrustedSec BOF print code.



PSHARE_INFO_1 listShares(wchar_t *servername) {
    PSHARE_INFO_1 pShareInfo = NULL;
    DWORD dwEntriesRead = 0, dwTotalEntries = 0, dwResumeHandle = 0;
    NET_API_STATUS nStatus;

    internal_printf("\n\nListing shares for: %ls\n", servername);
    internal_printf("=====================================================\n");
	
    do {
        nStatus = NETAPI32$NetShareEnum(servername, 1, (LPBYTE*)&pShareInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
		
		
        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                internal_printf("Share Name: %-10ls <- ", pShareInfo[i].shi1_netname);
				
				if (KERNEL32$lstrcmpW(pShareInfo[i].shi1_netname, L"IPC$") == 0) {
                    internal_printf("[!] No file system access\n");
                    continue;
                }
				
                USE_INFO_2 useInfo = { 0 };
                wchar_t fullPath[260];
                MSVCRT$_snwprintf(fullPath, sizeof(fullPath) / sizeof(wchar_t) - 1, L"\\\\%s\\%s", servername ? servername : L"localhost", pShareInfo[i].shi1_netname);
                
                useInfo.ui2_remote = fullPath;
                useInfo.ui2_asg_type = USE_DISKDEV; 
                useInfo.ui2_username = NULL; // Use current user's credentials
                useInfo.ui2_password = L"";
				
                nStatus = NETAPI32$NetUseAdd(NULL, 2, (LPBYTE)&useInfo, NULL);
                if (nStatus == NERR_Success) {
                    internal_printf("[+] Accessible\n");
                    NETAPI32$NetUseDel(NULL, fullPath, USE_LOTS_OF_FORCE);
                } else {
                    internal_printf("[-] Error access denied\n");
                }
				
            }
			
            NETAPI32$NetApiBufferFree(pShareInfo);
            pShareInfo = NULL;
        } else {
            if (nStatus == ERROR_BAD_NETPATH) {
                internal_printf("Connection error: ERROR_BAD_NETPATH\n");
			} else if (nStatus == ERROR_ACCESS_DENIED) {
                internal_printf("Connection error: ERROR_ACCESS_DENIED\n");
            } else {
                internal_printf("Connection error code: %d\n", nStatus);
            }
            break;
        }
		
    } while (nStatus == ERROR_MORE_DATA);
	
	return pShareInfo;
}

int go(char *args, int len) {
	char* hostname;
	char* nextHostname;
    int iBytesLen = 0;
    CHAR *hostFileBytes;
	WCHAR wHostname[MAX_PATH];
    datap parser;
	
    BeaconDataParse(&parser, args, len);
    hostFileBytes = BeaconDataExtract(&parser, &iBytesLen);
	if(!bofstart()) return;

	if(iBytesLen != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Loaded hostname file in memory with a size of %d bytes\n", iBytesLen); 
		
        hostname = MSVCRT$strtok(hostFileBytes, "\r\n");
        while (hostname != NULL) {
			nextHostname = MSVCRT$strtok(NULL, "\r\n");
            if (nextHostname == NULL) {
                break;
            }
			
			KERNEL32$MultiByteToWideChar(CP_ACP, 0, hostname, -1, wHostname, MAX_PATH);
			PSHARE_INFO_1 pShareInfo = listShares(wHostname);
            hostname = nextHostname;

			NETAPI32$NetApiBufferFree(pShareInfo);
        }
		printoutput(TRUE);
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Finished enumerating!\n"); 
		
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Couldn't load the host file from disk.\n");
    }
	
    return 0;
}




