#include <stdio.h>
#include <Windows.h>
#include <Lm.h>
#include "enumshares.h"
#include "beacon.h"

#pragma comment(lib, "Netapi32.lib")





//https://github.com/outflanknl/C2-Tool-Collection/blob/main/BOF/Psx/SOURCE/Psx.c
HRESULT BeaconPrintToStreamW(_In_z_ LPCWSTR lpwFormat, ...) {
	HRESULT hr = S_FALSE;
	va_list argList;
	DWORD dwWritten = 0;

	if (g_lpStream <= (LPSTREAM)1) {
		hr = OLE32$CreateStreamOnHGlobal(NULL, TRUE, &g_lpStream);
		if (FAILED(hr)) {
			return hr;
		}
	}

	if (g_lpwPrintBuffer <= (LPWSTR)1) { 
		g_lpwPrintBuffer = (LPWSTR)MSVCRT$calloc(MAX_STRING, sizeof(WCHAR));
		if (g_lpwPrintBuffer == NULL) {
			hr = E_FAIL;
			goto CleanUp;
		}
	}

	va_start(argList, lpwFormat);
	if (!MSVCRT$_vsnwprintf_s(g_lpwPrintBuffer, MAX_STRING, MAX_STRING -1, lpwFormat, argList)) {
		hr = E_FAIL;
		goto CleanUp;
	}

	if (g_lpStream != NULL) {
		if (FAILED(hr = g_lpStream->lpVtbl->Write(g_lpStream, g_lpwPrintBuffer, (ULONG)MSVCRT$wcslen(g_lpwPrintBuffer) * sizeof(WCHAR), &dwWritten))) {
			goto CleanUp;
		}
	}

	hr = S_OK;

CleanUp:

	if (g_lpwPrintBuffer != NULL) {
		MSVCRT$memset(g_lpwPrintBuffer, 0, MAX_STRING * sizeof(WCHAR)); 
	}

	va_end(argList);
	return hr;
}

//https://github.com/outflanknl/C2-Tool-Collection/blob/main/BOF/Psx/SOURCE/Psx.c
VOID BeaconOutputStreamW() {
	STATSTG ssStreamData = { 0 };
	SIZE_T cbSize = 0;
	ULONG cbRead = 0;
	LARGE_INTEGER pos;
	LPWSTR lpwOutput = NULL;

	if (FAILED(g_lpStream->lpVtbl->Stat(g_lpStream, &ssStreamData, STATFLAG_NONAME))) {
		return;
	}

	cbSize = ssStreamData.cbSize.LowPart;
	lpwOutput = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize + 1);
	if (lpwOutput != NULL) {
		pos.QuadPart = 0;
		if (FAILED(g_lpStream->lpVtbl->Seek(g_lpStream, pos, STREAM_SEEK_SET, NULL))) {
			goto CleanUp;
		}

		if (FAILED(g_lpStream->lpVtbl->Read(g_lpStream, lpwOutput, (ULONG)cbSize, &cbRead))) {		
			goto CleanUp;
		}

		BeaconPrintf(CALLBACK_OUTPUT, "%ls", lpwOutput);
	}

CleanUp:
	if (g_lpStream != NULL) {
		g_lpStream->lpVtbl->Release(g_lpStream);
		g_lpStream = NULL;
	}

	if (g_lpwPrintBuffer != NULL) {
		MSVCRT$free(g_lpwPrintBuffer); 
		g_lpwPrintBuffer = NULL;
	}

	if (lpwOutput != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwOutput);
	}
	return;
}




PSHARE_INFO_1 listShares(wchar_t *servername) {
    PSHARE_INFO_1 pShareInfo = NULL;
    DWORD dwEntriesRead = 0, dwTotalEntries = 0, dwResumeHandle = 0;
    NET_API_STATUS nStatus;

    BeaconPrintToStreamW(L"\nListing shares for: %ls\n", servername);
    BeaconPrintToStreamW(L"=====================================================\n");
	
    do {
        nStatus = NETAPI32$NetShareEnum(servername, 1, (LPBYTE*)&pShareInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
		
		
        if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA)) {
            for (DWORD i = 0; i < dwEntriesRead; i++) {
                BeaconPrintToStreamW(L"Share Name: %-10ls <- ", pShareInfo[i].shi1_netname);
				
				if (KERNEL32$lstrcmpW(pShareInfo[i].shi1_netname, L"IPC$") == 0) {
                    BeaconPrintToStreamW(L"[!] No file system access\n");
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
                    BeaconPrintToStreamW(L"[+] Accessible\n");
                    NETAPI32$NetUseDel(NULL, fullPath, USE_LOTS_OF_FORCE);
                } else {
                    BeaconPrintToStreamW(L"[-] Error access denied\n");
                }
				
            }
			
            NETAPI32$NetApiBufferFree(pShareInfo);
            pShareInfo = NULL;
        } else {
            if (nStatus == ERROR_BAD_NETPATH) {
                BeaconPrintToStreamW(L"Connection error: ERROR_BAD_NETPATH\n");
			} else if (nStatus == ERROR_ACCESS_DENIED) {
                BeaconPrintToStreamW(L"Connection error: ERROR_ACCESS_DENIED\n");
            } else {
                BeaconPrintToStreamW(L"Connection error code: %d\n", nStatus);
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

	if(iBytesLen != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Loaded hostname file in memory with a size of %d bytes\n[*] Start share enumeration..\n", iBytesLen); 
		
        hostname = MSVCRT$strtok(hostFileBytes, "\r\n");
        while (hostname != NULL) {
			nextHostname = MSVCRT$strtok(NULL, "\r\n");
            if (nextHostname == NULL) {
                break;
            }
			
			KERNEL32$MultiByteToWideChar(CP_ACP, 0, hostname, -1, wHostname, MAX_PATH);
			PSHARE_INFO_1 pShareInfo = listShares(wHostname);
            hostname = nextHostname;
			
			BeaconOutputStreamW();
			NETAPI32$NetApiBufferFree(pShareInfo);
			
        }
		
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Done!\n"); 
		
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Couldn't load the host file from disk.\n");
    }
	
    return 0;
}




