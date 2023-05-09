#include <windows.h>
#include <stdio.h>
#include "findwebclient.h"
#include "beacon.h"





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




int go(char *args, int len) {
    char* pipeNameHead = "\\\\";
    char* pipeNameTail = "\\pipe\\DAV RPC SERVICE";
    BOOL pipeStatus = 0;
    char* hostname;
	char* nextHostname;
	char* debug;
    int iBytesLen = 0;
    CHAR *hostFileBytes;
	WCHAR wHostname[256];
    datap parser;

    BeaconDataParse(&parser, args, len);
    hostFileBytes = BeaconDataExtract(&parser, &iBytesLen);
	debug = BeaconDataExtract(&parser, NULL);
	
    if(iBytesLen != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Loaded file in memory with a size of %d bytes\n[*] Start WebClient enumeration..\n", iBytesLen); 
		
		BeaconPrintToStreamW(L"\nEnumeration results:\n");
		BeaconPrintToStreamW(L"==============================================\n");
	
        hostname = MSVCRT$strtok(hostFileBytes, "\r\n");
        while (hostname != NULL) {
			nextHostname = MSVCRT$strtok(NULL, "\r\n");
            if (nextHostname == NULL) {
                break;
            }

            size_t len = MSVCRT$strlen(hostname);
            char* fullPipeName = (char*) MSVCRT$malloc(len + MSVCRT$strlen(pipeNameHead) + MSVCRT$strlen(pipeNameTail) + 1);
            MSVCRT$strcpy(fullPipeName, pipeNameHead);
            MSVCRT$strcat(fullPipeName, hostname);
            MSVCRT$strcat(fullPipeName, pipeNameTail);
		
            pipeStatus = KERNEL32$WaitNamedPipeA(fullPipeName, 3000);

			if (pipeStatus == 0 && (MSVCRT$strcmp(debug, "debug") == 0)) {
				KERNEL32$MultiByteToWideChar(CP_ACP, 0, hostname, -1, wHostname, 256);
				BeaconPrintToStreamW(L"[-] WebClient service not found on %s\n", wHostname);
			} else if (pipeStatus == 0) {
            } else {
				KERNEL32$MultiByteToWideChar(CP_ACP, 0, hostname, -1, wHostname, 256);
				BeaconPrintToStreamW(L"[+] WebClient running on %s\n", wHostname);
            }
            MSVCRT$free(fullPipeName);
            hostname = nextHostname;
        }
		BeaconOutputStreamW();

    } else {
        BeaconPrintf(CALLBACK_ERROR, "Couldn't load the host file from disk.\n");
    }
	
	
    return 0;
}

