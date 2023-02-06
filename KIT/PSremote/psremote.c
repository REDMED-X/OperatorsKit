#include <windows.h>
#include <stdio.h>
#include <wtsapi32.h>
#include "beacon.h"
#include "psremote.h"



//Code from: https://github.com/outflanknl/C2-Tool-Collection/blob/main/BOF/Psx/SOURCE/Psx.c
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

	// For BOF we need to avoid large stack buffers, so put print buffer on heap.
	if (g_lpwPrintBuffer <= (LPWSTR)1) { // Allocate once and free in BeaconOutputStreamW. 
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
		MSVCRT$memset(g_lpwPrintBuffer, 0, MAX_STRING * sizeof(WCHAR)); // Clear print buffer.
	}

	va_end(argList);
	return hr;
}

//Code from: https://github.com/outflanknl/C2-Tool-Collection/blob/main/BOF/Psx/SOURCE/Psx.c
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
		//BeaconPrintf(CALLBACK_OUTPUT, "DONE"); //DEBUG
	}

CleanUp:

	if (g_lpStream != NULL) {
		g_lpStream->lpVtbl->Release(g_lpStream);
		g_lpStream = NULL;
	}

	if (g_lpwPrintBuffer != NULL) {
		MSVCRT$free(g_lpwPrintBuffer); // Free print buffer.
		g_lpwPrintBuffer = NULL;
	}

	if (lpwOutput != NULL) {
		KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpwOutput);
	}

	return;
}


int ListProcesses(HANDLE handleTargetHost) {

	WTS_PROCESS_INFOA * proc_info;
	DWORD pi_count = 0;
	LPSTR procName; 
	WCHAR WCprocName[256];
	
	if (!WTSAPI32$WTSEnumerateProcessesA(handleTargetHost, 0, 1, &proc_info, &pi_count)) {
		 BeaconPrintf(CALLBACK_ERROR, "Failed to get a valid handle to the specified host!\n");
		return -1;
	}
	
	BeaconPrintToStreamW(L"\nProcess name\t\t\t\tPID\t\t\tSessionID\n");
	BeaconPrintToStreamW(L"===================================================================================\n");
	for (int i = 0 ; i < pi_count ; i++ ) {
		procName = proc_info[i].pProcessName;
		KERNEL32$MultiByteToWideChar(CP_ACP, 0, procName, -1, WCprocName, 256);
		BeaconPrintToStreamW(L"%-40s\t%d\t%23d\n",WCprocName ,proc_info[i].ProcessId ,proc_info[i].SessionId);
	}
	
	WTSAPI32$WTSCloseServer(handleTargetHost);
	
	return 0;
}

void go(char *args, int len) {
	
	CHAR *hostName;
	datap parser;
	DWORD argSize = NULL;
	HANDLE handleTargetHost = NULL;
	int res;

	BeaconDataParse(&parser, args, len);
    hostName = BeaconDataExtract(&parser, &argSize);

	handleTargetHost = WTSAPI32$WTSOpenServerA(hostName);
	
	res = ListProcesses(handleTargetHost);
	
	//print data to CS console
	BeaconOutputStreamW();

	return 0;
}