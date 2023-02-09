#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <winternl.h>
#include "beacon.h"
#include "findrwx.h"


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
		MSVCRT$memset(g_lpwPrintBuffer, 0, MAX_STRING * sizeof(WCHAR)); // Clear print buffer.
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


BOOL FindRWX(HANDLE hProcess) {
	
	BOOL foundRWX = FALSE;
	LPVOID addr = 0;
	MEMORY_BASIC_INFORMATION mbi;
	mbi.BaseAddress = 0;
	mbi.AllocationBase = 0;
	mbi.AllocationProtect = 0;
	mbi.RegionSize = 0;
	mbi.State = 0;
	mbi.Protect = 0;
	mbi.Type = 0;
	
	BeaconPrintToStreamW(L"\nMemory address\t\t\tByte size\n");
	BeaconPrintToStreamW(L"================================================\n");
	
	while (KERNEL32$VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
		addr = (LPVOID)((DWORD_PTR) mbi.BaseAddress + mbi.RegionSize);

		if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
			BeaconPrintToStreamW(L"%#-30llx\t%#7llu\n", mbi.BaseAddress, mbi.RegionSize);
			foundRWX = TRUE;
			
		}
	}
	return foundRWX;
}





void go(char *args, int len) {
	int pID = 0;
	datap parser;
	HANDLE hProcess = NULL;
	BOOL res = NULL;
	
	BeaconDataParse(&parser, args, len);
	pID = BeaconDataInt(&parser);
	
	hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
	if (hProcess == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Error opening remote process or thread!\n");
		return -1;		
	}
	
	res = FindRWX(hProcess);
	if(!res) {
		BeaconPrintf(CALLBACK_ERROR, "No READ, WRITE, EXECUTE memory region found in the specified process!");
	}
	else {
		BeaconOutputStreamW();
		BeaconPrintf(CALLBACK_OUTPUT, "\n[+] DONE");
	}

	KERNEL32$CloseHandle(hProcess);
	return 0;
}


