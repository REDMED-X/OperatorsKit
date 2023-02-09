#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <winternl.h>
#include "beacon.h"
#include "finddotnet.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shlwapi.lib")


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



BOOL FindDotNet() {
	int p = 0;
	int pid = 0;
	char psPath[MAX_PATH];
	HANDLE currentProc = NULL;
	UNICODE_STRING sectionName = { 0 };
	WCHAR ProcNumber[30];
	OBJECT_ATTRIBUTES objectAttributes;
	BOOL dotNetFound = FALSE;
	LPCSTR procName;
	WCHAR WCprocName[256];
	
	NtGetNextProcess_t pNtGetNextProcess = (NtGetNextProcess_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtGetNextProcess");
	NtOpenSection_t pNtOpenSection = (NtOpenSection_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenSection");
	if (pNtGetNextProcess == NULL || pNtOpenSection == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Error resolving native API calls!\n");
		return -1;		
	}
	
	WCHAR objPath[] = L"\\BaseNamedObjects\\Cor_Private_IPCBlock_v4_";
	sectionName.Buffer = (PWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 500);

	BeaconPrintToStreamW(L"\nProcess name\t\t\t\t\t\tPID\n");
	BeaconPrintToStreamW(L"=====================================================================\n");

	while (!pNtGetNextProcess(currentProc, MAXIMUM_ALLOWED, 0, 0, &currentProc)) {
		
		pid = KERNEL32$GetProcessId(currentProc);
		if (pid == 0) continue;		

		USER32$wsprintfW(ProcNumber, L"%d", pid);

		MSVCRT$memset(sectionName.Buffer, 0, 500);
		MSVCRT$memcpy(sectionName.Buffer, objPath, MSVCRT$wcslen(objPath) * 2);   // add section name "prefix"
		KERNEL32$lstrcatW(sectionName.Buffer, ProcNumber);
		sectionName.Length = MSVCRT$wcslen(sectionName.Buffer) * 2;		// finally, adjust the string size
		sectionName.MaximumLength = sectionName.Length + 1;		
	
		InitializeObjectAttributes(&objectAttributes, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE sectionHandle = NULL;		
		NTSTATUS status = pNtOpenSection(&sectionHandle, SECTION_QUERY, &objectAttributes);
		
		if (NT_SUCCESS(status)) {
			KERNEL32$CloseHandle(sectionHandle);
			
			KERNEL32$K32GetProcessImageFileNameA(currentProc, psPath, MAX_PATH);
			procName = SHLWAPI$PathFindFileNameA(psPath);
			
			KERNEL32$MultiByteToWideChar(CP_ACP, 0, procName, -1, WCprocName, 256);
			BeaconPrintToStreamW(L"%-60s\t%d\n", WCprocName, pid);
			
			dotNetFound = TRUE;
		}
	}
	
	return dotNetFound;
}


int go(void) {
	BOOL res = NULL;
	
	res = FindDotNet();
	if(!res) {
		BeaconPrintf(CALLBACK_ERROR, "No .NET process found!");
	}
	else {
		BeaconOutputStreamW();
	}
	
	
	
	return 0;
}

