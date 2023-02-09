#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <Psapi.h>
#include "findhandle.h"
#include "beacon.h"

#pragma comment(lib, "shlwapi")


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




BOOL GetHandles(int basePid, const BYTE flags, int targetPid) {

	NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    HANDLE processHandle;
    ULONG i;
	char procHostName[MAX_PATH];
	BOOL foundHandle = FALSE;
	
	
	if (flags == QUERY_PROC) BeaconPrintToStreamW(L"[+] PROCESS HANDLE RESULTS\n==========================================");
	else BeaconPrintToStreamW(L"[+] THREAD HANDLE RESULTS\n==========================================");
	
	
    NtQuerySystemInformation_t pNtQuerySystemInformation = (NtQuerySystemInformation_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
    NtDuplicateObject_t pNtDuplicateObject = (NtDuplicateObject_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtDuplicateObject");
    NtQueryObject_t pNtQueryObject = (NtQueryObject_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryObject");

	WCHAR Filter[100];
	switch(flags) {
		case QUERY_PROC:	MSVCRT$swprintf_s(Filter, 50, L"%s", L"Process"); break;
		default:			MSVCRT$swprintf_s(Filter, 50, L"%s", L"Thread"); break;
	}

    handleInfo = (PSYSTEM_HANDLE_INFORMATION) MSVCRT$malloc(handleInfoSize);
    while ((status = pNtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
			handleInfo = (PSYSTEM_HANDLE_INFORMATION)MSVCRT$realloc(handleInfo, handleInfoSize *= 2);
 
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve process information!\n");
        return 1;
    }
	
    for (i = 0 ; i < handleInfo->NumberOfHandles ; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO objHandle = handleInfo->Handles[i];
		
        HANDLE dupHandle = NULL;
        POBJECT_TYPE_INFORMATION objectTypeInfo;
        PVOID objectNameInfo;
        UNICODE_STRING objectName;
        ULONG returnLength;
		
		if(objHandle.UniqueProcessId == 4) continue;
		
        if ((basePid != 0) && (objHandle.UniqueProcessId != basePid)) continue;
		
		if (objHandle.UniqueProcessId == KERNEL32$GetCurrentProcessId()) continue;
 
 
		if (!(processHandle = KERNEL32$OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, objHandle.UniqueProcessId))) {
			continue;
		}
 
		KERNEL32$K32GetProcessImageFileNameA(processHandle, procHostName, MAX_PATH);
		
        if (!NT_SUCCESS(pNtDuplicateObject(processHandle, (void *) objHandle.HandleValue, KERNEL32$GetCurrentProcess(), &dupHandle, 0, 0, DUPLICATE_SAME_ACCESS))) {
            continue;
        }
 
        objectTypeInfo = (POBJECT_TYPE_INFORMATION) MSVCRT$malloc(0x1000);
        if (!NT_SUCCESS(pNtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL))) {
            KERNEL32$CloseHandle(dupHandle);
            continue;
        }
	
		if (!SHLWAPI$StrStrIW(Filter, objectTypeInfo->Name.Buffer)) {
			MSVCRT$free(objectTypeInfo);
            KERNEL32$CloseHandle(dupHandle);
			continue;
		}
		
        objectNameInfo = MSVCRT$malloc(0x1000);
        objectName = *(PUNICODE_STRING) objectNameInfo;
		
		int procID = 0;
		if (flags == QUERY_PROC) procID = KERNEL32$GetProcessId(dupHandle);
		if (flags == QUERY_THREAD) procID = KERNEL32$GetProcessIdOfThread(dupHandle);

		char procNameTemp[MAX_PATH];
		if (procID != 0) {
			if (flags == QUERY_THREAD) {
				HANDLE pH = KERNEL32$OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, procID);
				if (pH) KERNEL32$K32GetProcessImageFileNameA(pH, procNameTemp, MAX_PATH);
				else MSVCRT$sprintf_s(procNameTemp, MAX_PATH, "%s", "non existent?");
				KERNEL32$CloseHandle(pH);
			}
			else {
				KERNEL32$K32GetProcessImageFileNameA(dupHandle, procNameTemp, MAX_PATH);
			}
		}
		
		if (targetPid != 0 && targetPid != procID) {
			MSVCRT$free(objectTypeInfo);
			MSVCRT$free(objectNameInfo);
			KERNEL32$CloseHandle(dupHandle);
			continue;
		}
		
		if(procID != 0 && objHandle.UniqueProcessId != procID) {
			WCHAR WprocHostName[100];
			WCHAR WprocNameTemp[100];
			KERNEL32$MultiByteToWideChar(CP_ACP, 0, SHLWAPI$PathFindFileNameA(procHostName), -1, WprocHostName, 100);
			KERNEL32$MultiByteToWideChar(CP_ACP, 0, SHLWAPI$PathFindFileNameA(procNameTemp), -1, WprocNameTemp, 100);
				
			BeaconPrintToStreamW(L"\nHandle from:\t%s [%d]\nHandle to:\t%s [%d]\nHandle object:\t%#x\nAccess rights:\t%#x\n", 
				WprocHostName,
				KERNEL32$GetProcessId(processHandle),
				WprocNameTemp,
				procID,
				objHandle.HandleValue,
				objHandle.GrantedAccess); //https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
			
			foundHandle = TRUE;
		}

        MSVCRT$free(objectTypeInfo);
        MSVCRT$free(objectNameInfo);
        KERNEL32$CloseHandle(dupHandle);
    }
 
    MSVCRT$free(handleInfo);
    KERNEL32$CloseHandle(processHandle);
	
	return foundHandle;
}


int go(char *args, int len) {
	int basePid = 0;
	int targetPid = 0;
	BYTE flags;
	CHAR *search;
	CHAR *query;
	BOOL res = NULL;
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	search = BeaconDataExtract(&parser, NULL);
	query = BeaconDataExtract(&parser, NULL);

	if (MSVCRT$strcmp(query, "proc") == 0) flags = QUERY_PROC;
	else if (MSVCRT$strcmp(query, "thread") == 0) flags = QUERY_THREAD;
	else {
		BeaconPrintf(CALLBACK_ERROR, "Please specify either proc (PROCESS_HANDLE) or 2 (THREAD_HANDLE) as handle search options.\n");
		return 0;
	}
	
	
	if (MSVCRT$strcmp(search, "all") == 0) {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Start enumerating all processes with handles to all other processes\n");
		res = GetHandles(0, flags, 0);
	}
	else if (MSVCRT$strcmp(search, "h2p") == 0) {
		targetPid = BeaconDataInt(&parser);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Start enumerating all processes that have a handle to PID: [%d]\n", targetPid);
		res = GetHandles(0, flags, targetPid);
	}
	else if (MSVCRT$strcmp(search, "p2h") == 0) {
		basePid = BeaconDataInt(&parser);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Start enumerating handles from PID [%d] to all other processes\n", basePid);
		res = GetHandles(basePid, flags, 0);
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "Please specify one of the following process search options: ht | h2p | p2h\n");
		return 0;
	}
	
	if(!res) BeaconPrintf(CALLBACK_ERROR, "No handle found for this search query!\n");
	else  {
		BeaconOutputStreamW();
		BeaconPrintf(CALLBACK_OUTPUT, "\n[+] DONE");
	}

    return 0;
}


