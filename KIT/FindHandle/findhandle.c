#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <Psapi.h>
#include "findhandle.h"
#include "beacon.h"

#pragma comment(lib, "shlwapi")


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



BOOL GetHandles(int basePid, const BYTE flags, int targetPid) {

	NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG handleInfoSize = 0x10000;
    HANDLE processHandle;
    ULONG i;
	char procHostName[MAX_PATH];
	BOOL foundHandle = FALSE;
	
	
	if (flags == QUERY_PROC) internal_printf("[+] PROCESS HANDLE RESULTS\n==========================================");
	else internal_printf("[+] THREAD HANDLE RESULTS\n==========================================");
	
	
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
			internal_printf("\nHandle from:\t%s [%d]\nHandle to:\t%s [%d]\nHandle object:\t%#x\nAccess rights:\t%#x\n", 
				procHostName,
				KERNEL32$GetProcessId(processHandle),
				procNameTemp,
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
	if(!bofstart()) return;

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
		printoutput(TRUE);
	}

    return 0;
}


