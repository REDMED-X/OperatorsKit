#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <winternl.h>
#include "beacon.h"
#include "enumdotnet.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Shlwapi.lib")


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
	//WCHAR WCprocName[256];
	
	NtGetNextProcess_t pNtGetNextProcess = (NtGetNextProcess_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtGetNextProcess");
	NtOpenSection_t pNtOpenSection = (NtOpenSection_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenSection");
	if (pNtGetNextProcess == NULL || pNtOpenSection == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Error resolving native API calls!\n");
		return -1;		
	}
	
	WCHAR objPath[] = L"\\BaseNamedObjects\\Cor_Private_IPCBlock_v4_";
	sectionName.Buffer = (PWSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, 500);

	internal_printf("\nProcess name\t\t\t\t\t\tPID\n");
	internal_printf("=====================================================================\n");

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
			
			//KERNEL32$MultiByteToWideChar(CP_ACP, 0, procName, -1, WCprocName, 256);
			internal_printf("%-60s\t%d\n", procName, pid);
			
			dotNetFound = TRUE;
		}
	}
	
	return dotNetFound;
}


int go(void) {
	BOOL res = NULL;
	
	if(!bofstart()) return;
	
	res = FindDotNet();
	if(!res) {
		BeaconPrintf(CALLBACK_ERROR, "No .NET process found!");
	}
	else {
		printoutput(TRUE);
	}

	return 0;
}

