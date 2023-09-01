#include <windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <winternl.h>
#include "beacon.h"
#include "findrwx.h"


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
	
	internal_printf("\nMemory address\t\t\tByte size\n");
	internal_printf("================================================\n");
	
	while (KERNEL32$VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
		addr = (LPVOID)((DWORD_PTR) mbi.BaseAddress + mbi.RegionSize);

		if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
			internal_printf("%#-30llx\t%#7llu\n", mbi.BaseAddress, mbi.RegionSize);
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
	if(!bofstart()) return;
	
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
		printoutput(TRUE);
	}

	KERNEL32$CloseHandle(hProcess);
	return 0;
}


