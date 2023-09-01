#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include "findlib.h"
#include "beacon.h"

#pragma comment(lib, "ntdll.lib")
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




BOOL ListModules(int pid, char *targetModName) {
    HANDLE hProcess;
    MEMORY_BASIC_INFORMATION mbi;
    char * base = NULL;
	BOOL foundModule = FALSE;

    hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL) return foundModule;

	while (KERNEL32$VirtualQueryEx(hProcess, base, &mbi, sizeof(mbi)) == sizeof(MEMORY_BASIC_INFORMATION)) {
		char fqModPath[MAX_PATH];
		char modName[MAX_PATH];

		if(targetModName != NULL) {
			// only focus on the base address regions
			if ((mbi.AllocationBase == mbi.BaseAddress) && (mbi.AllocationBase != NULL)) {
				if (KERNEL32$K32GetModuleBaseNameA(hProcess, (HMODULE) mbi.AllocationBase, (LPSTR) modName, sizeof(modName) / sizeof(TCHAR))) {
					if(MSVCRT$strcmp(targetModName, modName) == 0) {
						KERNEL32$K32GetModuleFileNameExA(hProcess, (HMODULE) mbi.AllocationBase, (LPSTR) fqModPath, sizeof(fqModPath) / sizeof(TCHAR));
						internal_printf("\nModulePath:\t%s\nModuleAddr:\t%#llx\n", fqModPath, mbi.AllocationBase);
						foundModule = TRUE;
					}
				}
			}
			// check the next region
			base += mbi.RegionSize;
		}
		else {
			
			// only focus on the base address regions
			if ((mbi.AllocationBase == mbi.BaseAddress) && (mbi.AllocationBase != NULL)) {
				if (KERNEL32$K32GetModuleFileNameExA(hProcess, (HMODULE) mbi.AllocationBase, (LPSTR) fqModPath, sizeof(fqModPath) / sizeof(TCHAR))) {
					internal_printf("ModulePath [%#llx]: %s\n", mbi.AllocationBase, fqModPath);
					foundModule = TRUE;
				}
			}
			// check the next region
			base += mbi.RegionSize;
		}
	}
	KERNEL32$CloseHandle(hProcess);
	return foundModule;
}


BOOL FindProcess(char *targetModName) {
	int procID = 0;
	HANDLE currentProc = NULL;
	char procPath[MAX_PATH];
	char procName[MAX_PATH];
	BOOL foundProc = FALSE;
	BOOL res = FALSE;
	
	// resolve function address
	NtGetNextProcess_t pNtGetNextProcess = (NtGetNextProcess_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtGetNextProcess");
	
	// loop through all processes
	while (!pNtGetNextProcess(currentProc, MAXIMUM_ALLOWED, 0, 0, &currentProc)) {
		procID = KERNEL32$GetProcessId(currentProc);
		
		if(procID == 4) continue;
		if (procID == KERNEL32$GetCurrentProcessId()) continue;
		if (procID != 0) foundProc = ListModules(procID, targetModName);
		if(foundProc) {
			KERNEL32$K32GetProcessImageFileNameA(currentProc, procPath, MAX_PATH);
			MSVCRT$strncpy(procName, SHLWAPI$PathFindFileNameA(procPath), MAX_PATH);
			internal_printf("ProcName:\t%s\nProcID:\t\t%d\nProcPath:\tC:\%s\n", procName, procID, procPath);
			res = TRUE;
		}
	}
	return res;
}


int go(char *args, int len) {
	int pid = 0;
	BOOL res = NULL;
	CHAR *option;
	CHAR *targetModName;
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	option = BeaconDataExtract(&parser, NULL);
	if(!bofstart()) return;
	
	if (MSVCRT$strcmp(option, "list") == 0) {
		pid = BeaconDataInt(&parser);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Start enumerating loaded modules for PID: %d\n\n", pid);
		internal_printf("[+] FOUND MODULES:\n==============================================================\n"); 
		res = ListModules(pid, NULL);
	}
	else if (MSVCRT$strcmp(option, "search") == 0) {
		targetModName = BeaconDataExtract(&parser, NULL);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Start enumerating processes that loaded module: %s\n[!] Can take some time..\n\n", targetModName);
		internal_printf("[+] FOUND PROCESSES:\n==============================================================\n"); 
		res = FindProcess(targetModName);
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "This enumeration option isn't supported. Please specify one of the following enumeration options: search | list\n");
		return 0;
	}

	if(!res) BeaconPrintf(CALLBACK_ERROR, "No modules found for this search query!\n\n");
	else {
		printoutput(TRUE);
	}
	return 0;
}



