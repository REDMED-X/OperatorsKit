#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlwapi.h>
#include "findlib.h"
#include "beacon.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Shlwapi.lib")


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





WCHAR ConvertToWCHAR(char input) {
	WCHAR output[100];
	KERNEL32$MultiByteToWideChar(CP_ACP, 0, input, -1, output, 100);
	return output;
}




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
						WCHAR wFqModPath[100];
						KERNEL32$K32GetModuleFileNameExA(hProcess, (HMODULE) mbi.AllocationBase, (LPSTR) fqModPath, sizeof(fqModPath) / sizeof(TCHAR));
						KERNEL32$MultiByteToWideChar(CP_ACP, 0, fqModPath, -1, wFqModPath, 100);
						BeaconPrintToStreamW(L"\nModulePath:\t%s\nModuleAddr:\t%#llx\n", wFqModPath, mbi.AllocationBase);
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
					WCHAR wFqModPath[100];
					KERNEL32$MultiByteToWideChar(CP_ACP, 0, fqModPath, -1, wFqModPath, 100);
					
					BeaconPrintToStreamW(L"ModulePath [%#llx]: %s\n", mbi.AllocationBase, wFqModPath);
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
			
			WCHAR wProcName[100];
			WCHAR wProcPath[256];
			
			KERNEL32$K32GetProcessImageFileNameA(currentProc, procPath, MAX_PATH);
			
			KERNEL32$MultiByteToWideChar(CP_ACP, 0, SHLWAPI$PathFindFileNameA(procPath), -1, wProcName, 100);
			KERNEL32$MultiByteToWideChar(CP_ACP, 0, procPath, -1, wProcPath, 256);
			
			BeaconPrintToStreamW(L"ProcName:\t%s\nProcID:\t\t%d\nProcPath:\tC:\%s\n", wProcName, procID, wProcPath);
			
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
	
	
	if (MSVCRT$strcmp(option, "list") == 0) {
		pid = BeaconDataInt(&parser);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Start enumerating loaded modules for PID: %d\n\n", pid);
		BeaconPrintToStreamW(L"[+] FOUND MODULES:\n==============================================================\n"); 
		res = ListModules(pid, NULL);
	}
	else if (MSVCRT$strcmp(option, "search") == 0) {
		targetModName = BeaconDataExtract(&parser, NULL);
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Start enumerating processes that loaded module: %s\n[!] Can take some time..\n\n", targetModName);
		BeaconPrintToStreamW(L"[+] FOUND PROCESSES:\n==============================================================\n"); 
		res = FindProcess(targetModName);
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "This enumeration option isn't supported. Please specify one of the following enumeration options: search | list\n");
		return 0;
	}

	if(!res) BeaconPrintf(CALLBACK_ERROR, "No modules found for this search query!\n\n");
	else {
		BeaconOutputStreamW();
		BeaconPrintf(CALLBACK_OUTPUT, "\n[+] DONE");
	}
	return 0;
}



