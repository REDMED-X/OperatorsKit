#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include "findfile.h"
#include "beacon.h"


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




bool keywordMatches(const char* content, const char* keyword) {
    size_t keywordLen = MSVCRT$strlen(keyword);
    
    // If keyword is "*example*"
    if (keyword[0] == '*' && keyword[keywordLen - 1] == '*') {
        char tempKeyword[MAX_PATH]; 
        MSVCRT$strncpy(tempKeyword, keyword + 1, keywordLen - 2);
        tempKeyword[keywordLen - 2] = '\0';
        if (MSVCRT$strstr(content, tempKeyword)) {
            return true;
        }
    }
    // If keyword is "example*"
    else if (keyword[keywordLen - 1] == '*') {
        char tempKeyword[MAX_PATH];
        MSVCRT$strncpy(tempKeyword, keyword, keywordLen - 1);
        tempKeyword[keywordLen - 1] = '\0';
        if (MSVCRT$strncmp(content, tempKeyword, keywordLen - 1) == 0) {
            return true;
        }
    }
    // If keyword is "*example"
    else if (keyword[0] == '*') {
        if (MSVCRT$strlen(content) >= keywordLen - 1 && 
            MSVCRT$strcmp(content + MSVCRT$strlen(content) - (keywordLen - 1), keyword + 1) == 0) {
            return true;
        }
    }
    // If keyword is "example"
    else if (MSVCRT$strstr(content, keyword)) {
        return true;
    }

    return false;
}



bool SearchFileForKeyword(const char* filePath, const char* keyword) {
    FILE *file = MSVCRT$fopen(filePath, "rb");  
    if (!file) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open file: %s\n", filePath);
        return false;
    }

    MSVCRT$fseek(file, 0, SEEK_END);
    long fileSize = MSVCRT$ftell(file);
    MSVCRT$fseek(file, 0, SEEK_SET);

    char* fileContents = (char*)MSVCRT$malloc(fileSize + 1); 
    if(!fileContents) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to allocate memory for file: %s\n", filePath);
        MSVCRT$fclose(file);
        return false;
    }
    
    MSVCRT$fread(fileContents, 1, fileSize, file);
    fileContents[fileSize] = '\0';  
    MSVCRT$fclose(file);

    // Convert file contents to lowercase
    for (long i = 0; i < fileSize; i++) {
        fileContents[i] = MSVCRT$tolower(fileContents[i]);
    }

    // Convert keyword to lowercase
    char* lowerKeyword = MSVCRT$_strdup(keyword);
    if (!lowerKeyword) {
        MSVCRT$free(fileContents);
        return false;
    }
    for (int i = 0; lowerKeyword[i]; i++) {
        lowerKeyword[i] = MSVCRT$tolower(lowerKeyword[i]);
    }
	
	//match line with keyword and return pattern if true
    wchar_t wideFullPath[MAX_PATH];
    wchar_t wideKeyword[MAX_PATH]; 
    wchar_t wideLine[MAX_PATH];  
	
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, filePath, -1, wideFullPath, MAX_PATH);
    KERNEL32$MultiByteToWideChar(CP_ACP, 0, keyword, -1, wideKeyword, MAX_PATH);
	
    char* line = MSVCRT$strtok(fileContents, "\n");
    bool found = false;
    bool firstPrint = true;
    while (line) {
        if (keywordMatches(line, lowerKeyword)) {
            found = true;
            KERNEL32$MultiByteToWideChar(CP_ACP, 0, line, -1, wideLine, MAX_PATH);
            
            if (firstPrint) {
                BeaconPrintToStreamW(L"\n[+] Keyword '%ls' found in file: %ls\n", wideKeyword, wideFullPath);
                firstPrint = false;
            }
            BeaconPrintToStreamW(L"\t- Matched on pattern: %ls\n", wideLine);
            // break; //stop after first match
        }
        line = MSVCRT$strtok(NULL, "\n");
    }

    MSVCRT$free(fileContents);
    MSVCRT$free(lowerKeyword);
	
    return found;
}


void SearchFilesRecursive(const char* lpFolder, const char* lpSearchPattern, const char* keyword) {
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    char szDir[MAX_PATH];
    DWORD dwError;

    // Build search path for files in the current directory
    MSVCRT$strcpy(szDir, lpFolder);
    MSVCRT$strcat(szDir, "\\");
    MSVCRT$strcat(szDir, lpSearchPattern);
	
	// Search for files
    hFind = KERNEL32$FindFirstFileA(szDir, &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
			if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				char fullPath[MAX_PATH];
				MSVCRT$sprintf(fullPath, "%s\\%s", lpFolder, findFileData.cFileName);
				
				wchar_t wideFullPath[MAX_PATH];
				KERNEL32$MultiByteToWideChar(CP_ACP, 0, fullPath, -1, wideFullPath, MAX_PATH);
				
				if (*keyword) { 
				    SearchFileForKeyword(fullPath, keyword); 
				} else if (!*keyword) {
					BeaconPrintToStreamW(L"[+] File found: %ls\n", wideFullPath);
				}
			}
		} while (KERNEL32$FindNextFileA(hFind, &findFileData) != 0);
		
		dwError = KERNEL32$GetLastError();
		if (dwError != ERROR_NO_MORE_FILES) {
			BeaconPrintf(CALLBACK_ERROR, "Error searching for next file: %d\n", dwError);
		}
		KERNEL32$FindClose(hFind);
	}
	
	//search for subdirectories and recurse into them
    MSVCRT$strcpy(szDir, lpFolder);
    MSVCRT$strcat(szDir, "\\*");

    hFind = KERNEL32$FindFirstFileA(szDir, &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                MSVCRT$strcmp(findFileData.cFileName, ".") != 0 && 
                MSVCRT$strcmp(findFileData.cFileName, "..") != 0) {
				
				// Build path for the subdirectory
                char subDir[MAX_PATH];
                MSVCRT$strcpy(subDir, lpFolder);
                MSVCRT$strcat(subDir, "\\");
                MSVCRT$strcat(subDir, findFileData.cFileName);

                SearchFilesRecursive(subDir, lpSearchPattern, keyword);
            }
        } while (KERNEL32$FindNextFileA(hFind, &findFileData) != 0);
		
        dwError = KERNEL32$GetLastError();
        if (dwError != ERROR_NO_MORE_FILES) {
            BeaconPrintf(CALLBACK_ERROR, "Error searching for next file: %d\n", dwError);
        }
		KERNEL32$FindClose(hFind);
    }
}


int go(char *args, int len) {
	datap parser;
    CHAR *lpDirectory = "";
    CHAR *lpSearchPattern = "";
    CHAR *keyword = ""; // If not empty, SearchFileForKeyword is called to verify if the keyword is in the text file

	BeaconDataParse(&parser, args, len);
	lpDirectory = BeaconDataExtract(&parser, NULL);
	lpSearchPattern = BeaconDataExtract(&parser, NULL);
	keyword = BeaconDataExtract(&parser, NULL);
	
	BeaconPrintToStreamW(L"==========FILE SEARCH RESULTS==========\n");
	
    SearchFilesRecursive(lpDirectory, lpSearchPattern, keyword);
	
	BeaconOutputStreamW();
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Finished searching!\n");

    return 0;
}


		
		