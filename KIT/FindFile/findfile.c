#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include "findfile.h"
#include "beacon.h"

#define MAX_PREVIEW_LENGTH 200

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
	char* line = MSVCRT$strtok(fileContents, "\n");
	bool found = false;
	bool firstPrint = true;
	char preview[MAX_PREVIEW_LENGTH + 1]; 

	while (line) {
		if (keywordMatches(line, lowerKeyword)) {
			found = true;
			int lineLength = MSVCRT$strlen(line);
	
			if (lineLength > MAX_PREVIEW_LENGTH) {
				MSVCRT$strncpy(preview, line, MAX_PREVIEW_LENGTH);
				preview[MAX_PREVIEW_LENGTH] = '\0'; 
			} else {
				MSVCRT$strcpy(preview, line);
			}
			if (firstPrint) {
				internal_printf("\n[+] Keyword '%s' found in file: %s\n", keyword, filePath);
				firstPrint = false;
			}
			internal_printf("\t- Matched on pattern: %s\n", preview);
			// break; // Uncomment to stop after the first match
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
				
				if (*keyword) { 
				    SearchFileForKeyword(fullPath, keyword); 
				} else if (!*keyword) {
					internal_printf("[+] File found: %s\n", fullPath);
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
	if(!bofstart()) return;
	
	internal_printf("====================FILE SEARCH RESULTS====================\n");
	
    SearchFilesRecursive(lpDirectory, lpSearchPattern, keyword);
	
	printoutput(TRUE);
	BeaconPrintf(CALLBACK_OUTPUT, "[+] Finished searching!\n");

    return 0;
}


		
		