#include <windows.h>
#include <stdio.h>
#include "findwebclient.h"
#include "beacon.h"


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


int go(char *args, int len) {
    char* pipeNameHead = "\\\\";
    char* pipeNameTail = "\\pipe\\DAV RPC SERVICE";
    BOOL pipeStatus = 0;
    char* hostname;
	char* nextHostname;
	char* debug;
    int iBytesLen = 0;
    CHAR *hostFileBytes;
    datap parser;

    BeaconDataParse(&parser, args, len);
    hostFileBytes = BeaconDataExtract(&parser, &iBytesLen);
	debug = BeaconDataExtract(&parser, NULL);
	if(!bofstart()) return;
	
    if(iBytesLen != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Loaded file in memory with a size of %d bytes\n", iBytesLen); 
		
		internal_printf("\nEnumeration results:\n");
		internal_printf("==============================================\n");
	
        hostname = MSVCRT$strtok(hostFileBytes, "\r\n");
        while (hostname != NULL) {
			nextHostname = MSVCRT$strtok(NULL, "\r\n");
            if (nextHostname == NULL) {
                break;
            }

            size_t len = MSVCRT$strlen(hostname);
            char* fullPipeName = (char*) MSVCRT$malloc(len + MSVCRT$strlen(pipeNameHead) + MSVCRT$strlen(pipeNameTail) + 1);
            MSVCRT$strcpy(fullPipeName, pipeNameHead);
            MSVCRT$strcat(fullPipeName, hostname);
            MSVCRT$strcat(fullPipeName, pipeNameTail);
		
            pipeStatus = KERNEL32$WaitNamedPipeA(fullPipeName, 3000);

			if (pipeStatus == 0 && (MSVCRT$strcmp(debug, "debug") == 0)) {
				internal_printf("[-] WebClient service not running on %s\n", hostname);
			} else if (pipeStatus == 0) {
            } else {
				internal_printf("[+] WebClient running on %s\n", hostname);
            }
            MSVCRT$free(fullPipeName);
            hostname = nextHostname;
        }
		printoutput(TRUE);

    } else {
        BeaconPrintf(CALLBACK_ERROR, "Couldn't load the host file from disk.\n");
    }
	
	
    return 0;
}

