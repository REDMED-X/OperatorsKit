#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "enumlocalcert.h"
#include "beacon.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")



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



BOOL printCertProperties(PCCERT_CONTEXT pCertContext) {
    LPWSTR pszName = NULL;
    DWORD dwSize;
	BYTE thumbprint[20];
	DWORD thumbprintSize = sizeof(thumbprint);
	WCHAR thumbprintStr[41];

    // Get the "Issued By" property
    if (!CRYPT32$CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0)) return FALSE;

    dwSize = CRYPT32$CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
    pszName = (LPWSTR)KERNEL32$LocalAlloc(LPTR, dwSize * sizeof(wchar_t));
    if (!pszName) return FALSE;

    if (!CRYPT32$CertGetNameStringW(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszName, dwSize)) return FALSE;

    internal_printf("\nIssued By: %ls\n", pszName);
    KERNEL32$LocalFree(pszName);
	
	// Get the "Thumbprint" property
	if (CRYPT32$CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, thumbprint, &thumbprintSize)) {
		for (DWORD i = 0; i < thumbprintSize; ++i) {
			MSVCRT$_snwprintf_s(thumbprintStr + (i * 2), 3, 2, L"%02X", thumbprint[i]);
		}
		thumbprintStr[40] = L'\0';
		internal_printf("Thumbprint: %ls\n", thumbprintStr);
	}
	else {
		internal_printf("Failed to get thumbprint.\n");
	}

	// Get the "Friendly Name" property
	dwSize = 0;
	dwSize = CRYPT32$CertGetNameStringW(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, NULL, 0);
	if (dwSize == 1) { 
		internal_printf("Friendly Name: none\n");
	}
	else
	{
		pszName = (LPWSTR)KERNEL32$LocalAlloc(LPTR, dwSize * sizeof(wchar_t));
		if (!pszName) return FALSE;
		if (!CRYPT32$CertGetNameStringW(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, pszName, dwSize)) return FALSE;

		internal_printf("Friendly Name: %ls\n", pszName);
		KERNEL32$LocalFree(pszName);
	}
	

	// Get the "Expiration Date" property
	SYSTEMTIME stExpirationDate;
	KERNEL32$FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &stExpirationDate);

	WCHAR szExpirationDate[256];
	KERNEL32$GetDateFormatW(LOCALE_USER_DEFAULT, 0, &stExpirationDate, L"yyyy-MM-dd", szExpirationDate, sizeof(szExpirationDate) / sizeof(WCHAR));
	internal_printf("Expiration Date: %ls\n", szExpirationDate);

	
	// Get the "Intended Purposes" property
	PCERT_ENHKEY_USAGE pUsage = NULL;
	DWORD dwUsageSize = 0;
	if (!CRYPT32$CertGetEnhancedKeyUsage(pCertContext, 0, NULL, &dwUsageSize)) return FALSE;

	pUsage = (PCERT_ENHKEY_USAGE)KERNEL32$LocalAlloc(LPTR, dwUsageSize);
	if (!pUsage) return FALSE;

	if (!CRYPT32$CertGetEnhancedKeyUsage(pCertContext, 0, pUsage, &dwUsageSize)) return FALSE;

	internal_printf("Intended Purposes:\n");
	for (DWORD i = 0; i < pUsage->cUsageIdentifier; ++i)
	{
		LPCSTR pszOID = pUsage->rgpszUsageIdentifier[i];
		PCCRYPT_OID_INFO pInfo = CRYPT32$CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (void*)pszOID, 0);
		if (pInfo)
		{
			internal_printf("  - %ls (%s)\n", pInfo->pwszName, pszOID);
		}
		else
		{
			internal_printf("  - Unknown OID: %s\n", pszOID);
		}
	}
	KERNEL32$LocalFree(pUsage);
	
	
	internal_printf("\n");
	return TRUE;
}



int go(char *args, int len) {
	BOOL res = NULL;
	WCHAR *store; // Options: ROOT, MY, TRUST, CA, USERDS, AuthRoot, Disallowed
	HCERTSTORE hStore = NULL;
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	store = BeaconDataExtract(&parser, NULL);
	if(!bofstart()) return;
	
	// Open Local Computer store
	hStore = CRYPT32$CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, (HCRYPTPROV)NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, store); 
	if (!hStore) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to open specified certificate store\n");
		return 1;
	}


	PCCERT_CONTEXT pCertContext = NULL;
	while (pCertContext = CRYPT32$CertEnumCertificatesInStore(hStore, pCertContext)) {
			res = printCertProperties(pCertContext);
		}
	
	if(!res) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to list certificates in specified store.\n");
		return 0;
	}
	else  {
		printoutput(TRUE);
	}
	
	if (pCertContext) CRYPT32$CertFreeCertificateContext(pCertContext);
	if (hStore) CRYPT32$CertCloseStore(hStore, 0);

	return 0;
}
	
	
	
	
