#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "enumlocalcert.h"
#include "beacon.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")


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


void replace_wchar(LPWSTR str, wchar_t old_char, wchar_t new_char) {
    for (size_t i = 0; str[i] != L'\0'; i++) {
        if (str[i] == old_char) {
            str[i] = new_char;
        }
    }
}



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

    BeaconPrintToStreamW(L"\nIssued By: %s\n", pszName);
    KERNEL32$LocalFree(pszName);
	
	// Get the "Thumbprint" property
	if (CRYPT32$CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, thumbprint, &thumbprintSize)) {
		for (DWORD i = 0; i < thumbprintSize; ++i) {
			MSVCRT$_snwprintf_s(thumbprintStr + (i * 2), 3, 2, L"%02X", thumbprint[i]);
		}
		thumbprintStr[40] = L'\0';
		BeaconPrintToStreamW(L"Thumbprint: %s\n", thumbprintStr);
	}
	else {
		BeaconPrintToStreamW(L"Failed to get thumbprint.\n");
	}

	// Get the "Friendly Name" property
	dwSize = 0;
	dwSize = CRYPT32$CertGetNameStringW(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, NULL, 0);
	if (dwSize == 1) { 
		BeaconPrintToStreamW(L"Friendly Name: none\n");
	}
	else
	{
		pszName = (LPWSTR)KERNEL32$LocalAlloc(LPTR, dwSize * sizeof(wchar_t));
		if (!pszName) return FALSE;
		if (!CRYPT32$CertGetNameStringW(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, pszName, dwSize)) return FALSE;

		replace_wchar(pszName, L'\x2013', L'-');
		BeaconPrintToStreamW(L"Friendly Name: %ls\n", pszName);
		
		KERNEL32$LocalFree(pszName);
	}
	

	// Get the "Expiration Date" property
	SYSTEMTIME stExpirationDate;
	KERNEL32$FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &stExpirationDate);

	WCHAR szExpirationDate[256];
	KERNEL32$GetDateFormatW(LOCALE_USER_DEFAULT, 0, &stExpirationDate, L"yyyy-MM-dd", szExpirationDate, sizeof(szExpirationDate) / sizeof(WCHAR));
	BeaconPrintToStreamW(L"Expiration Date: %s\n", szExpirationDate);

	
	// Get the "Intended Purposes" property
	PCERT_ENHKEY_USAGE pUsage = NULL;
	DWORD dwUsageSize = 0;
	if (!CRYPT32$CertGetEnhancedKeyUsage(pCertContext, 0, NULL, &dwUsageSize)) return FALSE;

	pUsage = (PCERT_ENHKEY_USAGE)KERNEL32$LocalAlloc(LPTR, dwUsageSize);
	if (!pUsage) return FALSE;

	if (!CRYPT32$CertGetEnhancedKeyUsage(pCertContext, 0, pUsage, &dwUsageSize)) return FALSE;

	BeaconPrintToStreamW(L"Intended Purposes:\n");
	for (DWORD i = 0; i < pUsage->cUsageIdentifier; ++i)
	{
		LPCSTR pszOID = pUsage->rgpszUsageIdentifier[i];
		PCCRYPT_OID_INFO pInfo = CRYPT32$CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, (void*)pszOID, 0);
		if (pInfo)
		{
			BeaconPrintToStreamW(L"  - %s (%S)\n", pInfo->pwszName, pszOID);
		}
		else
		{
			BeaconPrintToStreamW(L"  - Unknown OID: %S\n", pszOID);
		}
	}
	KERNEL32$LocalFree(pUsage);
	
	
	BeaconPrintToStreamW(L"\n");
	return TRUE;
}



int go(char *args, int len) {
	BOOL res = NULL;
	WCHAR *store; // Options: ROOT, MY, TRUST, CA, USERDS, AuthRoot, Disallowed
	HCERTSTORE hStore = NULL;
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	store = BeaconDataExtract(&parser, NULL);
	
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
		BeaconOutputStreamW();
		BeaconPrintf(CALLBACK_OUTPUT, "[+] DONE");
	}
	
	if (pCertContext) CRYPT32$CertFreeCertificateContext(pCertContext);
	if (hStore) CRYPT32$CertCloseStore(hStore, 0);

	return 0;
}
	
	
	
	
