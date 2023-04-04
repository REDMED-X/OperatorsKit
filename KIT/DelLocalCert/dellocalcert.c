#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include "dellocalcert.h"
#include "beacon.h"

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")


BOOL deleteCertificateFromRootStore(const char *thumbprint, wchar_t *store) {
    BOOL result = FALSE;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;

    // Open Local Computer store
    hStore = CRYPT32$CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, (HCRYPTPROV)NULL, CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG, store);
    if (!hStore) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to open specified certificate store.\n");
        goto cleanup;
    }

    // Find the certificate with the matching thumbprint
    while (pCertContext = CRYPT32$CertEnumCertificatesInStore(hStore, pCertContext)) {
        BYTE certThumbprint[20];
        DWORD certThumbprintSize = sizeof(certThumbprint);
        CHAR certThumbprintStr[41];

        // Get the "Thumbprint" property
        if (CRYPT32$CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, certThumbprint, &certThumbprintSize)) {
            for (DWORD i = 0; i < certThumbprintSize; ++i) {
                MSVCRT$sprintf(certThumbprintStr + (i * 2), "%02X", certThumbprint[i]);
            }
            certThumbprintStr[40] = '\0';

            // Check if the thumbprint matches
            if (MSVCRT$strcmp(certThumbprintStr, thumbprint) == 0) {
                break;
            }
        }
    }

    if (!pCertContext) {
        BeaconPrintf(CALLBACK_ERROR, "Certificate not found in the store based on the provided thumbprint.\n");
        goto cleanup;
    }
	
    // Delete the certificate from the store
    if (!CRYPT32$CertDeleteCertificateFromStore(pCertContext)) {
        DWORD dwError = KERNEL32$GetLastError();
        BeaconPrintf(CALLBACK_ERROR, "Failed to delete certificate from the store with error code: %x\n", dwError);
        goto cleanup;
    }
	
    result = TRUE;
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Certificate deleted successfully from store!\n");

cleanup:
    if (hStore) CRYPT32$CertCloseStore(hStore, 0);
    if (pCertContext) CRYPT32$CertFreeCertificateContext(pCertContext);
    return result;
}



int go(char *args, int len) {
    WCHAR *store = NULL; // Options: ROOT, MY, TRUST, CA, USERDS, AuthRoot, Disallowed
    CHAR *thumbprint = NULL; // must be all caps like 8D435430B9A409885ED90B3103F43EB85FCC0969
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	store = BeaconDataExtract(&parser, NULL);
	thumbprint = BeaconDataExtract(&parser, NULL);
	
	if(store != NULL) {
		if(thumbprint != NULL) {
			deleteCertificateFromRootStore(thumbprint, store);
		}
		else BeaconPrintf(CALLBACK_ERROR,"Please specify a thumbprint.\n");
	}
	else BeaconPrintf(CALLBACK_ERROR,"Please specify a store name.\n");
	
    return 0;
}

