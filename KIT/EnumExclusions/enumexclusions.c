#include <stdio.h>
#include <Windows.h>
#include <wbemidl.h>
#include "enumexclusions.h"
#include "beacon.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")


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



int EnumerateDefenderExclusions() {
    HRESULT hr;
	int result = 0;
    
    hr = OLE32$CoInitializeEx(0, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) goto Cleanup;
	
	IWbemLocator *pLoc = NULL;
	IID CLSIDWbemLocator = {0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
	IID IIDIWbemLocator = {0xdc12a687, 0x737f, 0x11cf, {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
    hr = OLE32$CoCreateInstance(&CLSIDWbemLocator, 0, CLSCTX_INPROC_SERVER, &IIDIWbemLocator, (LPVOID *)&pLoc);
    if (FAILED(hr)) goto Cleanup;
	
	IWbemServices *pSvc = NULL;
    hr = pLoc->lpVtbl->ConnectServer(pLoc, OLEAUT32$SysAllocString(L"ROOT\\Microsoft\\Windows\\Defender"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hr)) goto Cleanup;

    hr = OLE32$CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    IEnumWbemClassObject* pEnumerator = NULL;
	hr = pSvc->lpVtbl->ExecQuery(pSvc, OLEAUT32$SysAllocString(L"WQL"), OLEAUT32$SysAllocString(L"SELECT * FROM MSFT_MpPreference"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
	if (FAILED(hr)) goto Cleanup;

	internal_printf("\nExclusion enumeration results:\n====================================================\n");
	
	ULONG returnedCount = 0;
	IWbemClassObject *pResult = NULL;
	while (pEnumerator) {
		hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pResult, &returnedCount);
		if (0 == returnedCount) break;
		
		//folder and files
		VARIANT pathName;
		hr = pResult->lpVtbl->Get(pResult, L"ExclusionPath", 0, &pathName, 0, 0);
		if (SUCCEEDED(hr)) {
			if (pathName.vt == VT_NULL) {
				internal_printf("[-] No file or folder exclusion configured\n");
				result = 1; 
			} else if (pathName.vt == (VT_ARRAY | VT_BSTR)) {
				
				SAFEARRAY* sa = pathName.parray;
				BSTR* bstrArray;
				long lBound, uBound;

				OLEAUT32$SafeArrayGetLBound(sa, 1, &lBound);
				OLEAUT32$SafeArrayGetUBound(sa, 1, &uBound);
				OLEAUT32$SafeArrayAccessData(sa, (void**)&bstrArray);

				for (long i = lBound; i <= uBound; i++) {
					if (MSVCRT$wcscmp(bstrArray[i], L"N/A: Must be an administrator to view exclusions") == 0) {
						BeaconPrintf(CALLBACK_ERROR, "Access Denied! The current user does not have sufficient permissions to enumerate exclusions.\n");
						goto Cleanup;
					} else {
						internal_printf("[+] Found folder/file exclusion: %ls\n", bstrArray[i]);
						result = 1; 
					}
				}
				OLEAUT32$SafeArrayUnaccessData(sa);
			} else BeaconPrintf(CALLBACK_ERROR, "Error occurred! Couldn't properly parse path data with error code: %d\n", pathName.vt);

			OLEAUT32$VariantClear(&pathName);
		}
		
		//extention
		VARIANT extName;
		hr = pResult->lpVtbl->Get(pResult, L"ExclusionExtension", 0, &extName, 0, 0);
		if (SUCCEEDED(hr)) {
			if (extName.vt == VT_NULL) {
				internal_printf("[-] No extention exclusion configured\n");
				result = 1; 
			} else if (extName.vt == (VT_ARRAY | VT_BSTR)) {
				
				SAFEARRAY* sa = extName.parray;
				BSTR* bstrArray;
				long lBound, uBound;

				OLEAUT32$SafeArrayGetLBound(sa, 1, &lBound);
				OLEAUT32$SafeArrayGetUBound(sa, 1, &uBound);
				OLEAUT32$SafeArrayAccessData(sa, (void**)&bstrArray);

				for (long i = lBound; i <= uBound; i++) {
					internal_printf("[+] Found extention exclusion: %ls\n", bstrArray[i]);
					result = 1; 
				}
				OLEAUT32$SafeArrayUnaccessData(sa);
			} else BeaconPrintf(CALLBACK_ERROR, "Error occurred! Couldn't properly parse extention data with error code: %d\n", extName.vt);
			
			OLEAUT32$VariantClear(&extName);
		}
		
		//processes
		VARIANT procName;
		hr = pResult->lpVtbl->Get(pResult, L"ExclusionProcess", 0, &procName, 0, 0);
		if (SUCCEEDED(hr)) {
			if (procName.vt == VT_NULL) {
				internal_printf("[-] No process exclusion configured\n");
				result = 1; 
			} else if (procName.vt == (VT_ARRAY | VT_BSTR)) {
				
				SAFEARRAY* sa = procName.parray;
				BSTR* bstrArray;
				long lBound, uBound;

				OLEAUT32$SafeArrayGetLBound(sa, 1, &lBound);
				OLEAUT32$SafeArrayGetUBound(sa, 1, &uBound);
				OLEAUT32$SafeArrayAccessData(sa, (void**)&bstrArray);

				for (long i = lBound; i <= uBound; i++) {
					internal_printf("[+] Found process exclusion: %ls\n", bstrArray[i]);
					result = 1; 
				}
				OLEAUT32$SafeArrayUnaccessData(sa);
			} else BeaconPrintf(CALLBACK_ERROR, "Error occurred! Couldn't properly parse process data with error code: %d\n", procName.vt);
			
			OLEAUT32$VariantClear(&procName);
		}
	}
	
Cleanup:
    if (pSvc) pSvc->lpVtbl->Release(pSvc);
    if (pLoc) pLoc->lpVtbl->Release(pLoc);
    if (pEnumerator) pEnumerator->lpVtbl->Release(pEnumerator);
	if (pResult) pResult->lpVtbl->Release(pResult);
    OLE32$CoUninitialize();

	return result;
}


int go() {
	int result = 0; 
	
	if(!bofstart()) return;
	
	result = EnumerateDefenderExclusions();
	if(result) printoutput(TRUE);
	
	return 0;
}
