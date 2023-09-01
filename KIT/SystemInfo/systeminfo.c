#include <stdio.h>
#include <wbemidl.h>
#include "systeminfo.h"
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


int go() {
	BOOL SomethingToPrint = 0;
    HRESULT hr = S_OK;
    IWbemLocator *pLoc = NULL;
    IWbemServices *pSvc = NULL;
    IEnumWbemClassObject* pEnumerator = NULL;
    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
	VARIANT vtProp;
	BSTR strNetworkResource = NULL;
	BSTR strQueryLanguage = NULL;
	BSTR strQuery = NULL;
	
	if(!bofstart()) return;

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) goto cleanup;

    hr = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) {
		if(hr == RPC_E_TOO_LATE) {
			BeaconPrintf(CALLBACK_ERROR, "COM error RPC_E_TOO_LATE (COM security settings already set for this process). Will attempt to do it with the current security settings..", hr);
		} else {
			BeaconPrintf(CALLBACK_ERROR, "CoInitializeSecurity failed with error: 0x%lx\n", hr);
			goto cleanup;
		}
	}

    IID CLSIDWbemLocator = {0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
	IID IIDIWbemLocator = {0xdc12a687, 0x737f, 0x11cf, {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
    hr = OLE32$CoCreateInstance(&CLSIDWbemLocator, NULL, CLSCTX_INPROC_SERVER, &IIDIWbemLocator, (void**)&pLoc);
    if (FAILED(hr)) goto cleanup;

    strNetworkResource = OLEAUT32$SysAllocString(L"ROOT\\CIMV2");
    hr = pLoc->lpVtbl->ConnectServer(pLoc, strNetworkResource, NULL, NULL, NULL, 0, NULL, NULL, &pSvc);
    if (FAILED(hr)) goto cleanup;

	//Win32_OperatingSystem
    strQueryLanguage = OLEAUT32$SysAllocString(L"WQL");
    strQuery = OLEAUT32$SysAllocString(L"SELECT * FROM Win32_OperatingSystem");
    hr = pSvc->lpVtbl->ExecQuery(pSvc, strQueryLanguage, strQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr)) goto cleanup;
	
	internal_printf("===================SYSTEM INFORMATION===================\n\n");

    while (pEnumerator) {
        hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
			if (hr == WBEM_E_ACCESS_DENIED) {
				BeaconPrintf(CALLBACK_ERROR, "COM error WBEM_E_ACCESS_DENIED. Current COM security permissions don't allow for this operation in the current process.", hr);
				goto cleanup;
			}
            break;
        }
		
        hr = pclsObj->lpVtbl->Get(pclsObj, L"Caption", 0, &vtProp, 0, 0);	
		internal_printf("%-20ls %ls\n", L"OS Name:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"Version", 0, &vtProp, 0, 0);	
		internal_printf("%-20ls %ls\n", L"OS Version:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"ProductType", 0, &vtProp, 0, 0);	
		switch(vtProp.uintVal) {
			case 1: internal_printf("%-20ls Standalone Workstation\n", L"OS Configuration:"); break;
			case 2: internal_printf("%-20ls Domain Controller\n", L"OS Configuration:"); break;
			case 3: internal_printf("%-20ls Server\n", L"OS Configuration:"); break;
			default: internal_printf("%-20ls Unknown\n", L"OS Configuration:");
		}
		OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"RegisteredUser", 0, &vtProp, 0, 0);	
		internal_printf("%-20ls %ls\n", L"Registered Owner:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"WindowsDirectory", 0, &vtProp, 0, 0);	
		internal_printf("%-20ls %ls\n", L"Windows Directory:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"LastBootUpTime", 0, &vtProp, 0, 0);	
		internal_printf("%-20ls %ls\n", L"System Boot Time:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"Locale", 0, &vtProp, 0, 0);	
		internal_printf("%-20ls %ls\n", L"System Locale:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		SomethingToPrint = 1;
		
        pclsObj->lpVtbl->Release(pclsObj);
    }
	
	//Win32_ComputerSystem
	OLEAUT32$SysFreeString(strQuery);
	strQuery = OLEAUT32$SysAllocString(L"SELECT * FROM Win32_ComputerSystem");
    hr = pSvc->lpVtbl->ExecQuery(pSvc, strQueryLanguage, strQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr)) goto cleanup;

    while (pEnumerator) {
        hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"Model", 0, &vtProp, 0, 0);	
		internal_printf("%-20ls %ls\n", L"System Model:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"SystemType", 0, &vtProp, 0, 0);	
		internal_printf("%-20ls %ls\n", L"System Type:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"Domain", 0, &vtProp, 0, 0);	
		internal_printf("%-20ls %ls\n", L"Domain:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);

        pclsObj->lpVtbl->Release(pclsObj);
    }
	
	//Win32_QuickFixEngineering
	OLEAUT32$SysFreeString(strQuery);
	strQuery = OLEAUT32$SysAllocString(L"SELECT * FROM Win32_QuickFixEngineering");
    hr = pSvc->lpVtbl->ExecQuery(pSvc, strQueryLanguage, strQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr)) goto cleanup;

	internal_printf("Hotfixes Installed:\n");
    while (pEnumerator) {
        hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"HotFixID", 0, &vtProp, 0, 0);	
		internal_printf("%-20ls %ls\n", L"", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
	
        pclsObj->lpVtbl->Release(pclsObj);
    }

cleanup:
    if (pEnumerator) pEnumerator->lpVtbl->Release(pEnumerator);
    if (pLoc) pLoc->lpVtbl->Release(pLoc);
    if (pSvc) pSvc->lpVtbl->Release(pSvc);
	if (strNetworkResource) OLEAUT32$SysFreeString(strNetworkResource);
    if (strQueryLanguage) OLEAUT32$SysFreeString(strQueryLanguage);
    if (strQuery) OLEAUT32$SysFreeString(strQuery);
    OLE32$CoUninitialize();
	
	
	if(SomethingToPrint) {
		printoutput(TRUE);
	} else BeaconPrintf(CALLBACK_ERROR, "Failed to load system information.\n");
	
    return 0;
}





		
		