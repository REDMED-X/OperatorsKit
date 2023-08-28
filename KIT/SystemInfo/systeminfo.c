#include <stdio.h>
#include <wbemidl.h>
#include "systeminfo.h"
#include "beacon.h"


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
		MSVCRT$memset(g_lpwPrintBuffer, 0, MAX_STRING * sizeof(WCHAR)); // Clear print buffer.
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
	
	BeaconPrintToStreamW(L"===================SYSTEM INFORMATION===================\n\n");

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
		BeaconPrintToStreamW(L"%-20s %s\n", L"OS Name:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"Version", 0, &vtProp, 0, 0);	
		BeaconPrintToStreamW(L"%-20s %s\n", L"OS Version:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"ProductType", 0, &vtProp, 0, 0);	
		switch(vtProp.uintVal) {
			case 1: BeaconPrintToStreamW(L"%-20s Standalone Workstation\n", L"OS Configuration:"); break;
			case 2: BeaconPrintToStreamW(L"%-20s Domain Controller\n", L"OS Configuration:"); break;
			case 3: BeaconPrintToStreamW(L"%-20s Server\n", L"OS Configuration:"); break;
			default: BeaconPrintToStreamW(L"%-20s Unknown\n", L"OS Configuration:");
		}
		OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"RegisteredUser", 0, &vtProp, 0, 0);	
		BeaconPrintToStreamW(L"%-20s %s\n", L"Registered Owner:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"WindowsDirectory", 0, &vtProp, 0, 0);	
		BeaconPrintToStreamW(L"%-20s %s\n", L"Windows Directory:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"LastBootUpTime", 0, &vtProp, 0, 0);	
		BeaconPrintToStreamW(L"%-20s %s\n", L"System Boot Time:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"Locale", 0, &vtProp, 0, 0);	
		BeaconPrintToStreamW(L"%-20s %s\n", L"System Locale:", vtProp.bstrVal);
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
		BeaconPrintToStreamW(L"%-20s %s\n", L"System Model:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"SystemType", 0, &vtProp, 0, 0);	
		BeaconPrintToStreamW(L"%-20s %s\n", L"System Type:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"Domain", 0, &vtProp, 0, 0);	
		BeaconPrintToStreamW(L"%-20s %s\n", L"Domain:", vtProp.bstrVal);
        OLEAUT32$VariantClear(&vtProp);

        pclsObj->lpVtbl->Release(pclsObj);
    }
	
	//Win32_QuickFixEngineering
	OLEAUT32$SysFreeString(strQuery);
	strQuery = OLEAUT32$SysAllocString(L"SELECT * FROM Win32_QuickFixEngineering");
    hr = pSvc->lpVtbl->ExecQuery(pSvc, strQueryLanguage, strQuery, WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
    if (FAILED(hr)) goto cleanup;

	BeaconPrintToStreamW(L"Hotfixes Installed:\n");
    while (pEnumerator) {
        hr = pEnumerator->lpVtbl->Next(pEnumerator, WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
		
		hr = pclsObj->lpVtbl->Get(pclsObj, L"HotFixID", 0, &vtProp, 0, 0);	
		BeaconPrintToStreamW(L"%-20s %s\n", "", vtProp.bstrVal);
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
		BeaconOutputStreamW();
	} else BeaconPrintf(CALLBACK_ERROR, "Failed to load system information.\n");
	
    return 0;
}





		
		