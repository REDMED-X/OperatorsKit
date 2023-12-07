#include <stdio.h>
#include <Windows.h>
#include <wbemidl.h>
#include "delexclusion.h"
#include "beacon.h"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

typedef enum {
    EXCLUSION_TYPE_PATH,
    EXCLUSION_TYPE_PROCESS,
    EXCLUSION_TYPE_EXTENSION
} EXCLUSION_TYPE;

INT RemoveDefenderExclusion(const WCHAR* exclData, EXCLUSION_TYPE type) {
    HRESULT hr;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    IWbemClassObject* pClass = NULL;
    IWbemClassObject* pInSignature = NULL;
    IWbemClassObject* pClassInstance = NULL;
    SAFEARRAY* psaStrings = NULL;
    BSTR Clname = NULL;
    BSTR MethodName = NULL;
	int result = 0;

    hr = OLE32$CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr)) goto Cleanup;

    hr = OLE32$CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hr)) goto Cleanup;

	IID CLSIDWbemLocator = {0x4590f811, 0x1d3a, 0x11d0, {0x89, 0x1f, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
    IID IIDIWbemLocator = {0xdc12a687, 0x737f, 0x11cf, {0x88, 0x4d, 0x00, 0xaa, 0x00, 0x4b, 0x2e, 0x24}};
    hr = OLE32$CoCreateInstance(&CLSIDWbemLocator, 0, CLSCTX_INPROC_SERVER, &IIDIWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) goto Cleanup;

    Clname = OLEAUT32$SysAllocString(L"ROOT\\Microsoft\\Windows\\Defender");
    hr = pLoc->lpVtbl->ConnectServer(pLoc, Clname, NULL, NULL, 0, NULL, 0, 0, &pSvc);
    OLEAUT32$SysFreeString(Clname);
    if (FAILED(hr)) goto Cleanup;
	
    hr = OLE32$CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hr)) goto Cleanup;

    Clname = OLEAUT32$SysAllocString(L"MSFT_MpPreference");
    MethodName = OLEAUT32$SysAllocString(L"Remove");
    hr = pSvc->lpVtbl->GetObject(pSvc, Clname, 0, NULL, &pClass, NULL);
    hr = pClass->lpVtbl->GetMethod(pClass, MethodName, 0, &pInSignature, NULL);

    OLEAUT32$SysFreeString(MethodName);
    if (FAILED(hr)) goto Cleanup;

    hr = pInSignature->lpVtbl->SpawnInstance(pInSignature, 0, &pClassInstance);
    if (FAILED(hr)) goto Cleanup;

    SAFEARRAYBOUND rgsaBounds[1];
    rgsaBounds[0].cElements = 1;
    rgsaBounds[0].lLbound = 0;
    psaStrings = OLEAUT32$SafeArrayCreate(VT_BSTR, 1, rgsaBounds);

    VARIANT vString;
    OLEAUT32$VariantInit(&vString);
    V_VT(&vString) = VT_BSTR;
    V_BSTR(&vString) = OLEAUT32$SysAllocString(exclData);
    LONG lArrayIndex = 0;
    OLEAUT32$SafeArrayPutElement(psaStrings, &lArrayIndex, V_BSTR(&vString));
    OLEAUT32$SysFreeString(V_BSTR(&vString));

    VARIANT vStringList;
    OLEAUT32$VariantInit(&vStringList);
    V_VT(&vStringList) = VT_ARRAY | VT_BSTR;
    V_ARRAY(&vStringList) = psaStrings;

    WCHAR* propertyName;
    switch (type) {
        case EXCLUSION_TYPE_PATH:
            propertyName = L"ExclusionPath";
            break;
        case EXCLUSION_TYPE_PROCESS:
            propertyName = L"ExclusionProcess";
            break;
        case EXCLUSION_TYPE_EXTENSION:
            propertyName = L"ExclusionExtension";
            break;
        default:
            hr = E_INVALIDARG;
            goto Cleanup;
    }

    hr = pClassInstance->lpVtbl->Put(pClassInstance, propertyName, 0, &vStringList, CIM_STRING|CIM_FLAG_ARRAY);
    if (FAILED(hr)) goto Cleanup;

	hr = pSvc->lpVtbl->ExecMethod(pSvc, Clname, MethodName, 0, NULL, pClassInstance, NULL, NULL);
	if (FAILED(hr)) {
		if (hr == 0x8004102e) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to remove the exclusion (WBEM_E_NOT_FOUND). The specified data/name was not recognized or doens't exist.\n");
		} else if (hr == 0x80041001) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to remove the exclusion (WBEM_E_FAILED). Do you have sufficient permissions?\n");
		} else {
			BeaconPrintf(CALLBACK_ERROR, "Failed to remove the exclusion with error code: 0x%08lx\n", hr);
		}
		result = 2;
		goto Cleanup;
	}
	
	result = 1;

Cleanup:
	if (psaStrings) OLEAUT32$SafeArrayDestroy(psaStrings);
	if (Clname) OLEAUT32$SysFreeString(Clname);
	if (pLoc) pLoc->lpVtbl->Release(pLoc);
	if (pSvc) pSvc->lpVtbl->Release(pSvc);
	if (pClass) pClass->lpVtbl->Release(pClass);
	if (pInSignature) pInSignature->lpVtbl->Release(pInSignature);
	if (pClassInstance) pClassInstance->lpVtbl->Release(pClassInstance);
	OLE32$CoUninitialize();

	return result;
}


int go(char *args, int len) {
    int result = 0; 
    CHAR* exclType = ""; //path | process | extension
    WCHAR* exclData = L""; 
    datap parser;
    
    BeaconDataParse(&parser, args, len);
    exclType = BeaconDataExtract(&parser, NULL);
    exclData = BeaconDataExtract(&parser, NULL);

    if(MSVCRT$strcmp(exclType, "path") == 0) result = RemoveDefenderExclusion(exclData, EXCLUSION_TYPE_PATH);
    else if(MSVCRT$strcmp(exclType, "process") == 0) result = RemoveDefenderExclusion(exclData, EXCLUSION_TYPE_PROCESS);
    else if(MSVCRT$strcmp(exclType, "extension") == 0) result = RemoveDefenderExclusion(exclData, EXCLUSION_TYPE_EXTENSION);
    else {
        BeaconPrintf(CALLBACK_ERROR, "Please specify one of the following exclusion types: path (folder/file), process, extension.\n");
        return 0;
    }
    
    if(result == 1) BeaconPrintf(CALLBACK_OUTPUT, "[+] The following exclusion was successfully removed: %ls\n", exclData); 
    else if (result == 2); //output handeling specified in RemoveDefenderExclusion
    else BeaconPrintf(CALLBACK_ERROR, "Failed to remove exclusion. COM error occurred!\n"); 

    return 0;
}
