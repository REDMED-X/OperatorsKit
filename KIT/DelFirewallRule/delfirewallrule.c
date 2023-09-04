#include <stdio.h>
#include <Windows.h>
#include <netfw.h>
#include "delfirewallrule.h"
#include "beacon.h"

#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")


HRESULT RemoveFirewallRule(BSTR ruleName) {
    HRESULT hr = S_OK;

    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pRules = NULL;

    // Initialize COM.
    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) goto Cleanup;

    // Create an instance of the firewall settings manager.
    IID CLSIDNetFwPolicy2 = {0xe2b3c97f, 0x6ae1, 0x41ac, {0x81, 0x7a, 0xf6, 0xf9, 0x21, 0x66, 0xd7, 0xdd}};
    IID IIDINetFwPolicy2 = {0x98325047, 0xc671, 0x4174, {0x8d, 0x81, 0xde, 0xfc, 0xd3, 0xf0, 0x31, 0x86}};
    hr = OLE32$CoCreateInstance(&CLSIDNetFwPolicy2, NULL, CLSCTX_INPROC_SERVER, &IIDINetFwPolicy2, (void**)&pNetFwPolicy2);
    if (FAILED(hr)) goto Cleanup;

    // Retrieve the firewall rules collection.
    hr = pNetFwPolicy2->lpVtbl->get_Rules(pNetFwPolicy2, &pRules);
    if (FAILED(hr)) goto Cleanup;

    // Remove the rule.
    hr = pRules->lpVtbl->Remove(pRules, ruleName);
    if (FAILED(hr)) goto Cleanup;

Cleanup:
    if (pRules) pRules->lpVtbl->Release(pRules);
    if (pNetFwPolicy2) pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);

    OLE32$CoUninitialize();
    return hr;
}

int go(char *args, int len) {
    HRESULT hr;
	datap parser;
	WCHAR *w_ruleName = "";

	BeaconDataParse(&parser, args, len);
	w_ruleName = BeaconDataExtract(&parser, NULL);
	
    BSTR ruleName = OLEAUT32$SysAllocString(w_ruleName);
    
    hr = RemoveFirewallRule(ruleName);
    if (SUCCEEDED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Firewall rule removed successfully.\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "Failed to remove the firewall rule with error code: 0x%08lx\n", hr);
    }

    OLEAUT32$SysFreeString(ruleName);
    return 0;
}

