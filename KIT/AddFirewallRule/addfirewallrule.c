#include <stdio.h>
#include <Windows.h>
#include <netfw.h>
#include "addfirewallrule.h"
#include "beacon.h"

#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")


HRESULT AddFirewallRule(BSTR ruleName, BSTR ruleDescription, BSTR ruleGroup, NET_FW_RULE_DIRECTION direction, BSTR localPorts, LONG protocol) {
    HRESULT hr = S_OK;

    INetFwPolicy2 *pNetFwPolicy2 = NULL;
    INetFwRules *pRules = NULL;
    INetFwRule *pRule = NULL;
	
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

    // Create a new rule object.
    IID CLSIDNetFwRule = {0x2c5bc43e, 0x3369, 0x4c33, {0xab, 0x0c, 0xbe, 0x94, 0x69, 0x67, 0x7a, 0xf4}};
	IID IIDINetFwRule = {0xaf230d27, 0xbaba, 0x4e42, {0xac, 0xed, 0xf5, 0x24, 0xf2, 0x2c, 0xfc, 0xe2}};
    hr = OLE32$CoCreateInstance(&CLSIDNetFwRule, NULL, CLSCTX_INPROC_SERVER, &IIDINetFwRule, (void**)&pRule);
    if (FAILED(hr)) goto Cleanup;

	pRule->lpVtbl->put_Direction(pRule, direction);
	pRule->lpVtbl->put_Protocol(pRule, protocol);
	pRule->lpVtbl->put_LocalPorts(pRule, localPorts);
	pRule->lpVtbl->put_Action(pRule, NET_FW_ACTION_ALLOW);
    pRule->lpVtbl->put_Profiles(pRule, NET_FW_PROFILE2_ALL);
    pRule->lpVtbl->put_Name(pRule, ruleName);
    pRule->lpVtbl->put_Description(pRule, ruleDescription);
    pRule->lpVtbl->put_Grouping(pRule, ruleGroup);
    pRule->lpVtbl->put_Enabled(pRule, VARIANT_TRUE);

    // Add the rule.
    hr = pRules->lpVtbl->Add(pRules, pRule);
    if (FAILED(hr)) goto Cleanup;

Cleanup:
    if (pRule) pRule->lpVtbl->Release(pRule);
    if (pRules) pRules->lpVtbl->Release(pRules);
    if (pNetFwPolicy2) pNetFwPolicy2->lpVtbl->Release(pNetFwPolicy2);

    OLE32$CoUninitialize();
    return hr;
}


int go(char *args, int len) {
	HRESULT hr;
	datap parser;
	CHAR *directionOption = "in"; //in | out
	WCHAR *w_ruleName = "";
    WCHAR *w_ruleDescription = "";
    WCHAR *w_ruleGroup = "";
    WCHAR *w_localPorts = "";

	BeaconDataParse(&parser, args, len);
	directionOption = BeaconDataExtract(&parser, NULL);
	w_localPorts = BeaconDataExtract(&parser, NULL);
	w_ruleName = BeaconDataExtract(&parser, NULL);
	w_ruleGroup = BeaconDataExtract(&parser, NULL);
	w_ruleDescription = BeaconDataExtract(&parser, NULL);
	
	
	LONG protocol = NET_FW_IP_PROTOCOL_TCP;
    BSTR ruleName = OLEAUT32$SysAllocString(w_ruleName);
    BSTR ruleDescription = OLEAUT32$SysAllocString(w_ruleDescription);
    BSTR ruleGroup = OLEAUT32$SysAllocString(w_ruleGroup);
    BSTR localPorts = OLEAUT32$SysAllocString(w_localPorts);
    
	if(MSVCRT$strcmp(directionOption, "in") == 0) {
		NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_IN;
		hr = AddFirewallRule(ruleName, ruleDescription, ruleGroup, direction, localPorts, protocol);
		if (SUCCEEDED(hr)) BeaconPrintf(CALLBACK_OUTPUT, "[+] Inbound firewall rule added successfully.\n");
        else BeaconPrintf(CALLBACK_ERROR, "Add failed: 0x%08lx\n", hr);
	} 
	else {
		NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_OUT;
		hr = AddFirewallRule(ruleName, ruleDescription, ruleGroup, direction, localPorts, protocol);
		if (SUCCEEDED(hr)) BeaconPrintf(CALLBACK_OUTPUT, "[+] Outbound firewall rule added successfully.\n");
        else BeaconPrintf(CALLBACK_ERROR, "Add failed: 0x%08lx\n", hr);
	}

    OLEAUT32$SysFreeString(ruleName);
    OLEAUT32$SysFreeString(ruleDescription);
    OLEAUT32$SysFreeString(ruleGroup);
    OLEAUT32$SysFreeString(localPorts);

    return 0;
}
