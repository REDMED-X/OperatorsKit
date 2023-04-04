#include <stdio.h>
#include <windows.h>
#include <taskschd.h>
#include <combaseapi.h>
#include "deltaskscheduler.h"
#include "beacon.h"


BOOL DeleteScheduledTask(wchar_t* taskName, wchar_t* host) {
    BOOL actionResult = FALSE;
	HRESULT hr = S_OK;

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return actionResult;

	IID CTaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
	IID IIDITaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
	ITaskService *pTaskService = NULL;
    hr = OLE32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDITaskService, (void**)&pTaskService);
    if (FAILED(hr)) {
        //MSVCRT$printf("Failed to create ITaskService: %x\n", hr); //DEBUG
        OLE32$CoUninitialize();
        return actionResult;
    }
	
	VARIANT Vhost;
	VARIANT VNull;
	OLEAUT32$VariantInit(&Vhost);
	OLEAUT32$VariantInit(&VNull);
	Vhost.vt = VT_BSTR;
	Vhost.bstrVal = OLEAUT32$SysAllocString(host);
	
	hr = pTaskService->lpVtbl->Connect(pTaskService, Vhost, VNull, VNull, VNull); 
    if (FAILED(hr)) {
        //MSVCRT$printf("ITaskService::Connect failed: %x\n", hr); //DEBUG
        pTaskService->lpVtbl->Release(pTaskService);
        OLE32$CoUninitialize();
        return actionResult;
    }
	
	ITaskFolder* pTaskFolder = NULL;
	BSTR folderPathBstr = OLEAUT32$SysAllocString(L"\\");
	hr = pTaskService->lpVtbl->GetFolder(pTaskService, folderPathBstr, &pTaskFolder);
	if (FAILED(hr)) {
		//MSVCRT$printf("ITaskService::GetFolder failed: %x\n", hr); //DEBUG
		pTaskService->lpVtbl->Release(pTaskService);
		OLE32$CoUninitialize();
		OLEAUT32$SysFreeString(folderPathBstr);
		return actionResult;
	}
	OLEAUT32$SysFreeString(folderPathBstr);

    hr = pTaskFolder->lpVtbl->DeleteTask(pTaskFolder, taskName, 0);
	
	if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to delete the scheduled task with error code: %x\n", hr);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Scheduled task '%ls' deleted successfully!\n", taskName);
        actionResult = TRUE;
    }

    pTaskFolder->lpVtbl->Release(pTaskFolder);
	pTaskService->lpVtbl->Release(pTaskService);
	
	OLEAUT32$VariantClear(&Vhost);
	OLEAUT32$VariantClear(&VNull);
	OLE32$CoUninitialize();

    return actionResult;
}


int go(char *args, int len) {
	BOOL res = NULL;
	datap parser;
	
    WCHAR *taskName; 
	WCHAR *hostName = L""; 
	
	BeaconDataParse(&parser, args, len);
	taskName = BeaconDataExtract(&parser, NULL);
	hostName = BeaconDataExtract(&parser, NULL);
	
	res = DeleteScheduledTask(taskName, hostName);
	
	return 0;
}


