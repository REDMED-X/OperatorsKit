#include <stdio.h>
#include <windows.h>
#include <taskschd.h>
#include <combaseapi.h>
#include "enumtaskscheduler.h"
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



BOOL EnumScheduledTasks(wchar_t * host) {
    HRESULT hr = S_OK;

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return FALSE;

    IID CTaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
    IID IIDITaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
    ITaskService *pTaskService = NULL;
    hr = OLE32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDITaskService, (void**)&pTaskService);
    if (FAILED(hr)) {
        return FALSE;
    }
    
	VARIANT Vhost;
	VARIANT VNull;
	OLEAUT32$VariantInit(&Vhost);
	OLEAUT32$VariantInit(&VNull);
    Vhost.vt = VT_BSTR;
    Vhost.bstrVal = OLEAUT32$SysAllocString(host);
    
    hr = pTaskService->lpVtbl->Connect(pTaskService, Vhost, VNull, VNull, VNull); 
    if (FAILED(hr)) {
        goto cleanup;
    }
	
    ITaskFolder* pRootFolder = NULL;
    hr = pTaskService->lpVtbl->GetFolder(pTaskService, L"\\", &pRootFolder);
    if (FAILED(hr)) {
        goto cleanup;
    }
	
    IRegisteredTaskCollection* pTaskCollection = NULL;
    hr = pRootFolder->lpVtbl->GetTasks(pRootFolder, 0, &pTaskCollection);
    if (FAILED(hr)) {
        goto cleanup;
    }


    long numTasks = 0;
    hr = pTaskCollection->lpVtbl->get_Count(pTaskCollection, &numTasks);

	BeaconPrintToStreamW(L"[+] Scheduled tasks in root folder:\n");
	BeaconPrintToStreamW(L"=======================================================\n\n");

	for (long i = 1; i <= numTasks; i++) { 
		IRegisteredTask* pRegisteredTask = NULL;
		VARIANT index;
		index.vt = VT_I4;
		index.lVal = i;

		hr = pTaskCollection->lpVtbl->get_Item(pTaskCollection, index, &pRegisteredTask);
		if (SUCCEEDED(hr)) {
			BSTR taskName = NULL;
			hr = pRegisteredTask->lpVtbl->get_Name(pRegisteredTask, &taskName);
			if (SUCCEEDED(hr)) {
				BeaconPrintToStreamW(L"Task Name: %ls\n", taskName);
				OLEAUT32$SysFreeString(taskName);
			}
			
			
			ITaskDefinition* pTaskDef = NULL;
			hr = pRegisteredTask->lpVtbl->get_Definition(pRegisteredTask, &pTaskDef);
			if (SUCCEEDED(hr)) {
				
				
				// Fetching the Principal information and print the user account
				IPrincipal* pPrincipal = NULL;
				hr = pTaskDef->lpVtbl->get_Principal(pTaskDef, &pPrincipal);
				if (SUCCEEDED(hr)) {
					BSTR userId = NULL;
					hr = pPrincipal->lpVtbl->get_UserId(pPrincipal, &userId);
					if (SUCCEEDED(hr)) {
						BeaconPrintToStreamW(L"- Task running as: %ls\n", userId);
						OLEAUT32$SysFreeString(userId);
					}
					pPrincipal->lpVtbl->Release(pPrincipal);
				}

				// Fetching Action Information
				ITaskDefinition* pTaskDef = NULL;
				hr = pRegisteredTask->lpVtbl->get_Definition(pRegisteredTask, &pTaskDef);
				if (SUCCEEDED(hr)) {
					IActionCollection* pActionColl = NULL;
					hr = pTaskDef->lpVtbl->get_Actions(pTaskDef, &pActionColl);
					if (SUCCEEDED(hr)) {
						long actionCount = 0;
						hr = pActionColl->lpVtbl->get_Count(pActionColl, &actionCount);
						if (SUCCEEDED(hr)) {
							for (long j = 1; j <= actionCount; j++) {
								IAction* pAction = NULL;
								long actionIndex = j;

								hr = pActionColl->lpVtbl->get_Item(pActionColl, actionIndex, &pAction);
								if (SUCCEEDED(hr)) {
									TASK_ACTION_TYPE actionType;
									hr = pAction->lpVtbl->get_Type(pAction, &actionType);
									if (SUCCEEDED(hr)) {
										WCHAR* actionTypes[] = {
											L"Start a program",
											L"Send an e-mail (Deprecated)",
											L"Display a message (Deprecated)"
										};

										WCHAR* actionTypeName = actionTypes[actionType];  // Using actionType as an index
										BeaconPrintToStreamW(L"- Action type: %s\n", actionTypeName);

										if (actionType == TASK_ACTION_EXEC) {
											IExecAction* pExecAction = (IExecAction*) pAction;
											BSTR execPath;
											hr = pExecAction->lpVtbl->get_Path(pExecAction, &execPath);
											if (SUCCEEDED(hr)) {
												BeaconPrintToStreamW(L"- Executable path: %ls\n", execPath);
												OLEAUT32$SysFreeString(execPath);
											}
										}
									}

									pAction->lpVtbl->Release(pAction);
								}
							}
						}
					}
				}
				
				// Fetching Trigger Information
				ITriggerCollection* pTriggerColl = NULL;
				hr = pTaskDef->lpVtbl->get_Triggers(pTaskDef, &pTriggerColl);
				if (SUCCEEDED(hr)) {
					long triggerCount = 0;
					hr = pTriggerColl->lpVtbl->get_Count(pTriggerColl, &triggerCount);
					if (SUCCEEDED(hr)) {
						for (long j = 1; j <= triggerCount; j++) {
							ITrigger* pTrigger = NULL;
							long triggerIndex = j;

							hr = pTriggerColl->lpVtbl->get_Item(pTriggerColl, triggerIndex, &pTrigger);
							if (SUCCEEDED(hr)) {
								TASK_TRIGGER_TYPE2 triggerType;
								hr = pTrigger->lpVtbl->get_Type(pTrigger, &triggerType);
								if (SUCCEEDED(hr)) {
									static const WCHAR* triggerTypeNames[] = {
										L"On an event",    // 1
										L"On a schedule",     // 2
										L"Daily",    // 3
										L"Weekly",   // 4
										L"Monthly",  // 5
										L"MonthlyDOW", // 6
										L"On idle",       // 7
										L"At task creation/modification", // 8
										L"At startup",       // 9
										L"At log on",      // 10
										L"SessionStateChange (lock/unlock/connection)",  // 11
										L"SessionStateChange (lock/unlock/connection)"  // 12
									};

									const WCHAR* triggerTypeName = (triggerType >= 0 && triggerType < sizeof(triggerTypeNames) / sizeof(triggerTypeNames[0])) 
																  ? triggerTypeNames[triggerType] 
																  : L"Unknown";

									BeaconPrintToStreamW(L"- Trigger type: %s\n", triggerTypeName);
								}

								pTrigger->lpVtbl->Release(pTrigger);
							}
						}
					}

					pTriggerColl->lpVtbl->Release(pTriggerColl);
				}

				pTaskDef->lpVtbl->Release(pTaskDef);
			}

			if (pRegisteredTask) {
				pRegisteredTask->lpVtbl->Release(pRegisteredTask);
			}
		}
		BeaconPrintToStreamW(L"----------------------------------------------------\n\n");
	}

cleanup:
    if (pTaskCollection) {
        pTaskCollection->lpVtbl->Release(pTaskCollection);
    }
    if (pRootFolder) {
        pRootFolder->lpVtbl->Release(pRootFolder);
	}
    if (pTaskService) {
        pTaskService->lpVtbl->Release(pTaskService);
    }

    OLEAUT32$VariantClear(&Vhost);
    OLE32$CoUninitialize();

    return TRUE;
}



int go(char *args, int len) {
	BOOL res = NULL;
	datap parser;
	WCHAR *hostName  = L""; 
	
	BeaconDataParse(&parser, args, len);
	hostName = BeaconDataExtract(&parser, NULL);

	res = EnumScheduledTasks(hostName);

	if(!res) BeaconPrintf(CALLBACK_ERROR, "Failed to enumerate scheduled tasks.\n");
	else  {
		BeaconOutputStreamW();
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Done enumerating!\n");
	}


	return 0;
}


		
		