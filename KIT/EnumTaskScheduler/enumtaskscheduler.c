#include <stdio.h>
#include <windows.h>
#include <taskschd.h>
#include <combaseapi.h>
#include "enumtaskscheduler.h"
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

	internal_printf("[+] Scheduled tasks in root folder:\n");
	internal_printf("=======================================================\n\n");

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
				internal_printf("Task Name: %ls\n", taskName);
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
						internal_printf("- Task running as: %ls\n", userId);
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
										internal_printf("- Action type: %ls\n", actionTypeName);

										if (actionType == TASK_ACTION_EXEC) {
											IExecAction* pExecAction = (IExecAction*) pAction;
											BSTR execPath;
											hr = pExecAction->lpVtbl->get_Path(pExecAction, &execPath);
											if (SUCCEEDED(hr)) {
												internal_printf("- Executable path: %ls\n", execPath);
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

									internal_printf("- Trigger type: %ls\n", triggerTypeName);
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
		internal_printf("----------------------------------------------------\n\n");
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
	if(!bofstart()) return;

	res = EnumScheduledTasks(hostName);

	if(!res) BeaconPrintf(CALLBACK_ERROR, "Failed to enumerate scheduled tasks.\n");
	else  {
		printoutput(TRUE);
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Finished enumerating!\n");
	}


	return 0;
}


		
		