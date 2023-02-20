#include <windows.h>
#include <stdio.h>
#include <tdh.h>
#include <pla.h>
#include <oleauto.h>
#include <tlhelp32.h>
#include <fltuser.h>
#include "findsysmon.h"
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
		MSVCRT$memset(g_lpwPrintBuffer, 0, MAX_STRING * sizeof(WCHAR)); 
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


//IID: https://gist.githubusercontent.com/stevemk14ebr/af8053c506ef895cd520f8017a81f913/raw/98944bc6ae995229d5231568a8ae73dd287e8b4f/guids
BOOL PrintSysmonPID(wchar_t * guid) {
	HRESULT hr = S_OK;
	ITraceDataProvider *itdProvider = NULL;
	IID CTraceDataProvider = {0x03837513,0x098b,0x11d8,{0x94,0x14,0x50,0x50,0x54,0x50,0x30,0x30}};
	IID IIDITraceDataProvider = {0x03837512,0x098b,0x11d8,{0x94,0x14,0x50,0x50,0x54,0x50,0x30,0x30}};
	IID IIDIEnumVARIANT = {0x00020404,0x0000,0x0000,{0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
	IID IIDIValueMapItem = {0x03837533,0x098b,0x11d8,{0x94,0x14,0x50,0x50,0x54,0x50,0x30,0x30}};
	BOOL activeSysmon = FALSE;
	
	hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if(FAILED(hr)) return FALSE;

	hr = OLE32$CoCreateInstance(&CTraceDataProvider, 0, CLSCTX_INPROC_SERVER, &IIDITraceDataProvider, (LPVOID *) &itdProvider); 
	if(FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR,"Failed to create instance of object: %lX", hr);
	}
	
	hr = itdProvider->lpVtbl->Query(itdProvider, guid, NULL);
	if(FAILED(hr))
	{
		BeaconPrintf(CALLBACK_ERROR,"Failed to query the process based on the GUID: %lX\n", hr);
	}
	IValueMap *ivmProcesses = NULL;
	hr = itdProvider->lpVtbl->GetRegisteredProcesses(itdProvider, &ivmProcesses);
	
	if(hr == S_OK) {
		long count = 0;
		hr = ivmProcesses->lpVtbl->get_Count(ivmProcesses, &count);
		
		if (count > 0) {
			IUnknown *pUnk = NULL;
			hr = ivmProcesses->lpVtbl->get__NewEnum(ivmProcesses, &pUnk);
			IEnumVARIANT *pItems = NULL;
			hr = pUnk->lpVtbl->QueryInterface(pUnk, &IIDIEnumVARIANT, (void **)&pItems);
			pUnk->lpVtbl->Release(pUnk);
			
			VARIANT vItem;
			VARIANT vPID;
			OLEAUT32$VariantInit(&vItem);
			OLEAUT32$VariantInit(&vPID);
			
			IValueMapItem *pProc = NULL;
			while ((hr = pItems->lpVtbl->Next(pItems, 1, &vItem, NULL)) == S_OK) {
				vItem.punkVal->lpVtbl->QueryInterface(vItem.punkVal, &IIDIValueMapItem, (void **) &pProc);
				pProc->lpVtbl->get_Value(pProc, &vPID);
				
				if (vPID.ulVal) {
					BeaconPrintToStreamW(L"Sysmon procID:\t\t%d\n", vPID.ulVal);
					activeSysmon = TRUE;
				}

				OLEAUT32$VariantClear(&vPID);
				pProc->lpVtbl->Release(pProc);
				OLEAUT32$VariantClear(&vItem);
			}
		}
	}
	ivmProcesses->lpVtbl->Release(ivmProcesses);
	itdProvider->lpVtbl->Release(itdProvider);
	OLE32$CoUninitialize();

	return activeSysmon;
}


BOOL FindSysmon() {
    DWORD status = ERROR_SUCCESS;
    PROVIDER_ENUMERATION_INFO * penum = NULL;    
    PROVIDER_ENUMERATION_INFO * ptemp = NULL;
    DWORD BufferSize = 0;                       
    HRESULT hr = S_OK;                          
    WCHAR StringGuid[MAX_GUID_SIZE];
	
    HKEY hKey;
	DWORD cbLength = MAX_DATA_LENGTH;
	DWORD dwType;
	char* RegData = NULL;
	wchar_t guid[256];	
	BOOL activeSysmon = FALSE;


	if(ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Sysmon/Operational"), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		RegData = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, cbLength);
		if (RegData == NULL) {
			return FALSE;
		}

		if(ADVAPI32$RegGetValueA(hKey,	NULL, "OwningPublisher", RRF_RT_ANY, &dwType, (PVOID)RegData, &cbLength) != ERROR_SUCCESS) {
			return FALSE;
		}
		
		if (MSVCRT$strlen(RegData) != 0) {
			KERNEL32$MultiByteToWideChar(CP_UTF8, 0, RegData, -1, guid, 256);
		}
		else return FALSE;
	}
	else return FALSE;
	if(RegData) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, RegData);
	ADVAPI32$RegCloseKey(hKey);
	
	
    status = TDH$TdhEnumerateProviders(penum, &BufferSize);
    while (status == ERROR_INSUFFICIENT_BUFFER) {
        ptemp = (PROVIDER_ENUMERATION_INFO *) MSVCRT$realloc(penum, BufferSize);
        if (ptemp == NULL) {
            return FALSE;
        }

        penum = ptemp;
        ptemp = NULL;

        status = TDH$TdhEnumerateProviders(penum, &BufferSize);
    }
	
    if (status != ERROR_SUCCESS) 
		BeaconPrintf(CALLBACK_ERROR,"TdhEnumerateProviders failed.\n");
	
    else {
        for (DWORD i = 0; i < penum->NumberOfProviders; i++) {
            hr = OLE32$StringFromGUID2(&penum->TraceProviderInfoArray[i].ProviderGuid, StringGuid, ARRAYSIZE(StringGuid));
            if (FAILED(hr)) return FALSE;
			
			if (!MSVCRT$_wcsicmp(StringGuid, (wchar_t *)guid)) { 

				BeaconPrintToStreamW(L"[!] Sysmon service found:\n===============================================================\n");
				activeSysmon = PrintSysmonPID(guid);	

				if(!activeSysmon) BeaconPrintToStreamW(L"Sysmon service status:\tStopped\n");
				else BeaconPrintToStreamW(L"Sysmon service status:\tRunning\n");
				
				BeaconPrintToStreamW(L"Sysmon provider name:\t%s\nSysmon provider GUID:\t%s\n", (LPWSTR)((PBYTE)(penum)+penum->TraceProviderInfoArray[i].ProviderNameOffset), StringGuid); 
				if (penum) {
					MSVCRT$free(penum);
					penum = NULL;
				}
				return TRUE;
			}
			
        }
    }

    if (penum) {
        MSVCRT$free(penum);
        penum = NULL;
    }
	
	return FALSE;
}



int PrintMiniFilterData(FILTER_AGGREGATE_STANDARD_INFORMATION * lpFilterInfo) {

	FILTER_AGGREGATE_STANDARD_INFORMATION * fltInfo = NULL;
	char * fltName, * fltAlt;
	
	fltInfo = (FILTER_AGGREGATE_STANDARD_INFORMATION *) lpFilterInfo;

	int fltName_size = fltInfo->Type.MiniFilter.FilterNameLength;
	LONGLONG src = ((LONGLONG) lpFilterInfo) + fltInfo->Type.MiniFilter.FilterNameBufferOffset;
	fltName = (char *) MSVCRT$malloc(fltName_size + 2);
	MSVCRT$memset(fltName, 0, fltName_size + 2);
	MSVCRT$memcpy(fltName, (void *) src, fltName_size);
	
	int fltAlt_size = fltInfo->Type.MiniFilter.FilterAltitudeLength;
	src = ((LONGLONG) lpFilterInfo) + fltInfo->Type.MiniFilter.FilterAltitudeBufferOffset;
	fltAlt = (char *) MSVCRT$malloc(fltAlt_size + 2);
	MSVCRT$memset(fltAlt, 0, fltAlt_size + 2);
	MSVCRT$memcpy(fltAlt, (void *) src, fltAlt_size);	
	
	if (fltInfo->Flags == FLTFL_ASI_IS_MINIFILTER) {
		BeaconPrintToStreamW(L"%-29s%s\t%26d\n", fltName, fltAlt, fltInfo->Type.MiniFilter.NumberOfInstances);
	}
	MSVCRT$free(fltName);
	MSVCRT$free(fltAlt);	
	
	return 0;
}


BOOL FindMiniFilters() {
	HRESULT res;
	DWORD dwBytesReturned;
	HANDLE hFilterFind;
	DWORD dwFilterInfoSize = 1024;
	LPVOID lpFilterInfo = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), NULL, dwFilterInfoSize);
	BOOL foundMinifilter = FALSE;
	
	res = Fltlib$FilterFindFirst(FilterAggregateStandardInformation, lpFilterInfo, dwFilterInfoSize, &dwBytesReturned, &hFilterFind);
	if (res == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) return foundMinifilter;
	if (res != S_OK) return foundMinifilter;
	
	BeaconPrintToStreamW(L"[+] Found MiniFilter drivers.\n[*] Check if you can identify one that is associated with Sysmon (e.g. SysmonDrv):\n\n");
	BeaconPrintToStreamW(L"Name Minifilter\t\tPriority altitude\t\tLoaded instances\n=======================================================================\n");
	PrintMiniFilterData((FILTER_AGGREGATE_STANDARD_INFORMATION *) lpFilterInfo);
	foundMinifilter = TRUE;

	while(true) {
		res = Fltlib$FilterFindNext(hFilterFind, FilterAggregateStandardInformation, lpFilterInfo, dwFilterInfoSize, &dwBytesReturned);
		if (res == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) break;
		if (res != S_OK) return foundMinifilter;
		PrintMiniFilterData((FILTER_AGGREGATE_STANDARD_INFORMATION *) lpFilterInfo);		
	}
	
	KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), NULL, lpFilterInfo);
    return foundMinifilter;
}



int go(char *args, int len) {
	BOOL res = NULL;
	CHAR *action;
	datap parser;
	
	BeaconDataParse(&parser, args, len);
	action = BeaconDataExtract(&parser, NULL);
	
	if (MSVCRT$strcmp(action, "reg") == 0) {
		res = FindSysmon();
		if(!res) {
			BeaconPrintf(CALLBACK_OUTPUT, "[+] No Sysmon service found :)\n");
			return 0;
		}
		else  {
			BeaconOutputStreamW();
			BeaconPrintf(CALLBACK_OUTPUT, "[+] DONE");
		}
	}
	else if (MSVCRT$strcmp(action, "driver") == 0) {
		res = FindMiniFilters();
		if(!res) {
			BeaconPrintf(CALLBACK_ERROR,"[-] Couldn't list Minifilter drivers (high enough privileges?)\n");
			return 0;
		}
		else  {
			BeaconOutputStreamW();
			BeaconPrintf(CALLBACK_OUTPUT, "[+] DONE");

		}
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "Please specify one of the following enumeration options: reg | driver (must be elevated)\n");
	}

	return 0;
}


