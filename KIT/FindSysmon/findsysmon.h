#include <windows.h>  

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "Ole32.lib") 
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "FltLib.lib" )

#define HRESULT_FROM_WIN32(x) (x ? ((HRESULT) (((x) & 0x0000FFFF) | (FACILITY_WIN32 << 16) | 0x80000000)) : 0)
#define MAX_GUID_SIZE 39
#define MAX_DATA_LENGTH 65000
#define true 1

//PrintSysmonPID
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance (REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT void WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);

//FindSysmon
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT LSTATUS WINAPI ADVAPI32$RegGetValueA(HKEY hkey, LPCSTR lpSubKey, LPCSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
//DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
//DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
//DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT int __cdecl OLE32$StringFromGUID2(REFGUID rguid, LPOLESTR lpsz, int cchMax);
WINBASEAPI TDHSTATUS WINAPI TDH$TdhEnumerateProviders(PPROVIDER_ENUMERATION_INFO pBuffer, ULONG *pBufferSize);
WINBASEAPI void* __cdecl MSVCRT$realloc(void *ptr, size_t size);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *str);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *str1, const wchar_t *str2);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

//PrintMiniFilterData
WINBASEAPI void * __cdecl MSVCRT$malloc(size_t size);
//WINBASEAPI void * __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);
//WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$wprintf(const wchar_t *format, ...);
//WINBASEAPI void __cdecl MSVCRT$free(void *ptr);

//FindMiniFilters
WINBASEAPI HRESULT WINAPI Fltlib$FilterFindFirst(FILTER_INFORMATION_CLASS dwInformationClass, LPVOID lpBuffer, DWORD dwBufferSize, LPDWORD lpBytesReturned, LPHANDLE lpFilterFind);
WINBASEAPI HRESULT WINAPI Fltlib$FilterFindNext(HANDLE hFilterFind, FILTER_INFORMATION_CLASS dwInformationClass, LPVOID lpBuffer, DWORD dwBufferSize, LPDWORD lpBytesReturned);

//main
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
WINBASEAPI int __cdecl MSVCRT$getchar(void);


//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);