#include <windows.h>  

DECLSPEC_IMPORT DWORD    WINAPI WLANAPI$WlanOpenHandle(
    DWORD dwClientVersion,
    PVOID pReserved,
    PDWORD pdwNegotiatedVersion,
    PHANDLE phClientHandle
);
DECLSPEC_IMPORT DWORD    WINAPI WLANAPI$WlanEnumInterfaces(
    HANDLE hClientHandle,
    PVOID pReserved,
    PWLAN_INTERFACE_INFO_LIST *ppIfList
);
DECLSPEC_IMPORT DWORD    WINAPI WLANAPI$WlanGetProfileList(
    HANDLE hClientHandle,
    const GUID *pInterfaceGuid,
    PVOID pReserved,
    PWLAN_PROFILE_INFO_LIST *ppProfileList
);
DECLSPEC_IMPORT DWORD    WINAPI WLANAPI$WlanGetProfile(
    HANDLE hClientHandle,
    const GUID *pInterfaceGuid,
    LPCWSTR strProfileName,
    PVOID pReserved,
    LPWSTR *pstrProfileXml,
    PDWORD pdwFlags,
    PVOID pReserved2
);
DECLSPEC_IMPORT VOID     WINAPI WLANAPI$WlanFreeMemory(PVOID pMemory);
DECLSPEC_IMPORT DWORD    WINAPI WLANAPI$WlanCloseHandle(
    HANDLE hClientHandle,
    PVOID pReserved
);

DECLSPEC_IMPORT int      WINAPI KERNEL32$WideCharToMultiByte(
    UINT CodePage,
    DWORD dwFlags,
    LPCWSTR lpWideCharStr,
    int cchWideChar,
    LPSTR lpMultiByteStr,
    int cbMultiByte,
    LPCSTR lpDefaultChar,
    LPBOOL lpUsedDefaultChar
);

//
WINBASEAPI void * __cdecl    MSVCRT$malloc(size_t size);
WINBASEAPI void   __cdecl    MSVCRT$free(void *ptr);
WINBASEAPI errno_t __cdecl   MSVCRT$wcscpy_s(wchar_t *strDestination, size_t numberOfElements, const wchar_t *strSource);
WINBASEAPI size_t __cdecl    MSVCRT$wcslen(const wchar_t *str);
WINBASEAPI wchar_t * __cdecl MSVCRT$wcsstr(const wchar_t *str1, const wchar_t *str2);
WINBASEAPI int    __cdecl    MSVCRT$wprintf(const wchar_t *format, ...);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);

//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);



