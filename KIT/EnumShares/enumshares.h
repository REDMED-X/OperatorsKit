#include <windows.h>  

//Go
DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char* _String, const char* _Delimiters);

//listShares
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetShareEnum(LMSTR servername, DWORD level, LPBYTE *bufptr, DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries, LPDWORD resume_handle);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetUseAdd(LMSTR uncname, DWORD level, LPBYTE buf, LPDWORD parm_err);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetApiBufferFree(LPVOID Buffer);
DECLSPEC_IMPORT NET_API_STATUS NET_API_FUNCTION NETAPI32$NetUseDel(LMSTR uncname, LMSTR use_name, DWORD force_cond);
WINBASEAPI int __cdecl MSVCRT$_snwprintf(wchar_t *buffer, size_t count, const wchar_t *format, ...);
WINBASEAPI int WINAPI KERNEL32$lstrcmpW(LPCWSTR lpString1, LPCWSTR lpString2);


//BeaconPrintToStreamW + BeaconOutputStreamW
#define MAX_STRING 8192
INT g_iGarbage = 1;
LPSTREAM g_lpStream = (LPSTREAM)1;
LPWSTR g_lpwPrintBuffer = (LPWSTR)1;
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CreateStreamOnHGlobal(HGLOBAL hGlobal, BOOL fDeleteOnRelease, LPSTREAM *ppstm);
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int __cdecl MSVCRT$_vsnwprintf_s(wchar_t *buffer, size_t sizeOfBuffer, size_t count, const wchar_t *format, va_list argptr);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *_Str);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);




