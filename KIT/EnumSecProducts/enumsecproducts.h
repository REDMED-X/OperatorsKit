#include <windows.h>

//CheckSecProc
DECLSPEC_IMPORT void * WINAPI KERNEL32$VirtualAlloc (LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT int WINAPI KERNEL32$VirtualFree (LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI char* __cdecl MSVCRT$strcpy(char* _Dest, const char* _Source);
WINBASEAPI int __cdecl MSVCRT$tolower(int _C);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
DECLSPEC_IMPORT HANDLE WINAPI WTSAPI32$WTSOpenServerA(LPSTR pServerName);
DECLSPEC_IMPORT BOOL WINAPI WTSAPI32$WTSEnumerateProcessesA(HANDLE hServer, DWORD Reserved, DWORD Version, PWTS_PROCESS_INFOA *ppProcessInfo, DWORD *pCount);
DECLSPEC_IMPORT HANDLE WINAPI WTSAPI32$WTSCloseServer(HANDLE hServer);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);


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


