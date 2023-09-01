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


//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);





