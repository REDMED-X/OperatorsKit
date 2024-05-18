
//main
WINBASEAPI DWORD WINAPI KERNEL32$GetLogicalDriveStringsA(DWORD nBufferLength, LPSTR lpBuffer);
WINBASEAPI UINT WINAPI KERNEL32$GetDriveTypeA(LPCSTR lpRootPathName);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *str);


//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);




