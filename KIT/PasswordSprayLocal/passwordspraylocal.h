// Process and Memory
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
WINBASEAPI void   WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI DWORD  WINAPI KERNEL32$GetTickCount(VOID);

// Strings
WINBASEAPI int    WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
WINBASEAPI char* __cdecl MSVCRT$strtok(char* _String, const char* _Delimiters);
WINBASEAPI int    __cdecl MSVCRT$_snwprintf(wchar_t *buffer, size_t count, const wchar_t *format, ...);

// Jitter
WINBASEAPI void   __cdecl MSVCRT$srand(unsigned int seed);
WINBASEAPI int    __cdecl MSVCRT$rand(void);

// SMB (MPR)
WINBASEAPI DWORD  WINAPI MPR$WNetAddConnection2W(LPNETRESOURCEW lpNetResource, LPCWSTR lpPassword, LPCWSTR lpUserName, DWORD dwFlags);
WINBASEAPI DWORD  WINAPI MPR$WNetCancelConnection2W(LPCWSTR lpName, DWORD dwFlags, BOOL fForce);

// Output
WINBASEAPI void* __cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI void   __cdecl MSVCRT$free(void *memblock);
WINBASEAPI void* __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI int    __cdecl MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);