// Process and Memory Management
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL   WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
WINBASEAPI void   WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI DWORD  WINAPI KERNEL32$GetTickCount(VOID);

// String and MultiByte Conversions
WINBASEAPI int    WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
WINBASEAPI char* __cdecl MSVCRT$strtok(char* _String, const char* _Delimiters);
WINBASEAPI int    __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
WINBASEAPI int    __cdecl MSVCRT$_stricmp(const char *str1, const char *str2);

// Randomization (for Jitter)
WINBASEAPI void   __cdecl MSVCRT$srand(unsigned int seed);
WINBASEAPI int    __cdecl MSVCRT$rand(void);

// LDAP Authentication (WLDAP32)
WINBASEAPI LDAP* WINAPI WLDAP32$ldap_initW(PWSTR HostName, ULONG PortNumber);
WINBASEAPI ULONG  WINAPI WLDAP32$ldap_connect(LDAP *ld, struct l_timeval *timeout);
WINBASEAPI ULONG  WINAPI WLDAP32$ldap_set_optionW(LDAP *ld, int option, void *invalue);
WINBASEAPI ULONG  WINAPI WLDAP32$ldap_simple_bind_sW(LDAP *ld, PWSTR dn, PWSTR passwd);
WINBASEAPI ULONG  WINAPI WLDAP32$ldap_unbind(LDAP *ld);

// TrustedSec BOF Printing & Buffer Management
WINBASEAPI void* __cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI void   __cdecl MSVCRT$free(void *memblock);
WINBASEAPI void* __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI int    __cdecl MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI int    __cdecl MSVCRT$_snwprintf(wchar_t *buffer, size_t count, const wchar_t *format, ...);