
//main
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI PVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, PVOID lpMem);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);

WINBASEAPI int WINAPI MSVCRT$printf(const char *format, ...);
WINBASEAPI size_t WINAPI MSVCRT$wcslen(const wchar_t *str);

WINBASEAPI int WSAAPI WS2_32$WSAStartup(WORD wVersionRequested, LPWSADATA lpWSAData);
WINBASEAPI int WSAAPI WS2_32$WSACleanup(void);
WINBASEAPI int WSAAPI WS2_32$getaddrinfo(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA *pHints, PADDRINFOA *ppResult);
WINBASEAPI void WSAAPI WS2_32$freeaddrinfo(PADDRINFOA pAddrInfo);

WINBASEAPI BOOL WINAPI SECUR32$AcquireCredentialsHandleW(PCWSTR pszPrincipal, PCWSTR pszPackage, ULONG fCredentialUse, PVOID pvLogonId, PVOID pAuthData, SEC_GET_KEY_FN pGetKeyFn, PVOID pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR *pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$AcceptSecurityContext(PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput, ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsTimeStamp);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(PCtxtHandle phContext);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle phCredential);
WINBASEAPI BOOL WINAPI SECUR32$GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer, PULONG nSize);

//
WINBASEAPI void __cdecl MSVCRT$srand(unsigned int seed);
WINBASEAPI int __cdecl MSVCRT$rand(void);
WINBASEAPI time_t __cdecl MSVCRT$time(time_t *timer);
WINBASEAPI clock_t __cdecl MSVCRT$clock(void);

DECLSPEC_IMPORT char* __cdecl MSVCRT$strtok(char* _String, const char* _Delimiters);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
WINBASEAPI int WINAPI KERNEL32$lstrcmpW(LPCWSTR lpString1, LPCWSTR lpString2);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

//TEST
WINBASEAPI DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR ComputerName, LPCWSTR DomainName, GUID* DomainGuid, LPCWSTR SiteName, ULONG Flags, PDOMAIN_CONTROLLER_INFO* DomainControllerInfo);
WINBASEAPI NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID Buffer);



//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);




