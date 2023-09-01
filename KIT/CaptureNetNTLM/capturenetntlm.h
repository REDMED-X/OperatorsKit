#include <windows.h>  

//GetNTLMChallengeAndResponse
//DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void* _Dst, const void* _Src, size_t _Size);
//DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleW(SEC_WCHAR* pszPrincipal, SEC_WCHAR* pszPackage, ULONG fCredentialUse, PLUID pvLogonID, PVOID pAuthData, SEC_GET_KEY_FN pGetKeyFn, PVOID pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry);
//DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(PCredHandle phCredential, PCtxtHandle phContext, SEC_WCHAR* pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcceptSecurityContext(PCredHandle phCredential, PCtxtHandle phContext, PSecBufferDesc pInput, ULONG fContextReq, ULONG TargetDataRep, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleA(LPCTSTR, LPCTSTR, ULONG, PLUID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextA(PCredHandle, PCtxtHandle, SEC_CHAR *, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);


//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);