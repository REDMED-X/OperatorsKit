/* OLE32.dll */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT VOID    WINAPI OLE32$CoUninitialize(VOID);

/* OLEAUT32.dll */
DECLSPEC_IMPORT VOID    WINAPI OLEAUT32$VariantInit(VARIANTARG *pvarg);
DECLSPEC_IMPORT HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);

/* ACTIVEDS.dll */
DECLSPEC_IMPORT HRESULT WINAPI ACTIVEDS$ADsOpenObject(LPCWSTR lpszPathName, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwReserved, REFIID riid, void **ppObject);

/* SECUR32.dll */
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleW(PVOID pszPrincipal, PVOID pszPackage, ULONG fCredentialUse, PVOID pvLogonID, PVOID pAuthData, PVOID pGetKeyFn, PVOID pvGetKeyArgument, PCredHandle phCredential, PTimeStamp ptsExpiry);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(PCredHandle phCredential, PCtxtHandle phContext, PSECURITY_STRING pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle phCredential);

/* CRYPT32.dll */
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptBinaryToStringA(const BYTE *pbBinary, DWORD cbBinary, DWORD dwFlags, LPSTR pszString, DWORD *pcchString);

/* KERNEL32.dll */
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);

/* MSVCRT.dll */
WINBASEAPI int      __cdecl MSVCRT$swprintf_s(wchar_t *string, size_t sizeInWords, const wchar_t *format, ...);
WINBASEAPI int      __cdecl MSVCRT$_wcsicmp(const wchar_t *_Str1, const wchar_t *_Str2);
WINBASEAPI size_t   __cdecl MSVCRT$wcslen(const wchar_t *_Str); 
WINBASEAPI int      __cdecl MSVCRT$vsnprintf(char *buffer, size_t count, const char *format, va_list argptr);
WINBASEAPI void* __cdecl MSVCRT$calloc(size_t num, size_t size);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);
WINBASEAPI void     __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void     __cdecl MSVCRT$free(void *memblock);