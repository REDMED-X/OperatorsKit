#include <windows.h>  

//printCertProperties
DECLSPEC_IMPORT DWORD WINAPI CRYPT32$CertGetNameStringW(PCCERT_CONTEXT pCertContext, DWORD dwType, DWORD dwFlags, void *pvTypePara, LPWSTR pszNameString, DWORD cchNameString);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FileTimeToSystemTime(const FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
DECLSPEC_IMPORT int WINAPI KERNEL32$GetDateFormatW(LCID Locale, DWORD dwFlags, const SYSTEMTIME *lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertGetEnhancedKeyUsage(PCCERT_CONTEXT pCertContext, DWORD dwFlags, PCERT_ENHKEY_USAGE pUsage, DWORD *pcbUsage);
DECLSPEC_IMPORT PCCRYPT_OID_INFO WINAPI CRYPT32$CryptFindOIDInfo(DWORD dwKeyType, void *pvKey, DWORD dwGroupId);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenSystemStoreW(HCRYPTPROV hProv, LPCWSTR szSubsystemProtocol);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCWSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV hCryptProv, DWORD dwFlags, const void *pvPara);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT pCertContext);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);
WINBASEAPI int __cdecl MSVCRT$wprintf(const wchar_t * _Format, ...);

DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void *pvData, DWORD *pcbData); //TEST
WINBASEAPI int __cdecl MSVCRT$_snwprintf_s(wchar_t * _DstBuf, size_t _DstSize, size_t _MaxCount, const wchar_t * _Format, ...);


//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);