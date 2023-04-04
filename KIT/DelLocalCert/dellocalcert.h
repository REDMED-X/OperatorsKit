#include <windows.h>  

//deleteCertificateFromRootStore
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCWSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV hCryptProv, DWORD dwFlags, const void *pvPara);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE hCertStore, PCCERT_CONTEXT pPrevCertContext);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT pCertContext);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);
WINBASEAPI int __cdecl MSVCRT$wprintf(const wchar_t * _Format, ...);
WINBASEAPI int __cdecl MSVCRT$sprintf(char * _DstBuf, const char * _Format, ...);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertDeleteCertificateFromStore(PCCERT_CONTEXT pCertContext);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertGetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, void *pvData, DWORD *pcbData); //TEST
WINBASEAPI int __cdecl MSVCRT$_snwprintf_s(wchar_t * _DstBuf, size_t _DstSize, size_t _MaxCount, const wchar_t * _Format, ...);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);

