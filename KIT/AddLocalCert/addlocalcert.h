#include <windows.h>  

//addCertificateToRootStore
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertAddEncodedCertificateToStore(HCERTSTORE hCertStore, DWORD dwCertEncodingType, const BYTE *pbCertEncoded, DWORD cbCertEncoded, DWORD dwAddDisposition, PCCERT_CONTEXT *ppCertContext);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertSetCertificateContextProperty(PCCERT_CONTEXT pCertContext, DWORD dwPropId, DWORD dwFlags, const void *pvData);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT pCertContext);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCWSTR lpszStoreProvider, DWORD dwEncodingType, HCRYPTPROV hCryptProv, DWORD dwFlags, const void *pvPara);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE hCertStore, DWORD dwFlags);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
WINBASEAPI int __cdecl MSVCRT$fopen_s(FILE **_File, const char *_Filename, const char *_Mode);
WINBASEAPI int __cdecl MSVCRT$fseek(FILE *_File, long _Offset, int _Origin);
WINBASEAPI long __cdecl MSVCRT$ftell(FILE *_File);
WINBASEAPI size_t __cdecl MSVCRT$fread(void * _DstBuf, size_t _ElementSize, size_t _Count, FILE * _File);
WINBASEAPI int __cdecl MSVCRT$fclose(FILE *_File);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);


