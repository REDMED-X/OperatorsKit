
//main
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance (REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CLSIDFromString(LPCOLESTR lpsz, LPCLSID pclsid);

WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t *str);
WINBASEAPI int __cdecl MSVCRT$wcsncmp(const wchar_t *str1, const wchar_t *str2, size_t num);
WINBASEAPI void* __cdecl MSVCRT$malloc(size_t size);
WINBASEAPI errno_t __cdecl MSVCRT$wcscpy_s(wchar_t *dest, size_t destsz, const wchar_t *src);
WINBASEAPI errno_t __cdecl MSVCRT$wcscat_s(wchar_t *dest, size_t destsz, const wchar_t *src);
WINBASEAPI int __cdecl MSVCRT$wprintf(const wchar_t *format, ...);