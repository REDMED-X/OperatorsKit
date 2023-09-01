#include <windows.h>  

//is_empty_or_whitespace
DECLSPEC_IMPORT int __cdecl MSVCRT$iswspace(wint_t _C);

//EnumWindowsProc
DECLSPEC_IMPORT int __cdecl MSVCRT$wcscmp(const wchar_t* _Str1, const wchar_t* _Str2);
DECLSPEC_IMPORT int WINAPI USER32$GetClassNameW(HWND hWnd, LPWSTR lpClassName, int nMaxCount);
DECLSPEC_IMPORT BOOL WINAPI USER32$PostMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

//PromptWithTimeout
DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep (DWORD dwMilliseconds);
DECLSPEC_IMPORT BOOL WINAPI USER32$EnumWindows(WNDENUMPROC lpEnumFunc, LPARAM lParam);

//PromptForCreds
DECLSPEC_IMPORT int __cdecl MSVCRT$_snwprintf(wchar_t* _Dst, size_t _MaxCount, const wchar_t* _Format, ...);
DECLSPEC_IMPORT BOOL WINAPI SECUR32$GetUserNameExW(EXTENDED_NAME_FORMAT NameFormat, LPWSTR lpNameBuffer, PULONG nSize);
DECLSPEC_IMPORT DWORD WINAPI CREDUI$CredUIPromptForWindowsCredentialsW(PCREDUI_INFOW pUiInfo, DWORD dwAuthError, ULONG *pulAuthPackage, LPCVOID pvInAuthBuffer, ULONG ulInAuthBufferSize, LPVOID *ppvOutAuthBuffer, ULONG *pulOutAuthBufferSize, BOOL *pfSave, DWORD dwFlags);
DECLSPEC_IMPORT BOOL WINAPI CREDUI$CredUnPackAuthenticationBufferW(DWORD dwFlags, PVOID pAuthBuffer, DWORD cbAuthBuffer, LPWSTR pszUserName, DWORD *pcchMaxUserName, LPWSTR pszDomainName, DWORD *pcchMaxDomainName, LPWSTR pszPassword, DWORD *pcchMaxPassword);
DECLSPEC_IMPORT BOOL WINAPI CREDUI$CredPackAuthenticationBufferW(DWORD dwFlags, LPWSTR pszUserName, LPWSTR pszPassword, PBYTE pPackedCredentials, DWORD *pcbPackedCredentials);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SetEvent(HANDLE hEvent);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
//DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void* _Dst, int _Val, size_t _Size);
DECLSPEC_IMPORT void WINAPI OLE32$CoTaskMemFree(LPVOID pv);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$TerminateThread(HANDLE hThread, DWORD dwExitCode);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
//DECLSPEC_IMPORT void __cdecl MSVCRT$free(void* _Block);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t* _Str);
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t _Size);
DECLSPEC_IMPORT HWND USER32$GetForegroundWindow();

//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);




