#include <windows.h>  

// Import user32 functions
DECLSPEC_IMPORT UINT WINAPI USER32$GetRawInputData(HRAWINPUT hRawInput, UINT uiCommand, LPVOID pData, PUINT pcbSize, UINT cbSizeHeader);
DECLSPEC_IMPORT SHORT WINAPI USER32$GetKeyboardState(PBYTE lpKeyState);
DECLSPEC_IMPORT int WINAPI USER32$ToAscii(UINT uVirtKey, UINT uScanCode, const BYTE *lpKeyState, LPWORD lpChar, UINT uFlags);
DECLSPEC_IMPORT VOID WINAPI USER32$PostQuitMessage(int nExitCode);
DECLSPEC_IMPORT LRESULT WINAPI USER32$DefWindowProcA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
DECLSPEC_IMPORT ATOM WINAPI USER32$RegisterClassA(const WNDCLASSA *lpWndClass);
DECLSPEC_IMPORT BOOL WINAPI USER32$GetClassInfoA(HINSTANCE hInstance, LPCSTR lpClassName, LPWNDCLASSA lpWndClass);
DECLSPEC_IMPORT HWND WINAPI USER32$CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);
DECLSPEC_IMPORT BOOL WINAPI USER32$RegisterRawInputDevices(PCRAWINPUTDEVICE pRawInputDevices, UINT uiNumDevices, UINT cbSize);
DECLSPEC_IMPORT ULONGLONG WINAPI KERNEL32$GetTickCount64(VOID);
DECLSPEC_IMPORT UINT WINAPI USER32$GetMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
DECLSPEC_IMPORT BOOL WINAPI USER32$TranslateMessage(const MSG *lpMsg);
DECLSPEC_IMPORT LRESULT WINAPI USER32$DispatchMessageA(const MSG *lpMsg);
DECLSPEC_IMPORT BOOL   WINAPI USER32$DestroyWindow(HWND hWnd);
DECLSPEC_IMPORT BOOL   WINAPI USER32$UnregisterClassA(LPCSTR lpClassName, HINSTANCE hInstance);

DECLSPEC_IMPORT BOOL   WINAPI USER32$PeekMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg);
DECLSPEC_IMPORT HWND   WINAPI USER32$FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName);
DECLSPEC_IMPORT HANDLE   WINAPI USER32$GetPropA(HWND hWnd, LPCSTR lpString);
DECLSPEC_IMPORT HANDLE   WINAPI USER32$RemovePropA(HWND hWnd, LPCSTR lpString);
DECLSPEC_IMPORT BOOL   WINAPI USER32$SetPropA(HWND hWnd, LPCSTR lpString, HANDLE hData);
DECLSPEC_IMPORT UINT   WINAPI USER32$MapVirtualKeyA(UINT uCode, UINT uMapType);
DECLSPEC_IMPORT int      WINAPI USER32$ToUnicodeEx(UINT wVirtKey, UINT wScanCode, const BYTE *lpKeyState, LPWSTR pwszBuff, int cchBuff, UINT wFlags, HKL dwhkl);
DECLSPEC_IMPORT HKL      WINAPI USER32$GetKeyboardLayout(DWORD idThread);

DECLSPEC_IMPORT DWORD      WINAPI USER32$MsgWaitForMultipleObjectsEx(DWORD nCount, const HANDLE *pHandles, DWORD dwMilliseconds, DWORD dwWakeMask,  DWORD dwFlags);

DECLSPEC_IMPORT HWND WINAPI USER32$GetForegroundWindow(void);
DECLSPEC_IMPORT DWORD WINAPI USER32$GetWindowThreadProcessId(HWND hWnd, LPDWORD lpdwProcessId);
DECLSPEC_IMPORT int WINAPI USER32$GetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount);


// Import kernel32 functions
DECLSPEC_IMPORT HINSTANCE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);




// Import msvcrt functions
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format, ...);
WINBASEAPI void * __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void * __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);
WINBASEAPI void* __cdecl MSVCRT$malloc(size_t size);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *str);
WINBASEAPI void __cdecl MSVCRT$free(void *ptr);
WINBASEAPI int    __cdecl MSVCRT$strcmp(const char * _Str1, const char * _Str2);

WINBASEAPI int    __cdecl MSVCRT$sprintf(char *str, const char *format, ...);
WINBASEAPI char* _cdecl MSVCRT$strcpy(char *dest, const char *src);