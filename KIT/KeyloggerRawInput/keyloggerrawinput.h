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
DECLSPEC_IMPORT BOOL WINAPI USER32$TranslateMessage(const MSG *lpMsg);
DECLSPEC_IMPORT LRESULT WINAPI USER32$DispatchMessageA(const MSG *lpMsg);
DECLSPEC_IMPORT BOOL   WINAPI USER32$PeekMessageA(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg);
DECLSPEC_IMPORT BOOL   WINAPI USER32$DestroyWindow(HWND hWnd);
DECLSPEC_IMPORT BOOL   WINAPI USER32$UnregisterClassA(LPCSTR lpClassName, HINSTANCE hInstance);
DECLSPEC_IMPORT HWND WINAPI USER32$GetForegroundWindow(void);
DECLSPEC_IMPORT int WINAPI USER32$GetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount);

// Import kernel32 functions
DECLSPEC_IMPORT HINSTANCE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(VOID);

// Import msvcrt functions
WINBASEAPI void * __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void * __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t count);
WINBASEAPI void* __cdecl MSVCRT$malloc(size_t size);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *str);
WINBASEAPI void __cdecl MSVCRT$free(void *ptr);
WINBASEAPI int    __cdecl MSVCRT$strcmp(const char * _Str1, const char * _Str2);
