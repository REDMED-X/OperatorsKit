#include <windows.h>  

DECLSPEC_IMPORT BOOL WINAPI USER32$GetLastInputInfo(PLASTINPUTINFO plii);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetTickCount(void);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);