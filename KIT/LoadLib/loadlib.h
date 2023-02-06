#include <windows.h>

#define RETVAL_TAG 0xDDCCBBAA

typedef NTSTATUS (NTAPI * RtlRemoteCall_t)(HANDLE Process, HANDLE Thread, PVOID CallSite, ULONG ArgumentCount, PULONG Arguments, BOOLEAN PassContext, BOOLEAN	AlreadySuspended);
typedef NTSTATUS (NTAPI * NtContinue_t)(PCONTEXT ThreadContext, BOOLEAN	RaiseAlert);
typedef HANDLE (WINAPI * OpenProcess_t)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
typedef HMODULE (WINAPI * LoadLibraryA_t)(LPCSTR lpLibFileName);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);
WINBASEAPI int __cdecl MSVCRT$getchar(void);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strcpy_s(char *dest, rsize_t dest_size, const char *src);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD th32ProcessID);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
DECLSPEC_IMPORT int WINAPI KERNEL32$lstrcmpiA (LPCSTR lpString1, LPCSTR lpString2);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$SuspendThread(HANDLE hThread);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ResumeThread(HANDLE hThread);
DECLSPEC_IMPORT VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);

