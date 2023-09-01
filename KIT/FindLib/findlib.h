#include <windows.h>

//ListModules
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...); 
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
DECLSPEC_IMPORT SIZE_T WINAPI KERNEL32$VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$K32GetModuleBaseNameA(HANDLE hProcess, HMODULE hModule, LPSTR lpBaseName, DWORD nSize);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$K32GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);


//FindProcess
typedef NTSTATUS (NTAPI * NtGetNextProcess_t)(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetProcessId(HANDLE Process);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcessId();
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$K32GetProcessImageFileNameA(HANDLE hProcess, LPSTR lpImageFileName, DWORD nSize);
DECLSPEC_IMPORT LPCSTR WINAPI SHLWAPI$PathFindFileNameA(LPCSTR pszPath);
WINBASEAPI char* WINAPI MSVCRT$strncpy(char* dest, const char* src, size_t n);


//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);