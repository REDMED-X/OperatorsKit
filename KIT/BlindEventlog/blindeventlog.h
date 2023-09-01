#include <windows.h>  

#define ENABLE 1
#define DISABLE 0

typedef enum _SC_SERVICE_TAG_QUERY_TYPE {
	ServiceNameFromTagInformation = 1,
	ServiceNameReferencingModuleInformation,
	ServiceNameTagMappingInformation,
} SC_SERVICE_TAG_QUERY_TYPE, *PSC_SERVICE_TAG_QUERY_TYPE;

typedef struct _SC_SERVICE_TAG_QUERY {
	ULONG   processId;
	ULONG   serviceTag;
	ULONG   reserved;
	PVOID   pBuffer;
} SC_SERVICE_TAG_QUERY, *PSC_SERVICE_TAG_QUERY;

typedef struct _CLIENT_ID {
	DWORD       uniqueProcess;
	DWORD       uniqueThread;

} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS    exitStatus;
	PVOID       pTebBaseAddress;
	CLIENT_ID   clientId;
	KAFFINITY   AffinityMask;
	int			Priority;
	int			BasePriority;
	int			v;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;


//SetPrivilege
DECLSPEC_IMPORT BOOL WINAPI Advapi32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT BOOL WINAPI Advapi32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);


//Eventlog
typedef ULONG (WINAPI * I_QueryTagInformation_t)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);
typedef NTSTATUS (WINAPI * NtQueryInformationThread_t)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);
DECLSPEC_IMPORT SC_HANDLE WINAPI Advapi32$OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
DECLSPEC_IMPORT SC_HANDLE WINAPI Advapi32$OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
DECLSPEC_IMPORT BOOL WINAPI Advapi32$QueryServiceStatusEx(SC_HANDLE hService, SC_STATUS_TYPE dwInfoLevel, LPBYTE lpBuffer, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD th32ProcessID);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$Thread32Next(HANDLE, LPTHREADENTRY32);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$IsWow64Process(HANDLE hProcess, PBOOL Wow64Process);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$SuspendThread(HANDLE hThread);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ResumeThread(HANDLE hThread);
WINBASEAPI int __cdecl MSVCRT$_wcsicmp(const wchar_t *str1, const wchar_t *str2);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);


//bofstart + internal_printf + printoutput
WINBASEAPI void *__cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void *memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);

